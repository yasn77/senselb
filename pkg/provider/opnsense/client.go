// Package opnsense implements the REST client for the OPNsense os-haproxy
// plugin API that the senselb OPNsense provider builds on.
//
// The client speaks the plugin's legacy MVC API: reads are GET requests that
// return JSON, while writes are form-encoded POSTs whose single top-level key
// is the singular model prefix, for example server[name] for a server object.
// Credentials travel in an HTTP Basic header and are never rendered in logs or
// error messages.
package opnsense

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/yasn77/senselb/pkg/provider"
)

const (
	// DefaultTimeout bounds a request when ClientConfig.Timeout is zero.
	DefaultTimeout = 30 * time.Second

	// redacted replaces credentials in any rendered configuration or error.
	redacted = "<redacted>"

	// maxErrorBody caps the response body retained in an APIError so that a
	// large failure page cannot flood the log.
	maxErrorBody = 512

	// truncationSuffix marks a capped APIError body.
	truncationSuffix = "… (truncated)"
)

// Object kinds are the singular model names the plugin endpoints and form
// prefixes are derived from.
const (
	kindFrontend    = "Frontend"
	kindBackend     = "Backend"
	kindServer      = "Server"
	kindACL         = "Acl"
	kindAction      = "Action"
	kindHealthcheck = "Healthcheck"
)

// The plugin reports a successful write with one of these result values.
const (
	resultSaved    = "saved"
	resultDeleted  = "deleted"
	resultNotFound = "not found"
	resultFailed   = "failed"
)

// configTestFailureMarkers are the case-insensitive substrings that mark a
// failed configuration test. The plugin returns the configd output as a plain
// string and offers no structured status, so the client treats any output that
// mentions an error or a failure as a failure. The provider phase may refine
// this heuristic.
var configTestFailureMarkers = []string{"error", "failed"}

// objectKinds maps each accepted kind to the singular, lowercase model prefix
// the plugin uses as the top-level form key. The same kind name is also the
// endpoint suffix: settings/addBackend, settings/setFrontend/<uuid>, and so on.
var objectKinds = map[string]string{
	kindFrontend:    "frontend",
	kindBackend:     "backend",
	kindServer:      "server",
	kindACL:         "acl",
	kindAction:      "action",
	kindHealthcheck: "healthcheck",
}

// ClientConfig configures a Client.
type ClientConfig struct {
	// URL is the full API base URL, including the /api/haproxy path, for
	// example https://firewall.example.net:8443/api/haproxy.
	URL string
	// Key and Secret are the OPNsense API credentials used for HTTP Basic
	// authentication.
	Key    string
	Secret string
	// InsecureSkipVerify disables certificate verification. OPNsense commonly
	// serves a self-signed certificate on a management port, so the operator
	// must opt in to this weakening of transport security.
	InsecureSkipVerify bool
	// CA is an optional PEM-encoded CA bundle. A nil value uses the system
	// certificate pool.
	CA []byte
	// Timeout bounds each request. A zero or negative value selects
	// DefaultTimeout.
	Timeout time.Duration
}

// String renders the configuration with both credentials redacted. It exists so
// that %v, %s and %q of a ClientConfig can never disclose the key or secret.
func (c ClientConfig) String() string {
	ca := "<system pool>"
	if c.CA != nil {
		ca = fmt.Sprintf("%d bytes", len(c.CA))
	}
	return fmt.Sprintf(
		"opnsense.ClientConfig{URL: %q, Key: %s, Secret: %s, InsecureSkipVerify: %t, CA: %s, Timeout: %s}",
		redactURL(c.URL),
		redact(c.Key),
		redact(c.Secret),
		c.InsecureSkipVerify,
		ca,
		c.Timeout,
	)
}

// GoString implements fmt.GoStringer so that %#v is redacted as well.
func (c ClientConfig) GoString() string { return c.String() }

// redact renders a credential value for logs without disclosing it.
func redact(string) string { return redacted }

// redactURL renders a URL for logs after removing user information and the
// query, either of which may carry a credential. An unparseable URL is replaced
// entirely rather than echoed.
func redactURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return redacted
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

// Client is an HTTP client for one OPNsense firewall's HAProxy plugin. It is
// safe for concurrent use.
//
// Mutation primitives (Add, Set and Del) do not lock; the plugin serialises
// writes with a server-side configuration lock and rejects overlapping ones, so
// a caller must run every mutation sequence inside WithLock. Read-only methods
// need no lock.
type Client struct {
	baseURL    *url.URL
	auth       string
	httpClient *http.Client
	mutation   sync.Mutex
}

// String renders the client with its credentials redacted.
func (c *Client) String() string {
	return fmt.Sprintf("opnsense.Client{URL: %q}", c.baseURL.Redacted())
}

// GoString implements fmt.GoStringer so that %#v is redacted as well.
func (c *Client) GoString() string { return c.String() }

// NewClient validates cfg and returns a client for it.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.URL == "" {
		return nil, errors.New("opnsense: URL must not be empty")
	}
	if cfg.Key == "" {
		return nil, errors.New("opnsense: key must not be empty")
	}
	if cfg.Secret == "" {
		return nil, errors.New("opnsense: secret must not be empty")
	}

	// The parse error is deliberately not wrapped: Go's url.Error quotes the
	// offending URL, which may embed user information.
	base, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, errors.New("opnsense: URL is not a valid absolute URL")
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, errors.New("opnsense: URL scheme must be http or https")
	}
	if base.Host == "" {
		return nil, errors.New("opnsense: URL must include a host")
	}
	if base.User != nil {
		return nil, errors.New("opnsense: URL must not embed user information; supply Key and Secret separately")
	}
	base.Path = strings.TrimSuffix(base.Path, "/")

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		//nolint:gosec // A self-signed management-port certificate is the normal deployment; the operator opts in.
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}
	if cfg.CA != nil {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(cfg.CA) {
			return nil, errors.New("opnsense: CA bundle contains no valid PEM certificate")
		}
		tlsConfig.RootCAs = pool
	}

	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		baseTransport = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	transport := baseTransport.Clone()
	transport.TLSClientConfig = tlsConfig
	// The firewall API is point-to-point. Honouring an ambient HTTPS_PROXY would
	// route the Basic credentials through an arbitrary proxy, so the client
	// never proxies.
	transport.Proxy = nil

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	return &Client{
		baseURL: base,
		auth:    base64.StdEncoding.EncodeToString([]byte(cfg.Key + ":" + cfg.Secret)),
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			// A redirect signals a misconfigured API base URL. Refusing to
			// follow it also keeps the Authorization header from being
			// replayed to another location.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Settings is the raw decoded settings/get payload. The plugin's root "haproxy"
// key is preserved exactly as returned; the client does not map it onto the
// canonical model, and callers navigate the nested maps themselves.
type Settings map[string]any

// Get reads the complete plugin configuration with GET settings/get.
func (c *Client) Get() (Settings, error) {
	body, err := c.get("settings/get")
	if err != nil {
		return nil, err
	}
	var settings Settings
	if err := json.Unmarshal(body, &settings); err != nil {
		return nil, fmt.Errorf("opnsense: decode settings/get response: %w", err)
	}
	return settings, nil
}

// Add creates an object with POST settings/add<Kind> and returns the uuid the
// plugin assigned.
func (c *Client) Add(kind string, form url.Values) (string, error) {
	prefix, err := formPrefix(kind)
	if err != nil {
		return "", err
	}
	if err := validateForm(prefix, form); err != nil {
		return "", err
	}
	body, err := c.postForm("settings/add"+kind, form)
	if err != nil {
		return "", err
	}
	result, err := decodeResult(body)
	if err != nil {
		return "", err
	}
	switch result.Result {
	case resultSaved:
		if result.UUID == "" {
			return "", fmt.Errorf("opnsense: add %s: response carries no uuid", kind)
		}
		return result.UUID, nil
	case resultFailed:
		return "", newValidationError(kind, result.Validations)
	default:
		return "", fmt.Errorf("opnsense: add %s: unexpected result %q", kind, result.Result)
	}
}

// Set creates or updates the object with the given uuid using
// POST settings/set<Kind>/<uuid>.
//
// The endpoint has upsert semantics: a valid client-chosen uuid that does not
// yet exist is created.
func (c *Client) Set(kind, uuid string, form url.Values) error {
	prefix, err := formPrefix(kind)
	if err != nil {
		return err
	}
	if err := validateForm(prefix, form); err != nil {
		return err
	}
	if uuid == "" {
		return fmt.Errorf("opnsense: set %s: uuid must not be empty", kind)
	}
	body, err := c.postForm("settings/set"+kind+"/"+url.PathEscape(uuid), form)
	if err != nil {
		return err
	}
	result, err := decodeResult(body)
	if err != nil {
		return err
	}
	switch result.Result {
	case resultSaved:
		return nil
	case resultFailed:
		return newValidationError(kind, result.Validations)
	default:
		return fmt.Errorf("opnsense: set %s %s: unexpected result %q", kind, uuid, result.Result)
	}
}

// Del deletes the object with the given uuid using
// POST settings/del<Kind>/<uuid>.
//
// A plugin response of "not found" is treated as success, because the desired
// state (the object is absent) already holds; this keeps deletes idempotent for
// a retrying reconciler. Every other unexpected result is an error.
func (c *Client) Del(kind, uuid string) error {
	if _, err := formPrefix(kind); err != nil {
		return err
	}
	if uuid == "" {
		return fmt.Errorf("opnsense: delete %s: uuid must not be empty", kind)
	}
	body, err := c.postForm("settings/del"+kind+"/"+url.PathEscape(uuid), nil)
	if err != nil {
		return err
	}
	result, err := decodeResult(body)
	if err != nil {
		return err
	}
	switch result.Result {
	case resultDeleted, resultNotFound:
		return nil
	default:
		return fmt.Errorf("opnsense: delete %s %s: unexpected result %q", kind, uuid, result.Result)
	}
}

// ConfigTest asks the plugin to syntax-check the generated HAProxy
// configuration with POST service/configtest.
//
// The plugin returns the configd output as an unstructured string, so the
// client treats the check as failed when that string contains "error" or
// "failed" in any case. Lines the plugin emitted at WARNING level are removed
// first: a warning echoes object names and addresses, which can contain those
// substrings, and rollback on a warning would revert a valid configuration. A
// failed check returns *provider.ErrConfigTest carrying the complete output.
func (c *Client) ConfigTest() error {
	body, err := c.postAction("service/configtest")
	if err != nil {
		return err
	}
	var result struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("opnsense: decode service/configtest response: %w", err)
	}
	lowered := strings.ToLower(stripWarningLines(result.Result))
	for _, marker := range configTestFailureMarkers {
		if strings.Contains(lowered, marker) {
			return &provider.ErrConfigTest{Message: result.Result}
		}
	}
	return nil
}

// stripWarningLines removes the log lines the plugin marked as a warning, so the
// failure scan only reads lines that report an outcome.
func stripWarningLines(output string) string {
	lines := strings.Split(output, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "[warning]") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// Reconfigure regenerates the configuration and gracefully reloads HAProxy with
// POST service/reconfigure. An HTTP 200 means the plugin accepted the request;
// the reload outcome is verified by the following ConfigTest.
func (c *Client) Reconfigure() error {
	_, err := c.postAction("service/reconfigure")
	return err
}

// WithLock runs fn while holding the client's mutation lock, serialising an
// entire mutation sequence among goroutines. The lock is released even when fn
// returns an error, and that error is returned unchanged.
//
// Within fn, call Add, Set and Del directly: they do not take the lock
// themselves, so nesting WithLock would deadlock.
func (c *Client) WithLock(fn func() error) error {
	if fn == nil {
		return errors.New("opnsense: WithLock requires a function")
	}
	c.mutation.Lock()
	defer c.mutation.Unlock()
	return fn()
}

// formPrefix returns the singular, lowercase form key for kind, rejecting an
// unsupported kind with an *UnknownKindError. The mapper reuses it so that the
// kind-to-prefix mapping has exactly one definition.
func formPrefix(kind string) (string, error) {
	prefix, ok := objectKinds[kind]
	if !ok {
		return "", &UnknownKindError{Kind: kind}
	}
	return prefix, nil
}

// supportedKinds lists the accepted kinds in lexical order.
func supportedKinds() []string {
	kinds := make([]string, 0, len(objectKinds))
	for kind := range objectKinds {
		kinds = append(kinds, kind)
	}
	slices.Sort(kinds)
	return kinds
}

// validateForm rejects a form whose keys do not carry the kind's singular
// prefix, catching a mapper mistake before the write reaches the plugin. A nil
// or empty form is valid.
func validateForm(prefix string, form url.Values) error {
	for key := range form {
		if !strings.HasPrefix(key, prefix+"[") {
			return fmt.Errorf("opnsense: form field %q does not use the %s[...] prefix", key, prefix)
		}
	}
	return nil
}

// UnknownKindError reports an object kind the client does not support.
type UnknownKindError struct {
	// Kind is the rejected value.
	Kind string
}

// Error implements error.
func (e *UnknownKindError) Error() string {
	return fmt.Sprintf(
		"opnsense: unknown object kind %q (want one of %s)",
		e.Kind,
		strings.Join(supportedKinds(), ", "),
	)
}

// ValidationError reports a write the plugin rejected. Fields maps each
// offending form field to the plugin's message.
type ValidationError struct {
	// Kind is the object kind of the rejected write.
	Kind string
	// Fields carries one message per invalid form field.
	Fields map[string]string
}

// Error implements error, sorting fields so the message is deterministic.
func (e *ValidationError) Error() string {
	if len(e.Fields) == 0 {
		return fmt.Sprintf("opnsense: %s validation failed", e.Kind)
	}
	names := make([]string, 0, len(e.Fields))
	for name := range e.Fields {
		names = append(names, name)
	}
	slices.Sort(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+": "+e.Fields[name])
	}
	return fmt.Sprintf("opnsense: %s validation failed: %s", e.Kind, strings.Join(parts, "; "))
}

// APIError reports a response with an unexpected HTTP status. Body holds the
// truncated response body with any echo of the client's Authorization header
// scrubbed.
type APIError struct {
	// StatusCode is the received HTTP status code.
	StatusCode int
	// Body is the truncated, redacted response body.
	Body string
}

// Error implements error.
func (e *APIError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("opnsense: HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("opnsense: HTTP %d: %s", e.StatusCode, e.Body)
}

// validationFallbackField names the diagnostic entry used when the plugin
// rejects a write without naming any field.
const validationFallbackField = "(form)"

// newValidationError converts the plugin's validation payload into a
// ValidationError. A rejection that carries no per-field detail gets one
// synthetic entry naming the likely cause: the plugin validates the whole model
// server-side, so an invalid field anywhere in it can fail an unrelated write
// without pointing at the submitted form.
func newValidationError(kind string, validations map[string]any) *ValidationError {
	fields := make(map[string]string, len(validations))
	for field, message := range validations {
		fields[field] = fmt.Sprint(message)
	}
	if len(fields) == 0 {
		fields[validationFallbackField] =
			"the plugin rejected the write without field detail; a whole-model validation failure elsewhere in the HAProxy model is the likely cause"
	}
	return &ValidationError{Kind: kind, Fields: fields}
}

// resultEnvelope is the JSON shape shared by the plugin's write endpoints.
type resultEnvelope struct {
	Result      string         `json:"result"`
	UUID        string         `json:"uuid"`
	Validations map[string]any `json:"validations"`
}

// decodeResult decodes a write response envelope.
func decodeResult(body []byte) (resultEnvelope, error) {
	var result resultEnvelope
	if err := json.Unmarshal(body, &result); err != nil {
		return resultEnvelope{}, fmt.Errorf("opnsense: decode write response: %w", err)
	}
	return result, nil
}

// get issues a GET without a body.
func (c *Client) get(path string) ([]byte, error) {
	return c.send(http.MethodGet, path, nil, "")
}

// postForm issues a form-encoded POST. A nil form still sends an empty form body
// so that every write carries the plugin's expected Content-Type.
func (c *Client) postForm(path string, form url.Values) ([]byte, error) {
	if form == nil {
		form = url.Values{}
	}
	return c.send(
		http.MethodPost,
		path,
		strings.NewReader(form.Encode()),
		"application/x-www-form-urlencoded",
	)
}

// postAction issues a POST with no body, used by the service endpoints.
func (c *Client) postAction(path string) ([]byte, error) {
	return c.send(http.MethodPost, path, nil, "")
}

// send performs one request and returns the body of a 200 response. A non-200
// response becomes an *APIError.
func (c *Client) send(method, path string, body io.Reader, contentType string) ([]byte, error) {
	req, err := http.NewRequest(method, c.url(path), body)
	if err != nil {
		return nil, fmt.Errorf("opnsense: build %s %s request: %w", method, path, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Basic "+c.auth)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("opnsense: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("opnsense: read %s %s response: %w", method, path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Body:       truncate(c.scrub(string(data)), maxErrorBody),
		}
	}
	return data, nil
}

// url joins path onto the configured base URL.
func (c *Client) url(path string) string {
	target := *c.baseURL
	target.Path = c.baseURL.Path + "/" + path
	target.RawQuery = ""
	target.Fragment = ""
	return target.String()
}

// scrub removes the client's own Authorization header value from s, so a
// server that echoes the request cannot leak the credential through an error.
func (c *Client) scrub(s string) string {
	s = strings.ReplaceAll(s, "Basic "+c.auth, redacted)
	return strings.ReplaceAll(s, c.auth, redacted)
}

// truncate caps s at limit bytes, keeping the result valid UTF-8 and marking the
// cap with truncationSuffix.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return strings.ToValidUTF8(s[:limit], "") + truncationSuffix
}

// Compile-time assertions that the exported error types satisfy error.
var (
	_ error = (*UnknownKindError)(nil)
	_ error = (*ValidationError)(nil)
	_ error = (*APIError)(nil)
)
