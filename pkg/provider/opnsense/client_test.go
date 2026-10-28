package opnsense

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yasn77/senselb/pkg/provider"
)

const (
	testKey    = "testkey"
	testSecret = "testsecret"
	testUUID   = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
)

// fixtureSettings is the shape settings/get returns: the root "haproxy" key
// holding nested collections, with enum fields encoded as select objects.
const fixtureSettings = `{
  "haproxy": {
    "general": {
      "enabled": "1",
      "tuning": {"value": "default", "selected": 1}
    },
    "frontends": {
      "frontend": {
        "f47ac10b-58cc-4372-a567-0e02b2c3d479": {
          "name": "web",
          "mode": {"value": "http", "selected": 1},
          "linkedActions": {"action": ["a1"], "selected": 1}
        }
      }
    },
    "backends": {"backend": {}},
    "servers": {"server": {}},
    "acls": {"acl": {}},
    "actions": {"action": {}},
    "healthchecks": {"healthcheck": {}},
    "groups": {},
    "users": {},
    "resolvers": {},
    "mailers": {},
    "errorfiles": {},
    "mapfiles": {},
    "luas": {},
    "fcgis": {},
    "cpus": {}
  }
}`

// recordedRequest captures everything a test asserts about a request.
type recordedRequest struct {
	Method        string
	Path          string
	ContentType   string
	Accept        string
	Authorization string
	Body          string
}

// fakeAPI is an httptest server implementing the subset of the plugin API the
// client uses, recording every request.
type fakeAPI struct {
	t      *testing.T
	server *httptest.Server

	mu               sync.Mutex
	requests         []recordedRequest
	configTestResult string
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()

	api := &fakeAPI{
		t:                t,
		configTestResult: "Configuration file is valid",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/haproxy/settings/get", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, fixtureSettings)
	})
	mux.HandleFunc("POST /api/haproxy/settings/addServer", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, `{"result":"saved","uuid":"`+testUUID+`"}`)
	})
	mux.HandleFunc("POST /api/haproxy/settings/addBackend", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, `{"result":"failed","validations":{"name":"must be unique","balance":"unknown algorithm"}}`)
	})
	mux.HandleFunc("POST /api/haproxy/settings/addAcl", func(w http.ResponseWriter, r *http.Request) {
		// Adversarial: echo the credentials the server received, and pad the
		// body so truncation is exercised.
		body := "auth=" + r.Header.Get("Authorization") + " " + strings.Repeat("failure detail ", 100)
		writeJSON(w, http.StatusInternalServerError, `{"error":"`+body+`"}`)
	})
	mux.HandleFunc("POST /api/haproxy/settings/addFrontend", func(w http.ResponseWriter, _ *http.Request) {
		// A whole-model validation failure: the plugin rejects the write without
		// naming any submitted field.
		writeJSON(w, http.StatusOK, `{"result":"failed"}`)
	})
	mux.HandleFunc("POST /api/haproxy/settings/setFrontend/{uuid}", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, `{"result":"saved"}`)
	})
	mux.HandleFunc("POST /api/haproxy/settings/delAcl/{uuid}", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, `{"result":"deleted"}`)
	})
	mux.HandleFunc("POST /api/haproxy/settings/delServer/{uuid}", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, `{"result":"not found"}`)
	})
	mux.HandleFunc("POST /api/haproxy/service/configtest", func(w http.ResponseWriter, _ *http.Request) {
		api.mu.Lock()
		result := api.configTestResult
		api.mu.Unlock()
		writeJSON(w, http.StatusOK, fmt.Sprintf(`{"result":%q}`, result))
	})
	mux.HandleFunc("POST /api/haproxy/service/reconfigure", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, `{"result":"ok"}`)
	})

	api.server = httptest.NewServer(api.recorder(mux))
	t.Cleanup(api.server.Close)
	return api
}

// recorder records each request before the mux handles it.
func (a *fakeAPI) recorder(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			a.t.Errorf("read request body: %v", err)
		}
		a.mu.Lock()
		a.requests = append(a.requests, recordedRequest{
			Method:        r.Method,
			Path:          r.URL.Path,
			ContentType:   r.Header.Get("Content-Type"),
			Accept:        r.Header.Get("Accept"),
			Authorization: r.Header.Get("Authorization"),
			Body:          string(body),
		})
		a.mu.Unlock()
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		next.ServeHTTP(w, r)
	})
}

// client returns a client pointed at the fake server.
func (a *fakeAPI) client(t *testing.T) *Client {
	t.Helper()
	client, err := NewClient(ClientConfig{
		URL:     a.server.URL + "/api/haproxy",
		Key:     testKey,
		Secret:  testSecret,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient(): %v", err)
	}
	return client
}

func (a *fakeAPI) lastRequest(t *testing.T) recordedRequest {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.requests) == 0 {
		t.Fatal("no request recorded")
	}
	return a.requests[len(a.requests)-1]
}

func (a *fakeAPI) requestCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.requests)
}

func (a *fakeAPI) setConfigTestResult(result string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.configTestResult = result
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	//nolint:gosec // body is a test fixture, never external input.
	_, _ = io.WriteString(w, body)
}

// expectedBasicAuth is the header value the fake server must receive.
func expectedBasicAuth() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(testKey+":"+testSecret))
}

// assertNoCredentials fails if either credential appears in rendered.
func assertNoCredentials(t *testing.T, context, rendered string) {
	t.Helper()
	for _, credential := range []string{testKey, testSecret, expectedBasicAuth()[len("Basic "):]} {
		if strings.Contains(rendered, credential) {
			t.Fatalf("%s discloses credential %q: %q", context, credential, rendered)
		}
	}
}

func TestNewClientValidation(t *testing.T) {
	t.Parallel()

	valid := ClientConfig{URL: "https://firewall.example.net/api/haproxy", Key: testKey, Secret: testSecret}
	tests := []struct {
		name string
		cfg  ClientConfig
		want string
	}{
		{
			name: "empty URL",
			cfg:  ClientConfig{Key: testKey, Secret: testSecret},
			want: "URL must not be empty",
		},
		{
			name: "malformed URL",
			cfg:  ClientConfig{URL: "://missing-scheme", Key: testKey, Secret: testSecret},
			want: "not a valid absolute URL",
		},
		{
			name: "unsupported scheme",
			cfg:  ClientConfig{URL: "ftp://firewall.example.net/api/haproxy", Key: testKey, Secret: testSecret},
			want: "scheme must be http or https",
		},
		{
			name: "missing host",
			cfg:  ClientConfig{URL: "https:///api/haproxy", Key: testKey, Secret: testSecret},
			want: "must include a host",
		},
		{
			name: "embedded user information",
			cfg:  ClientConfig{URL: "https://admin:" + testSecret + "@firewall.example.net/api/haproxy", Key: testKey, Secret: testSecret},
			want: "must not embed user information",
		},
		{
			name: "empty key",
			cfg:  ClientConfig{URL: valid.URL, Secret: testSecret},
			want: "key must not be empty",
		},
		{
			name: "empty secret",
			cfg:  ClientConfig{URL: valid.URL, Key: testKey},
			want: "secret must not be empty",
		},
		{
			name: "invalid CA",
			cfg: ClientConfig{
				URL:    valid.URL,
				Key:    testKey,
				Secret: testSecret,
				CA:     []byte("not a PEM certificate"),
			},
			want: "CA bundle contains no valid PEM certificate",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client, err := NewClient(test.cfg)
			if err == nil {
				t.Fatalf("NewClient() = %v, want an error", client)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("NewClient() error = %q, want it to contain %q", err, test.want)
			}
			assertNoCredentials(t, "NewClient error", err.Error())
		})
	}
}

func TestNewClientDefaultsAndTLS(t *testing.T) {
	t.Parallel()

	t.Run("default timeout", func(t *testing.T) {
		t.Parallel()
		client, err := NewClient(ClientConfig{URL: "https://firewall.example.net/api/haproxy", Key: testKey, Secret: testSecret})
		if err != nil {
			t.Fatalf("NewClient(): %v", err)
		}
		if got := client.httpClient.Timeout; got != DefaultTimeout {
			t.Fatalf("Timeout = %s, want %s", got, DefaultTimeout)
		}
	})

	t.Run("configured timeout", func(t *testing.T) {
		t.Parallel()
		client, err := NewClient(ClientConfig{
			URL:     "https://firewall.example.net/api/haproxy",
			Key:     testKey,
			Secret:  testSecret,
			Timeout: 3 * time.Second,
		})
		if err != nil {
			t.Fatalf("NewClient(): %v", err)
		}
		if got := client.httpClient.Timeout; got != 3*time.Second {
			t.Fatalf("Timeout = %s, want 3s", got)
		}
	})

	t.Run("insecure skip verify", func(t *testing.T) {
		t.Parallel()
		client, err := NewClient(ClientConfig{
			URL:                "https://firewall.example.net/api/haproxy",
			Key:                testKey,
			Secret:             testSecret,
			InsecureSkipVerify: true,
		})
		if err != nil {
			t.Fatalf("NewClient(): %v", err)
		}
		transport, ok := client.httpClient.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("Transport = %T, want *http.Transport", client.httpClient.Transport)
		}
		if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
			t.Fatal("TLSClientConfig.InsecureSkipVerify = false, want true")
		}
	})

	t.Run("CA pool", func(t *testing.T) {
		t.Parallel()
		ca := testCACertificate(t)
		client, err := NewClient(ClientConfig{
			URL:    "https://firewall.example.net/api/haproxy",
			Key:    testKey,
			Secret: testSecret,
			CA:     ca,
		})
		if err != nil {
			t.Fatalf("NewClient(): %v", err)
		}
		transport, ok := client.httpClient.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("Transport = %T, want *http.Transport", client.httpClient.Transport)
		}
		if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
			t.Fatal("RootCAs is nil, want the configured CA pool")
		}
	})
}

// testCACertificate returns a self-signed CA certificate in PEM form.
func testCACertificate(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "senselb-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestClientRedaction(t *testing.T) {
	t.Parallel()

	cfg := ClientConfig{
		URL:                "https://firewall.example.net/api/haproxy",
		Key:                testKey,
		Secret:             testSecret,
		InsecureSkipVerify: true,
		Timeout:            5 * time.Second,
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient(): %v", err)
	}

	rendered := []string{
		cfg.String(),
		fmt.Sprintf("%v", cfg),
		//nolint:staticcheck // The %s verb is exactly what this test exercises.
		fmt.Sprintf("%s", cfg),
		fmt.Sprintf("%+v", cfg),
		fmt.Sprintf("%#v", cfg),
		client.String(),
		fmt.Sprintf("%v", client),
		//nolint:staticcheck // The %s verb is exactly what this test exercises.
		fmt.Sprintf("%s", client),
		fmt.Sprintf("%+v", client),
		fmt.Sprintf("%#v", client),
	}
	for _, value := range rendered {
		assertNoCredentials(t, "rendered client", value)
	}
	if !strings.Contains(cfg.String(), redacted) {
		t.Fatalf("ClientConfig.String() = %q, want the %s marker", cfg.String(), redacted)
	}
	if !strings.Contains(client.String(), cfg.URL) {
		t.Fatalf("Client.String() = %q, want it to name the URL", client.String())
	}

	// A URL carrying user information must not leak it through a rendering,
	// even though NewClient rejects such a URL.
	leaky := ClientConfig{
		URL:    "https://admin:" + testSecret + "@firewall.example.net/api/haproxy?key=" + testSecret,
		Key:    testKey,
		Secret: testSecret,
	}
	assertNoCredentials(t, "rendered config with embedded user information", fmt.Sprintf("%v", leaky))
}

func TestGet(t *testing.T) {
	t.Parallel()

	api := newFakeAPI(t)
	settings, err := api.client(t).Get()
	if err != nil {
		t.Fatalf("Get(): %v", err)
	}

	request := api.lastRequest(t)
	if request.Method != http.MethodGet || request.Path != "/api/haproxy/settings/get" {
		t.Fatalf("request = %s %s, want GET /api/haproxy/settings/get", request.Method, request.Path)
	}
	if request.Authorization != expectedBasicAuth() {
		t.Fatalf("Authorization = %q, want the Basic credentials", request.Authorization)
	}
	if request.ContentType != "" {
		t.Fatalf("Content-Type = %q, want none on a GET", request.ContentType)
	}
	if request.Body != "" {
		t.Fatalf("body = %q, want empty on a GET", request.Body)
	}
	if request.Accept != "application/json" {
		t.Fatalf("Accept = %q, want application/json", request.Accept)
	}

	// The root key is preserved and the enum select objects decode as maps.
	root, ok := settings["haproxy"].(map[string]any)
	if !ok {
		t.Fatalf("settings[haproxy] = %T, want map[string]any", settings["haproxy"])
	}
	frontends := root["frontends"].(map[string]any)["frontend"].(map[string]any)
	frontend := frontends[testUUID].(map[string]any)
	if frontend["name"] != "web" {
		t.Fatalf("frontend name = %v, want web", frontend["name"])
	}
	mode := frontend["mode"].(map[string]any)
	if mode["value"] != "http" || mode["selected"] != float64(1) {
		t.Fatalf("mode = %#v, want the http select object", mode)
	}
	if _, ok := root["healthchecks"].(map[string]any)["healthcheck"]; !ok {
		t.Fatal("healthchecks.healthcheck is missing from the decoded payload")
	}
}

func TestAdd(t *testing.T) {
	t.Parallel()

	api := newFakeAPI(t)
	form := url.Values{
		"server[name]":    {"web-1"},
		"server[address]": {"1.2.3.4"},
		"server[port]":    {"8080"},
	}
	uuid, err := api.client(t).Add(kindServer, form)
	if err != nil {
		t.Fatalf("Add(): %v", err)
	}
	if uuid != testUUID {
		t.Fatalf("Add() uuid = %q, want %q", uuid, testUUID)
	}

	request := api.lastRequest(t)
	if request.Method != http.MethodPost || request.Path != "/api/haproxy/settings/addServer" {
		t.Fatalf("request = %s %s, want POST /api/haproxy/settings/addServer", request.Method, request.Path)
	}
	if request.ContentType != "application/x-www-form-urlencoded" {
		t.Fatalf("Content-Type = %q, want form encoding", request.ContentType)
	}
	if request.Authorization != expectedBasicAuth() {
		t.Fatalf("Authorization = %q, want the Basic credentials", request.Authorization)
	}
	if request.Body != form.Encode() {
		t.Fatalf("body = %q, want %q", request.Body, form.Encode())
	}
	if strings.HasPrefix(strings.TrimSpace(request.Body), "{") {
		t.Fatalf("body = %q, want form encoding rather than JSON", request.Body)
	}
	parsed, err := url.ParseQuery(request.Body)
	if err != nil {
		t.Fatalf("ParseQuery(%q): %v", request.Body, err)
	}
	for key := range parsed {
		if !strings.HasPrefix(key, "server[") {
			t.Fatalf("form key %q does not carry the server prefix", key)
		}
	}
}

func TestFormPrefixGuard(t *testing.T) {
	t.Parallel()

	api := newFakeAPI(t)
	client := api.client(t)

	if _, err := client.Add(kindBackend, url.Values{"server[name]": {"web"}}); err == nil {
		t.Fatal("Add() = nil, want a form prefix error")
	} else if !strings.Contains(err.Error(), `does not use the backend[...] prefix`) {
		t.Fatalf("Add() error = %q, want it to name the required prefix", err)
	}
	if err := client.Set(kindServer, testUUID, url.Values{"backend[name]": {"web"}}); err == nil {
		t.Fatal("Set() = nil, want a form prefix error")
	}
	if api.requestCount() != 0 {
		t.Fatalf("requests = %d, want none for a mismatched prefix", api.requestCount())
	}

	// Repeated multi-select keys are legitimate.
	if err := client.Set(kindFrontend, testUUID, url.Values{"frontend[linkedActions][]": {testUUID}}); err != nil {
		t.Fatalf("Set() with a repeated multi-select key = %v, want nil", err)
	}
}

func TestAddValidationFailure(t *testing.T) {
	t.Parallel()

	api := newFakeAPI(t)
	_, err := api.client(t).Add(kindBackend, url.Values{"backend[name]": {"web"}})
	if err == nil {
		t.Fatal("Add() = nil, want a validation error")
	}

	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("Add() error = %T, want *ValidationError", err)
	}
	if validation.Kind != kindBackend {
		t.Fatalf("Kind = %q, want %q", validation.Kind, kindBackend)
	}
	if validation.Fields["name"] != "must be unique" {
		t.Fatalf("Fields[name] = %q, want must be unique", validation.Fields["name"])
	}
	if got, want := err.Error(), "opnsense: Backend validation failed: balance: unknown algorithm; name: must be unique"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	assertNoCredentials(t, "validation error", err.Error())
}

// TestValidationFailureWithoutDetail covers a plugin rejection that names no
// field: the error still explains the likely cause.
func TestValidationFailureWithoutDetail(t *testing.T) {
	t.Parallel()

	api := newFakeAPI(t)
	_, err := api.client(t).Add(kindFrontend, url.Values{"frontend[name]": {"web"}})

	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("Add() error = %T, want *ValidationError", err)
	}
	if len(validation.Fields) != 1 {
		t.Fatalf("Fields = %v, want one fallback entry", validation.Fields)
	}
	message, ok := validation.Fields[validationFallbackField]
	if !ok {
		t.Fatalf("Fields = %v, want the %q fallback entry", validation.Fields, validationFallbackField)
	}
	if !strings.Contains(message, "whole-model") {
		t.Errorf("fallback message = %q, want it to name a whole-model failure", message)
	}
	if got, want := err.Error(),
		"opnsense: Frontend validation failed: (form): "+message; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestSet(t *testing.T) {
	t.Parallel()

	api := newFakeAPI(t)
	form := url.Values{"frontend[name]": {"web"}}
	if err := api.client(t).Set(kindFrontend, testUUID, form); err != nil {
		t.Fatalf("Set(): %v", err)
	}

	request := api.lastRequest(t)
	wantPath := "/api/haproxy/settings/setFrontend/" + testUUID
	if request.Method != http.MethodPost || request.Path != wantPath {
		t.Fatalf("request = %s %s, want POST %s", request.Method, request.Path, wantPath)
	}
	if request.ContentType != "application/x-www-form-urlencoded" {
		t.Fatalf("Content-Type = %q, want form encoding", request.ContentType)
	}
	if request.Body != form.Encode() {
		t.Fatalf("body = %q, want %q", request.Body, form.Encode())
	}
}

func TestDel(t *testing.T) {
	t.Parallel()

	t.Run("deleted is success", func(t *testing.T) {
		t.Parallel()
		api := newFakeAPI(t)
		if err := api.client(t).Del(kindACL, testUUID); err != nil {
			t.Fatalf("Del(): %v", err)
		}
		request := api.lastRequest(t)
		wantPath := "/api/haproxy/settings/delAcl/" + testUUID
		if request.Method != http.MethodPost || request.Path != wantPath {
			t.Fatalf("request = %s %s, want POST %s", request.Method, request.Path, wantPath)
		}
		if request.Body != "" {
			t.Fatalf("body = %q, want empty", request.Body)
		}
	})

	t.Run("not found is success", func(t *testing.T) {
		t.Parallel()
		api := newFakeAPI(t)
		if err := api.client(t).Del(kindServer, testUUID); err != nil {
			t.Fatalf("Del() on a missing object = %v, want nil", err)
		}
	})

	t.Run("empty uuid", func(t *testing.T) {
		t.Parallel()
		api := newFakeAPI(t)
		err := api.client(t).Del(kindServer, "")
		if err == nil || !strings.Contains(err.Error(), "uuid must not be empty") {
			t.Fatalf("Del() = %v, want a uuid error", err)
		}
		if api.requestCount() != 0 {
			t.Fatalf("requests = %d, want none", api.requestCount())
		}
	})
}

func TestUnknownKind(t *testing.T) {
	t.Parallel()

	api := newFakeAPI(t)
	client := api.client(t)

	if _, err := client.Add("Frobnicator", nil); err == nil {
		t.Fatal("Add() = nil, want an unknown kind error")
	} else {
		var unknown *UnknownKindError
		if !errors.As(err, &unknown) {
			t.Fatalf("Add() error = %T, want *UnknownKindError", err)
		}
		if unknown.Kind != "Frobnicator" {
			t.Fatalf("Kind = %q, want Frobnicator", unknown.Kind)
		}
		if !strings.Contains(err.Error(), "Action") || !strings.Contains(err.Error(), "Server") {
			t.Fatalf("Error() = %q, want it to list the supported kinds", err)
		}
	}
	if err := client.Set("Backends", testUUID, nil); err == nil {
		t.Fatal("Set() = nil, want an unknown kind error")
	}
	if err := client.Del("", testUUID); err == nil {
		t.Fatal("Del() = nil, want an unknown kind error")
	}
	if api.requestCount() != 0 {
		t.Fatalf("requests = %d, want none for rejected kinds", api.requestCount())
	}
}

func TestFormPrefix(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		kindFrontend:    "frontend",
		kindBackend:     "backend",
		kindServer:      "server",
		kindACL:         "acl",
		kindAction:      "action",
		kindHealthcheck: "healthcheck",
	}
	for kind, want := range tests {
		got, err := formPrefix(kind)
		if err != nil {
			t.Fatalf("formPrefix(%q): %v", kind, err)
		}
		if got != want {
			t.Fatalf("formPrefix(%q) = %q, want %q", kind, got, want)
		}
	}
	if _, err := formPrefix("frontend"); err == nil {
		t.Fatal("formPrefix(\"frontend\") = nil error, want a rejection of the lowercase spelling")
	}
}

func TestAPIError(t *testing.T) {
	t.Parallel()

	api := newFakeAPI(t)
	_, err := api.client(t).Add(kindACL, url.Values{"acl[name]": {"api"}})
	if err == nil {
		t.Fatal("Add() = nil, want an API error")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("Add() error = %T, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("StatusCode = %d, want 500", apiErr.StatusCode)
	}
	if len(apiErr.Body) > maxErrorBody+len(truncationSuffix) {
		t.Fatalf("Body length = %d, want at most %d", len(apiErr.Body), maxErrorBody+len(truncationSuffix))
	}
	if !strings.HasSuffix(apiErr.Body, truncationSuffix) {
		t.Fatalf("Body = %q, want the truncation suffix", apiErr.Body)
	}
	if !strings.Contains(apiErr.Body, redacted) {
		t.Fatalf("Body = %q, want the echoed Authorization header scrubbed", apiErr.Body)
	}
	assertNoCredentials(t, "API error", err.Error())
}

func TestTransportErrorHidesCredentials(t *testing.T) {
	t.Parallel()

	// Port 1 on the loopback interface refuses connections.
	client, err := NewClient(ClientConfig{
		URL:     "http://127.0.0.1:1/api/haproxy",
		Key:     testKey,
		Secret:  testSecret,
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient(): %v", err)
	}
	if _, err := client.Get(); err == nil {
		t.Fatal("Get() = nil, want a transport error")
	} else {
		assertNoCredentials(t, "transport error", err.Error())
	}
}

// TestNoAmbientProxy covers the point-to-point transport: an ambient proxy
// variable must not receive the firewall's Basic credentials. The fake server
// listens on http://, so a consulted HTTP_PROXY would fail the request outright.
func TestNoAmbientProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")

	api := newFakeAPI(t)
	client := api.client(t)

	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *http.Transport", client.httpClient.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("transport consults a proxy, want a direct connection")
	}

	if _, err := client.Get(); err != nil {
		t.Fatalf("Get() = %v, want the direct request to succeed", err)
	}
}

func TestRedirectRefused(t *testing.T) {
	t.Parallel()

	var followed atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/haproxy/settings/get", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})
	mux.HandleFunc("GET /elsewhere", func(w http.ResponseWriter, _ *http.Request) {
		followed.Add(1)
		writeJSON(w, http.StatusOK, `{}`)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client, err := NewClient(ClientConfig{URL: server.URL + "/api/haproxy", Key: testKey, Secret: testSecret})
	if err != nil {
		t.Fatalf("NewClient(): %v", err)
	}
	if _, err := client.Get(); err == nil {
		t.Fatal("Get() = nil, want the redirect reported as an API error")
	} else {
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("Get() error = %T, want *APIError", err)
		}
		if apiErr.StatusCode != http.StatusFound {
			t.Fatalf("StatusCode = %d, want 302", apiErr.StatusCode)
		}
	}
	if got := followed.Load(); got != 0 {
		t.Fatalf("redirect was followed %d times, want 0", got)
	}
}

func TestTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		writeJSON(w, http.StatusOK, `{}`)
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(ClientConfig{
		URL:     server.URL + "/api/haproxy",
		Key:     testKey,
		Secret:  testSecret,
		Timeout: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient(): %v", err)
	}
	if _, err := client.Get(); err == nil {
		t.Fatal("Get() = nil, want a timeout error")
	} else {
		assertNoCredentials(t, "timeout error", err.Error())
	}
}

func TestConfigTest(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		api := newFakeAPI(t)
		if err := api.client(t).ConfigTest(); err != nil {
			t.Fatalf("ConfigTest(): %v", err)
		}
		request := api.lastRequest(t)
		if request.Method != http.MethodPost || request.Path != "/api/haproxy/service/configtest" {
			t.Fatalf("request = %s %s, want POST /api/haproxy/service/configtest", request.Method, request.Path)
		}
		if request.Body != "" {
			t.Fatalf("body = %q, want empty", request.Body)
		}
	})

	t.Run("failure markers", func(t *testing.T) {
		t.Parallel()
		for _, result := range []string{
			"Fatal errors found in configuration",
			"[ALERT] backend 'web' has no server available (failed)",
			"configuration test FAILED",
		} {
			t.Run(result, func(t *testing.T) {
				t.Parallel()
				api := newFakeAPI(t)
				api.setConfigTestResult(result)

				err := api.client(t).ConfigTest()
				var configErr *provider.ErrConfigTest
				if !errors.As(err, &configErr) {
					t.Fatalf("ConfigTest() = %v, want *provider.ErrConfigTest", err)
				}
				if configErr.Message != result {
					t.Fatalf("Message = %q, want the complete output %q", configErr.Message, result)
				}
			})
		}
	})

	t.Run("warning lines are ignored", func(t *testing.T) {
		t.Parallel()
		api := newFakeAPI(t)
		api.setConfigTestResult(strings.Join([]string{
			"[WARNING] backend 'senselb-web-errors' is unreachable (failed health check)",
			"[WARNING] (config validation error suppressed for foreign_backend)",
			"Configuration file is valid",
		}, "\n"))

		if err := api.client(t).ConfigTest(); err != nil {
			t.Fatalf("ConfigTest() = %v, want nil: a warning must not fail the test", err)
		}
	})

	t.Run("error after a warning still fails", func(t *testing.T) {
		t.Parallel()
		api := newFakeAPI(t)
		api.setConfigTestResult("[WARNING] ignored\nFatal errors found in configuration")

		var configErr *provider.ErrConfigTest
		if err := api.client(t).ConfigTest(); !errors.As(err, &configErr) {
			t.Fatalf("ConfigTest() = %v, want *provider.ErrConfigTest", err)
		}
		if !strings.Contains(configErr.Message, "[WARNING]") {
			t.Error("Message dropped the plugin's complete output")
		}
	})

	t.Run("unstructured response", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, "<html>not json</html>")
		}))
		t.Cleanup(server.Close)

		client, err := NewClient(ClientConfig{URL: server.URL + "/api/haproxy", Key: testKey, Secret: testSecret})
		if err != nil {
			t.Fatalf("NewClient(): %v", err)
		}
		if err := client.ConfigTest(); err == nil || !strings.Contains(err.Error(), "decode service/configtest response") {
			t.Fatalf("ConfigTest() = %v, want a decode error", err)
		}
	})
}

func TestReconfigure(t *testing.T) {
	t.Parallel()

	api := newFakeAPI(t)
	if err := api.client(t).Reconfigure(); err != nil {
		t.Fatalf("Reconfigure(): %v", err)
	}
	request := api.lastRequest(t)
	if request.Method != http.MethodPost || request.Path != "/api/haproxy/service/reconfigure" {
		t.Fatalf("request = %s %s, want POST /api/haproxy/service/reconfigure", request.Method, request.Path)
	}
	if request.Body != "" {
		t.Fatalf("body = %q, want empty", request.Body)
	}
}

func TestWithLockSerialises(t *testing.T) {
	t.Parallel()

	client, err := NewClient(ClientConfig{
		URL:    "https://firewall.example.net/api/haproxy",
		Key:    testKey,
		Secret: testSecret,
	})
	if err != nil {
		t.Fatalf("NewClient(): %v", err)
	}

	const goroutines = 32
	var (
		active    atomic.Int32
		peak      atomic.Int32
		completed atomic.Int32
	)
	errs := make(chan error, goroutines)
	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := client.WithLock(func() error {
				current := active.Add(1)
				for {
					observed := peak.Load()
					if current <= observed || peak.CompareAndSwap(observed, current) {
						break
					}
				}
				defer active.Add(-1)
				time.Sleep(time.Millisecond)
				completed.Add(1)
				return nil
			})
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("WithLock() = %v, want nil", err)
	}
	if got := completed.Load(); got != goroutines {
		t.Fatalf("completed = %d, want %d", got, goroutines)
	}
	if got := peak.Load(); got != 1 {
		t.Fatalf("peak concurrent holders = %d, want 1", got)
	}
}

func TestWithLockReleaseOnError(t *testing.T) {
	t.Parallel()

	client, err := NewClient(ClientConfig{
		URL:    "https://firewall.example.net/api/haproxy",
		Key:    testKey,
		Secret: testSecret,
	})
	if err != nil {
		t.Fatalf("NewClient(): %v", err)
	}

	wantErr := errors.New("mutation failed")
	if err := client.WithLock(func() error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("WithLock() = %v, want %v", err, wantErr)
	}
	// The lock must have been released despite the error.
	if err := client.WithLock(func() error { return nil }); err != nil {
		t.Fatalf("second WithLock() = %v, want nil", err)
	}
	if err := client.WithLock(nil); err == nil {
		t.Fatal("WithLock(nil) = nil, want an error")
	}
}

func TestWriteResponseWithoutUUID(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, `{"result":"saved"}`)
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(ClientConfig{URL: server.URL + "/api/haproxy", Key: testKey, Secret: testSecret})
	if err != nil {
		t.Fatalf("NewClient(): %v", err)
	}
	if _, err := client.Add(kindServer, nil); err == nil || !strings.Contains(err.Error(), "no uuid") {
		t.Fatalf("Add() = %v, want a missing uuid error", err)
	}
}

func TestUnexpectedResults(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/haproxy/settings/addServer":
			writeJSON(w, http.StatusOK, `{"result":"mystery"}`)
		case "/api/haproxy/settings/setServer/x":
			writeJSON(w, http.StatusOK, `{"result":"not found"}`)
		case "/api/haproxy/settings/delServer/x":
			writeJSON(w, http.StatusOK, `{"result":"mystery"}`)
		default:
			writeJSON(w, http.StatusOK, `{"result":"ok"}`)
		}
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(ClientConfig{URL: server.URL + "/api/haproxy", Key: testKey, Secret: testSecret})
	if err != nil {
		t.Fatalf("NewClient(): %v", err)
	}

	if _, err := client.Add(kindServer, nil); err == nil || !strings.Contains(err.Error(), `unexpected result "mystery"`) {
		t.Fatalf("Add() = %v, want an unexpected result error", err)
	}
	if err := client.Set(kindServer, "x", nil); err == nil || !strings.Contains(err.Error(), `unexpected result "not found"`) {
		t.Fatalf("Set() = %v, want an unexpected result error", err)
	}
	if err := client.Del(kindServer, "x"); err == nil || !strings.Contains(err.Error(), `unexpected result "mystery"`) {
		t.Fatalf("Del() = %v, want an unexpected result error", err)
	}
}

func TestMalformedWriteResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, `not json`)
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(ClientConfig{URL: server.URL + "/api/haproxy", Key: testKey, Secret: testSecret})
	if err != nil {
		t.Fatalf("NewClient(): %v", err)
	}
	if _, err := client.Add(kindServer, nil); err == nil || !strings.Contains(err.Error(), "decode write response") {
		t.Fatalf("Add() = %v, want a decode error", err)
	}
}
