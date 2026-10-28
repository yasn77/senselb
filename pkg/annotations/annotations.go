// Package annotations parses the senselb annotation set from a Service's
// annotation map and resolves it against cluster defaults and built-ins.
//
// It works on a plain map[string]string, so it depends on the Go standard
// library only: it must not import Kubernetes or any third-party package. The
// controller passes the Service's annotations and the chosen ConfigMap defaults
// in, and receives a fully resolved Values.
package annotations

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
)

// DefaultPrefix is the annotation prefix used when Parse receives an empty
// prefix. Annotation keys are looked up as prefix+name, for example
// "senselb.io/listeners".
const DefaultPrefix = "senselb.io/"

// Annotation names, excluding the prefix. Parse refers to these constants when
// building keys and when rejecting unknown keys, so a typo is a compile error
// rather than an annotation that is silently ignored.
const (
	annotationEnabled         = "enabled"
	annotationListeners       = "listeners"
	annotationHost            = "host"
	annotationPath            = "path"
	annotationSNI             = "sni"
	annotationMode            = "mode"
	annotationAlgorithm       = "algorithm"
	annotationTargetMode      = "target-mode"
	annotationHealthCheck     = "healthcheck"
	annotationHealthCheckPath = "healthcheck-path"
	annotationProxyProtocol   = "proxy-protocol"
	annotationTimeoutConnect  = "timeout-connect"
	annotationTimeoutServer   = "timeout-server"
	annotationTimeoutClient   = "timeout-client"
	annotationMaxConn         = "maxconn"
	annotationWeight          = "weight"
	annotationSticky          = "sticky"
	annotationTLS             = "tls"
	annotationTLSCert         = "tls-cert"
	annotationTLSPassthrough  = "tls-passthrough"
	annotationBackendCustom   = "backend-custom"
	annotationBackendName     = "backend-name"
)

// annotationNames is the complete annotation set in documentation order. The
// order is also the order in which Parse applies the annotations to the running
// Values, although the final result does not depend on it.
var annotationNames = []string{
	annotationEnabled,
	annotationListeners,
	annotationHost,
	annotationPath,
	annotationSNI,
	annotationMode,
	annotationAlgorithm,
	annotationTargetMode,
	annotationHealthCheck,
	annotationHealthCheckPath,
	annotationProxyProtocol,
	annotationTimeoutConnect,
	annotationTimeoutServer,
	annotationTimeoutClient,
	annotationMaxConn,
	annotationWeight,
	annotationSticky,
	annotationTLS,
	annotationTLSCert,
	annotationTLSPassthrough,
	annotationBackendCustom,
	annotationBackendName,
}

// knownAnnotations is the set used to detect misspelt senselb-prefixed keys.
var knownAnnotations = newSet(annotationNames)

// TODO(Phase-5-docs): the operator-facing reference for this package is owned by
// Phase 5, which must state all of the following. The behaviour is settled; only
// the documentation is outstanding.
//
//   (a) timeout-connect, timeout-server and timeout-client are accepted by the
//       parser but rejected as unmodelled: "timeout client" is not valid in a
//       backend block, so BuildContribution reports them and the operator
//       expresses the same intent through backend-custom, where
//       "timeout connect <duration>" and "timeout server <duration>" are valid
//       backend directives.
//   (b) tls-passthrough is parsed but not implemented in v1; it is reported as
//       an issue rather than silently ignored.
//   (c) a ConfigMap boolean default cannot disable anything: the defaults layer
//       carries no presence information, so a default may only raise a boolean
//       to true. For enabled=false the Service annotation wins and is the only
//       way to switch senselb off.
//   (d) a created listener produces a frontend named "senselb-<listener>"; the
//       configured listener name is the logical handle used in annotations. A
//       backend-name annotation must start with "senselb-", because senselb only
//       owns objects carrying that prefix.

// Allowed string values. These are the canonical spellings stored in Values.
var (
	allowedModes       = []string{"http", "tcp"}
	allowedAlgorithms  = []string{"roundrobin", "source", "leastconn", "static-rr", "uri", "random"}
	allowedTargetModes = []string{"nodeport", "endpoint"}
)

// Values is the resolved configuration for one Service after the three
// precedence layers have been applied.
//
// The yaml tags use the annotation names without their prefix, so a ConfigMap
// can carry the cluster-wide default layer under "defaults". They affect
// serialisation only: the field names and Parse behaviour are unchanged.
type Values struct {
	// Enabled selects whether senselb manages the Service at all.
	Enabled bool `yaml:"enabled,omitempty"`
	// Listeners names the HAProxy listeners the Service attaches to, in the
	// order the annotation listed them.
	Listeners []string `yaml:"listeners,omitempty"`

	Host string `yaml:"host,omitempty"`
	Path string `yaml:"path,omitempty"`
	SNI  string `yaml:"sni,omitempty"`

	// Mode is the proxy mode, either "http" or "tcp".
	Mode string `yaml:"mode,omitempty"`
	// Algorithm is the canonical load-balancing algorithm name.
	Algorithm string `yaml:"algorithm,omitempty"`
	// TargetMode selects where backend servers come from, either "nodeport"
	// or "endpoint".
	TargetMode string `yaml:"target-mode,omitempty"`

	HealthCheck     bool   `yaml:"healthcheck,omitempty"`
	HealthCheckPath string `yaml:"healthcheck-path,omitempty"`
	ProxyProtocol   bool   `yaml:"proxy-protocol,omitempty"`

	// TimeoutConnect, TimeoutServer and TimeoutClient are Go duration strings,
	// for example "5s" or "2m", validated by time.ParseDuration.
	TimeoutConnect string `yaml:"timeout-connect,omitempty"`
	TimeoutServer  string `yaml:"timeout-server,omitempty"`
	TimeoutClient  string `yaml:"timeout-client,omitempty"`

	// MaxConn is the per-server connection limit; 0 leaves it unset.
	MaxConn int `yaml:"maxconn,omitempty"`
	// Weight is the server weight; 0 is meaningful and means "no traffic".
	Weight int `yaml:"weight,omitempty"`

	Sticky bool `yaml:"sticky,omitempty"`

	TLS            bool   `yaml:"tls,omitempty"`
	TLSCert        string `yaml:"tls-cert,omitempty"`
	TLSPassthrough bool   `yaml:"tls-passthrough,omitempty"`

	BackendCustom string `yaml:"backend-custom,omitempty"`
	BackendName   string `yaml:"backend-name,omitempty"`
}

// DefaultValues returns the built-in layer of the precedence order: the values
// that apply when neither the Service nor a ConfigMap default says otherwise.
func DefaultValues() Values {
	return Values{
		Enabled:    true,
		TargetMode: "nodeport",
		Algorithm:  "roundrobin",
	}
}

// Parse resolves the annotated configuration for one Service.
//
// Precedence is Service annotations, then the defaults argument (the ConfigMap
// layer), then DefaultValues.
//
// The defaults layer carries no presence information: Values is a plain struct,
// so Parse cannot tell an intentionally zero field from an omitted one. Every
// zero value is therefore treated as unset and skipped during the overlay:
// an empty string, an empty or nil slice, 0, and false. This has one visible
// consequence for booleans: a ConfigMap default can only raise a flag to true,
// never lower it to false, so defaults.Enabled = false does not disable
// Services. To disable a Service, annotate it explicitly, for example
// "senselb.io/enabled: \"false\"". The same rule applies to weight and maxconn,
// where 0 means unset; for maxconn 0 is also the built-in, and for weight 0 is
// both the built-in and a meaningful "no traffic" value, so the effective
// result is unchanged.
//
// A key present on the Service always overrides the defaults layer, even when
// its value is blank: an explicitly blank string clears an inherited default.
// (Annotations that require a value, such as listeners and the timeouts, still
// reject a blank value.)
//
// An empty prefix selects DefaultPrefix. A non-empty prefix is used verbatim as
// the key prefix, so callers should include the trailing slash, for example
// "senselb.example.com/".
//
// Enumeration values (mode, algorithm, target-mode) are trimmed and compared
// case-insensitively, and Values receives the canonical lowercase spelling.
// Every other string value is trimmed but otherwise kept verbatim.
//
// Parse validates only the Service annotations; the defaults layer is assumed
// to be trusted configuration. All problems are reported together in a single
// *InvalidAnnotationsError: an invalid value for any annotation, and any key
// that carries the configured prefix but is not in the annotation set. Keys
// with any other prefix or no prefix belong to other controllers and are
// ignored. When an error is returned the Values result is empty, so a caller
// cannot accidentally act on a partially parsed configuration.
func Parse(svc map[string]string, defaults Values, prefix string) (Values, error) {
	if prefix == "" {
		prefix = DefaultPrefix
	}

	values := DefaultValues()
	values.overlay(defaults)

	invalid := make(map[string]string)
	for _, name := range annotationNames {
		raw, present := svc[prefix+name]
		if !present {
			continue
		}
		if err := apply(&values, name, raw); err != nil {
			invalid[prefix+name] = err.Error()
		}
	}

	for key := range svc {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if _, known := knownAnnotations[strings.TrimPrefix(key, prefix)]; !known {
			invalid[key] = "unknown annotation"
		}
	}

	if len(invalid) > 0 {
		return Values{}, &InvalidAnnotationsError{Annotations: invalid}
	}
	return values, nil
}

// InvalidAnnotationsError aggregates every invalid annotation found in one
// Parse call, so an operator can correct them all at once rather than one per
// reconcile.
type InvalidAnnotationsError struct {
	// Annotations maps each offending annotation key, including its prefix, to
	// the reason it was rejected.
	Annotations map[string]string
}

// Error implements the error interface. Annotations are rendered in sorted key
// order, one per line, so the message is stable.
func (e *InvalidAnnotationsError) Error() string {
	noun := "problems"
	if len(e.Annotations) == 1 {
		noun = "problem"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "invalid annotations: %d %s", len(e.Annotations), noun)
	for _, key := range slices.Sorted(maps.Keys(e.Annotations)) {
		fmt.Fprintf(&b, "\n  %s: %s", key, e.Annotations[key])
	}
	return b.String()
}

// overlay copies every non-zero field of defaults into v. Zero values are
// unset; see Parse for the exact rule and its consequence for booleans.
//
// The field-by-field form is deliberate rather than a reflective table of
// (pointer, set-check) pairs: each if-block states the zero-means-unset rule for
// one field in plain sight, and the reflection a generic form needs would be
// harder to review than the repetition. Considered and kept explicit.
func (v *Values) overlay(defaults Values) {
	if len(defaults.Listeners) > 0 {
		v.Listeners = slices.Clone(defaults.Listeners)
	}
	if defaults.Host != "" {
		v.Host = defaults.Host
	}
	if defaults.Path != "" {
		v.Path = defaults.Path
	}
	if defaults.SNI != "" {
		v.SNI = defaults.SNI
	}
	if defaults.Mode != "" {
		v.Mode = defaults.Mode
	}
	if defaults.Algorithm != "" {
		v.Algorithm = defaults.Algorithm
	}
	if defaults.TargetMode != "" {
		v.TargetMode = defaults.TargetMode
	}
	if defaults.HealthCheck {
		v.HealthCheck = true
	}
	if defaults.HealthCheckPath != "" {
		v.HealthCheckPath = defaults.HealthCheckPath
	}
	if defaults.ProxyProtocol {
		v.ProxyProtocol = true
	}
	if defaults.TimeoutConnect != "" {
		v.TimeoutConnect = defaults.TimeoutConnect
	}
	if defaults.TimeoutServer != "" {
		v.TimeoutServer = defaults.TimeoutServer
	}
	if defaults.TimeoutClient != "" {
		v.TimeoutClient = defaults.TimeoutClient
	}
	if defaults.MaxConn != 0 {
		v.MaxConn = defaults.MaxConn
	}
	if defaults.Weight != 0 {
		v.Weight = defaults.Weight
	}
	if defaults.Sticky {
		v.Sticky = true
	}
	if defaults.TLS {
		v.TLS = true
	}
	if defaults.TLSCert != "" {
		v.TLSCert = defaults.TLSCert
	}
	if defaults.TLSPassthrough {
		v.TLSPassthrough = true
	}
	if defaults.BackendCustom != "" {
		v.BackendCustom = defaults.BackendCustom
	}
	if defaults.BackendName != "" {
		v.BackendName = defaults.BackendName
	}
}

// apply parses one annotation value into v. name is the annotation name without
// its prefix and is assumed to be known.
func apply(v *Values, name, raw string) error {
	trimmed := strings.TrimSpace(raw)

	switch name {
	case annotationEnabled:
		return parseBool(&v.Enabled, raw)

	case annotationListeners:
		listeners, err := parseListeners(raw)
		if err != nil {
			return err
		}
		v.Listeners = listeners
		return nil

	case annotationHost:
		v.Host = trimmed
	case annotationPath:
		v.Path = trimmed
	case annotationSNI:
		v.SNI = trimmed

	case annotationMode:
		return parseEnum(&v.Mode, raw, allowedModes)

	case annotationAlgorithm:
		return parseEnum(&v.Algorithm, raw, allowedAlgorithms)

	case annotationTargetMode:
		return parseEnum(&v.TargetMode, raw, allowedTargetModes)

	case annotationHealthCheck:
		return parseBool(&v.HealthCheck, raw)

	case annotationHealthCheckPath:
		v.HealthCheckPath = trimmed

	case annotationProxyProtocol:
		return parseBool(&v.ProxyProtocol, raw)

	case annotationTimeoutConnect:
		return parseDuration(&v.TimeoutConnect, raw)

	case annotationTimeoutServer:
		return parseDuration(&v.TimeoutServer, raw)

	case annotationTimeoutClient:
		return parseDuration(&v.TimeoutClient, raw)

	case annotationMaxConn:
		return parseInt(&v.MaxConn, raw, 1)

	case annotationWeight:
		return parseInt(&v.Weight, raw, 0)

	case annotationSticky:
		return parseBool(&v.Sticky, raw)

	case annotationTLS:
		return parseBool(&v.TLS, raw)

	case annotationTLSCert:
		v.TLSCert = trimmed

	case annotationTLSPassthrough:
		return parseBool(&v.TLSPassthrough, raw)

	case annotationBackendCustom:
		v.BackendCustom = trimmed

	case annotationBackendName:
		v.BackendName = trimmed
	}

	return nil
}

// parseListeners splits a comma-separated listener list. Entries are trimmed,
// empty entries are dropped, and the remaining order is preserved. At least one
// listener is required.
func parseListeners(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	listeners := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			listeners = append(listeners, trimmed)
		}
	}
	if len(listeners) == 0 {
		return nil, errors.New("must name at least one listener")
	}
	return listeners, nil
}

// parseBool stores the strictly parsed boolean value. strconv.ParseBool accepts
// only the forms it documents, such as "true" and "false"; anything else is an
// error.
func parseBool(field *bool, raw string) error {
	parsed, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("must be a boolean, got %q", raw)
	}
	*field = parsed
	return nil
}

// parseInt stores an integer that must be at least minimum.
func parseInt(field *int, raw string, minimum int) error {
	parsed, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("must be an integer, got %q", raw)
	}
	if parsed < minimum {
		return fmt.Errorf("must be at least %d, got %d", minimum, parsed)
	}
	*field = parsed
	return nil
}

// parseDuration stores a duration string after confirming time.ParseDuration
// accepts it. The stored spelling is the trimmed input, not its canonical form.
func parseDuration(field *string, raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return errors.New(`must be a duration such as "30s" or "2m", got a blank value`)
	}
	if _, err := time.ParseDuration(trimmed); err != nil {
		return fmt.Errorf("must be a duration such as %q or %q, got %q", "30s", "2m", raw)
	}
	*field = trimmed
	return nil
}

// parseEnum stores the canonical lowercase enum value.
func parseEnum(field *string, raw string, allowed []string) error {
	value := strings.ToLower(strings.TrimSpace(raw))
	if !slices.Contains(allowed, value) {
		return fmt.Errorf("must be one of %s, got %q", strings.Join(allowed, ", "), raw)
	}
	*field = value
	return nil
}

// newSet builds a membership set from names.
func newSet(names []string) map[string]struct{} {
	set := make(map[string]struct{}, len(names))
	for _, name := range names {
		set[name] = struct{}{}
	}
	return set
}
