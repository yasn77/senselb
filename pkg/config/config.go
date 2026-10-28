// Package config defines and loads the versioned controller configuration that
// a ConfigMap carries.
//
// Load is the only entry point the controller needs: it decodes the YAML with
// unknown keys rejected, fills the schema defaults and validates the result, so
// a malformed ConfigMap fails loudly at startup rather than midway through a
// reconcile.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/yasn77/senselb/pkg/annotations"
	"github.com/yasn77/senselb/pkg/haproxy"
)

// SchemaVersion is the only configuration schema version this build accepts.
// A ConfigMap that states any other version is rejected rather than guessed at,
// so a newer schema fails loudly instead of being partially honoured.
const SchemaVersion = "v1alpha1"

// Defaults that ApplyDefaults fills when the ConfigMap leaves a field empty.
const (
	// DefaultStoreName is the provider-side object store used when StoreName is
	// empty.
	DefaultStoreName = "senselb-store"
	// DefaultListenerMode is the mode of a listener that omits one.
	DefaultListenerMode = string(haproxy.ModeHTTP)
)

// listenerModes are the frontend modes a listener may state. They mirror the
// modes the haproxy package models for a frontend.
var listenerModes = []string{
	string(haproxy.ModeHTTP),
	string(haproxy.ModeTCP),
	string(haproxy.ModeSSL),
}

// ListenerConfig is one shared HAProxy frontend that Services attach to.
type ListenerConfig struct {
	// Name identifies the listener; a Service names it in its
	// "senselb.io/listeners" annotation.
	Name string `yaml:"name"`

	// Adopt attaches senselb's routing rules to ExistingFrontend instead of
	// creating a frontend from Bind.
	Adopt bool `yaml:"adopt"`
	// ExistingFrontend names the frontend to attach to. It is required when
	// Adopt is true and ignored otherwise.
	ExistingFrontend string `yaml:"existingFrontend"`

	// Bind lists the addresses of the frontend the listener creates, for
	// example "192.168.1.1:443". It is required when Adopt is false.
	Bind []string `yaml:"bind"`

	// Mode is the frontend proxy mode: http, tcp or ssl. An empty value means
	// http; ApplyDefaults fills it in.
	Mode string `yaml:"mode"`

	// DefaultBackend is the backend that serves requests no owned rule
	// matches. It is optional, and it also anchors where owned rules are
	// placed when the listener adopts an existing frontend.
	DefaultBackend string `yaml:"defaultBackend"`
}

// ProviderConfig locates the load-balancer platform senselb programs.
type ProviderConfig struct {
	// URL is the provider's base URL. It may be left empty when SecretName
	// supplies a URL instead.
	URL string `yaml:"url"`

	// SecretName names a Secret in the controller's namespace that holds the
	// provider credentials under the keys "key" and "secret", and optionally
	// "url".
	//
	// A non-empty "url" in that Secret overrides URL. The controller applies
	// that precedence when it reads the Secret, so Validate only enforces that
	// at least one URL source exists: URL or SecretName.
	SecretName string `yaml:"secretName"`

	// InsecureSkipVerify disables TLS certificate verification. It exists for
	// a self-signed platform certificate during bring-up; prefer
	// CACertSecretName.
	InsecureSkipVerify bool `yaml:"insecureSkipVerify"`

	// CACertSecretName names a Secret in the controller's namespace that holds
	// a PEM certificate bundle under the key "ca.crt". It is optional.
	CACertSecretName string `yaml:"caCertSecretName"`
}

// Config is the complete controller configuration carried by one ConfigMap.
type Config struct {
	// SchemaVersion is the configuration schema this document follows. Load
	// fills it with SchemaVersion when it is empty.
	SchemaVersion string `yaml:"schemaVersion"`

	// Listeners are the shared frontends Services attach to.
	Listeners []ListenerConfig `yaml:"listeners"`

	// Defaults are the cluster-wide annotation defaults: the second layer of
	// the annotation precedence order, applied to every Service that does not
	// override them.
	Defaults annotations.Values `yaml:"defaults"`

	// AnnotationPrefix is the prefix of the senselb annotations, including its
	// trailing slash. Load fills it with annotations.DefaultPrefix when it is
	// empty.
	AnnotationPrefix string `yaml:"annotationPrefix"`

	// NodeSelector restricts the nodes whose Service endpoints senselb
	// programs. An empty map selects every node.
	NodeSelector map[string]string `yaml:"nodeSelector"`

	// StoreName is the provider-side object store that holds senselb's own
	// state. Load fills it with DefaultStoreName when it is empty.
	StoreName string `yaml:"storeName"`

	// Provider locates the load-balancer platform senselb programs.
	Provider ProviderConfig `yaml:"provider"`
}

// Load decodes, defaults and validates one configuration document.
//
// Decoding is strict: the decoder rejects keys outside the schema, such as
// "replicas", so a misspelt or unsupported key is an error rather than a
// silently ignored field. Exactly one YAML document is accepted, and an empty
// document is an error.
//
// Defaults are applied after decoding and before validation, so a document may
// omit every field that ApplyDefaults fills. Every problem found - during
// decoding or during validation - is reported together in a single
// *InvalidConfigError. On error the returned Config is nil.
func Load(data []byte) (*Config, error) {
	cfg := &Config{}

	problems, fatal := decode(data, cfg)
	if fatal {
		return nil, &InvalidConfigError{Problems: problems}
	}

	cfg.ApplyDefaults()

	if err := cfg.Validate(); err != nil {
		var validation *InvalidConfigError
		if errors.As(err, &validation) {
			problems = append(problems, validation.Problems...)
		} else {
			problems = append(problems, err.Error())
		}
	}

	if len(problems) > 0 {
		return nil, &InvalidConfigError{Problems: problems}
	}
	return cfg, nil
}

// decode unmarshals exactly one YAML document into cfg.
//
// Unknown keys and type mismatches are returned as problems and decoding
// continues, so Load can report them alongside the validation problems of the
// fields that did decode. A syntax error is fatal: the rest of the document
// cannot be trusted, so the caller must stop.
func decode(data []byte, cfg *Config) (problems []string, fatal bool) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	// KnownFields makes a misspelt or unsupported key an error instead of a
	// silently ignored field. It is the strict-decoding switch of yaml.v3;
	// yaml.Unmarshal has no equivalent.
	dec.KnownFields(true)

	err := dec.Decode(cfg)
	switch {
	case errors.Is(err, io.EOF):
		return []string{"document: configuration is empty"}, true
	case err != nil:
		var typeErr *yaml.TypeError
		if !errors.As(err, &typeErr) {
			return []string{"document: " + err.Error()}, true
		}
		problems = append(problems, typeErr.Errors...)
	}

	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case err == nil:
		problems = append(problems, "document: configuration must contain exactly one YAML document")
	case !errors.Is(err, io.EOF):
		problems = append(problems, "document: "+err.Error())
	}

	return problems, false
}

// ApplyDefaults fills the fields a ConfigMap may omit: SchemaVersion,
// AnnotationPrefix, StoreName and each listener's Mode. Explicit values are
// left untouched, so loading a fully specified document changes nothing.
//
// Load calls ApplyDefaults before Validate.
func (c *Config) ApplyDefaults() {
	if c.SchemaVersion == "" {
		c.SchemaVersion = SchemaVersion
	}
	if c.AnnotationPrefix == "" {
		c.AnnotationPrefix = annotations.DefaultPrefix
	}
	if c.StoreName == "" {
		c.StoreName = DefaultStoreName
	}
	for i := range c.Listeners {
		if c.Listeners[i].Mode == "" {
			c.Listeners[i].Mode = DefaultListenerMode
		}
	}
}

// Validate reports every problem in the configuration, so an operator can
// correct a ConfigMap in one pass rather than one problem per reconcile. It
// returns nil when the configuration is valid, and an *InvalidConfigError
// enumerating all problems otherwise.
//
// Validate expects the defaults to have been applied, as Load does, so an unset
// SchemaVersion is reported as unsupported unless a caller filled it in first.
func (c *Config) Validate() error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if c.SchemaVersion != SchemaVersion {
		add("schemaVersion: %q is not supported; this build supports %q", c.SchemaVersion, SchemaVersion)
	}

	seen := make(map[string]struct{}, len(c.Listeners))
	for i, listener := range c.Listeners {
		scope := fmt.Sprintf("listeners[%d]", i)
		if listener.Name != "" {
			scope = fmt.Sprintf("listeners[%d] %q", i, listener.Name)
		}

		if listener.Name == "" {
			add("%s: name must not be empty", scope)
		} else {
			if _, duplicate := seen[listener.Name]; duplicate {
				add("%s: duplicate listener name", scope)
			}
			seen[listener.Name] = struct{}{}
		}

		switch {
		case listener.Adopt && strings.TrimSpace(listener.ExistingFrontend) == "":
			add("%s: adopt requires existingFrontend", scope)
		case !listener.Adopt && !hasBind(listener.Bind):
			add("%s: creating a frontend requires at least one bind address", scope)
		}

		for j, bind := range listener.Bind {
			if strings.TrimSpace(bind) == "" {
				add("%s: bind[%d] must not be empty", scope, j)
			}
		}

		if listener.Mode != "" && !slices.Contains(listenerModes, listener.Mode) {
			add("%s: mode %q is not valid; expected one of %s", scope, listener.Mode, quotedList(listenerModes))
		}
	}

	// A Secret may carry the provider URL, so a configuration with a Secret and
	// no URL is complete; one with neither cannot reach the provider at all.
	if c.Provider.URL == "" && c.Provider.SecretName == "" {
		add("provider: url or secretName must be set")
	}

	if len(problems) == 0 {
		return nil
	}
	return &InvalidConfigError{Problems: problems}
}

// ListenerNames returns the configured listener names in sorted order. The
// reconciler uses it where a stable order matters, such as rule placement.
func (c *Config) ListenerNames() []string {
	names := make([]string, 0, len(c.Listeners))
	for _, listener := range c.Listeners {
		names = append(names, listener.Name)
	}
	slices.Sort(names)
	return names
}

// InvalidConfigError aggregates every problem Load or Validate found, so an
// operator can correct them all at once.
type InvalidConfigError struct {
	// Problems lists each offending field, including its path, and the reason
	// it was rejected.
	Problems []string
}

// Error implements the error interface. Problems are rendered in the order they
// were found, one per line, so the message is stable.
func (e *InvalidConfigError) Error() string {
	noun := "problems"
	if len(e.Problems) == 1 {
		noun = "problem"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "invalid configuration: %d %s", len(e.Problems), noun)
	for _, problem := range e.Problems {
		fmt.Fprintf(&b, "\n  %s", problem)
	}
	return b.String()
}

// hasBind reports whether bind holds at least one non-blank address.
func hasBind(bind []string) bool {
	for _, address := range bind {
		if strings.TrimSpace(address) != "" {
			return true
		}
	}
	return false
}

// quotedList renders the allowed values as a comma-separated, quoted list.
func quotedList(values []string) string {
	quoted := make([]string, len(values))
	for i, value := range values {
		quoted[i] = fmt.Sprintf("%q", value)
	}
	return strings.Join(quoted, ", ")
}
