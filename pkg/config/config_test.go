package config_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/yasn77/senselb/pkg/annotations"
	"github.com/yasn77/senselb/pkg/config"
)

// exampleYAML is a complete, valid configuration. It exercises every top-level
// field and all three listener shapes: two adopted frontends and one created
// frontend that omits its mode, which therefore defaults to http.
const exampleYAML = `
schemaVersion: v1alpha1
annotationPrefix: senselb.io/
listeners:
  - name: external
    adopt: true
    existingFrontend: ingress-HTTPS
    mode: ssl
    defaultBackend: external-fallback
  - name: external-http
    adopt: true
    existingFrontend: HTTP
    mode: http
  - name: internal
    bind:
      - 172.16.16.1:443
defaults:
  enabled: true
  target-mode: nodeport
  algorithm: roundrobin
  timeout-connect: 5s
  timeout-server: 50s
nodeSelector:
  kubernetes.io/os: linux
storeName: senselb-store
provider:
  url: https://opnsense.home.izms.net/api
  secretName: senselb-opnsense
  insecureSkipVerify: false
  caCertSecretName: senselb-opnsense-ca
`

// loadOK loads data and fails the test on error.
func loadOK(t *testing.T, data []byte) *config.Config {
	t.Helper()

	cfg, err := config.Load(data)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	return cfg
}

// configError extracts the aggregated error from Load or Validate.
func configError(t *testing.T, err error) *config.InvalidConfigError {
	t.Helper()

	if err == nil {
		t.Fatal("error = nil, want a configuration error")
	}
	var configErr *config.InvalidConfigError
	if !errors.As(err, &configErr) {
		t.Fatalf("error = %T %v, want *config.InvalidConfigError", err, err)
	}
	return configErr
}

func TestLoadExample(t *testing.T) {
	t.Parallel()

	cfg := loadOK(t, []byte(exampleYAML))

	if cfg.SchemaVersion != config.SchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", cfg.SchemaVersion, config.SchemaVersion)
	}
	if cfg.AnnotationPrefix != annotations.DefaultPrefix {
		t.Errorf("AnnotationPrefix = %q, want %q", cfg.AnnotationPrefix, annotations.DefaultPrefix)
	}
	if cfg.StoreName != config.DefaultStoreName {
		t.Errorf("StoreName = %q, want %q", cfg.StoreName, config.DefaultStoreName)
	}
	if !reflect.DeepEqual(cfg.NodeSelector, map[string]string{"kubernetes.io/os": "linux"}) {
		t.Errorf("NodeSelector = %v, want kubernetes.io/os=linux", cfg.NodeSelector)
	}

	wantDefaults := annotations.Values{
		Enabled:        true,
		TargetMode:     "nodeport",
		Algorithm:      "roundrobin",
		TimeoutConnect: "5s",
		TimeoutServer:  "50s",
	}
	if !reflect.DeepEqual(cfg.Defaults, wantDefaults) {
		t.Errorf("Defaults = %+v, want %+v", cfg.Defaults, wantDefaults)
	}

	wantProvider := config.ProviderConfig{ //nolint:gosec // Secret names are references, not credentials.
		URL:              "https://opnsense.home.izms.net/api",
		SecretName:       "senselb-opnsense",
		CACertSecretName: "senselb-opnsense-ca",
	}
	if cfg.Provider != wantProvider {
		t.Errorf("Provider = %+v, want %+v", cfg.Provider, wantProvider)
	}

	wantListeners := []config.ListenerConfig{
		{
			Name:             "external",
			Adopt:            true,
			ExistingFrontend: "ingress-HTTPS",
			Mode:             "ssl",
			DefaultBackend:   "external-fallback",
		},
		{
			Name:             "external-http",
			Adopt:            true,
			ExistingFrontend: "HTTP",
			Mode:             "http",
		},
		{
			Name: "internal",
			Bind: []string{"172.16.16.1:443"},
			Mode: config.DefaultListenerMode,
		},
	}
	if !reflect.DeepEqual(cfg.Listeners, wantListeners) {
		t.Errorf("Listeners = %+v, want %+v", cfg.Listeners, wantListeners)
	}

	wantNames := []string{"external", "external-http", "internal"}
	if got := cfg.ListenerNames(); !reflect.DeepEqual(got, wantNames) {
		t.Errorf("ListenerNames() = %v, want %v", got, wantNames)
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	t.Parallel()

	cfg := loadOK(t, []byte(`
listeners:
  - name: internal
    bind:
      - 172.16.16.1:443
provider:
  secretName: senselb-opnsense
`))

	if cfg.SchemaVersion != config.SchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", cfg.SchemaVersion, config.SchemaVersion)
	}
	if cfg.AnnotationPrefix != annotations.DefaultPrefix {
		t.Errorf("AnnotationPrefix = %q, want %q", cfg.AnnotationPrefix, annotations.DefaultPrefix)
	}
	if cfg.StoreName != config.DefaultStoreName {
		t.Errorf("StoreName = %q, want %q", cfg.StoreName, config.DefaultStoreName)
	}
	if got := cfg.Listeners[0].Mode; got != config.DefaultListenerMode {
		t.Errorf("Listeners[0].Mode = %q, want %q", got, config.DefaultListenerMode)
	}
	if got := cfg.Listeners[0].Bind; !reflect.DeepEqual(got, []string{"172.16.16.1:443"}) {
		t.Errorf("Listeners[0].Bind = %v, want [172.16.16.1:443]", got)
	}

	// The annotation default layer is not config-level defaulting: it stays
	// zero here and the annotation layer supplies the built-ins.
	if got := cfg.Defaults; !reflect.DeepEqual(got, annotations.Values{}) {
		t.Errorf("Defaults = %+v, want the zero value", got)
	}
}

func TestLoadKeepsExplicitValues(t *testing.T) {
	t.Parallel()

	cfg := loadOK(t, []byte(`
schemaVersion: v1alpha1
annotationPrefix: senselb.izms.net/
storeName: custom-store
listeners:
  - name: internal
    bind:
      - 172.16.16.1:443
    mode: tcp
    defaultBackend: internal-fallback
provider:
  secretName: senselb-opnsense
`))

	if cfg.AnnotationPrefix != "senselb.izms.net/" {
		t.Errorf("AnnotationPrefix = %q, want senselb.izms.net/", cfg.AnnotationPrefix)
	}
	if cfg.StoreName != "custom-store" {
		t.Errorf("StoreName = %q, want custom-store", cfg.StoreName)
	}
	if got := cfg.Listeners[0].Mode; got != "tcp" {
		t.Errorf("Listeners[0].Mode = %q, want tcp", got)
	}
	if cfg.Provider.URL != "" {
		t.Errorf("Provider.URL = %q, want empty; a Secret supplies the URL", cfg.Provider.URL)
	}
}

func TestLoadRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		yaml  string
		wants []string
	}{
		{
			name:  "malformed yaml",
			yaml:  "listeners: [oops\n",
			wants: []string{"document:"},
		},
		{
			name:  "empty document",
			yaml:  "",
			wants: []string{"configuration is empty"},
		},
		{
			name:  "multiple documents",
			yaml:  "schemaVersion: v1alpha1\n---\nschemaVersion: v1alpha1\n",
			wants: []string{"exactly one YAML document"},
		},
		{
			name:  "unknown schema version",
			yaml:  "schemaVersion: v2\n",
			wants: []string{`"v2" is not supported`, `"v1alpha1"`},
		},
		{
			name:  "unknown key",
			yaml:  "replicas: []\n",
			wants: []string{"replicas"},
		},
		{
			name: "duplicate listener names",
			yaml: `
listeners:
  - name: edge
    adopt: true
    existingFrontend: ingress-HTTPS
  - name: edge
    adopt: true
    existingFrontend: HTTP
`,
			wants: []string{`listeners[1] "edge": duplicate listener name`},
		},
		{
			name: "invalid listener mode",
			yaml: `
listeners:
  - name: edge
    adopt: true
    existingFrontend: ingress-HTTPS
    mode: udp
`,
			wants: []string{`listeners[0] "edge": mode "udp" is not valid`, `"http", "tcp", "ssl"`},
		},
		{
			name: "adopt without existing frontend",
			yaml: `
listeners:
  - name: edge
    adopt: true
`,
			wants: []string{`listeners[0] "edge": adopt requires existingFrontend`},
		},
		{
			name: "create without bind",
			yaml: `
listeners:
  - name: edge
`,
			wants: []string{`listeners[0] "edge": creating a frontend requires at least one bind address`},
		},
		{
			name: "blank bind address",
			yaml: `
listeners:
  - name: edge
    bind: ["  "]
`,
			wants: []string{`listeners[0] "edge": bind[0] must not be empty`},
		},
		{
			name: "empty listener name",
			yaml: `
listeners:
  - bind: ["172.16.16.1:443"]
`,
			wants: []string{"listeners[0]: name must not be empty"},
		},
		{
			name:  "no provider url source",
			yaml:  "listeners: []\n",
			wants: []string{"provider: url or secretName must be set"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := config.Load([]byte(test.yaml))
			configErr := configError(t, err)
			for _, want := range test.wants {
				if !strings.Contains(configErr.Error(), want) {
					t.Errorf("Error() = %q, want it to contain %q", configErr.Error(), want)
				}
			}
		})
	}
}

// TestLoadReportsAllProblemsAtOnce checks that decoding and validation
// problems are collected into one error rather than stopping at the first.
func TestLoadReportsAllProblemsAtOnce(t *testing.T) {
	t.Parallel()

	_, err := config.Load([]byte(`
schemaVersion: v9
bogus: value
listeners:
  - name: edge
    adopt: true
    existingFrontend: ingress-HTTPS
    mode: udp
  - name: edge
    adopt: true
    existingFrontend: HTTP
`))

	configErr := configError(t, err)
	if got, want := len(configErr.Problems), 5; got != want {
		t.Fatalf("problems = %d %v, want %d", got, configErr.Problems, want)
	}
	for _, want := range []string{
		`"v9" is not supported`,
		"bogus",
		"duplicate listener name",
		`mode "udp" is not valid`,
		"url or secretName must be set",
	} {
		if !strings.Contains(configErr.Error(), want) {
			t.Errorf("Error() = %q, want it to contain %q", configErr.Error(), want)
		}
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	valid := func() *config.Config {
		return &config.Config{
			SchemaVersion: config.SchemaVersion,
			Listeners: []config.ListenerConfig{
				{Name: "internal", Bind: []string{"172.16.16.1:443"}, Mode: "http"},
			},
			Provider: config.ProviderConfig{SecretName: "senselb-opnsense"}, //nolint:gosec // A Secret name is a reference, not a credential.
		}
	}

	if err := valid().Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}

	// Validate is documented to run after ApplyDefaults, so an unset version is
	// a validation problem rather than silently accepted.
	if err := (&config.Config{Provider: config.ProviderConfig{URL: "https://example.com"}}).Validate(); err == nil {
		t.Fatal("Validate() error = nil, want a schemaVersion problem")
	}
}

func TestValidateReportsEveryListenerProblem(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		SchemaVersion: config.SchemaVersion,
		Listeners: []config.ListenerConfig{
			{Name: "", Adopt: false},
			{Name: "edge", Adopt: true, Mode: "udp"},
		},
		Provider: config.ProviderConfig{URL: "https://example.com"},
	}

	configErr := configError(t, cfg.Validate())
	if len(configErr.Problems) != 4 {
		t.Fatalf("problems = %d %v, want 4", len(configErr.Problems), configErr.Problems)
	}
}

func TestInvalidConfigErrorGrammar(t *testing.T) {
	t.Parallel()

	single := &config.InvalidConfigError{Problems: []string{"provider: url or secretName must be set"}}
	if got := single.Error(); !strings.Contains(got, "1 problem\n") {
		t.Errorf("Error() = %q, want the singular noun", got)
	}

	multiple := &config.InvalidConfigError{Problems: []string{"a", "b"}}
	if got := multiple.Error(); !strings.Contains(got, "2 problems\n") {
		t.Errorf("Error() = %q, want the plural noun", got)
	}
	if got := multiple.Error(); !strings.Contains(got, "\n  a\n  b") {
		t.Errorf("Error() = %q, want problems in order, one per line", got)
	}
}
