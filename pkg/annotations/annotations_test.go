package annotations_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/yasn77/senselb/pkg/annotations"
)

// parseOK parses svc with prefix and fails the test on error.
func parseOK(t *testing.T, svc map[string]string, defaults annotations.Values, prefix string) annotations.Values {
	t.Helper()

	got, err := annotations.Parse(svc, defaults, prefix)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	return got
}

// invalidError extracts the aggregated error from Parse.
func invalidError(t *testing.T, err error) *annotations.InvalidAnnotationsError {
	t.Helper()

	if err == nil {
		t.Fatal("Parse() error = nil, want an annotations error")
	}
	var invalid *annotations.InvalidAnnotationsError
	if !errors.As(err, &invalid) {
		t.Fatalf("Parse() error = %T %v, want *annotations.InvalidAnnotationsError", err, err)
	}
	return invalid
}

func TestDefaultValues(t *testing.T) {
	t.Parallel()

	want := annotations.Values{
		Enabled:    true,
		TargetMode: "nodeport",
		Algorithm:  "roundrobin",
	}
	if got := annotations.DefaultValues(); !reflect.DeepEqual(got, want) {
		t.Fatalf("DefaultValues() = %+v, want %+v", got, want)
	}
}

func TestParseEveryAnnotation(t *testing.T) {
	t.Parallel()

	svc := map[string]string{
		"senselb.io/enabled":          "true",
		"senselb.io/listeners":        " public-http , internal-http ,",
		"senselb.io/host":             " app.example.com ",
		"senselb.io/path":             " /app ",
		"senselb.io/sni":              " app.example.com ",
		"senselb.io/mode":             " HTTP ",
		"senselb.io/algorithm":        "Source",
		"senselb.io/target-mode":      "Endpoint",
		"senselb.io/healthcheck":      "true",
		"senselb.io/healthcheck-path": " /healthz ",
		"senselb.io/proxy-protocol":   "true",
		"senselb.io/timeout-connect":  " 5s ",
		"senselb.io/timeout-server":   "50s",
		"senselb.io/timeout-client":   "30s",
		"senselb.io/maxconn":          "100",
		"senselb.io/weight":           "0",
		"senselb.io/sticky":           "true",
		"senselb.io/tls":              "true",
		"senselb.io/tls-cert":         " app-tls ",
		"senselb.io/tls-passthrough":  "true",
		"senselb.io/backend-custom":   " custom-backend ",
		"senselb.io/backend-name":     " app-backend ",
	}

	want := annotations.Values{
		Enabled:         true,
		Listeners:       []string{"public-http", "internal-http"},
		Host:            "app.example.com",
		Path:            "/app",
		SNI:             "app.example.com",
		Mode:            "http",
		Algorithm:       "source",
		TargetMode:      "endpoint",
		HealthCheck:     true,
		HealthCheckPath: "/healthz",
		ProxyProtocol:   true,
		TimeoutConnect:  "5s",
		TimeoutServer:   "50s",
		TimeoutClient:   "30s",
		MaxConn:         100,
		Weight:          0,
		Sticky:          true,
		TLS:             true,
		TLSCert:         "app-tls",
		TLSPassthrough:  true,
		BackendCustom:   "custom-backend",
		BackendName:     "app-backend",
	}

	got := parseOK(t, svc, annotations.Values{}, "")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse() = %+v\nwant %+v", got, want)
	}
}

func TestParsePrecedence(t *testing.T) {
	t.Parallel()

	listenerDefaults := annotations.Values{Listeners: []string{"default-listener"}}

	tests := []struct {
		name     string
		svc      map[string]string
		defaults annotations.Values
		want     annotations.Values
	}{
		{
			name: "built-ins apply when nothing is configured",
			want: annotations.DefaultValues(),
		},
		{
			name:     "configmap defaults override built-ins",
			defaults: annotations.Values{Algorithm: "leastconn", TargetMode: "endpoint", Mode: "tcp"},
			want: annotations.Values{
				Enabled:    true,
				Algorithm:  "leastconn",
				TargetMode: "endpoint",
				Mode:       "tcp",
			},
		},
		{
			name: "service annotations override configmap defaults",
			svc: map[string]string{
				"senselb.io/algorithm": "source",
				"senselb.io/mode":      "http",
			},
			defaults: annotations.Values{Algorithm: "leastconn", Mode: "tcp"},
			want: annotations.Values{
				Enabled:    true,
				Algorithm:  "source",
				Mode:       "http",
				TargetMode: "nodeport",
			},
		},
		{
			name:     "absent annotation falls through to the configmap default",
			svc:      map[string]string{"senselb.io/host": "app.example.com"},
			defaults: annotations.Values{Algorithm: "leastconn", Host: "default.example.com"},
			want: annotations.Values{
				Enabled:    true,
				Host:       "app.example.com",
				Algorithm:  "leastconn",
				TargetMode: "nodeport",
			},
		},
		{
			name:     "absent annotation falls through to the built-in",
			svc:      map[string]string{"senselb.io/host": "app.example.com"},
			defaults: annotations.Values{Algorithm: "leastconn"},
			want: annotations.Values{
				Enabled:    true,
				Host:       "app.example.com",
				Algorithm:  "leastconn",
				TargetMode: "nodeport",
			},
		},
		{
			name:     "enabled false in defaults does not disable an unannotated service",
			defaults: annotations.Values{Enabled: false, Algorithm: "leastconn"},
			want: annotations.Values{
				Enabled:    true,
				Algorithm:  "leastconn",
				TargetMode: "nodeport",
			},
		},
		{
			name: "service annotation disables the service",
			svc:  map[string]string{"senselb.io/enabled": "false"},
			want: annotations.Values{
				Enabled:    false,
				Algorithm:  "roundrobin",
				TargetMode: "nodeport",
			},
		},
		{
			name:     "listener default is inherited",
			defaults: listenerDefaults,
			want: annotations.Values{
				Enabled:    true,
				Listeners:  []string{"default-listener"},
				Algorithm:  "roundrobin",
				TargetMode: "nodeport",
			},
		},
		{
			name:     "listener annotation overrides the default",
			svc:      map[string]string{"senselb.io/listeners": "public-http"},
			defaults: listenerDefaults,
			want: annotations.Values{
				Enabled:    true,
				Listeners:  []string{"public-http"},
				Algorithm:  "roundrobin",
				TargetMode: "nodeport",
			},
		},
		{
			name:     "an explicitly blank string clears the default",
			svc:      map[string]string{"senselb.io/host": ""},
			defaults: annotations.Values{Host: "default.example.com"},
			want: annotations.Values{
				Enabled:    true,
				Host:       "",
				Algorithm:  "roundrobin",
				TargetMode: "nodeport",
			},
		},
		{
			name:     "boolean defaults are inherited",
			defaults: annotations.Values{HealthCheck: true, Sticky: true, TLS: true, ProxyProtocol: true, TLSPassthrough: true},
			want: annotations.Values{
				Enabled:        true,
				HealthCheck:    true,
				Sticky:         true,
				TLS:            true,
				ProxyProtocol:  true,
				TLSPassthrough: true,
				Algorithm:      "roundrobin",
				TargetMode:     "nodeport",
			},
		},
		{
			name: "every configmap default is inherited",
			defaults: annotations.Values{
				Listeners:       []string{"default-listener"},
				Host:            "default.example.com",
				Path:            "/",
				SNI:             "default.example.com",
				Mode:            "tcp",
				Algorithm:       "leastconn",
				TargetMode:      "endpoint",
				HealthCheck:     true,
				HealthCheckPath: "/healthz",
				ProxyProtocol:   true,
				TimeoutConnect:  "5s",
				TimeoutServer:   "50s",
				TimeoutClient:   "30s",
				MaxConn:         100,
				Weight:          10,
				Sticky:          true,
				TLS:             true,
				TLSCert:         "default-tls",
				TLSPassthrough:  true,
				BackendCustom:   "custom-backend",
				BackendName:     "default-backend",
			},
			want: annotations.Values{
				Enabled:         true,
				Listeners:       []string{"default-listener"},
				Host:            "default.example.com",
				Path:            "/",
				SNI:             "default.example.com",
				Mode:            "tcp",
				Algorithm:       "leastconn",
				TargetMode:      "endpoint",
				HealthCheck:     true,
				HealthCheckPath: "/healthz",
				ProxyProtocol:   true,
				TimeoutConnect:  "5s",
				TimeoutServer:   "50s",
				TimeoutClient:   "30s",
				MaxConn:         100,
				Weight:          10,
				Sticky:          true,
				TLS:             true,
				TLSCert:         "default-tls",
				TLSPassthrough:  true,
				BackendCustom:   "custom-backend",
				BackendName:     "default-backend",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := parseOK(t, tc.svc, tc.defaults, "")
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Parse() = %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestParseInheritedListenersAreACopy(t *testing.T) {
	t.Parallel()

	defaults := annotations.Values{Listeners: []string{"public-http"}}
	got := parseOK(t, nil, defaults, "")

	got.Listeners[0] = "mutated"
	if defaults.Listeners[0] != "public-http" {
		t.Fatalf("Parse() aliased the defaults listener slice: %v", defaults.Listeners)
	}
}

func TestParseListeners(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		want    []string
		wantErr bool
	}{
		{name: "single listener", raw: "public-http", want: []string{"public-http"}},
		{name: "spaces are trimmed", raw: " public-http , internal-http ", want: []string{"public-http", "internal-http"}},
		{name: "empty entries are dropped", raw: "public-http,,internal-http,", want: []string{"public-http", "internal-http"}},
		{name: "order and duplicates are preserved", raw: "b,a,b", want: []string{"b", "a", "b"}},
		{name: "blank list", raw: "", wantErr: true},
		{name: "only separators", raw: " , , ", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			svc := map[string]string{"senselb.io/listeners": tc.raw}
			got, err := annotations.Parse(svc, annotations.Values{}, "")
			if tc.wantErr {
				invalid := invalidError(t, err)
				if _, ok := invalid.Annotations["senselb.io/listeners"]; !ok {
					t.Fatalf("annotations = %v, want a listeners entry", invalid.Annotations)
				}
				if !strings.Contains(invalid.Annotations["senselb.io/listeners"], "at least one listener") {
					t.Fatalf("reason = %q, want it to mention at least one listener", invalid.Annotations["senselb.io/listeners"])
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if !reflect.DeepEqual(got.Listeners, tc.want) {
				t.Fatalf("Listeners = %v, want %v", got.Listeners, tc.want)
			}
		})
	}
}

func TestParseInvalidAnnotationValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		key    string
		value  string
		reason string
	}{
		{name: "enabled is not boolean", key: "enabled", value: "yes", reason: "must be a boolean"},
		{name: "healthcheck is not boolean", key: "healthcheck", value: "yes", reason: "must be a boolean"},
		{name: "proxy-protocol is not boolean", key: "proxy-protocol", value: "enabled", reason: "must be a boolean"},
		{name: "sticky is not boolean", key: "sticky", value: "yes", reason: "must be a boolean"},
		{name: "tls is not boolean", key: "tls", value: "maybe", reason: "must be a boolean"},
		{name: "tls-passthrough is not a strict boolean", key: "tls-passthrough", value: "on", reason: "must be a boolean"},
		{name: "listeners is blank", key: "listeners", value: " ", reason: "at least one listener"},
		{name: "mode is unknown", key: "mode", value: "udp", reason: "must be one of http, tcp"},
		{name: "algorithm is unknown", key: "algorithm", value: "weighted", reason: "must be one of roundrobin, source, leastconn, static-rr, uri, random"},
		{name: "target mode is unknown", key: "target-mode", value: "clusterip", reason: "must be one of nodeport, endpoint"},
		{name: "timeout is not a duration", key: "timeout-connect", value: "fast", reason: "must be a duration"},
		{name: "timeout lacks a unit", key: "timeout-server", value: "10", reason: "must be a duration"},
		{name: "timeout is blank", key: "timeout-client", value: " ", reason: "blank value"},
		{name: "maxconn is not an integer", key: "maxconn", value: "lots", reason: "must be an integer"},
		{name: "maxconn is zero", key: "maxconn", value: "0", reason: "must be at least 1"},
		{name: "maxconn is negative", key: "maxconn", value: "-5", reason: "must be at least 1"},
		{name: "weight is not an integer", key: "weight", value: "heavy", reason: "must be an integer"},
		{name: "weight is negative", key: "weight", value: "-1", reason: "must be at least 0"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			svc := map[string]string{"senselb.io/" + tc.key: tc.value}
			invalid := invalidError(t, mustParseError(t, svc))

			if len(invalid.Annotations) != 1 {
				t.Fatalf("annotations = %v, want exactly one entry", invalid.Annotations)
			}
			reason, ok := invalid.Annotations["senselb.io/"+tc.key]
			if !ok {
				t.Fatalf("annotations = %v, want key %q", invalid.Annotations, "senselb.io/"+tc.key)
			}
			if !strings.Contains(reason, tc.reason) {
				t.Fatalf("reason = %q, want it to contain %q", reason, tc.reason)
			}
		})
	}
}

// mustParseError calls Parse and returns its error, failing when Parse
// unexpectedly succeeds.
func mustParseError(t *testing.T, svc map[string]string) error {
	t.Helper()

	_, err := annotations.Parse(svc, annotations.Values{}, "")
	if err == nil {
		t.Fatal("Parse() error = nil, want an error")
	}
	return err
}

func TestInvalidAnnotationsErrorSingularMessage(t *testing.T) {
	t.Parallel()

	invalid := invalidError(t, mustParseError(t, map[string]string{"senselb.io/mode": "udp"}))

	message := invalid.Error()
	if !strings.Contains(message, "1 problem") || strings.Contains(message, "1 problems") {
		t.Fatalf("Error() = %q, want the singular noun", message)
	}
}

func TestParseReportsEveryInvalidAnnotation(t *testing.T) {
	t.Parallel()

	svc := map[string]string{
		"senselb.io/enabled":      "yes",
		"senselb.io/maxconn":      "0",
		"senselb.io/algorithm":    "weighted",
		"senselb.io/listenrs":     "public-http",
		"senselb.io/backend-name": "app-backend",
	}

	got, err := annotations.Parse(svc, annotations.Values{}, "")
	invalid := invalidError(t, err)

	if !reflect.DeepEqual(got, annotations.Values{}) {
		t.Fatalf("Parse() values = %+v, want the empty Values on error", got)
	}

	want := []string{
		"senselb.io/enabled",
		"senselb.io/maxconn",
		"senselb.io/algorithm",
		"senselb.io/listenrs",
	}
	if len(invalid.Annotations) != len(want) {
		t.Fatalf("annotations = %v, want %d entries", invalid.Annotations, len(want))
	}
	for _, key := range want {
		if _, ok := invalid.Annotations[key]; !ok {
			t.Errorf("annotations = %v, want key %q", invalid.Annotations, key)
		}
	}

	message := invalid.Error()
	for _, key := range want {
		if !strings.Contains(message, key) {
			t.Errorf("Error() = %q, want it to name %q", message, key)
		}
	}
	if strings.Contains(message, "backend-name") {
		t.Errorf("Error() = %q, want it not to name the valid backend-name annotation", message)
	}
}

func TestParseUnknownAnnotations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		svc        map[string]string
		prefix     string
		wantKey    string
		wantParsed annotations.Values
	}{
		{
			name:    "misspelt senselb key is rejected",
			svc:     map[string]string{"senselb.io/listenrs": "public-http"},
			wantKey: "senselb.io/listenrs",
		},
		{
			name: "foreign annotations are ignored",
			svc: map[string]string{
				"example.com/owner": "team-a",
				"bare-key":          "value",
			},
			wantParsed: annotations.DefaultValues(),
		},
		{
			name: "a key with a different prefix is ignored",
			svc: map[string]string{
				"senselb.io/listenrs": "public-http",
				"other.example/sni":   "app.example.com",
			},
			prefix:     "senselb.example.com/",
			wantParsed: annotations.DefaultValues(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := annotations.Parse(tc.svc, annotations.Values{}, tc.prefix)
			if tc.wantKey == "" {
				if err != nil {
					t.Fatalf("Parse() error = %v, want nil", err)
				}
				if !reflect.DeepEqual(got, tc.wantParsed) {
					t.Fatalf("Parse() = %+v, want %+v", got, tc.wantParsed)
				}
				return
			}

			invalid := invalidError(t, err)
			if _, ok := invalid.Annotations[tc.wantKey]; !ok {
				t.Fatalf("annotations = %v, want key %q", invalid.Annotations, tc.wantKey)
			}
		})
	}
}

func TestParseCustomPrefix(t *testing.T) {
	t.Parallel()

	svc := map[string]string{
		"senselb.example.com/listeners": "custom-listener",
		"senselb.example.com/algorithm": "leastconn",
		// A default-prefixed key is foreign under the custom prefix and must
		// neither apply nor error.
		"senselb.io/listeners": "wrong-listener",
		"senselb.io/enabled":   "false",
	}

	want := annotations.Values{
		Enabled:    true,
		Listeners:  []string{"custom-listener"},
		Algorithm:  "leastconn",
		TargetMode: "nodeport",
	}
	got := parseOK(t, svc, annotations.Values{}, "senselb.example.com/")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse() = %+v\nwant %+v", got, want)
	}
}

func TestParseAcceptedEdgeValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		key   string
		value string
		check func(got annotations.Values) bool
	}{
		{
			name:  "weight zero means no traffic",
			key:   "weight",
			value: "0",
			check: func(got annotations.Values) bool { return got.Weight == 0 },
		},
		{
			name:  "maxconn one is the minimum",
			key:   "maxconn",
			value: "1",
			check: func(got annotations.Values) bool { return got.MaxConn == 1 },
		},
		{
			name:  "strconv bool numeric spelling",
			key:   "proxy-protocol",
			value: "1",
			check: func(got annotations.Values) bool { return got.ProxyProtocol },
		},
		{
			name:  "duration is stored trimmed",
			key:   "timeout-connect",
			value: " 1500ms ",
			check: func(got annotations.Values) bool { return got.TimeoutConnect == "1500ms" },
		},
		{
			name:  "mode is normalised",
			key:   "mode",
			value: " TCP ",
			check: func(got annotations.Values) bool { return got.Mode == "tcp" },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := parseOK(t, map[string]string{"senselb.io/" + tc.key: tc.value}, annotations.Values{}, "")
			if !tc.check(got) {
				t.Fatalf("Parse() = %+v, value %q was not accepted as expected", got, tc.value)
			}
		})
	}
}
