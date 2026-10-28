package opnsense

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/yasn77/senselb/pkg/haproxy"
)

const (
	uuidFrontendHTTP     = "00000000-0000-0000-0000-000000000001"
	uuidFrontendHTTPS    = "00000000-0000-0000-0000-000000000002"
	uuidBackendHTTP      = "00000000-0000-0000-0000-000000000003"
	uuidBackendHTTPS     = "00000000-0000-0000-0000-000000000004"
	uuidBackendACME      = "00000000-0000-0000-0000-000000000005"
	uuidServerHTTP       = "00000000-0000-0000-0000-000000000006"
	uuidACLACME          = "00000000-0000-0000-0000-000000000007"
	uuidActionACME       = "00000000-0000-0000-0000-000000000008"
	uuidServerHTTPS      = "00000000-0000-0000-0000-000000000009"
	uuidHealthcheck      = "00000000-0000-0000-0000-000000000010"
	uuidServerACME       = "00000000-0000-0000-0000-000000000011"
	uuidCertificate      = "5f2a0c1e-0000-0000-0000-0000000000c1"
	acmeACLParameters    = "(X-Acme-Challenge) -i 1"
	acmeChallengeRule    = "redirect_acme_challenges"
	acmeChallengeACL     = "find_acme_challenge"
	acmeChallengeAddress = "127.0.0.1"
)

// fixtureSettingsJSON mirrors a live settings/get payload: the root "haproxy"
// object, collections keyed by uuid, enum fields as select objects, and linkage
// as uuid-keyed selects.
const fixtureSettingsJSON = `{
  "haproxy": {
    "general": {"enabled": "1"},
    "frontends": {
      "frontend": {
        "00000000-0000-0000-0000-000000000001": {
          "name": "HTTP",
          "description": "",
          "enabled": "1",
          "bind": {
            "0.0.0.0:80": {"value": "0.0.0.0:80", "selected": 1}
          },
          "mode": {
            "http": {"value": "HTTP / HTTPS (SSL offloading) [default]", "selected": 1},
            "ssl": {"value": "SSL / HTTPS (TCP mode)", "selected": 0},
            "tcp": {"value": "TCP", "selected": 0}
          },
          "defaultBackend": {
            "": {"value": "", "selected": 0}
          },
          "ssl_enabled": "0",
          "ssl_certificates": {
            "": {"value": "", "selected": 0}
          },
          "ssl_default_certificate": {
            "": {"value": "", "selected": 0}
          },
          "customOptions": "",
          "linkedActions": {
            "00000000-0000-0000-0000-000000000008": {"value": "redirect_acme_challenges", "selected": 1},
            "": {"value": "", "selected": 0}
          }
        },
        "00000000-0000-0000-0000-000000000002": {
          "name": "ingress-HTTPS",
          "description": "",
          "enabled": "1",
          "bind": {
            "0.0.0.0:443": {"value": "0.0.0.0:443", "selected": 1}
          },
          "mode": {
            "http": {"value": "HTTP / HTTPS (SSL offloading) [default]", "selected": 1},
            "ssl": {"value": "SSL / HTTPS (TCP mode)", "selected": 0},
            "tcp": {"value": "TCP", "selected": 0}
          },
          "defaultBackend": {
            "00000000-0000-0000-0000-000000000004": {"value": "k8s-ingress-HTTPS", "selected": 1},
            "": {"value": "", "selected": 0}
          },
          "ssl_enabled": "1",
          "ssl_certificates": {
            "5f2a0c1e-0000-0000-0000-0000000000c1": {"value": "k8s-ingress.pem", "selected": 1}
          },
          "ssl_default_certificate": {
            "5f2a0c1e-0000-0000-0000-0000000000c1": {"value": "k8s-ingress.pem", "selected": 1},
            "": {"value": "", "selected": 0}
          },
          "customOptions": "",
          "linkedActions": {
            "": {"value": "", "selected": 0}
          }
        }
      }
    },
    "backends": {
      "backend": {
        "00000000-0000-0000-0000-000000000003": {
          "name": "k8s-ingress-HTTP",
          "description": "",
          "enabled": "1",
          "mode": {
            "http": {"value": "HTTP (Layer 7) [default]", "selected": 1},
            "tcp": {"value": "TCP (Layer 4)", "selected": 0}
          },
          "algorithm": {
            "source": {"value": "Source-IP Hash [default]", "selected": 0},
            "roundrobin": {"value": "Round Robin", "selected": 1},
            "static-rr": {"value": "Static Round Robin", "selected": 0},
            "leastconn": {"value": "Least Connections", "selected": 0}
          },
          "linkedServers": {
            "00000000-0000-0000-0000-000000000006": {"value": "k8s_HTTP", "selected": 1},
            "": {"value": "", "selected": 0}
          },
          "linkedActions": {
            "": {"value": "", "selected": 0}
          },
          "healthCheckEnabled": "1",
          "healthCheck": {
            "00000000-0000-0000-0000-000000000010": {"value": "k8s-http", "selected": 1},
            "": {"value": "", "selected": 0}
          },
          "healthCheckFall": "3",
          "healthCheckRise": "2",
          "healthCheckProxyProto": {
            "backend": {"value": "Follow Backend Pool settings [default]", "selected": 1},
            "enable": {"value": "Enable for Health Check", "selected": 0},
            "disable": {"value": "Disable for Health Check", "selected": 0}
          },
          "persistence": {
            "sticktable": {"value": "Stick-table persistence [default]", "selected": 1},
            "cookie": {"value": "Cookie-based persistence (HTTP/HTTPS only)", "selected": 0}
          },
          "customOptions": "option forwardfor"
        },
        "00000000-0000-0000-0000-000000000004": {
          "name": "k8s-ingress-HTTPS",
          "description": "",
          "enabled": "1",
          "mode": {
            "http": {"value": "HTTP (Layer 7) [default]", "selected": 1},
            "tcp": {"value": "TCP (Layer 4)", "selected": 0}
          },
          "algorithm": {
            "source": {"value": "Source-IP Hash [default]", "selected": 1},
            "roundrobin": {"value": "Round Robin", "selected": 0}
          },
          "linkedServers": {
            "00000000-0000-0000-0000-000000000009": {"value": "k8s_HTTPS", "selected": 1},
            "": {"value": "", "selected": 0}
          },
          "linkedActions": {
            "": {"value": "", "selected": 0}
          },
          "healthCheckEnabled": "0",
          "healthCheck": {
            "": {"value": "", "selected": 0}
          },
          "persistence": {
            "sticktable": {"value": "Stick-table persistence [default]", "selected": 0},
            "cookie": {"value": "Cookie-based persistence (HTTP/HTTPS only)", "selected": 1}
          },
          "customOptions": ""
        },
        "00000000-0000-0000-0000-000000000005": {
          "name": "acme_challenge_backend",
          "description": "",
          "enabled": "1",
          "mode": {
            "http": {"value": "HTTP (Layer 7) [default]", "selected": 1},
            "tcp": {"value": "TCP (Layer 4)", "selected": 0}
          },
          "algorithm": {
            "roundrobin": {"value": "Round Robin", "selected": 1},
            "source": {"value": "Source-IP Hash [default]", "selected": 0}
          },
          "linkedServers": {
            "00000000-0000-0000-0000-000000000011": {"value": "acme_challenge_host", "selected": 1},
            "": {"value": "", "selected": 0}
          },
          "linkedActions": {
            "": {"value": "", "selected": 0}
          },
          "healthCheckEnabled": "0",
          "healthCheck": {
            "": {"value": "", "selected": 0}
          },
          "customOptions": ""
        }
      }
    },
    "servers": {
      "server": {
        "00000000-0000-0000-0000-000000000006": {
          "name": "k8s_HTTP",
          "description": "",
          "enabled": "1",
          "address": "192.168.1.176",
          "port": "30400",
          "checkport": "",
          "mode": {
            "active": {"value": "active [default]", "selected": 1},
            "backup": {"value": "backup", "selected": 0},
            "disabled": {"value": "disabled", "selected": 0}
          },
          "type": {
            "static": {"value": "static", "selected": 1},
            "template": {"value": "template", "selected": 0},
            "unix": {"value": "unix socket", "selected": 0}
          },
          "weight": "0",
          "maxConnections": "0",
          "checkInterval": "3s",
          "checkDownInterval": "",
          "source": ""
        },
        "00000000-0000-0000-0000-000000000009": {
          "name": "k8s_HTTPS",
          "description": "",
          "enabled": "1",
          "address": "192.168.1.176",
          "port": "30388",
          "checkport": "",
          "mode": {
            "active": {"value": "active [default]", "selected": 1},
            "backup": {"value": "backup", "selected": 0},
            "disabled": {"value": "disabled", "selected": 0}
          },
          "type": {
            "static": {"value": "static", "selected": 1},
            "template": {"value": "template", "selected": 0},
            "unix": {"value": "unix socket", "selected": 0}
          },
          "weight": "0",
          "maxConnections": "0",
          "checkInterval": "",
          "checkDownInterval": "",
          "source": ""
        },
        "00000000-0000-0000-0000-000000000011": {
          "name": "acme_challenge_host",
          "description": "",
          "enabled": "1",
          "address": "127.0.0.1",
          "port": "43580",
          "checkport": "",
          "mode": {
            "active": {"value": "active [default]", "selected": 1},
            "backup": {"value": "backup", "selected": 0},
            "disabled": {"value": "disabled", "selected": 0}
          },
          "type": {
            "static": {"value": "static", "selected": 1},
            "template": {"value": "template", "selected": 0},
            "unix": {"value": "unix socket", "selected": 0}
          },
          "weight": "0",
          "maxConnections": "0",
          "checkInterval": "",
          "checkDownInterval": "",
          "source": ""
        }
      }
    },
    "acls": {
      "acl": {
        "00000000-0000-0000-0000-000000000007": {
          "name": "find_acme_challenge",
          "description": "",
          "expression": {
            "cust_hdr_beg": {"value": "hdr_beg - specified HTTP Header starts with", "selected": 1},
            "hdr_beg": {"value": "hdr_beg - HTTP Host Header starts with", "selected": 0},
            "path_beg": {"value": "path_beg - Path starts with", "selected": 0}
          },
          "cust_hdr_beg_name": "X-Acme-Challenge",
          "cust_hdr_beg": "1",
          "caseSensitive": "0"
        }
      }
    },
    "actions": {
      "action": {
        "00000000-0000-0000-0000-000000000008": {
          "name": "redirect_acme_challenges",
          "description": "",
          "enabled": "1",
          "type": {
            "use_backend": {"value": "use_backend", "selected": 1},
            "http-request": {"value": "http-request", "selected": 0}
          },
          "testType": {
            "if": {"value": "if", "selected": 1},
            "unless": {"value": "unless", "selected": 0}
          },
          "linkedAcls": {
            "00000000-0000-0000-0000-000000000007": {"value": "find_acme_challenge", "selected": 1},
            "": {"value": "", "selected": 0}
          },
          "operator": {
            "and": {"value": "and", "selected": 1},
            "or": {"value": "or", "selected": 0}
          },
          "use_backend": {
            "00000000-0000-0000-0000-000000000005": {"value": "acme_challenge_backend", "selected": 1},
            "": {"value": "", "selected": 0}
          },
          "use_server": {
            "": {"value": "", "selected": 0}
          },
          "http_request_action": "",
          "custom": ""
        }
      }
    },
    "healthchecks": {
      "healthcheck": {
        "00000000-0000-0000-0000-000000000010": {
          "name": "k8s-http",
          "description": "",
          "type": {
            "http": {"value": "HTTP [default]", "selected": 1},
            "tcp": {"value": "TCP", "selected": 0}
          },
          "interval": "5s",
          "http_uri": "/healthz"
        }
      }
    }
  }
}`

// fixtureSettings decodes the representative settings payload.
func decodeFixtureSettings(t *testing.T) Settings {
	t.Helper()
	var settings Settings
	if err := json.Unmarshal([]byte(fixtureSettingsJSON), &settings); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return settings
}

// minimalSettings returns a structurally complete payload with empty
// collections, so a test can add the one object it exercises.
func minimalSettings() Settings {
	return Settings{
		"haproxy": map[string]any{
			"frontends":    map[string]any{"frontend": map[string]any{}},
			"backends":     map[string]any{"backend": map[string]any{}},
			"servers":      map[string]any{"server": map[string]any{}},
			"acls":         map[string]any{"acl": map[string]any{}},
			"actions":      map[string]any{"action": map[string]any{}},
			"healthchecks": map[string]any{"healthcheck": map[string]any{}},
		},
	}
}

// collection returns one decoded collection for a test to mutate.
func collection(t *testing.T, settings Settings, name, item string) map[string]any {
	t.Helper()
	root, ok := settings["haproxy"].(map[string]any)
	if !ok {
		t.Fatal("fixture has no haproxy root")
	}
	container, ok := root[name].(map[string]any)
	if !ok {
		t.Fatalf("fixture collection %q is missing", name)
	}
	objects, ok := container[item].(map[string]any)
	if !ok {
		t.Fatalf("fixture container %q.%q is missing", name, item)
	}
	return objects
}

func findFrontend(t *testing.T, model *haproxy.Model, name string) haproxy.Frontend {
	t.Helper()
	for _, frontend := range model.Frontends {
		if frontend.Name == name {
			return frontend
		}
	}
	t.Fatalf("frontend %q not found", name)
	return haproxy.Frontend{}
}

func findBackend(t *testing.T, model *haproxy.Model, name string) haproxy.Backend {
	t.Helper()
	for _, backend := range model.Backends {
		if backend.Name == name {
			return backend
		}
	}
	t.Fatalf("backend %q not found", name)
	return haproxy.Backend{}
}

// assertMalformed requires err to be a *MalformedSettingsError with wantPath.
func assertMalformed(t *testing.T, err error, wantPath string) {
	t.Helper()
	var malformed *MalformedSettingsError
	if !errors.As(err, &malformed) {
		t.Fatalf("error = %v, want *MalformedSettingsError", err)
	}
	if malformed.Path != wantPath {
		t.Errorf("error path = %q, want %q", malformed.Path, wantPath)
	}
}

func TestFromSettings(t *testing.T) {
	model, dangling, err := FromSettings(decodeFixtureSettings(t))
	if err != nil {
		t.Fatalf("FromSettings: %v", err)
	}
	if len(dangling) != 0 {
		t.Errorf("dangling references = %v, want none", dangling)
	}

	if len(model.Frontends) != 2 {
		t.Fatalf("frontends = %d, want 2", len(model.Frontends))
	}
	if len(model.Backends) != 3 {
		t.Fatalf("backends = %d, want 3", len(model.Backends))
	}

	t.Run("frontend HTTP", func(t *testing.T) {
		frontend := findFrontend(t, model, "HTTP")
		if frontend.UUID != uuidFrontendHTTP {
			t.Errorf("uuid = %q, want %q", frontend.UUID, uuidFrontendHTTP)
		}
		if !slices.Equal(frontend.Bind, []string{"0.0.0.0:80"}) {
			t.Errorf("bind = %v, want [0.0.0.0:80]", frontend.Bind)
		}
		if frontend.Mode != haproxy.ModeHTTP {
			t.Errorf("mode = %q, want http", frontend.Mode)
		}
		if frontend.DefaultBackend != "" {
			t.Errorf("default backend = %q, want empty", frontend.DefaultBackend)
		}
		if frontend.SSLEnabled {
			t.Error("ssl enabled = true, want false")
		}

		if len(frontend.Rules) != 1 {
			t.Fatalf("rules = %d, want 1", len(frontend.Rules))
		}
		rule := frontend.Rules[0]
		if rule.UUID != uuidActionACME || rule.Name != acmeChallengeRule {
			t.Errorf("rule = %q (%q), want %q (%q)", rule.Name, rule.UUID, acmeChallengeRule, uuidActionACME)
		}
		if rule.Type != haproxy.RuleTypeUseBackend {
			t.Errorf("rule type = %q, want use_backend", rule.Type)
		}
		if rule.TestType != haproxy.RuleTestTypeIf {
			t.Errorf("test type = %q, want if", rule.TestType)
		}
		if rule.Operator != haproxy.RuleOperatorAnd {
			t.Errorf("operator = %q, want and", rule.Operator)
		}
		if !slices.Equal(rule.LinkedACLs, []string{acmeChallengeACL}) {
			t.Errorf("linked acls = %v, want [%s]", rule.LinkedACLs, acmeChallengeACL)
		}
		if rule.UseBackend != "acme_challenge_backend" {
			t.Errorf("use backend = %q, want acme_challenge_backend", rule.UseBackend)
		}
		if rule.UseServer != "" {
			t.Errorf("use server = %q, want empty", rule.UseServer)
		}

		if len(frontend.ACLs) != 1 {
			t.Fatalf("acls = %d, want 1", len(frontend.ACLs))
		}
		acl := frontend.ACLs[0]
		if acl.UUID != uuidACLACME || acl.Name != acmeChallengeACL {
			t.Errorf("acl = %q (%q), want %q (%q)", acl.Name, acl.UUID, acmeChallengeACL, uuidACLACME)
		}
		if acl.Expression != haproxy.ACLExpressionHdrBeg {
			t.Errorf("expression = %q, want hdr_beg", acl.Expression)
		}
		if acl.Parameters != acmeACLParameters {
			t.Errorf("parameters = %q, want %q", acl.Parameters, acmeACLParameters)
		}
	})

	t.Run("frontend ingress-HTTPS", func(t *testing.T) {
		frontend := findFrontend(t, model, "ingress-HTTPS")
		if frontend.UUID != uuidFrontendHTTPS {
			t.Errorf("uuid = %q, want %q", frontend.UUID, uuidFrontendHTTPS)
		}
		if !slices.Equal(frontend.Bind, []string{"0.0.0.0:443"}) {
			t.Errorf("bind = %v, want [0.0.0.0:443]", frontend.Bind)
		}
		if frontend.DefaultBackend != "k8s-ingress-HTTPS" {
			t.Errorf("default backend = %q, want k8s-ingress-HTTPS", frontend.DefaultBackend)
		}
		if !frontend.SSLEnabled {
			t.Error("ssl enabled = false, want true")
		}
		if !slices.Equal(frontend.SSLCertificates, []string{uuidCertificate}) {
			t.Errorf("ssl certificates = %v, want [%s]", frontend.SSLCertificates, uuidCertificate)
		}
		if frontend.SSLDefaultCert != uuidCertificate {
			t.Errorf("ssl default certificate = %q, want %q", frontend.SSLDefaultCert, uuidCertificate)
		}
	})

	t.Run("backend k8s-ingress-HTTP", func(t *testing.T) {
		backend := findBackend(t, model, "k8s-ingress-HTTP")
		if backend.UUID != uuidBackendHTTP {
			t.Errorf("uuid = %q, want %q", backend.UUID, uuidBackendHTTP)
		}
		if backend.Mode != haproxy.ModeHTTP {
			t.Errorf("mode = %q, want http", backend.Mode)
		}
		if backend.Algorithm != haproxy.AlgorithmRoundRobin {
			t.Errorf("algorithm = %q, want roundrobin", backend.Algorithm)
		}
		if !backend.Sticky {
			t.Error("sticky = false, want true")
		}
		if backend.CustomOptions != "option forwardfor" {
			t.Errorf("custom options = %q, want option forwardfor", backend.CustomOptions)
		}
		if len(backend.Servers) != 1 {
			t.Fatalf("servers = %d, want 1", len(backend.Servers))
		}
		server := backend.Servers[0]
		if server.UUID != uuidServerHTTP || server.Name != "k8s_HTTP" {
			t.Errorf("server = %q (%q), want k8s_HTTP (%q)", server.Name, server.UUID, uuidServerHTTP)
		}
		if server.Address != "192.168.1.176" || server.Port != 30400 {
			t.Errorf("server address = %s:%d, want 192.168.1.176:30400", server.Address, server.Port)
		}
		if server.Mode != haproxy.ServerModeActive || server.Type != haproxy.ServerTypeStatic {
			t.Errorf("server mode/type = %q/%q, want active/static", server.Mode, server.Type)
		}
		// The plugin keeps checkInterval in a text field; the model keeps
		// seconds, so the unit suffix is dropped.
		if server.CheckInterval != 3 {
			t.Errorf("check interval = %d, want 3", server.CheckInterval)
		}

		if backend.HealthCheck == nil {
			t.Fatal("health check = nil, want a decoded check")
		}
		check := *backend.HealthCheck
		if !check.Enabled {
			t.Error("health check enabled = false, want true")
		}
		if check.Type != haproxy.HealthCheckTypeHTTP {
			t.Errorf("health check type = %q, want http", check.Type)
		}
		if check.Path != "/healthz" {
			t.Errorf("health check path = %q, want /healthz", check.Path)
		}
		if check.Interval != 5 {
			t.Errorf("health check interval = %d, want 5", check.Interval)
		}
		if check.Fall != 3 || check.Rise != 2 {
			t.Errorf("health check fall/rise = %d/%d, want 3/2", check.Fall, check.Rise)
		}
		if check.ProxyProto {
			t.Error("health check proxy protocol = true, want false")
		}
	})

	t.Run("backend k8s-ingress-HTTPS", func(t *testing.T) {
		backend := findBackend(t, model, "k8s-ingress-HTTPS")
		if backend.UUID != uuidBackendHTTPS {
			t.Errorf("uuid = %q, want %q", backend.UUID, uuidBackendHTTPS)
		}
		if backend.Algorithm != haproxy.AlgorithmSource {
			t.Errorf("algorithm = %q, want source", backend.Algorithm)
		}
		if backend.Sticky {
			t.Error("sticky = true, want false")
		}
		if backend.HealthCheck != nil {
			t.Errorf("health check = %+v, want nil", backend.HealthCheck)
		}
		if len(backend.Servers) != 1 {
			t.Fatalf("servers = %d, want 1", len(backend.Servers))
		}
		if server := backend.Servers[0]; server.UUID != uuidServerHTTPS || server.Port != 30388 {
			t.Errorf("server = %q (%q) on %d, want k8s_HTTPS (%q) on 30388", server.Name, server.UUID, server.Port, uuidServerHTTPS)
		}
	})

	t.Run("backend acme_challenge_backend", func(t *testing.T) {
		backend := findBackend(t, model, "acme_challenge_backend")
		if len(backend.Servers) != 1 {
			t.Fatalf("servers = %d, want 1", len(backend.Servers))
		}
		server := backend.Servers[0]
		if server.UUID != uuidServerACME || server.Address != acmeChallengeAddress || server.Port != 43580 {
			t.Errorf("server = %q (%q) on %s:%d, want acme_challenge_host (%q) on %s:43580",
				server.Name, server.UUID, server.Address, server.Port, uuidServerACME, acmeChallengeAddress)
		}
		if len(backend.Rules) != 0 || len(backend.ACLs) != 0 {
			t.Errorf("rules/acls = %d/%d, want 0/0", len(backend.Rules), len(backend.ACLs))
		}
	})
}

// TestFromSettingsRebuildsACLParameters covers the plugin shape that carries an
// ACL's argument in the expression's own field rather than in "parameters".
func TestFromSettingsRebuildsACLParameters(t *testing.T) {
	values := map[string]any{
		"name": acmeChallengeACL,
		"expression": map[string]any{
			"cust_hdr_beg": map[string]any{"value": "hdr_beg - specified HTTP Header starts with", "selected": float64(1)},
			"hdr_beg":      map[string]any{"value": "hdr_beg - HTTP Host Header starts with", "selected": float64(0)},
		},
		"cust_hdr_beg_name": "X-Acme-Challenge",
		"cust_hdr_beg":      "1",
		"caseSensitive":     "0",
	}

	acl, err := decodeACL(settingsObject{
		uuid:   uuidACLACME,
		path:   "haproxy.acls.acl." + uuidACLACME,
		values: values,
	})
	if err != nil {
		t.Fatalf("decodeACL: %v", err)
	}
	if acl.Expression != haproxy.ACLExpressionHdrBeg {
		t.Errorf("expression = %q, want hdr_beg", acl.Expression)
	}
	if acl.Parameters != acmeACLParameters {
		t.Errorf("parameters = %q, want %q", acl.Parameters, acmeACLParameters)
	}
}

func TestFromSettingsMalformed(t *testing.T) {
	t.Run("missing root", func(t *testing.T) {
		_, _, err := FromSettings(Settings{})
		assertMalformed(t, err, "haproxy")
	})

	t.Run("missing collection", func(t *testing.T) {
		settings := decodeFixtureSettings(t)
		delete(settings["haproxy"].(map[string]any), "frontends")
		_, _, err := FromSettings(settings)
		assertMalformed(t, err, "haproxy.frontends")
	})

	t.Run("collection of wrong type", func(t *testing.T) {
		settings := decodeFixtureSettings(t)
		settings["haproxy"].(map[string]any)["frontends"] = 42
		_, _, err := FromSettings(settings)
		assertMalformed(t, err, "haproxy.frontends")
	})

	t.Run("field of wrong type", func(t *testing.T) {
		settings := decodeFixtureSettings(t)
		collection(t, settings, "servers", "server")[uuidServerHTTP].(map[string]any)["port"] = "not-a-number"
		_, _, err := FromSettings(settings)
		assertMalformed(t, err, "haproxy.servers.server."+uuidServerHTTP+".port")
	})

	t.Run("entry of wrong type", func(t *testing.T) {
		settings := decodeFixtureSettings(t)
		collection(t, settings, "frontends", "frontend")[uuidFrontendHTTP] = "not-an-object"
		_, _, err := FromSettings(settings)
		assertMalformed(t, err, "haproxy.frontends.frontend."+uuidFrontendHTTP)
	})

	t.Run("unknown relation is skipped", func(t *testing.T) {
		settings := decodeFixtureSettings(t)
		collection(t, settings, "frontends", "frontend")[uuidFrontendHTTPS].(map[string]any)["defaultBackend"] = map[string]any{
			"00000000-0000-0000-0000-00000000dead": map[string]any{"value": "gone", "selected": float64(1)},
		}
		model, dangling, err := FromSettings(settings)
		if err != nil {
			t.Fatalf("FromSettings: %v", err)
		}
		frontend := findFrontend(t, model, "ingress-HTTPS")
		if frontend.DefaultBackend != "" {
			t.Errorf("default backend = %q, want empty for a dangling reference", frontend.DefaultBackend)
		}
		want := "haproxy.frontends.frontend." + uuidFrontendHTTPS +
			".defaultBackend.00000000-0000-0000-0000-00000000dead"
		if len(dangling) != 1 || dangling[0] != want {
			t.Errorf("dangling references = %v, want [%s]", dangling, want)
		}
	})

	t.Run("empty array collection", func(t *testing.T) {
		settings := minimalSettings()
		settings["haproxy"].(map[string]any)["backends"] = []any{}
		model, _, err := FromSettings(settings)
		if err != nil {
			t.Fatalf("FromSettings: %v", err)
		}
		if len(model.Backends) != 0 {
			t.Errorf("backends = %d, want 0", len(model.Backends))
		}
	})
}

func TestFlattenSelect(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{name: "selected option", value: map[string]any{
			"http": map[string]any{"value": "HTTP", "selected": float64(1)},
			"tcp":  map[string]any{"value": "TCP", "selected": float64(0)},
		}, want: "http"},
		{name: "selected as string flag", value: map[string]any{
			"backup": map[string]any{"value": "backup", "selected": "1"},
			"active": map[string]any{"value": "active", "selected": "0"},
		}, want: "backup"},
		{name: "plain string", value: "tcp", want: "tcp"},
		{name: "nil", value: nil, want: ""},
		{name: "empty object", value: map[string]any{}, want: ""},
		{name: "unselected empty key", value: map[string]any{
			"": map[string]any{"value": "", "selected": float64(1)},
		}, want: ""},
		{name: "unexpected type", value: float64(3), want: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := flattenSelect(test.value); got != test.want {
				t.Errorf("flattenSelect(%v) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}

// assertSinglePrefix requires every form key to belong to want's key family.
func assertSinglePrefix(t *testing.T, form url.Values, want string) {
	t.Helper()
	if len(form) == 0 {
		t.Fatal("form is empty")
	}
	for key := range form {
		open := strings.IndexByte(key, '[')
		if open < 0 || key[:open] != want {
			t.Errorf("form key %q does not belong to the %s[...] family", key, want)
		}
	}
}

// assertFormValue checks one form field.
func assertFormValue(t *testing.T, form url.Values, key, want string) {
	t.Helper()
	if got := form.Get(key); got != want {
		t.Errorf("%s = %q, want %q", key, got, want)
	}
}

func TestToServerForm(t *testing.T) {
	server := haproxy.Server{
		Name:    "k8s_HTTP",
		Address: "192.168.1.176",
		Port:    30400,
		Mode:    haproxy.ServerModeActive,
		Type:    haproxy.ServerTypeStatic,
		Weight:  10,
		MaxConn: 100,
	}
	form := ToServerForm(server)
	assertSinglePrefix(t, form, "server")

	assertFormValue(t, form, "server[enabled]", "1")
	assertFormValue(t, form, "server[name]", "k8s_HTTP")
	assertFormValue(t, form, "server[address]", "192.168.1.176")
	assertFormValue(t, form, "server[port]", "30400")
	assertFormValue(t, form, "server[mode]", "active")
	assertFormValue(t, form, "server[type]", "static")
	assertFormValue(t, form, "server[weight]", "10")
	assertFormValue(t, form, "server[maxConnections]", "100")
	assertFormValue(t, form, "server[checkport]", "")
}

// TestToServerFormDurationUnits covers finding that HAProxy reads a bare interval
// as milliseconds: the plugin's interval fields must carry their seconds unit.
func TestToServerFormDurationUnits(t *testing.T) {
	server := haproxy.Server{
		Name:              "k8s_HTTP",
		Address:           "192.168.1.176",
		Port:              30400,
		CheckInterval:     3,
		CheckDownInterval: 15,
	}
	form := ToServerForm(server)
	assertFormValue(t, form, "server[checkInterval]", "3s")
	assertFormValue(t, form, "server[checkDownInterval]", "15s")

	server.CheckInterval = 0
	server.CheckDownInterval = 0
	form = ToServerForm(server)
	assertFormValue(t, form, "server[checkInterval]", "")
	assertFormValue(t, form, "server[checkDownInterval]", "")
}

// TestServerIntervalStoreRoundTrip writes a server with a check interval and
// reads it back: 3 seconds must reach the plugin as "3s" and return as 3.
func TestServerIntervalStoreRoundTrip(t *testing.T) {
	t.Parallel()

	baseURL, fake := newFakeServer(t)
	client, err := NewClient(ClientConfig{URL: baseURL, Key: testKey, Secret: testSecret})
	if err != nil {
		t.Fatalf("NewClient(): %v", err)
	}

	want := haproxy.Server{
		Name:              "senselb-app-1",
		Address:           "10.0.0.1",
		Port:              30080,
		Mode:              haproxy.ServerModeActive,
		Type:              haproxy.ServerTypeStatic,
		CheckInterval:     3,
		CheckDownInterval: 30,
	}
	const uuid = "00000000-0000-0000-0000-0000000000f1"
	if err := client.Set(kindServer, uuid, ToServerForm(want)); err != nil {
		t.Fatalf("Set(): %v", err)
	}

	_, stored, found := fake.findObject(kindServer, want.Name)
	if !found {
		t.Fatal("the server was not stored")
	}
	if got := firstValue(stored["checkInterval"]); got != "3s" {
		t.Errorf("stored checkInterval = %q, want %q", got, "3s")
	}

	settings, err := client.Get()
	if err != nil {
		t.Fatalf("Get(): %v", err)
	}
	values, found := settingsObjectValues(settings, kindServer, uuid)
	if !found {
		t.Fatal("the server is missing from the settings payload")
	}
	got, err := decodeServer(settingsObject{uuid: uuid, path: "haproxy.servers.server." + uuid, values: values})
	if err != nil {
		t.Fatalf("decodeServer: %v", err)
	}
	if got.CheckInterval != want.CheckInterval || got.CheckDownInterval != want.CheckDownInterval {
		t.Errorf("round trip intervals = %d/%d, want %d/%d",
			got.CheckInterval, got.CheckDownInterval, want.CheckInterval, want.CheckDownInterval)
	}
}

func TestToBackendForm(t *testing.T) {
	backend := haproxy.Backend{
		Name:          "k8s-ingress-HTTP",
		Mode:          haproxy.ModeHTTP,
		Algorithm:     haproxy.AlgorithmRoundRobin,
		Sticky:        true,
		CustomOptions: "option forwardfor",
	}
	form := ToBackendForm(backend)
	assertSinglePrefix(t, form, "backend")

	assertFormValue(t, form, "backend[enabled]", "1")
	assertFormValue(t, form, "backend[name]", "k8s-ingress-HTTP")
	assertFormValue(t, form, "backend[mode]", "http")
	assertFormValue(t, form, "backend[algorithm]", "roundrobin")
	assertFormValue(t, form, "backend[persistence]", "sticktable")
	assertFormValue(t, form, "backend[customOptions]", "option forwardfor")
	if form.Has("backend[linkedServers][]") {
		t.Error("form carries linkedServers; linkage belongs to the provider")
	}

	backend.Sticky = false
	if got := ToBackendForm(backend).Get("backend[persistence]"); got != "" {
		t.Errorf("backend[persistence] = %q, want empty for a non-sticky backend", got)
	}
}

func TestToFrontendForm(t *testing.T) {
	frontend := haproxy.Frontend{
		Name:            "ingress-HTTPS",
		Bind:            []string{"0.0.0.0:443", "[::]:443"},
		Mode:            haproxy.ModeHTTP,
		DefaultBackend:  "k8s-ingress-HTTPS",
		SSLEnabled:      true,
		SSLCertificates: []string{uuidCertificate, "another-cert"},
		SSLDefaultCert:  uuidCertificate,
		CustomOptions:   "option httplog",
	}
	form := ToFrontendForm(frontend)
	assertSinglePrefix(t, form, "frontend")

	assertFormValue(t, form, "frontend[enabled]", "1")
	assertFormValue(t, form, "frontend[name]", "ingress-HTTPS")
	assertFormValue(t, form, "frontend[mode]", "http")
	assertFormValue(t, form, "frontend[ssl_enabled]", "1")
	assertFormValue(t, form, "frontend[ssl_default_certificate]", uuidCertificate)
	assertFormValue(t, form, "frontend[customOptions]", "option httplog")

	if got, want := form["frontend[bind][]"], []string{"0.0.0.0:443", "[::]:443"}; !slices.Equal(got, want) {
		t.Errorf("bind = %v, want %v", got, want)
	}
	if got, want := form["frontend[ssl_certificates][]"], []string{uuidCertificate, "another-cert"}; !slices.Equal(got, want) {
		t.Errorf("ssl certificates = %v, want %v", got, want)
	}
	if form.Has("frontend[defaultBackend]") {
		t.Error("form carries defaultBackend; linkage belongs to the provider")
	}
	if form.Has("frontend[linkedActions][]") {
		t.Error("form carries linkedActions; linkage belongs to the provider")
	}
}

func TestToACLForm(t *testing.T) {
	t.Run("plain argument", func(t *testing.T) {
		acl := haproxy.ACL{
			Name:        acmeChallengeACL,
			Description: "",
			Expression:  haproxy.ACLExpressionPathBeg,
			Parameters:  "/.well-known/acme-challenge",
		}
		form := ToACLForm(acl)
		assertSinglePrefix(t, form, "acl")

		assertFormValue(t, form, "acl[name]", acmeChallengeACL)
		assertFormValue(t, form, "acl[expression]", "path_beg")
		assertFormValue(t, form, "acl[path_beg]", "/.well-known/acme-challenge")
		// A parameter without -i is case-sensitive in the plugin's encoding.
		assertFormValue(t, form, "acl[caseSensitive]", formTrue)
		if form.Has("acl[parameters]") {
			t.Error("form carries acl[parameters]; the plugin ACL model has no such field")
		}
		if form.Has("acl[enabled]") {
			t.Error("form carries enabled; an ACL has no enabled flag")
		}
	})

	t.Run("host header", func(t *testing.T) {
		acl := haproxy.ACL{
			Name:       "host-acl",
			Expression: haproxy.ACLExpressionHdrBeg,
			Parameters: "(host) -i example.com",
		}
		form := ToACLForm(acl)
		assertSinglePrefix(t, form, "acl")

		assertFormValue(t, form, "acl[expression]", "hdr_beg")
		assertFormValue(t, form, "acl[hdr_beg]", "example.com")
		assertFormValue(t, form, "acl[caseSensitive]", formFalse)
		if form.Has("acl[cust_hdr_beg]") {
			t.Error("form carries cust_hdr_beg for the host header")
		}
		if form.Has("acl[parameters]") {
			t.Error("form carries acl[parameters]; the plugin ACL model has no such field")
		}
	})
}

// TestACLFormRoundTripFixture covers the inversion of the read path: the
// fixture's cust_hdr_beg ACL maps onto the form that recreates it.
func TestACLFormRoundTripFixture(t *testing.T) {
	model, _, err := FromSettings(decodeFixtureSettings(t))
	if err != nil {
		t.Fatalf("FromSettings: %v", err)
	}
	frontend := findFrontend(t, model, "HTTP")
	if len(frontend.ACLs) != 1 {
		t.Fatalf("acls = %d, want 1", len(frontend.ACLs))
	}

	form := ToACLForm(frontend.ACLs[0])
	assertFormValue(t, form, "acl[expression]", "cust_hdr_beg")
	assertFormValue(t, form, "acl[cust_hdr_beg]", "1")
	assertFormValue(t, form, "acl[cust_hdr_beg_name]", "X-Acme-Challenge")
	assertFormValue(t, form, "acl[caseSensitive]", formFalse)
	if form.Has("acl[parameters]") {
		t.Error("form carries acl[parameters]; the plugin ACL model has no such field")
	}
}

// TestACLStoreRoundTrip writes an ACL form into the fake plugin store and reads
// it back through decodeACL, proving the write encoding is the inverse of the
// read encoding.
func TestACLStoreRoundTrip(t *testing.T) {
	t.Parallel()

	baseURL, fake := newFakeServer(t)
	fake.seedFixture()
	client, err := NewClient(ClientConfig{URL: baseURL, Key: testKey, Secret: testSecret})
	if err != nil {
		t.Fatalf("NewClient(): %v", err)
	}

	cases := []haproxy.ACL{
		{
			Name:       "senselb-host-acl",
			Expression: haproxy.ACLExpressionHdrBeg,
			Parameters: "(host) -i example.com",
		},
		{
			Name:       "senselb-header-acl",
			Expression: haproxy.ACLExpressionHdrSub,
			Parameters: "(X-Senselb) api",
		},
		{
			Name:       "senselb-path-reg-acl",
			Expression: haproxy.ACLExpressionPathReg,
			Parameters: "-i ^/api/v[0-9]+$",
		},
		{
			Name:       "senselb-src-acl",
			Expression: haproxy.ACLExpressionSrc,
			Parameters: "10.0.0.0/8",
		},
	}
	for i, want := range cases {
		uuid := fmt.Sprintf("00000000-0000-0000-0000-0000000000c%d", i+1)
		if err := client.Set(kindACL, uuid, ToACLForm(want)); err != nil {
			t.Fatalf("Set(%q): %v", want.Name, err)
		}
	}

	settings, err := client.Get()
	if err != nil {
		t.Fatalf("Get(): %v", err)
	}
	for _, want := range cases {
		uuid, found := settingsUUIDByName(settings, kindACL, want.Name)
		if !found {
			t.Fatalf("ACL %q was not stored", want.Name)
		}
		values, found := settingsObjectValues(settings, kindACL, uuid)
		if !found {
			t.Fatalf("ACL %q has no stored object", want.Name)
		}
		got, err := decodeACL(settingsObject{
			uuid:   uuid,
			path:   "haproxy.acls.acl." + uuid,
			values: values,
		})
		if err != nil {
			t.Fatalf("decodeACL(%q): %v", want.Name, err)
		}
		if got.Expression != want.Expression || got.Parameters != want.Parameters {
			t.Errorf("round trip = %q %q, want %q %q",
				got.Expression, got.Parameters, want.Expression, want.Parameters)
		}
		if form := ToACLForm(got); form.Has("acl[parameters]") {
			t.Errorf("form for %q carries acl[parameters]; the plugin model has no such field", want.Name)
		}
	}
}

func TestToRuleForm(t *testing.T) {
	rule := haproxy.Rule{
		Name:              acmeChallengeRule,
		Type:              haproxy.RuleTypeUseBackend,
		TestType:          haproxy.RuleTestTypeIf,
		LinkedACLs:        []string{acmeChallengeACL},
		Operator:          haproxy.RuleOperatorAnd,
		UseBackend:        "acme_challenge_backend",
		HTTPRequestAction: "",
	}
	form := ToRuleForm(rule)
	assertSinglePrefix(t, form, "action")

	assertFormValue(t, form, "action[enabled]", "1")
	assertFormValue(t, form, "action[name]", acmeChallengeRule)
	assertFormValue(t, form, "action[type]", "use_backend")
	assertFormValue(t, form, "action[testType]", "if")
	assertFormValue(t, form, "action[operator]", "and")
	if form.Has("action[linkedAcls][]") {
		t.Error("form carries linkedAcls; linkage belongs to the provider")
	}
	if form.Has("action[use_backend]") {
		t.Error("form carries use_backend; linkage belongs to the provider")
	}
}

func TestIsOwned(t *testing.T) {
	for _, name := range []string{"k8s_HTTP", acmeChallengeACL, acmeChallengeRule, "ingress-HTTPS"} {
		if IsOwned(name, OwnedDescription) {
			t.Errorf("IsOwned(%q) = true, want false", name)
		}
	}

	if !IsOwned("senselb-web-prod-80", OwnedDescription) {
		t.Error("IsOwned of a prefixed name with the managed description = false, want true")
	}
	if IsOwned("senselb-web-prod-80", "someone else's description") {
		t.Error("IsOwned with a foreign description = true, want false")
	}
	if IsOwned("web-prod-80", OwnedDescription) {
		t.Error("IsOwned of an unprefixed name = true, want false")
	}
}

func TestOwnedName(t *testing.T) {
	tests := []struct {
		name  string
		parts []string
		want  string
	}{
		{name: "three parts", parts: []string{"web", "prod", "80"}, want: "senselb-web-prod-80"},
		{name: "lowercased", parts: []string{"Web", "Prod"}, want: "senselb-web-prod"},
		{name: "no parts", parts: nil, want: ""},
		{name: "empty part", parts: []string{"web", "", "80"}, want: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := OwnedName(test.parts...); got != test.want {
				t.Errorf("OwnedName(%q) = %q, want %q", test.parts, got, test.want)
			}
		})
	}
}
