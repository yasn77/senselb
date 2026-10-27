package haproxy_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/yasn77/senselb/pkg/haproxy"
)

// validModel returns a fully populated model that exercises every construct
// and must pass validation.
func validModel() *haproxy.Model {
	routeArgocd := haproxy.NewRule("route-argocd", haproxy.RuleTypeUseBackend)
	routeArgocd.LinkedACLs = []string{"host-argocd"}
	routeArgocd.UseBackend = "argocd"

	routeAPI := haproxy.NewRule("route-api", haproxy.RuleTypeUseBackend)
	routeAPI.LinkedACLs = []string{"host-argocd", "path-api"}
	routeAPI.Operator = haproxy.RuleOperatorOr
	routeAPI.UseBackend = "api"

	forwardedProto := haproxy.NewRule("forwarded-proto", haproxy.RuleTypeHTTPRequest)
	forwardedProto.HTTPRequestAction = "set-header X-Forwarded-Proto https"

	selectNode := haproxy.NewRule("select-node-1", haproxy.RuleTypeUseServer)
	selectNode.LinkedACLs = []string{"src-lan"}
	selectNode.UseServer = "node-1"

	customTuning := haproxy.NewRule("custom-tuning", haproxy.RuleTypeCustom)
	customTuning.Custom = "option forwardfor"

	external := haproxy.NewFrontend("external", haproxy.ModeSSL, "0.0.0.0:443")
	external.DefaultBackend = "default"
	external.ACLs = []haproxy.ACL{
		haproxy.NewACL("host-argocd", haproxy.ACLExpressionHdr, "(host) -i argocd.example.com"),
		haproxy.NewACL("path-api", haproxy.ACLExpressionPathBeg, "/api"),
	}
	external.Rules = []haproxy.Rule{routeArgocd, routeAPI, forwardedProto}
	external.SSLEnabled = true
	external.SSLCertificates = []string{"example.pem"}
	external.SSLDefaultCert = "example.pem"

	argocd := haproxy.NewBackend("argocd", haproxy.ModeHTTP)
	argocd.Servers = []haproxy.Server{haproxy.NewServer("node-1", "10.0.0.11", 30080)}
	argocd.HealthCheck = &haproxy.HealthCheck{
		Enabled:  true,
		Type:     haproxy.HealthCheckTypeHTTP,
		Path:     "/healthz",
		Interval: 2,
		Fall:     3,
		Rise:     2,
	}

	api := haproxy.NewBackend("api", haproxy.ModeTCP)
	api.Algorithm = haproxy.AlgorithmLeastConn
	api.ACLs = []haproxy.ACL{
		haproxy.NewACL("src-lan", haproxy.ACLExpressionSrc, "10.0.0.0/8"),
	}
	api.Servers = []haproxy.Server{haproxy.NewServer("node-1", "10.0.0.11", 30081)}
	api.Rules = []haproxy.Rule{selectNode, customTuning}

	fallback := haproxy.NewBackend("default", haproxy.ModeHTTP)
	fallback.Algorithm = haproxy.AlgorithmSource
	fallback.Servers = []haproxy.Server{haproxy.NewServer("default", "10.0.0.12", 30082)}

	return &haproxy.Model{
		Frontends: []haproxy.Frontend{external},
		Backends:  []haproxy.Backend{argocd, api, fallback},
		Listeners: []haproxy.Listener{
			haproxy.NewListener("external", haproxy.ModeSSL, false, "", "0.0.0.0:443"),
			haproxy.NewListener("internal", haproxy.ModeHTTP, true, "internal-fe"),
		},
	}
}

func TestValidateAcceptsValidModel(t *testing.T) {
	if err := validModel().Validate(); err != nil {
		t.Fatalf("valid model was rejected: %v", err)
	}
}

func TestValidateRejectsInvalidModels(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*haproxy.Model)
		want   string
	}{
		{
			name:   "empty frontend name",
			mutate: func(m *haproxy.Model) { m.Frontends[0].Name = "" },
			want:   "frontend[0]: name must not be empty",
		},
		{
			name: "duplicate frontend name",
			mutate: func(m *haproxy.Model) {
				m.Frontends = append(m.Frontends, haproxy.NewFrontend("external", haproxy.ModeHTTP, "0.0.0.0:80"))
			},
			want: `frontend "external": duplicate name`,
		},
		{
			name:   "invalid frontend mode",
			mutate: func(m *haproxy.Model) { m.Frontends[0].Mode = "udp" },
			want:   `frontend "external": mode "udp" is not valid`,
		},
		{
			name: "duplicate ACL name in a frontend",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].ACLs[1].Name = "host-argocd"
			},
			want: `frontend "external" ACL "host-argocd": duplicate name`,
		},
		{
			name: "invalid ACL expression",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].ACLs[0].Expression = "cookie"
			},
			want: `frontend "external" ACL "host-argocd": expression "cookie" is not valid`,
		},
		{
			name: "duplicate rule name in a frontend",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].Rules[1].Name = "route-argocd"
			},
			want: `frontend "external" rule "route-argocd": duplicate name`,
		},
		{
			name: "invalid rule type",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].Rules[0].Type = "deny"
			},
			want: `rule "route-argocd": type "deny" is not valid`,
		},
		{
			name: "invalid rule test type",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].Rules[0].TestType = "when"
			},
			want: `rule "route-argocd": test type "when" is not valid`,
		},
		{
			name: "invalid rule operator",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].Rules[0].Operator = "xor"
			},
			want: `rule "route-argocd": operator "xor" is not valid`,
		},
		{
			name: "use_backend without a backend",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].Rules[0].UseBackend = ""
			},
			want: `rule "route-argocd": use_backend requires a backend`,
		},
		{
			name: "use_backend naming an undeclared backend",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].Rules[0].UseBackend = "missing"
			},
			want: `rule "route-argocd": backend "missing" is not declared`,
		},
		{
			name: "use_server without a server",
			mutate: func(m *haproxy.Model) {
				m.Backends[1].Rules[0].UseServer = ""
			},
			want: `backend "api" rule "select-node-1": use_server requires a server`,
		},
		{
			name: "dangling ACL reference in a frontend rule",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].Rules[0].LinkedACLs = []string{"no-such-acl"}
			},
			want: `rule "route-argocd": ACL "no-such-acl" is not declared in this frontend`,
		},
		{
			name: "dangling ACL reference in a backend rule",
			mutate: func(m *haproxy.Model) {
				m.Backends[1].Rules[0].LinkedACLs = []string{"no-such-acl"}
			},
			want: `rule "select-node-1": ACL "no-such-acl" is not declared in this backend`,
		},
		{
			name: "frontend default backend is undeclared",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].DefaultBackend = "missing"
			},
			want: `frontend "external": default backend "missing" is not declared`,
		},
		{
			name:   "empty backend name",
			mutate: func(m *haproxy.Model) { m.Backends[2].Name = "" },
			want:   "backend[2]: name must not be empty",
		},
		{
			name: "duplicate backend name",
			mutate: func(m *haproxy.Model) {
				m.Backends[1].Name = "argocd"
			},
			want: `backend "argocd": duplicate name`,
		},
		{
			name:   "backend in SSL mode",
			mutate: func(m *haproxy.Model) { m.Backends[0].Mode = haproxy.ModeSSL },
			want:   `backend "argocd": mode "ssl" is not valid`,
		},
		{
			name: "invalid algorithm",
			mutate: func(m *haproxy.Model) {
				m.Backends[0].Algorithm = "hash"
			},
			want: `backend "argocd": algorithm "hash" is not valid`,
		},
		{
			name: "duplicate server name",
			mutate: func(m *haproxy.Model) {
				m.Backends[0].Servers = append(m.Backends[0].Servers,
					haproxy.NewServer("node-1", "10.0.0.13", 30083))
			},
			want: `backend "argocd" server "node-1": duplicate name`,
		},
		{
			name: "invalid server mode",
			mutate: func(m *haproxy.Model) {
				m.Backends[0].Servers[0].Mode = "drain"
			},
			want: `backend "argocd" server "node-1": mode "drain" is not valid`,
		},
		{
			name: "invalid server type",
			mutate: func(m *haproxy.Model) {
				m.Backends[0].Servers[0].Type = "dns"
			},
			want: `backend "argocd" server "node-1": type "dns" is not valid`,
		},
		{
			name: "invalid health check type",
			mutate: func(m *haproxy.Model) {
				m.Backends[0].HealthCheck.Type = "icmp"
			},
			want: `backend "argocd": health check type "icmp" is not valid`,
		},
		{
			name: "use_backend in a backend",
			mutate: func(m *haproxy.Model) {
				m.Backends[1].Rules[0].Type = haproxy.RuleTypeUseBackend
				m.Backends[1].Rules[0].UseServer = ""
				m.Backends[1].Rules[0].UseBackend = "argocd"
			},
			want: `backend "api" rule "select-node-1": use_backend is only valid in a frontend`,
		},
		{
			name: "use_server in a frontend",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].Rules[0].Type = haproxy.RuleTypeUseServer
				m.Frontends[0].Rules[0].UseBackend = ""
				m.Frontends[0].Rules[0].UseServer = "node-1"
			},
			want: `frontend "external" rule "route-argocd": use_server is only valid in a backend`,
		},
		{
			name: "server weight above the maximum",
			mutate: func(m *haproxy.Model) {
				m.Backends[0].Servers[0].Weight = 257
			},
			want: `backend "argocd" server "node-1": weight 257 must be between 0 and 256`,
		},
		{
			name: "negative server weight",
			mutate: func(m *haproxy.Model) {
				m.Backends[0].Servers[0].Weight = -1
			},
			want: `backend "argocd" server "node-1": weight -1 must be between 0 and 256`,
		},
		{
			name: "port outside the valid range",
			mutate: func(m *haproxy.Model) {
				m.Backends[0].Servers[0].Port = 70000
			},
			want: `backend "argocd" server "node-1": port 70000 must be between 1 and 65535`,
		},
		{
			name: "static server without a port",
			mutate: func(m *haproxy.Model) {
				m.Backends[0].Servers[0].Port = 0
			},
			want: `backend "argocd" server "node-1": port 0 must be between 1 and 65535`,
		},
		{
			name: "unix server with a port",
			mutate: func(m *haproxy.Model) {
				m.Backends[0].Servers[0].Type = haproxy.ServerTypeUnix
			},
			want: `backend "argocd" server "node-1": port must be 0 for a unix server`,
		},
		{
			name: "check port outside the valid range",
			mutate: func(m *haproxy.Model) {
				m.Backends[0].Servers[0].CheckPort = -1
			},
			want: `backend "argocd" server "node-1": check port -1 must be between 1 and 65535`,
		},
		{
			name: "negative health check interval",
			mutate: func(m *haproxy.Model) {
				m.Backends[0].HealthCheck.Interval = -1
			},
			want: `backend "argocd": health check interval -1 must not be negative`,
		},
		{
			name: "empty ACL parameters",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].ACLs[0].Parameters = ""
			},
			want: `frontend "external" ACL "host-argocd": parameters must not be empty`,
		},
		{
			name: "hdr ACL without a parenthesised argument",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].ACLs[0].Parameters = "host argocd.example.com"
			},
			want: `frontend "external" ACL "host-argocd": hdr requires a parenthesised header argument`,
		},
		{
			name: "newline in an ACL parameter",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].ACLs[0].Parameters = "(host) -i app.example.com\nuse_backend evil"
			},
			want: `frontend "external" ACL "host-argocd": parameters contains control character '\n'`,
		},
		{
			name: "newline in a rule custom directive",
			mutate: func(m *haproxy.Model) {
				m.Backends[1].Rules[1].Custom = "option forwardfor\noption httplog"
			},
			want: `backend "api" rule "custom-tuning": custom contains control character '\n'`,
		},
		{
			name: "carriage return in frontend custom options",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].CustomOptions = "option httplog\r"
			},
			want: `frontend "external": custom options contains control character '\r'`,
		},
		{
			name: "tab in backend custom options",
			mutate: func(m *haproxy.Model) {
				m.Backends[0].CustomOptions = "retries\t3"
			},
			want: `backend "argocd": custom options contains control character '\t'`,
		},
		{
			name: "newline in a server address",
			mutate: func(m *haproxy.Model) {
				m.Backends[0].Servers[0].Address = "10.0.0.11\rX-Injected: 1"
			},
			want: `backend "argocd" server "node-1": address contains control character '\r'`,
		},
		{
			name: "newline in a server source address",
			mutate: func(m *haproxy.Model) {
				m.Backends[0].Servers[0].Source = "10.0.0.1\nX-Injected: 1"
			},
			want: `backend "argocd" server "node-1": source contains control character '\n'`,
		},
		{
			name: "newline in a frontend name",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].Name = "external\nfrontend evil"
			},
			want: `name contains control character '\n'`,
		},
		{
			name: "newline in a frontend bind address",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].Bind = []string{"0.0.0.0:443\n\tdefault_backend evil"}
			},
			want: `frontend "external": bind contains control character '\n'`,
		},
		{
			name: "frontend without a bind address",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].Bind = nil
			},
			want: `frontend "external": requires at least one bind address`,
		},
		{
			name: "comment marker in a server address",
			mutate: func(m *haproxy.Model) {
				m.Backends[0].Servers[0].Address = "10.0.0.11:30080# comment"
			},
			want: `backend "argocd" server "node-1": address contains '#', which starts an HAProxy comment`,
		},
		{
			name: "newline in a health check path",
			mutate: func(m *haproxy.Model) {
				m.Backends[0].HealthCheck.Path = "/healthz\noption forwardfor"
			},
			want: `backend "argocd": health check path contains control character '\n'`,
		},
		{
			name: "newline in a rule action",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].Rules[2].HTTPRequestAction = "set-header X-Forwarded-Proto https\nuse_backend evil"
			},
			want: `frontend "external" rule "forwarded-proto": action contains control character '\n'`,
		},
		{
			name: "newline in a use_server target",
			mutate: func(m *haproxy.Model) {
				m.Backends[1].Rules[0].UseServer = "node-1\nuse_backend evil"
			},
			want: `backend "api" rule "select-node-1": use_server contains control character '\n'`,
		},
		{
			name: "parenthesised argument on a non-hdr ACL",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].ACLs[1].Expression = haproxy.ACLExpressionPathReg
				m.Frontends[0].ACLs[1].Parameters = "(^/api)"
			},
			want: `frontend "external" ACL "path-api": path_reg takes a plain argument`,
		},
		{
			name: "http-request rule without an action",
			mutate: func(m *haproxy.Model) {
				m.Frontends[0].Rules[2].HTTPRequestAction = ""
			},
			want: `frontend "external" rule "forwarded-proto": http-request requires an action`,
		},
		{
			name: "custom rule without a directive",
			mutate: func(m *haproxy.Model) {
				m.Backends[1].Rules[1].Custom = ""
			},
			want: `backend "api" rule "custom-tuning": custom requires a directive`,
		},
		{
			name: "duplicate listener name",
			mutate: func(m *haproxy.Model) {
				m.Listeners = append(m.Listeners,
					haproxy.NewListener("external", haproxy.ModeHTTP, false, "", "0.0.0.0:80"))
			},
			want: `listener "external": duplicate name`,
		},
		{
			name: "adopted listener without an existing frontend",
			mutate: func(m *haproxy.Model) {
				m.Listeners[1].ExistingFrontend = ""
			},
			want: `listener "internal": adopting requires an existing frontend`,
		},
		{
			name: "created listener without a bind address",
			mutate: func(m *haproxy.Model) {
				m.Listeners[0].Bind = nil
			},
			want: `listener "external": creating a frontend requires at least one bind address`,
		},
		{
			name: "listener default backend is undeclared",
			mutate: func(m *haproxy.Model) {
				m.Listeners[0].DefaultBackend = "missing"
			},
			want: `listener "external": default backend "missing" is not declared`,
		},
		{
			name: "invalid listener mode",
			mutate: func(m *haproxy.Model) {
				m.Listeners[0].Mode = "udp"
			},
			want: `listener "external": mode "udp" is not valid`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			model := validModel()
			test.mutate(model)

			err := model.Validate()
			if err == nil {
				t.Fatal("invalid model was accepted")
			}

			var validationErr *haproxy.ValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("error is not a *ValidationError: %T", err)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error does not contain %q:\n%v", test.want, err)
			}
		})
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	model := validModel()
	model.Frontends[0].Name = ""
	model.Backends[0].Algorithm = "hash"
	model.Listeners[0].Bind = nil

	err := model.Validate()
	if err == nil {
		t.Fatal("invalid model was accepted")
	}

	var validationErr *haproxy.ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error is not a *ValidationError: %T", err)
	}

	problems := validationErr.Errors()
	if len(problems) != 3 {
		t.Fatalf("got %d problems, want 3:\n%v", len(problems), err)
	}

	for _, want := range []string{
		"frontend[0]: name must not be empty",
		`backend "argocd": algorithm "hash" is not valid`,
		`listener "external": creating a frontend requires at least one bind address`,
	} {
		found := false
		for _, problem := range problems {
			if strings.Contains(problem.Error(), want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("problem %q missing from:\n%v", want, err)
		}
	}
}

func TestValidateAcceptsDisabledHealthCheckWithoutType(t *testing.T) {
	// A disabled check is inert and emits no directive, so its type and
	// numbers are not validated.
	model := validModel()
	model.Backends[0].HealthCheck = &haproxy.HealthCheck{Enabled: false, Interval: -1}

	if err := model.Validate(); err != nil {
		t.Fatalf("disabled health check was rejected: %v", err)
	}
}

func TestValidateAcceptsUnixServerWithoutPort(t *testing.T) {
	model := validModel()
	model.Backends[0].Servers = []haproxy.Server{{
		Name:    "socket",
		Address: "/run/senselb.sock",
		Type:    haproxy.ServerTypeUnix,
		Mode:    haproxy.ServerModeActive,
	}}

	if err := model.Validate(); err != nil {
		t.Fatalf("unix server without a port was rejected: %v", err)
	}
}

func TestConstructorsApplyDefaults(t *testing.T) {
	server := haproxy.NewServer("node-1", "10.0.0.11", 30080)
	if server.Mode != haproxy.ServerModeActive {
		t.Fatalf("server mode = %q, want %q", server.Mode, haproxy.ServerModeActive)
	}
	if server.Type != haproxy.ServerTypeStatic {
		t.Fatalf("server type = %q, want %q", server.Type, haproxy.ServerTypeStatic)
	}

	rule := haproxy.NewRule("route", haproxy.RuleTypeUseBackend)
	if rule.TestType != haproxy.RuleTestTypeIf {
		t.Fatalf("rule test type = %q, want %q", rule.TestType, haproxy.RuleTestTypeIf)
	}
	if rule.Operator != haproxy.RuleOperatorAnd {
		t.Fatalf("rule operator = %q, want %q", rule.Operator, haproxy.RuleOperatorAnd)
	}

	backend := haproxy.NewBackend("api", haproxy.ModeHTTP)
	if backend.Algorithm != haproxy.AlgorithmRoundRobin {
		t.Fatalf("backend algorithm = %q, want %q", backend.Algorithm, haproxy.AlgorithmRoundRobin)
	}

	listener := haproxy.NewListener("external", haproxy.ModeHTTP, true, "external-fe", "0.0.0.0:80")
	if listener.ExistingFrontend != "external-fe" {
		t.Fatalf("listener existing frontend = %q, want %q", listener.ExistingFrontend, "external-fe")
	}
	if len(listener.Bind) != 0 {
		t.Fatalf("adopted listener kept bind addresses: %v", listener.Bind)
	}
}
