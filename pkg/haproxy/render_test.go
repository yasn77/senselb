package haproxy_test

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/yasn77/senselb/pkg/haproxy"
)

// updateGolden rewrites the golden file from the current renderer output.
var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/model.golden")

// goldenModel returns a model that exercises every construct the renderer
// emits. Frontends and backends are declared out of order so the golden file
// also proves name-based block ordering.
func goldenModel() *haproxy.Model {
	routeApp := haproxy.NewRule("route-app", haproxy.RuleTypeUseBackend)
	routeApp.LinkedACLs = []string{"host-app"}
	routeApp.UseBackend = "app"

	routeAPI := haproxy.NewRule("route-api", haproxy.RuleTypeUseBackend)
	routeAPI.LinkedACLs = []string{"host-app", "path-api"}
	routeAPI.Operator = haproxy.RuleOperatorOr
	routeAPI.TestType = haproxy.RuleTestTypeUnless
	routeAPI.UseBackend = "api"

	routeLAN := haproxy.NewRule("route-lan", haproxy.RuleTypeUseBackend)
	routeLAN.LinkedACLs = []string{"src-lan", "path-api"}
	routeLAN.UseBackend = "api"

	forwardedProto := haproxy.NewRule("forwarded-proto", haproxy.RuleTypeHTTPRequest)
	forwardedProto.LinkedACLs = []string{"host-app"}
	forwardedProto.HTTPRequestAction = "set-header X-Forwarded-Proto https"

	forwardfor := haproxy.NewRule("forwardfor", haproxy.RuleTypeCustom)
	forwardfor.Custom = "option forwardfor"

	selectNode := haproxy.NewRule("select-node-1", haproxy.RuleTypeUseServer)
	selectNode.LinkedACLs = []string{"src-lan"}
	selectNode.UseServer = "node-1"

	redispatch := haproxy.NewRule("redispatch", haproxy.RuleTypeCustom)
	redispatch.Custom = "option redispatch"

	backendHeader := haproxy.NewRule("backend-header", haproxy.RuleTypeHTTPRequest)
	backendHeader.LinkedACLs = []string{"src-lan"}
	backendHeader.HTTPRequestAction = "set-header X-Backend app"

	public := haproxy.NewFrontend("public", haproxy.ModeSSL, "0.0.0.0:443", "[::]:443")
	public.DefaultBackend = "default"

	internal := haproxy.NewFrontend("internal", haproxy.ModeHTTP, "10.0.0.1:80")
	internal.DefaultBackend = "default"
	internal.ACLs = []haproxy.ACL{
		haproxy.NewACL("host-app", haproxy.ACLExpressionHdr, "(host) -i app.example.com"),
		haproxy.NewACL("path-api", haproxy.ACLExpressionPathBeg, "/api"),
		haproxy.NewACL("src-lan", haproxy.ACLExpressionSrc, "10.0.0.0/8"),
	}
	internal.Rules = []haproxy.Rule{routeApp, routeAPI, routeLAN, forwardedProto, forwardfor}
	internal.CustomOptions = "option httplog"

	nodeOne := haproxy.NewServer("node-1", "10.0.0.11", 30081)
	nodeOne.Weight = 10
	nodeOne.MaxConn = 100
	nodeOne.CheckPort = 30081
	nodeOne.CheckInterval = 2000
	nodeOne.CheckDownInterval = 500
	nodeOne.Source = "10.0.0.1"

	nodeTwo := haproxy.NewServer("node-2", "10.0.0.12", 30081)
	nodeTwo.Mode = haproxy.ServerModeBackup

	nodeThree := haproxy.NewServer("node-3", "10.0.0.13", 30081)
	nodeThree.Mode = haproxy.ServerModeDisabled

	api := haproxy.NewBackend("api", haproxy.ModeTCP)
	api.Algorithm = haproxy.AlgorithmLeastConn
	api.Sticky = true
	api.HealthCheck = &haproxy.HealthCheck{
		Enabled:  true,
		Type:     haproxy.HealthCheckTypeTCP,
		Interval: 1000,
		Fall:     3,
		Rise:     2,
	}
	api.ACLs = []haproxy.ACL{
		haproxy.NewACL("src-lan", haproxy.ACLExpressionSrc, "10.0.0.0/8"),
	}
	api.Rules = []haproxy.Rule{selectNode, redispatch}
	api.Servers = []haproxy.Server{nodeOne, nodeTwo, nodeThree}

	appNode := haproxy.NewServer("node-1", "10.0.0.11", 30080)
	appNode.Weight = 50
	appBackup := haproxy.NewServer("node-2", "10.0.0.12", 30080)
	appBackup.Mode = haproxy.ServerModeBackup

	app := haproxy.NewBackend("app", haproxy.ModeHTTP)
	app.HealthCheck = &haproxy.HealthCheck{
		Enabled:  true,
		Type:     haproxy.HealthCheckTypeHTTP,
		Path:     "/healthz",
		Interval: 2000,
		Fall:     3,
		Rise:     2,
	}
	app.ACLs = []haproxy.ACL{
		haproxy.NewACL("src-lan", haproxy.ACLExpressionSrc, "10.0.0.0/8"),
	}
	app.Rules = []haproxy.Rule{backendHeader}
	app.Servers = []haproxy.Server{appNode, appBackup}
	app.CustomOptions = "retries 3"

	fallback := haproxy.NewBackend("default", haproxy.ModeHTTP)
	fallback.Algorithm = haproxy.AlgorithmSource
	fallback.Servers = []haproxy.Server{haproxy.NewServer("default", "10.0.0.99", 30082)}

	return &haproxy.Model{
		Frontends: []haproxy.Frontend{public, internal},
		Backends:  []haproxy.Backend{fallback, app, api},
		Listeners: []haproxy.Listener{
			haproxy.NewListener("gateway", haproxy.ModeHTTP, false, "", "10.0.0.1:80"),
			haproxy.NewListener("shared", haproxy.ModeSSL, true, "public"),
		},
	}
}

func TestRenderGolden(t *testing.T) {
	rendered, err := haproxy.Render(goldenModel())
	if err != nil {
		t.Fatalf("Render rejected a valid model: %v", err)
	}

	path := filepath.Join("testdata", "model.golden")
	if *updateGolden {
		if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
			t.Fatalf("write golden file: %v", err)
		}
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden file: %v", err)
	}
	if rendered != string(want) {
		t.Fatalf("rendered configuration differs from %s\n--- got ---\n%s\n--- want ---\n%s", path, rendered, want)
	}
}

func TestRenderEmitsTCPForPassThroughSSLMode(t *testing.T) {
	// ModeSSL is the plugin's TLS pass-through mode; HAProxy has no ssl mode,
	// so it must render as tcp while the model keeps the plugin value.
	frontend := haproxy.NewFrontend("public", haproxy.ModeSSL, "0.0.0.0:443")
	if frontend.Mode != haproxy.ModeSSL {
		t.Fatalf("frontend mode = %q, want %q", frontend.Mode, haproxy.ModeSSL)
	}

	rendered, err := haproxy.Render(&haproxy.Model{Frontends: []haproxy.Frontend{frontend}})
	if err != nil {
		t.Fatalf("Render rejected a valid model: %v", err)
	}
	if want := "frontend public\n\tbind 0.0.0.0:443\n\tmode tcp\n"; rendered != want {
		t.Fatalf("rendered ssl-mode frontend as\n%q\nwant\n%q", rendered, want)
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	model := goldenModel()

	first, err := haproxy.Render(model)
	if err != nil {
		t.Fatalf("first Render call failed: %v", err)
	}
	second, err := haproxy.Render(model)
	if err != nil {
		t.Fatalf("second Render call failed: %v", err)
	}
	if first != second {
		t.Fatalf("Render is not deterministic:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
}

func TestRenderRejectsInvalidModel(t *testing.T) {
	model := &haproxy.Model{
		Frontends: []haproxy.Frontend{{Name: "broken"}},
	}

	rendered, err := haproxy.Render(model)
	if err == nil {
		t.Fatal("Render accepted an invalid model")
	}
	if rendered != "" {
		t.Fatalf("Render returned partial configuration %q alongside an error", rendered)
	}

	var validationErr *haproxy.ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error is %T, want *haproxy.ValidationError", err)
	}
}

func TestRenderRejectsNilModel(t *testing.T) {
	rendered, err := haproxy.Render(nil)
	if err == nil {
		t.Fatal("Render accepted a nil model")
	}
	if rendered != "" {
		t.Fatalf("Render returned %q for a nil model", rendered)
	}
}

func TestRenderOrdersACLsBeforeRules(t *testing.T) {
	rendered, err := haproxy.Render(goldenModel())
	if err != nil {
		t.Fatalf("Render rejected a valid model: %v", err)
	}
	lines := blockLines(t, rendered, "frontend internal")

	lastACL, firstRule := -1, -1
	for i, line := range lines {
		if strings.HasPrefix(line, "acl ") {
			lastACL = i
		}
		if firstRule < 0 && (strings.HasPrefix(line, "use_backend ") || strings.HasPrefix(line, "http-request ")) {
			firstRule = i
		}
	}
	if lastACL < 0 {
		t.Fatal("frontend internal has no acl lines")
	}
	if firstRule < 0 {
		t.Fatal("frontend internal has no rule lines")
	}
	if lastACL > firstRule {
		t.Fatalf("acl line %d follows rule line %d in frontend internal", lastACL, firstRule)
	}

	want := []string{
		"use_backend app if host-app",
		"use_backend api unless host-app or path-api",
		"use_backend api if src-lan path-api",
	}
	var got []string
	for _, line := range lines {
		if strings.HasPrefix(line, "use_backend ") {
			got = append(got, line)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("use_backend rules rendered as %q, want %q", got, want)
	}
}

// blockLines returns the tab-indented lines of the named block, with the
// leading indentation removed.
func blockLines(t *testing.T, rendered, header string) []string {
	t.Helper()

	var lines []string
	inBlock := false
	for _, line := range strings.Split(rendered, "\n") {
		switch {
		case line == header:
			inBlock = true
		case inBlock && line == "":
			return lines
		case inBlock:
			lines = append(lines, strings.TrimPrefix(line, "\t"))
		}
	}
	t.Fatalf("block %q not found in rendered configuration", header)
	return nil
}
