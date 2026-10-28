package controller

import (
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/yasn77/senselb/pkg/annotations"
	"github.com/yasn77/senselb/pkg/config"
	"github.com/yasn77/senselb/pkg/haproxy"
)

// buildConfig returns a controller configuration with one created listener,
// one created listener carrying a platform-owned default backend, and one
// adopted listener.
func buildConfig() *config.Config {
	return &config.Config{
		AnnotationPrefix: annotations.DefaultPrefix,
		Listeners: []config.ListenerConfig{
			{Name: "web", Bind: []string{"172.16.16.1:80"}, Mode: "http"},
			{Name: "secure", Bind: []string{"172.16.16.1:443"}, Mode: "http", DefaultBackend: "platform-default"},
			{Name: "edge", Adopt: true, ExistingFrontend: "acme-frontend"},
		},
	}
}

func testServiceName() types.NamespacedName {
	return types.NamespacedName{Namespace: "default", Name: "app"}
}

func tcpPort(port, nodePort int32) corev1.ServicePort {
	return corev1.ServicePort{Name: "http", Port: port, NodePort: nodePort, Protocol: corev1.ProtocolTCP}
}

func findBackend(t *testing.T, model *haproxy.Model, name string) haproxy.Backend {
	t.Helper()
	for _, backend := range model.Backends {
		if backend.Name == name {
			return backend
		}
	}
	t.Fatalf("backend %q not found in %v", name, backendNames(model))
	return haproxy.Backend{}
}

func findFrontend(t *testing.T, model *haproxy.Model, name string) haproxy.Frontend {
	t.Helper()
	for _, frontend := range model.Frontends {
		if frontend.Name == name {
			return frontend
		}
	}
	t.Fatalf("frontend %q not found in %v", name, frontendNames(model))
	return haproxy.Frontend{}
}

func backendNames(model *haproxy.Model) []string {
	names := make([]string, 0, len(model.Backends))
	for _, backend := range model.Backends {
		names = append(names, backend.Name)
	}
	return names
}

func frontendNames(model *haproxy.Model) []string {
	names := make([]string, 0, len(model.Frontends))
	for _, frontend := range model.Frontends {
		names = append(names, frontend.Name)
	}
	return names
}

func requireNoIssues(t *testing.T, issues []error) {
	t.Helper()
	if len(issues) != 0 {
		t.Fatalf("unexpected issues: %v", issues)
	}
}

func TestBuildContributionNodePort(t *testing.T) {
	values := annotations.Values{
		Enabled:         true,
		Listeners:       []string{"web"},
		Host:            "app.example.com",
		Path:            "/api",
		Mode:            "http",
		Algorithm:       "leastconn",
		TargetMode:      "nodeport",
		HealthCheck:     true,
		HealthCheckPath: "/healthz",
		ProxyProtocol:   true,
		Sticky:          true,
		MaxConn:         100,
		Weight:          50,
		BackendCustom:   "http-reuse safe",
	}
	nodes := []NodeInfo{
		{Name: "node-a", Addresses: []string{"fd00::1", "10.0.0.1"}},
		{Name: "node-b", Addresses: []string{"10.0.0.2"}},
	}

	model, issues := BuildContribution(buildConfig(), values, testServiceName(), []corev1.ServicePort{tcpPort(80, 30080)}, nodes, nil)
	requireNoIssues(t, issues)
	if model == nil {
		t.Fatal("expected a contribution")
	}
	if err := model.Validate(); err != nil {
		t.Fatalf("model must be valid: %v", err)
	}
	if err := ValidateContribution(model); err != nil {
		t.Fatalf("contribution must be valid: %v", err)
	}

	backend := findBackend(t, model, "senselb-default-app-80")
	if backend.Mode != haproxy.ModeHTTP {
		t.Errorf("backend mode = %q, want http", backend.Mode)
	}
	if backend.Algorithm != haproxy.AlgorithmLeastConn {
		t.Errorf("algorithm = %q, want leastconn", backend.Algorithm)
	}
	if !backend.Sticky {
		t.Error("sticky must be set")
	}
	if backend.CustomOptions != "http-reuse safe" {
		t.Errorf("custom options = %q", backend.CustomOptions)
	}
	if backend.HealthCheck == nil || !backend.HealthCheck.Enabled {
		t.Fatal("health check must be enabled")
	}
	if backend.HealthCheck.Type != haproxy.HealthCheckTypeHTTP || backend.HealthCheck.Path != "/healthz" {
		t.Errorf("health check = %+v", *backend.HealthCheck)
	}
	if !backend.HealthCheck.ProxyProto {
		t.Error("proxy-protocol must be recorded on the health check")
	}

	if len(backend.Servers) != 2 {
		t.Fatalf("servers = %d, want 2", len(backend.Servers))
	}
	wantServers := []struct{ name, address string }{
		{"senselb-node-a-80", "10.0.0.1"},
		{"senselb-node-b-80", "10.0.0.2"},
	}
	for i, want := range wantServers {
		server := backend.Servers[i]
		if server.Name != want.name {
			t.Errorf("server[%d] name = %q, want %q", i, server.Name, want.name)
		}
		if server.Address != want.address {
			t.Errorf("server[%d] address = %q, want the first IPv4 %q", i, server.Address, want.address)
		}
		if server.Port != 30080 {
			t.Errorf("server[%d] port = %d, want the nodePort 30080", i, server.Port)
		}
		if server.MaxConn != 100 || server.Weight != 50 {
			t.Errorf("server[%d] tuning = maxconn %d weight %d", i, server.MaxConn, server.Weight)
		}
		if server.Mode != haproxy.ServerModeActive || server.Type != haproxy.ServerTypeStatic {
			t.Errorf("server[%d] mode/type = %q/%q", i, server.Mode, server.Type)
		}
	}

	frontend := findFrontend(t, model, "senselb-web")
	if len(frontend.Bind) != 1 || frontend.Bind[0] != "172.16.16.1:80" {
		t.Errorf("bind = %v", frontend.Bind)
	}
	if frontend.Mode != haproxy.ModeHTTP {
		t.Errorf("frontend mode = %q", frontend.Mode)
	}
	if len(frontend.ACLs) != 2 {
		t.Fatalf("ACLs = %v, want host and path", frontend.ACLs)
	}
	if frontend.ACLs[0].Expression != haproxy.ACLExpressionHdrBeg || frontend.ACLs[0].Parameters != "(host) -i app.example.com" {
		t.Errorf("host ACL = %+v", frontend.ACLs[0])
	}
	if frontend.ACLs[1].Expression != haproxy.ACLExpressionPathBeg || frontend.ACLs[1].Parameters != "/api" {
		t.Errorf("path ACL = %+v", frontend.ACLs[1])
	}
	if len(frontend.Rules) != 1 {
		t.Fatalf("rules = %v", frontend.Rules)
	}
	rule := frontend.Rules[0]
	if rule.Type != haproxy.RuleTypeUseBackend || rule.UseBackend != "senselb-default-app-80" {
		t.Errorf("rule = %+v", rule)
	}
	if rule.TestType != haproxy.RuleTestTypeIf || rule.Operator != haproxy.RuleOperatorAnd {
		t.Errorf("rule test/operator = %q/%q", rule.TestType, rule.Operator)
	}
	if len(rule.LinkedACLs) != 2 || rule.LinkedACLs[0] != frontend.ACLs[0].Name || rule.LinkedACLs[1] != frontend.ACLs[1].Name {
		t.Errorf("linked ACLs = %v", rule.LinkedACLs)
	}
}

func TestBuildContributionEndpointServersAreStable(t *testing.T) {
	values := annotations.Values{
		Enabled:    true,
		Listeners:  []string{"web"},
		Host:       "app.example.com",
		TargetMode: "endpoint",
	}
	ports := []corev1.ServicePort{tcpPort(80, 0)}
	endpoints := []EndpointInfo{{IP: "10.0.0.5", Port: 8080}, {IP: "10.0.0.6", Port: 8080}}

	model, issues := BuildContribution(buildConfig(), values, testServiceName(), ports, nil, endpoints)
	requireNoIssues(t, issues)
	backend := findBackend(t, model, "senselb-default-app-80")
	if len(backend.Servers) != 2 {
		t.Fatalf("servers = %d, want 2", len(backend.Servers))
	}
	for _, server := range backend.Servers {
		if !strings.HasPrefix(server.Name, "senselb-") || !strings.HasSuffix(server.Name, "-80") {
			t.Errorf("endpoint server name %q does not follow the senselb-<hash>-<port> rule", server.Name)
		}
		if len(server.Name) != len("senselb-")+8+len("-80") {
			t.Errorf("endpoint hash is not eight hex digits: %q", server.Name)
		}
		if server.Port != 8080 {
			t.Errorf("endpoint server port = %d, want 8080", server.Port)
		}
	}

	// Order independence: the name follows the IP, not the position.
	reversed := []EndpointInfo{{IP: "10.0.0.6", Port: 8080}, {IP: "10.0.0.5", Port: 8080}}
	again, issues := BuildContribution(buildConfig(), values, testServiceName(), ports, nil, reversed)
	requireNoIssues(t, issues)
	reversedBackend := findBackend(t, again, "senselb-default-app-80")
	for i, server := range reversedBackend.Servers {
		if server.Name != backend.Servers[i].Name {
			t.Errorf("server[%d] name changed with input order: %q != %q", i, server.Name, backend.Servers[i].Name)
		}
	}
}

func TestBuildContributionZeroNodes(t *testing.T) {
	values := annotations.Values{Enabled: true, Listeners: []string{"web"}, TargetMode: "nodeport"}
	model, issues := BuildContribution(buildConfig(), values, testServiceName(), []corev1.ServicePort{tcpPort(80, 30080)}, nil, nil)
	requireNoIssues(t, issues)
	backend := findBackend(t, model, "senselb-default-app-80")
	if len(backend.Servers) != 0 {
		t.Errorf("servers = %v, want none", backend.Servers)
	}
	if err := model.Validate(); err != nil {
		t.Fatalf("a backend without servers is valid: %v", err)
	}
}

func TestBuildContributionPartialListeners(t *testing.T) {
	values := annotations.Values{Enabled: true, Listeners: []string{"web", "missing"}, Host: "app.example.com"}

	model, issues := BuildContribution(buildConfig(), values, testServiceName(), []corev1.ServicePort{tcpPort(80, 30080)}, nil, nil)
	if model == nil {
		t.Fatal("the valid listener must still contribute")
	}
	if len(model.Frontends) != 1 || model.Frontends[0].Name != CreatedFrontendName("web") {
		t.Errorf("frontends = %v, want only web", frontendNames(model))
	}
	if len(issues) != 1 {
		t.Fatalf("issues = %v, want one", issues)
	}
	var unknown *UnknownListenerError
	if !errors.As(issues[0], &unknown) || unknown.Listener != "missing" {
		t.Errorf("issue = %v, want *UnknownListenerError for missing", issues[0])
	}
}

func TestBuildContributionNoUsableListener(t *testing.T) {
	for name, values := range map[string]annotations.Values{
		"empty":  {Enabled: true},
		"absent": {Enabled: true, Listeners: []string{"nope"}},
	} {
		t.Run(name, func(t *testing.T) {
			model, issues := BuildContribution(buildConfig(), values, testServiceName(), []corev1.ServicePort{tcpPort(80, 30080)}, nil, nil)
			if model != nil {
				t.Fatalf("model = %v, want nil", model)
			}
			if len(issues) != 1 {
				t.Fatalf("issues = %v, want one", issues)
			}
			var unknown *UnknownListenerError
			if !errors.As(issues[0], &unknown) {
				t.Errorf("issue = %v, want *UnknownListenerError", issues[0])
			}
		})
	}
}

func TestBuildContributionProtocols(t *testing.T) {
	values := annotations.Values{Enabled: true, Listeners: []string{"web"}, TargetMode: "nodeport"}
	ports := []corev1.ServicePort{
		tcpPort(80, 30080),
		{Name: "dns", Port: 53, Protocol: corev1.ProtocolUDP},
	}

	model, issues := BuildContribution(buildConfig(), values, testServiceName(), ports, nil, nil)
	if model == nil {
		t.Fatal("the TCP port must still contribute")
	}
	requireUDPIssue(t, issues, 53, "UDP")
	if len(model.Backends) != 1 || model.Backends[0].Name != "senselb-default-app-80" {
		t.Errorf("backends = %v, want only the TCP backend", backendNames(model))
	}

	model, issues = BuildContribution(buildConfig(), values, testServiceName(),
		[]corev1.ServicePort{{Name: "dns", Port: 53, Protocol: corev1.ProtocolUDP}}, nil, nil)
	if model != nil {
		t.Fatalf("model = %v, want nil when every port is excluded", model)
	}
	requireUDPIssue(t, issues, 53, "UDP")

	_, issues = BuildContribution(buildConfig(), values, testServiceName(),
		[]corev1.ServicePort{{Name: "sctp", Port: 3868, Protocol: corev1.ProtocolSCTP}}, nil, nil)
	requireUDPIssue(t, issues, 3868, "SCTP")
}

func requireUDPIssue(t *testing.T, issues []error, port int32, protocol string) {
	t.Helper()
	for _, issue := range issues {
		var unsupported *UDPUnsupportedError
		if errors.As(issue, &unsupported) && unsupported.Port == port && unsupported.Protocol == protocol {
			return
		}
	}
	t.Fatalf("no %s issue for port %d in %v", protocol, port, issues)
}

func TestBuildContributionAdoptedListener(t *testing.T) {
	values := annotations.Values{Enabled: true, Listeners: []string{"edge"}, Host: "app.example.com", SNI: "app.example.com"}

	model, issues := BuildContribution(buildConfig(), values, testServiceName(), []corev1.ServicePort{tcpPort(80, 30080)}, nil, nil)
	requireNoIssues(t, issues)

	frontend := findFrontend(t, model, "acme-frontend")
	if len(frontend.Bind) != 0 {
		t.Errorf("adopted frontend bind = %v, want none", frontend.Bind)
	}
	if frontend.Mode != "" {
		t.Errorf("adopted frontend mode = %q, want zero", frontend.Mode)
	}
	if frontend.SSLEnabled || len(frontend.SSLCertificates) != 0 {
		t.Errorf("adopted frontend must not carry TLS: %+v", frontend)
	}
	if len(frontend.ACLs) != 2 || len(frontend.Rules) != 1 {
		t.Fatalf("adopted frontend carries its own rules: ACLs %d rules %d", len(frontend.ACLs), len(frontend.Rules))
	}
	if frontend.ACLs[0].Name != "senselb-default-app-80-edge-host" {
		t.Errorf("ACL name = %q", frontend.ACLs[0].Name)
	}
	if frontend.ACLs[1].Expression != haproxy.ACLExpressionSSLFcSNI || frontend.ACLs[1].Parameters != "app.example.com" {
		t.Errorf("SNI ACL = %+v", frontend.ACLs[1])
	}
	if frontend.Rules[0].Operator != haproxy.RuleOperatorAnd {
		t.Errorf("operator = %q", frontend.Rules[0].Operator)
	}

	// The partial deliberately fails whole-model validation, which is why
	// ValidateContribution exists.
	if err := model.Validate(); err == nil {
		t.Fatal("a bind-less frontend must fail Model.Validate")
	}
	if err := ValidateContribution(model); err != nil {
		t.Fatalf("ValidateContribution must accept the adopted partial: %v", err)
	}
}

func TestBuildContributionUnconditionalRouting(t *testing.T) {
	values := annotations.Values{Enabled: true, Listeners: []string{"web"}, TargetMode: "nodeport"}

	model, issues := BuildContribution(buildConfig(), values, testServiceName(), []corev1.ServicePort{tcpPort(80, 30080)}, nil, nil)
	requireNoIssues(t, issues)
	frontend := findFrontend(t, model, "senselb-web")
	if len(frontend.ACLs) != 0 {
		t.Errorf("ACLs = %v, want none", frontend.ACLs)
	}
	if len(frontend.Rules) != 1 {
		t.Fatalf("rules = %v", frontend.Rules)
	}
	if len(frontend.Rules[0].LinkedACLs) != 0 {
		t.Errorf("linked ACLs = %v, want an unconditional rule", frontend.Rules[0].LinkedACLs)
	}
	if frontend.Rules[0].UseBackend != "senselb-default-app-80" {
		t.Errorf("use_backend = %q", frontend.Rules[0].UseBackend)
	}
}

func TestBuildContributionTLS(t *testing.T) {
	values := annotations.Values{
		Enabled:   true,
		Listeners: []string{"secure"},
		TLS:       true,
		TLSCert:   "wildcard.example.com.pem",
	}

	model, issues := BuildContribution(buildConfig(), values, testServiceName(), []corev1.ServicePort{tcpPort(443, 30443)}, nil, nil)
	requireNoIssues(t, issues)
	frontend := findFrontend(t, model, "senselb-secure")
	if !frontend.SSLEnabled {
		t.Error("TLS must enable SSL on a created frontend")
	}
	if len(frontend.SSLCertificates) != 1 || frontend.SSLCertificates[0] != "wildcard.example.com.pem" {
		t.Errorf("certificates = %v", frontend.SSLCertificates)
	}
	if frontend.SSLDefaultCert != "wildcard.example.com.pem" {
		t.Errorf("default certificate = %q", frontend.SSLDefaultCert)
	}
	// A default backend the listener owns at the platform level is allowed to
	// be absent from the fragment.
	if err := ValidateContribution(model); err != nil {
		t.Fatalf("ValidateContribution = %v", err)
	}

	adopted, issues := BuildContribution(buildConfig(),
		annotations.Values{Enabled: true, Listeners: []string{"edge"}, TLS: true, TLSCert: "cert.pem"},
		testServiceName(), []corev1.ServicePort{tcpPort(443, 30443)}, nil, nil)
	if adopted == nil {
		t.Fatal("the adopted listener still contributes its rules")
	}
	if len(issues) != 1 {
		t.Fatalf("issues = %v, want one for the ignored TLS", issues)
	}
	var annotationError *AnnotationError
	if !errors.As(issues[0], &annotationError) {
		t.Errorf("issue = %v, want *AnnotationError", issues[0])
	}
	if findFrontend(t, adopted, "acme-frontend").SSLEnabled {
		t.Error("an adopted frontend must not gain TLS from the annotation")
	}

	missing, issues := BuildContribution(buildConfig(),
		annotations.Values{Enabled: true, Listeners: []string{"secure"}, TLS: true},
		testServiceName(), []corev1.ServicePort{tcpPort(443, 30443)}, nil, nil)
	if len(issues) != 1 || !errors.As(issues[0], &annotationError) {
		t.Fatalf("issues = %v, want one *AnnotationError for the missing certificate", issues)
	}
	if findFrontend(t, missing, "senselb-secure").SSLEnabled {
		t.Error("TLS without a certificate must not enable SSL")
	}
}

func TestBuildContributionBackendName(t *testing.T) {
	single := annotations.Values{Enabled: true, Listeners: []string{"web"}, BackendName: "senselb-myapp"}
	model, issues := BuildContribution(buildConfig(), single, testServiceName(), []corev1.ServicePort{tcpPort(80, 30080)}, nil, nil)
	requireNoIssues(t, issues)
	if len(model.Backends) != 1 || model.Backends[0].Name != "senselb-myapp" {
		t.Errorf("backends = %v, want the annotated name verbatim", backendNames(model))
	}
	if model.Frontends[0].Rules[0].UseBackend != "senselb-myapp" {
		t.Errorf("use_backend = %q", model.Frontends[0].Rules[0].UseBackend)
	}

	multi := annotations.Values{Enabled: true, Listeners: []string{"web"}, BackendName: "senselb-myapp"}
	model, issues = BuildContribution(buildConfig(), multi, testServiceName(),
		[]corev1.ServicePort{tcpPort(80, 30080), tcpPort(443, 30443)}, nil, nil)
	requireNoIssues(t, issues)
	if got := backendNames(model); len(got) != 2 || got[0] != "senselb-myapp-80" || got[1] != "senselb-myapp-443" {
		t.Errorf("backends = %v, want port-suffixed names", got)
	}
	if err := model.Validate(); err != nil {
		t.Fatalf("multi-port model = %v", err)
	}
}

func TestBuildContributionRejectsUnownedBackendName(t *testing.T) {
	values := annotations.Values{Enabled: true, Listeners: []string{"web"}, BackendName: "myapp"}

	model, issues := BuildContribution(buildConfig(), values, testServiceName(),
		[]corev1.ServicePort{tcpPort(80, 30080)}, nil, nil)
	if model != nil {
		t.Fatalf("model = %v, want nil: an unowned name must not contribute", backendNames(model))
	}
	if len(issues) != 1 {
		t.Fatalf("issues = %v, want one", issues)
	}
	var annotationError *AnnotationError
	if !errors.As(issues[0], &annotationError) {
		t.Fatalf("issue = %v, want *AnnotationError", issues[0])
	}
	if annotationError.Annotation != annotations.DefaultPrefix+"backend-name" {
		t.Errorf("annotation = %q, want the backend-name key", annotationError.Annotation)
	}
	if !strings.Contains(annotationError.Reason, `must start with "senselb-"`) {
		t.Errorf("reason = %q, want the prefix requirement", annotationError.Reason)
	}
	if got := issueReason(issues[0]); got != ReasonAnnotationError {
		t.Errorf("issueReason = %q, want %q", got, ReasonAnnotationError)
	}
}

func TestCreatedFrontendName(t *testing.T) {
	if got := CreatedFrontendName("web"); got != "senselb-web" {
		t.Errorf("CreatedFrontendName(web) = %q, want senselb-web", got)
	}
	if got := CreatedFrontendName("edge-https"); got != "senselb-edge-https" {
		t.Errorf("CreatedFrontendName(edge-https) = %q", got)
	}
}

func TestBuildContributionEndpointMultiPort(t *testing.T) {
	values := annotations.Values{Enabled: true, Listeners: []string{"web"}, TargetMode: "endpoint"}
	ports := []corev1.ServicePort{tcpPort(80, 0), tcpPort(443, 0)}
	endpoints := []EndpointInfo{{IP: "10.0.0.5", Port: 8080}, {IP: "10.0.0.5", Port: 9090}}

	model, issues := BuildContribution(buildConfig(), values, testServiceName(), ports, nil, endpoints)
	if model != nil {
		t.Fatalf("model = %v, want nil: endpoint mode cannot correlate ports", backendNames(model))
	}
	if len(issues) != 1 {
		t.Fatalf("issues = %v, want one", issues)
	}
	var annotationError *AnnotationError
	if !errors.As(issues[0], &annotationError) {
		t.Fatalf("issue = %v, want *AnnotationError", issues[0])
	}
	if annotationError.Annotation != annotations.DefaultPrefix+"target-mode" {
		t.Errorf("annotation = %q, want the target-mode key", annotationError.Annotation)
	}
	if !strings.Contains(annotationError.Reason, "single Service port") {
		t.Errorf("reason = %q, want the single-port requirement", annotationError.Reason)
	}
}

func TestBuildContributionNodePortMultiPort(t *testing.T) {
	// The endpoint restriction must not leak into nodeport mode: a multi-port
	// Service keeps contributing one backend per port.
	values := annotations.Values{Enabled: true, Listeners: []string{"web"}, TargetMode: "nodeport"}
	ports := []corev1.ServicePort{tcpPort(80, 30080), tcpPort(443, 30443)}
	nodes := []NodeInfo{{Name: "node-a", Addresses: []string{"10.0.0.1"}}}

	model, issues := BuildContribution(buildConfig(), values, testServiceName(), ports, nodes, nil)
	requireNoIssues(t, issues)
	if got := backendNames(model); len(got) != 2 {
		t.Fatalf("backends = %v, want one per port", got)
	}
	if len(model.Backends[0].Servers) != 1 || model.Backends[0].Servers[0].Port != 30080 {
		t.Errorf("port 80 servers = %+v, want the 30080 nodePort", model.Backends[0].Servers)
	}
	if len(model.Backends[1].Servers) != 1 || model.Backends[1].Servers[0].Port != 30443 {
		t.Errorf("port 443 servers = %+v, want the 30443 nodePort", model.Backends[1].Servers)
	}
}

func TestBuildContributionMultiPortDefaultNames(t *testing.T) {
	values := annotations.Values{Enabled: true, Listeners: []string{"web"}, Host: "app.example.com"}

	model, issues := BuildContribution(buildConfig(), values, testServiceName(),
		[]corev1.ServicePort{tcpPort(80, 30080), tcpPort(443, 30443)}, nil, nil)
	requireNoIssues(t, issues)
	if got := backendNames(model); len(got) != 2 || got[0] != "senselb-default-app-80" || got[1] != "senselb-default-app-443" {
		t.Errorf("backends = %v", got)
	}
	if len(model.Frontends[0].Rules) != 2 {
		t.Errorf("rules = %v, want one per port", model.Frontends[0].Rules)
	}
	if model.Frontends[0].Rules[0].Name == model.Frontends[0].Rules[1].Name {
		t.Error("rule names must differ per port")
	}
	if err := model.Validate(); err != nil {
		t.Fatalf("multi-port model = %v", err)
	}
}

func TestBuildContributionModeDefault(t *testing.T) {
	values := annotations.Values{Enabled: true, Listeners: []string{"web"}}
	model, issues := BuildContribution(buildConfig(), values, testServiceName(), []corev1.ServicePort{tcpPort(80, 30080)}, nil, nil)
	requireNoIssues(t, issues)
	if model.Backends[0].Mode != haproxy.ModeHTTP {
		t.Errorf("backend mode = %q, want the http default", model.Backends[0].Mode)
	}
	if model.Backends[0].Algorithm != haproxy.AlgorithmRoundRobin {
		t.Errorf("algorithm = %q, want the roundrobin default", model.Backends[0].Algorithm)
	}

	values.Mode = "tcp"
	model, issues = BuildContribution(buildConfig(), values, testServiceName(), []corev1.ServicePort{tcpPort(80, 30080)}, nil, nil)
	requireNoIssues(t, issues)
	if model.Backends[0].Mode != haproxy.ModeTCP {
		t.Errorf("backend mode = %q, want tcp", model.Backends[0].Mode)
	}
}

func TestBuildContributionUnsupportedAnnotations(t *testing.T) {
	values := annotations.Values{
		Enabled:        true,
		Listeners:      []string{"web"},
		TimeoutConnect: "5s",
		TLSPassthrough: true,
	}

	model, issues := BuildContribution(buildConfig(), values, testServiceName(), []corev1.ServicePort{tcpPort(80, 30080)}, nil, nil)
	if model == nil {
		t.Fatal("an unsupported annotation must not drop the contribution")
	}
	if len(issues) != 2 {
		t.Fatalf("issues = %v, want one per unsupported annotation", issues)
	}
	for _, issue := range issues {
		var annotationError *AnnotationError
		if !errors.As(issue, &annotationError) {
			t.Errorf("issue = %v, want *AnnotationError", issue)
		}
	}
	if !strings.Contains(issues[0].Error(), "timeout") {
		t.Errorf("first issue = %v, want the timeout message", issues[0])
	}
}

func TestBuildContributionDuplicateListenerCountsOnce(t *testing.T) {
	values := annotations.Values{Enabled: true, Listeners: []string{"web", "web"}, Host: "app.example.com"}

	model, issues := BuildContribution(buildConfig(), values, testServiceName(), []corev1.ServicePort{tcpPort(80, 30080)}, nil, nil)
	requireNoIssues(t, issues)
	if len(model.Frontends) != 1 || len(model.Frontends[0].Rules) != 1 {
		t.Errorf("frontends/rules = %d/%d, want 1/1", len(model.Frontends), len(model.Frontends[0].Rules))
	}
	if err := model.Validate(); err != nil {
		t.Fatalf("model = %v", err)
	}
}

func TestValidateContributionRejectsNil(t *testing.T) {
	if err := ValidateContribution(nil); err == nil {
		t.Fatal("expected an error for a nil model")
	}
}

func TestFirstIPv4(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addresses []string
		want      string
	}{
		{"prefers IPv4 over an earlier IPv6 address", []string{"fd00::1", "10.0.0.1"}, "10.0.0.1"},
		{"falls back to the first address", []string{"", "fd00::1"}, "fd00::1"},
		{"ignores blanks", []string{" ", "10.0.0.9"}, "10.0.0.9"},
		{"empty", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstIPv4(tc.addresses); got != tc.want {
				t.Errorf("firstIPv4(%v) = %q, want %q", tc.addresses, got, tc.want)
			}
		})
	}
}
