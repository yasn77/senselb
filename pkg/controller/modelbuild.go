package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/yasn77/senselb/pkg/annotations"
	"github.com/yasn77/senselb/pkg/config"
	"github.com/yasn77/senselb/pkg/haproxy"
)

// NodeInfo is one ready node that can serve a nodeport-mode backend.
// Addresses lists the node's reachable addresses in preference order; the
// first IPv4 address wins, and the first address overall is the fallback.
type NodeInfo struct {
	Name      string
	Addresses []string
}

// EndpointInfo is one ready pod address:port pair for endpoint-mode backends.
type EndpointInfo struct {
	IP   string
	Port int32
}

// UnknownListenerError reports a listener the Service names that the controller
// configuration does not define. An empty Listener means the Service named no
// listener at all.
type UnknownListenerError struct {
	Listener string
}

// Error implements error.
func (e *UnknownListenerError) Error() string {
	if e.Listener == "" {
		return "no listener is configured for this Service"
	}
	return fmt.Sprintf("listener %q is not defined in the controller configuration", e.Listener)
}

// UDPUnsupportedError reports a Service port whose protocol senselb does not
// proxy. Despite the name it covers every non-TCP protocol, including SCTP; the
// name is fixed by the approved plan.
type UDPUnsupportedError struct {
	Port     int32
	Protocol string
}

// Error implements error.
func (e *UDPUnsupportedError) Error() string {
	return fmt.Sprintf("port %d uses protocol %s, which senselb does not proxy", e.Port, e.Protocol)
}

// AnnotationError reports an annotation senselb can parse but cannot honour, or
// a combination it needs completed. Annotation is the full annotation key.
type AnnotationError struct {
	Annotation string
	Reason     string
}

// Error implements error.
func (e *AnnotationError) Error() string {
	return fmt.Sprintf("annotation %s: %s", e.Annotation, e.Reason)
}

// BuildContribution builds the desired HAProxy objects for one Service.
//
// The result is a fragment: Task 4.4 merges every Service's contribution into
// one model before diffing against the live configuration. Model is nil when
// the Service contributes nothing at all; issues then lists every problem, and
// each issue also applies when Model is non-nil (a partially usable Service
// still contributes its TCP listeners while the problem is reported).
//
// Rules:
//
//   - Listeners come from ann.Listeners and must be defined in cfg. An unknown
//     listener is reported as *UnknownListenerError and skipped; the remaining
//     valid listeners still contribute. Naming the same listener twice counts
//     once, in first-mention order.
//   - Each (listener × TCP Service port) pair contributes one backend, one
//     routing rule and its ACLs. Backends are never merged across ports.
//   - A created listener's frontend is named CreatedFrontendName(listener),
//     "senselb-<listener>"; the configured listener name stays the logical
//     handle annotations use. An adopted listener keeps the live frontend's
//     name, which is the object it attaches to.
//   - The backend name is "senselb-<ns>-<svc>-<port>", or ann.BackendName for a
//     single-port Service; with several ports ann.BackendName is suffixed with
//     "-<port>" so the names stay unique and deterministic. ann.BackendName must
//     start with "senselb-", because senselb only owns objects carrying its
//     prefix; a name without it is reported as *AnnotationError and the Service
//     contributes nothing. A BackendName that two Services both use is the
//     user's own conflict; the ownership check surfaces it at apply time.
//   - Servers in nodeport mode come from nodes; the address is the first IPv4
//     address, falling back to the first address of any family. Servers in
//     endpoint mode come from endpoints, named with the first eight hex digits
//     of the SHA-256 of the pod IP so the name is stable across reconciles.
//     A backend with zero servers is valid (HAProxy accepts it); reporting that
//     state is the reconciler's job. Endpoint addresses carry no per-port
//     correlation, so endpoint mode is only supported for a single TCP port: a
//     multi-port Service is reported as *AnnotationError and contributes
//     nothing rather than feeding every backend the same flattened list.
//   - Routing uses one use_backend rule per (listener × port). Each non-empty
//     routing term contributes one ACL following the model's raw-token
//     contract: Host is hdr_beg with "(host) -i <host>", Path is path_beg with
//     "<path>", and SNI is ssl_fc_sni with the bare value. With no routing term
//     the rule is unconditional. Two Services claiming unconditional routing on
//     one listener is a conflict HAProxy resolves first-by-name; detecting it
//     is a later task.
//   - ann.TLS attaches the certificate to a listener that creates a frontend.
//     An adopted listener already carries its own TLS material, so the
//     annotation is ignored there and reported as *AnnotationError. TLS without
//     a certificate is reported the same way.
//   - Non-TCP ports are excluded from the model and reported as
//     *UDPUnsupportedError; the Service's TCP ports still contribute.
//   - The timeout annotations are not applied: the canonical model has no
//     timeout fields and "timeout client" is not valid in a backend block, so
//     silently appending the directives to the backend custom options would
//     risk an invalid configuration. They are reported as *AnnotationError and
//     the operator can express them through backend-custom instead.
//   - tls-passthrough is accepted by the parser but not implemented yet, so it
//     is reported as *AnnotationError rather than ignored.
//   - proxy-protocol is recorded on the backend health check, where the model
//     carries it; emitting the directive belongs to the provider.
//
// The returned model is not necessarily valid whole: an adopted listener's
// frontend deliberately carries only its name, rules and ACLs. Use
// ValidateContribution to check a contribution.
func BuildContribution(cfg *config.Config, ann annotations.Values, svcName types.NamespacedName,
	ports []corev1.ServicePort, nodes []NodeInfo, endpoints []EndpointInfo) (*haproxy.Model, []error) {

	var issues []error

	issues = append(issues, annotationIssues(cfg, ann)...)

	if ann.BackendName != "" && !strings.HasPrefix(ann.BackendName, OwnedPrefix) {
		issues = append(issues, &AnnotationError{
			Annotation: annotationKey(cfg, "backend-name"),
			Reason:     `backend-name must start with "senselb-" so senselb can own the object`,
		})
		return nil, issues
	}

	if len(ann.Listeners) == 0 {
		issues = append(issues, &UnknownListenerError{})
		return nil, issues
	}

	listeners := resolveListeners(cfg, ann.Listeners, &issues)
	if len(listeners) == 0 {
		return nil, issues
	}

	tcpPorts := make([]corev1.ServicePort, 0, len(ports))
	for _, port := range ports {
		protocol := port.Protocol
		if protocol == "" {
			protocol = corev1.ProtocolTCP
		}
		if protocol != corev1.ProtocolTCP {
			issues = append(issues, &UDPUnsupportedError{Port: port.Port, Protocol: string(protocol)})
			continue
		}
		tcpPorts = append(tcpPorts, port)
	}
	if len(tcpPorts) == 0 {
		return nil, issues
	}

	// EndpointInfo carries no per-port correlation, so every backend of a
	// multi-port Service would receive the same flattened address list and the
	// ports would cross-wire. Refuse the whole Service rather than serve wrong
	// traffic; a single-port Service is unambiguous.
	if ann.TargetMode == "endpoint" && len(tcpPorts) > 1 {
		issues = append(issues, &AnnotationError{
			Annotation: annotationKey(cfg, "target-mode"),
			Reason: "endpoint target-mode supports a single Service port; " +
				"use one TCP port with target-mode endpoint, or target-mode nodeport for a multi-port Service",
		})
		return nil, issues
	}

	model := &haproxy.Model{}
	frontendIndex := make(map[string]int, len(listeners))

	for _, listener := range listeners {
		frontend := contributedFrontend(listener)
		if ann.TLS {
			switch {
			case listener.Adopt:
				issues = append(issues, &AnnotationError{
					Annotation: annotationKey(cfg, "tls"),
					Reason:     fmt.Sprintf("ignored for adopted listener %q, which carries its own TLS material", listener.Name),
				})
			case ann.TLSCert == "":
				issues = append(issues, &AnnotationError{
					Annotation: annotationKey(cfg, "tls-cert"),
					Reason:     "a certificate is required when tls is enabled",
				})
			default:
				frontend.SSLEnabled = true
				frontend.SSLCertificates = []string{ann.TLSCert}
				frontend.SSLDefaultCert = ann.TLSCert
			}
		}
		frontendIndex[listener.Name] = len(model.Frontends)
		model.Frontends = append(model.Frontends, frontend)
	}

	// model.Frontends holds copies, so rules and ACLs are written back through
	// the index: the map records where each listener's frontend landed.
	for _, port := range tcpPorts {
		backendName := backendNameFor(ann, svcName, port.Port, len(tcpPorts))
		backend := haproxy.NewBackend(backendName, backendMode(ann.Mode))
		backend.Algorithm = algorithmOrDefault(ann.Algorithm)
		backend.Servers = buildServers(ann, port, nodes, endpoints)
		backend.HealthCheck = buildHealthCheck(ann)
		backend.Sticky = ann.Sticky
		backend.CustomOptions = ann.BackendCustom
		model.Backends = append(model.Backends, backend)

		for _, listener := range listeners {
			index := frontendIndex[listener.Name]
			frontend := &model.Frontends[index]

			rule := haproxy.NewRule(contributionObjectName(svcName, port.Port), haproxy.RuleTypeUseBackend)
			rule.UseBackend = backendName
			for _, acl := range routingACLs(ann, svcName, port.Port, listener.Name) {
				frontend.ACLs = append(frontend.ACLs, acl)
				rule.LinkedACLs = append(rule.LinkedACLs, acl.Name)
			}
			frontend.Rules = append(frontend.Rules, rule)
		}
	}

	return model, issues
}

// ValidateContribution validates a model produced by BuildContribution.
//
// Two deliberate relaxations make a fragment validate on its own:
//
//   - A frontend with no bind address is treated as the partial for an adopted
//     listener: a sentinel bind and the default HTTP mode are substituted so the
//     bind-required check does not fire. The merge in Task 4.4 validates the
//     whole model against the live frontend instead.
//   - A frontend's DefaultBackend may name a platform-level backend that
//     senselb does not own, so an undeclared default backend is cleared before
//     validation. Rules still have to resolve: use_backend targets senselb
//     builds.
func ValidateContribution(m *haproxy.Model) error {
	if m == nil {
		return errors.New("validate contribution: model is nil")
	}

	declared := make(map[string]struct{}, len(m.Backends))
	for _, backend := range m.Backends {
		declared[backend.Name] = struct{}{}
	}

	clone := &haproxy.Model{
		Frontends: make([]haproxy.Frontend, len(m.Frontends)),
		Backends:  m.Backends,
		Listeners: m.Listeners,
	}
	for i, frontend := range m.Frontends {
		frontend.Bind = slices.Clone(frontend.Bind)
		if len(frontend.Bind) == 0 {
			frontend.Bind = []string{adoptedFrontendBind}
			if frontend.Mode == "" {
				frontend.Mode = haproxy.ModeHTTP
			}
		}
		if frontend.DefaultBackend != "" {
			if _, ok := declared[frontend.DefaultBackend]; !ok {
				frontend.DefaultBackend = ""
			}
		}
		clone.Frontends[i] = frontend
	}
	return clone.Validate()
}

// adoptedFrontendBind is the sentinel bind ValidateContribution substitutes for
// an adopted listener's partial frontend. It is never written to a provider.
const adoptedFrontendBind = "0.0.0.0:0"

// annotationIssues reports the annotations that parse but cannot be honoured.
func annotationIssues(cfg *config.Config, ann annotations.Values) []error {
	var issues []error
	for _, timeout := range []struct {
		name  string
		value string
	}{
		{"timeout-connect", ann.TimeoutConnect},
		{"timeout-server", ann.TimeoutServer},
		{"timeout-client", ann.TimeoutClient},
	} {
		if timeout.value == "" {
			continue
		}
		issues = append(issues, &AnnotationError{
			Annotation: annotationKey(cfg, timeout.name),
			Reason: "timeouts are not modelled; express them with " +
				annotationKey(cfg, "backend-custom") + ", for example \"timeout connect " + timeout.value + "\"",
		})
	}
	if ann.TLSPassthrough {
		issues = append(issues, &AnnotationError{
			Annotation: annotationKey(cfg, "tls-passthrough"),
			Reason:     "TLS pass-through is not implemented yet",
		})
	}
	return issues
}

// resolveListeners maps the named listeners onto their configuration, reporting
// unknown names. The result keeps the annotation's order and drops repeats.
func resolveListeners(cfg *config.Config, names []string, issues *[]error) []config.ListenerConfig {
	configured := make(map[string]config.ListenerConfig)
	if cfg != nil {
		for _, listener := range cfg.Listeners {
			configured[listener.Name] = listener
		}
	}

	listeners := make([]config.ListenerConfig, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}
		listener, ok := configured[name]
		if !ok {
			*issues = append(*issues, &UnknownListenerError{Listener: name})
			continue
		}
		listeners = append(listeners, listener)
	}
	return listeners
}

// contributedFrontend returns the frontend a listener contributes. A created
// listener carries its bind, mode and default backend, under the owned name
// CreatedFrontendName gives it. An adopted listener's frontend carries only the
// live frontend's name: bind, mode and TLS belong to the live object, and the
// provider's adoption union links the rules in.
func contributedFrontend(listener config.ListenerConfig) haproxy.Frontend {
	if listener.Adopt {
		return haproxy.Frontend{Name: listener.ExistingFrontend}
	}

	mode := listener.Mode
	if mode == "" {
		mode = config.DefaultListenerMode
	}
	frontend := haproxy.NewFrontend(CreatedFrontendName(listener.Name), haproxy.Mode(mode), listener.Bind...)
	frontend.DefaultBackend = listener.DefaultBackend
	return frontend
}

// CreatedFrontendName returns the name of the frontend a created listener owns.
//
// The configured listener name stays a logical handle: it is what Services name
// in their listeners annotation. The object senselb creates carries the owned
// prefix, so the inventory, the ownership preflight and the live filter all
// recognise it. Every site that names a created frontend must go through this
// helper, so the build path and the always-present union cannot disagree.
func CreatedFrontendName(listener string) string {
	return OwnedPrefix + listener
}

// buildServers returns the backend servers for one Service port.
func buildServers(ann annotations.Values, port corev1.ServicePort, nodes []NodeInfo, endpoints []EndpointInfo) []haproxy.Server {
	var servers []haproxy.Server

	if ann.TargetMode == "endpoint" {
		seen := make(map[string]struct{}, len(endpoints))
		for _, endpoint := range endpoints {
			if endpoint.IP == "" || endpoint.Port <= 0 {
				continue
			}
			address := net.JoinHostPort(endpoint.IP, strconv.Itoa(int(endpoint.Port)))
			if _, duplicate := seen[address]; duplicate {
				continue
			}
			seen[address] = struct{}{}
			name := fmt.Sprintf("senselb-%s-%d", shortHash(endpoint.IP), port.Port)
			servers = append(servers, tunedServer(haproxy.NewServer(name, endpoint.IP, int(endpoint.Port)), ann))
		}
		slices.SortFunc(servers, func(a, b haproxy.Server) int { return strings.Compare(a.Name, b.Name) })
		return servers
	}

	for _, node := range nodes {
		address := firstIPv4(node.Addresses)
		if address == "" {
			continue
		}
		name := fmt.Sprintf("senselb-%s-%d", node.Name, port.Port)
		servers = append(servers, tunedServer(haproxy.NewServer(name, address, int(port.NodePort)), ann))
	}
	return servers
}

// tunedServer applies the per-server annotations to a fresh server.
func tunedServer(server haproxy.Server, ann annotations.Values) haproxy.Server {
	server.MaxConn = ann.MaxConn
	server.Weight = ann.Weight
	return server
}

// buildHealthCheck returns the backend health check, or nil when disabled.
func buildHealthCheck(ann annotations.Values) *haproxy.HealthCheck {
	if !ann.HealthCheck {
		return nil
	}
	return &haproxy.HealthCheck{
		Enabled:    true,
		Type:       haproxy.HealthCheckTypeHTTP,
		Path:       ann.HealthCheckPath,
		ProxyProto: ann.ProxyProtocol,
	}
}

// routingACLs returns one ACL per non-empty routing term, in Host, Path, SNI
// order. The spellings follow the model's raw-token contract: an hdr-family
// expression takes its parenthesised fetch argument, everything else a plain
// value.
func routingACLs(ann annotations.Values, svcName types.NamespacedName, port int32, listener string) []haproxy.ACL {
	prefix := fmt.Sprintf("senselb-%s-%s-%d-%s", svcName.Namespace, svcName.Name, port, listener)
	var acls []haproxy.ACL
	if ann.Host != "" {
		acls = append(acls, haproxy.NewACL(prefix+"-host", haproxy.ACLExpressionHdrBeg, "(host) -i "+ann.Host))
	}
	if ann.Path != "" {
		acls = append(acls, haproxy.NewACL(prefix+"-path", haproxy.ACLExpressionPathBeg, ann.Path))
	}
	if ann.SNI != "" {
		acls = append(acls, haproxy.NewACL(prefix+"-sni", haproxy.ACLExpressionSSLFcSNI, ann.SNI))
	}
	return acls
}

// backendNameFor returns the deterministic backend name for one Service port.
func backendNameFor(ann annotations.Values, svcName types.NamespacedName, port int32, portCount int) string {
	if ann.BackendName != "" {
		if portCount == 1 {
			return ann.BackendName
		}
		return fmt.Sprintf("%s-%d", ann.BackendName, port)
	}
	return contributionObjectName(svcName, port)
}

// contributionObjectName is the default name stem for a Service port's backend
// and routing rule.
func contributionObjectName(svcName types.NamespacedName, port int32) string {
	return fmt.Sprintf("senselb-%s-%s-%d", svcName.Namespace, svcName.Name, port)
}

// backendMode maps the mode annotation onto the model, defaulting to HTTP.
func backendMode(mode string) haproxy.Mode {
	if mode == "" {
		return haproxy.ModeHTTP
	}
	return haproxy.Mode(mode)
}

// algorithmOrDefault returns the configured algorithm, or HAProxy's own default.
func algorithmOrDefault(algorithm string) string {
	if algorithm == "" {
		return haproxy.AlgorithmRoundRobin
	}
	return algorithm
}

// firstIPv4 returns the first IPv4 address in addresses, falling back to the
// first non-empty entry when none parses as IPv4.
func firstIPv4(addresses []string) string {
	first := ""
	for _, raw := range addresses {
		address := strings.TrimSpace(raw)
		if address == "" {
			continue
		}
		if first == "" {
			first = address
		}
		if ip := net.ParseIP(address); ip != nil && ip.To4() != nil {
			return address
		}
	}
	return first
}

// shortHash returns the first eight hex digits of the SHA-256 of value. It
// names endpoint servers stably without depending on the endpoint's position in
// the list.
func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:4])
}

// annotationKey renders the configured full key for an annotation name.
func annotationKey(cfg *config.Config, name string) string {
	prefix := annotations.DefaultPrefix
	if cfg != nil && cfg.AnnotationPrefix != "" {
		prefix = cfg.AnnotationPrefix
	}
	return prefix + name
}
