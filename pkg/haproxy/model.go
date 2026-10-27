// Package haproxy defines the platform-agnostic HAProxy domain model that
// senselb renders and reconciles.
//
// The types mirror the OPNsense os-haproxy plugin schema field for field, so a
// provider maps between a model and live platform objects mechanically. The
// package depends on the Go standard library only: it must not import a
// provider, Kubernetes or any third-party package.
package haproxy

import "slices"

// Mode is the HAProxy proxy mode of a frontend or backend.
type Mode string

const (
	// ModeHTTP proxies Layer 7 HTTP traffic and permits TLS offloading.
	ModeHTTP Mode = "http"
	// ModeTCP proxies raw Layer 4 TCP traffic.
	ModeTCP Mode = "tcp"
	// ModeSSL proxies TLS traffic without terminating it. The plugin accepts
	// this mode for frontends only.
	ModeSSL Mode = "ssl"
)

// Server is one member of a backend's server list.
type Server struct {
	// UUID identifies the corresponding live object. A provider fills it when
	// reading live configuration; desired models leave it empty and match by
	// name.
	UUID string `json:"-"`

	Name      string
	Address   string
	Port      int
	CheckPort int

	// Mode is the administrative state: ServerModeActive, ServerModeBackup or
	// ServerModeDisabled.
	Mode string
	// Type is the server kind: ServerTypeStatic, ServerTypeTemplate or
	// ServerTypeUnix.
	Type string

	Weight            int
	MaxConn           int
	CheckInterval     int
	CheckDownInterval int

	Source string
}

// Server administrative modes.
const (
	ServerModeActive   = "active"
	ServerModeBackup   = "backup"
	ServerModeDisabled = "disabled"
)

// Server types.
const (
	ServerTypeStatic   = "static"
	ServerTypeTemplate = "template"
	ServerTypeUnix     = "unix"
)

// ACL is a named condition that a rule references.
type ACL struct {
	// UUID identifies the corresponding live object; see Server.UUID.
	UUID string `json:"-"`

	Name        string
	Description string
	// Expression is one of the ACLExpression constants.
	Expression string
	// Parameters carries the raw argument tokens appended verbatim after the
	// expression, in the spelling the HAProxy manual uses. A parenthesised
	// fetch argument, such as "(host) -i example.com" for an hdr-family
	// expression, is appended with no separating space so the fetch renders
	// function-style: hdr(host) -i example.com. Any other argument, such as
	// "/api" for path_beg or "10.0.0.0/8" for src, is appended after a single
	// space. The value must not be empty for every expression senselb
	// supports, and an hdr-family expression must start with its
	// parenthesised argument.
	Parameters string
}

// ACL expressions supported by senselb. They are a subset of the option values
// the os-haproxy plugin publishes; add a constant here before emitting a new
// expression.
const (
	ACLExpressionHdr      = "hdr"        // Host header matches.
	ACLExpressionHdrBeg   = "hdr_beg"    // Host header begins with the value.
	ACLExpressionHdrEnd   = "hdr_end"    // Host header ends with the value.
	ACLExpressionHdrReg   = "hdr_reg"    // Host header matches the regular expression.
	ACLExpressionHdrSub   = "hdr_sub"    // Host header contains the value.
	ACLExpressionPathBeg  = "path_beg"   // Request path begins with the value.
	ACLExpressionPath     = "path"       // Request path matches the value.
	ACLExpressionPathReg  = "path_reg"   // Request path matches the regular expression.
	ACLExpressionSrc      = "src"        // Source address matches the value.
	ACLExpressionSSLFcSNI = "ssl_fc_sni" // Deciphered SNI matches the value.
)

// Rule is an HAProxy action: the construct that fires when its linked ACLs
// match. In the OPNsense plugin this is called an "action".
type Rule struct {
	// UUID identifies the corresponding live object; see Server.UUID.
	UUID string `json:"-"`

	Name string
	// Type is one of the RuleType constants.
	Type string
	// TestType is RuleTestTypeIf or RuleTestTypeUnless.
	TestType string
	// LinkedACLs names the ACLs that gate this rule. Each name must resolve to
	// an ACL declared in the same frontend or backend.
	LinkedACLs []string
	// Operator combines the linked ACLs: RuleOperatorAnd or RuleOperatorOr.
	Operator string

	UseBackend string
	UseServer  string
	// HTTPRequestAction carries the action body for the http-request,
	// http-response, tcp-request and tcp-response types, for example
	// "set-header X-Forwarded-Proto https".
	HTTPRequestAction string
	// Custom carries an unmodelled directive when Type is RuleTypeCustom.
	Custom string
}

// Rule types. The HTTPRequestAction field carries the payload of the
// http-request, http-response, tcp-request and tcp-response types.
const (
	RuleTypeUseBackend   = "use_backend"
	RuleTypeUseServer    = "use_server"
	RuleTypeHTTPRequest  = "http-request"
	RuleTypeHTTPResponse = "http-response"
	RuleTypeTCPRequest   = "tcp-request"
	RuleTypeTCPResponse  = "tcp-response"
	RuleTypeCustom       = "custom"
)

// Rule test types.
const (
	RuleTestTypeIf     = "if"
	RuleTestTypeUnless = "unless"
)

// Rule operators.
const (
	RuleOperatorAnd = "and"
	RuleOperatorOr  = "or"
)

// HealthCheck is a backend health check definition.
type HealthCheck struct {
	Enabled bool
	// Type is one of the HealthCheckType constants.
	Type string
	// Path is the URI probed by an HTTP health check. It comes from the
	// senselb.io/healthcheck-path annotation.
	Path string

	Interval int
	Fall     int
	Rise     int

	ProxyProto bool
}

// Health check types published by the os-haproxy plugin model.
const (
	HealthCheckTypeTCP        = "tcp"
	HealthCheckTypeHTTP       = "http"
	HealthCheckTypeAgent      = "agent"
	HealthCheckTypeLDAP       = "ldap"
	HealthCheckTypeMySQL      = "mysql"
	HealthCheckTypePostgreSQL = "pgsql"
	HealthCheckTypeRedis      = "redis"
	HealthCheckTypeSMTP       = "smtp"
	HealthCheckTypeESMTP      = "esmtp"
	HealthCheckTypeSSL        = "ssl"
)

// Backend is a named server group together with its load-balancing algorithm,
// health check and rules.
type Backend struct {
	// UUID identifies the corresponding live object; see Server.UUID.
	UUID string `json:"-"`

	Name string
	Mode Mode
	// Algorithm is one of the Algorithm constants.
	Algorithm string
	Servers   []Server
	// ACLs are declared here so that backend rules can reference them.
	ACLs        []ACL
	Rules       []Rule
	HealthCheck *HealthCheck
	Sticky      bool

	CustomOptions string
}

// Load-balancing algorithms published by the os-haproxy plugin model.
const (
	AlgorithmRoundRobin       = "roundrobin"
	AlgorithmSource           = "source"
	AlgorithmLeastConn        = "leastconn"
	AlgorithmStaticRoundRobin = "static-rr"
	AlgorithmURI              = "uri"
	AlgorithmRandom           = "random"
)

// Frontend is a bind address that accepts client connections and chooses the
// backend that serves each request.
type Frontend struct {
	// UUID identifies the corresponding live object; see Server.UUID.
	UUID string `json:"-"`

	Name           string
	Bind           []string
	Mode           Mode
	DefaultBackend string
	// Rules are evaluated in order, so place more specific rules first.
	Rules []Rule
	ACLs  []ACL

	SSLEnabled      bool
	SSLCertificates []string
	SSLDefaultCert  string

	CustomOptions string
}

// Listener is a named shared frontend that Services attach to.
type Listener struct {
	Name string
	// Adopt attaches senselb's routing rules to ExistingFrontend instead of
	// creating a frontend from Bind.
	Adopt            bool
	ExistingFrontend string
	Bind             []string
	Mode             Mode
	// DefaultBackend is used by a frontend the listener creates, and orders
	// listener placement.
	DefaultBackend string
}

// Model is a complete desired HAProxy configuration.
type Model struct {
	Frontends []Frontend
	Backends  []Backend
	Listeners []Listener
}

// NewFrontend returns a frontend with the given name, mode and bind addresses.
func NewFrontend(name string, mode Mode, bind ...string) Frontend {
	return Frontend{Name: name, Mode: mode, Bind: slices.Clone(bind)}
}

// NewBackend returns a backend with the given name and mode. The round-robin
// algorithm is HAProxy's own default.
func NewBackend(name string, mode Mode) Backend {
	return Backend{Name: name, Mode: mode, Algorithm: AlgorithmRoundRobin}
}

// NewServer returns an active, static server.
func NewServer(name, address string, port int) Server {
	return Server{
		Name:    name,
		Address: address,
		Port:    port,
		Mode:    ServerModeActive,
		Type:    ServerTypeStatic,
	}
}

// NewACL returns an ACL with the given expression and parameters.
func NewACL(name, expression, parameters string) ACL {
	return ACL{Name: name, Expression: expression, Parameters: parameters}
}

// NewRule returns a rule with the plugin's default test type and operator.
func NewRule(name, ruleType string) Rule {
	return Rule{
		Name:     name,
		Type:     ruleType,
		TestType: RuleTestTypeIf,
		Operator: RuleOperatorAnd,
	}
}

// NewListener returns a listener with the given name and mode. With adopt set,
// existingFrontend names the frontend to attach to and bind is discarded;
// otherwise bind supplies the addresses of the frontend the listener creates.
func NewListener(name string, mode Mode, adopt bool, existingFrontend string, bind ...string) Listener {
	listener := Listener{Name: name, Mode: mode, Adopt: adopt}
	if adopt {
		listener.ExistingFrontend = existingFrontend
	} else {
		listener.Bind = slices.Clone(bind)
	}
	return listener
}
