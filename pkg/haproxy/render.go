package haproxy

import (
	"cmp"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
)

// Render converts a validated Model into canonical HAProxy configuration
// text.
//
// Frontend and backend blocks are ordered by name, while binds, ACLs, rules
// and servers keep their declared order, so equal models render
// byte-identically. Listeners are an abstraction a provider resolves before
// rendering and are therefore never emitted, and TLS material is
// provider-managed, so a bind line never carries ssl parameters.
//
// Render validates the model first and returns an empty string with the
// validation error rather than a partial configuration.
func Render(m *Model) (string, error) {
	if m == nil {
		return "", fmt.Errorf("render HAProxy model: model is nil")
	}
	if err := m.Validate(); err != nil {
		return "", err
	}

	blocks := make([]string, 0, len(m.Frontends)+len(m.Backends))

	frontends := slices.Clone(m.Frontends)
	slices.SortFunc(frontends, func(a, b Frontend) int { return cmp.Compare(a.Name, b.Name) })
	for _, frontend := range frontends {
		blocks = append(blocks, renderFrontend(frontend))
	}

	backends := slices.Clone(m.Backends)
	slices.SortFunc(backends, func(a, b Backend) int { return cmp.Compare(a.Name, b.Name) })
	for _, backend := range backends {
		blocks = append(blocks, renderBackend(backend))
	}

	return strings.Join(blocks, "\n"), nil
}

// renderFrontend renders one frontend block. Optional fields are omitted
// entirely when empty.
func renderFrontend(frontend Frontend) string {
	lines := make([]string, 0, len(frontend.Bind)+len(frontend.ACLs)+len(frontend.Rules)+2)
	for _, bind := range frontend.Bind {
		lines = append(lines, "bind "+bind)
	}
	lines = append(lines, "mode "+renderMode(frontend.Mode))
	if frontend.DefaultBackend != "" {
		lines = append(lines, "default_backend "+frontend.DefaultBackend)
	}
	lines = append(lines, renderACLs(frontend.ACLs)...)
	lines = append(lines, renderRules(frontend.Rules)...)
	lines = append(lines, renderCustomOptions(frontend.CustomOptions)...)

	return formatBlock("frontend "+frontend.Name, lines)
}

// renderBackend renders one backend block.
func renderBackend(backend Backend) string {
	lines := make([]string, 0, len(backend.ACLs)+len(backend.Rules)+len(backend.Servers)+6)
	lines = append(lines, "mode "+renderMode(backend.Mode), "balance "+backend.Algorithm)

	if backend.Sticky {
		// Server affinity uses a source-address stick table rather than a
		// persistence cookie: it needs no per-server cookie name, which the
		// model does not carry, and is valid in both http and tcp mode.
		lines = append(lines, "stick-table type ip size 200k expire 30m", "stick on src")
	}

	if backend.HealthCheck != nil && backend.HealthCheck.Enabled {
		if backend.HealthCheck.Type == HealthCheckTypeHTTP && backend.HealthCheck.Path != "" {
			lines = append(lines, "option httpchk GET "+backend.HealthCheck.Path)
		}
	}

	lines = append(lines, renderACLs(backend.ACLs)...)
	lines = append(lines, renderRules(backend.Rules)...)
	for _, server := range backend.Servers {
		lines = append(lines, renderServer(server, backend.HealthCheck))
	}
	lines = append(lines, renderCustomOptions(backend.CustomOptions)...)

	return formatBlock("backend "+backend.Name, lines)
}

// renderServer renders one server line. Health-check timings and thresholds
// are server keywords in HAProxy, so they are emitted on the server line
// rather than as backend directives.
func renderServer(server Server, healthCheck *HealthCheck) string {
	parts := []string{"server", server.Name, serverAddress(server)}

	if server.Mode == ServerModeDisabled {
		// Keep the definition so the server stays addressable, but start it
		// in maintenance mode; health checks and weights are meaningless.
		return strings.Join(append(parts, ServerModeDisabled), " ")
	}

	if server.Weight != 0 {
		parts = append(parts, "weight", strconv.Itoa(server.Weight))
	}
	if server.MaxConn != 0 {
		parts = append(parts, "maxconn", strconv.Itoa(server.MaxConn))
	}
	if healthCheck != nil && healthCheck.Enabled {
		parts = append(parts, "check")
		if server.CheckPort > 0 {
			parts = append(parts, "port", strconv.Itoa(server.CheckPort))
		}
		interval := server.CheckInterval
		if interval == 0 {
			interval = healthCheck.Interval
		}
		if interval != 0 {
			parts = append(parts, "inter", strconv.Itoa(interval))
		}
		if server.CheckDownInterval != 0 {
			parts = append(parts, "downinter", strconv.Itoa(server.CheckDownInterval))
		}
		if healthCheck.Fall != 0 {
			parts = append(parts, "fall", strconv.Itoa(healthCheck.Fall))
		}
		if healthCheck.Rise != 0 {
			parts = append(parts, "rise", strconv.Itoa(healthCheck.Rise))
		}
	}
	if server.Mode == ServerModeBackup {
		parts = append(parts, "backup")
	}
	if server.Source != "" {
		parts = append(parts, "source", server.Source)
	}

	return strings.Join(parts, " ")
}

// serverAddress renders the server endpoint. A unix server names a socket
// path, which HAProxy accepts in place of an address and port pair.
func serverAddress(server Server) string {
	if server.Type == ServerTypeUnix {
		return server.Address
	}
	return net.JoinHostPort(server.Address, strconv.Itoa(server.Port))
}

// renderMode converts a model mode into the value of an HAProxy mode keyword.
// HAProxy itself defines only http and tcp; the plugin's ssl mode means TLS
// pass-through, which upstream renders as tcp so the proxy forwards the
// encrypted stream untouched.
func renderMode(mode Mode) string {
	if mode == ModeSSL {
		return string(ModeTCP)
	}
	return string(mode)
}

// renderACLs renders one acl line per declaration, preserving their order.
// Parameters are appended verbatim: a parenthesised fetch argument joins the
// expression with no space (hdr(host) -i example.com), while a value argument
// follows one space (path_beg /api).
func renderACLs(acls []ACL) []string {
	lines := make([]string, 0, len(acls))
	for _, acl := range acls {
		line := "acl " + acl.Name + " " + acl.Expression
		switch {
		case acl.Parameters == "":
		case strings.HasPrefix(acl.Parameters, "("):
			line += acl.Parameters
		default:
			line += " " + acl.Parameters
		}
		lines = append(lines, line)
	}
	return lines
}

// renderRules renders rules in declared order, dropping those that would
// produce no directive.
func renderRules(rules []Rule) []string {
	lines := make([]string, 0, len(rules))
	for _, rule := range rules {
		if line := renderRule(rule); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// renderRule renders one rule as a single configuration directive.
func renderRule(rule Rule) string {
	switch rule.Type {
	case RuleTypeUseBackend:
		return "use_backend " + rule.UseBackend + ruleCondition(rule)
	case RuleTypeUseServer:
		return "use-server " + rule.UseServer + ruleCondition(rule)
	case RuleTypeHTTPRequest, RuleTypeHTTPResponse, RuleTypeTCPRequest, RuleTypeTCPResponse:
		if rule.HTTPRequestAction == "" {
			return ""
		}
		// The condition is part of the directive, so omitting it would widen
		// the action's scope to every request.
		return rule.Type + " " + rule.HTTPRequestAction + ruleCondition(rule)
	case RuleTypeCustom:
		return rule.Custom
	default:
		return ""
	}
}

// ruleCondition renders the if/unless clause gating a rule. HAProxy combines
// ACLs in a condition with an implicit AND and an explicit "or" keyword; it
// has no "and" keyword.
func ruleCondition(rule Rule) string {
	if len(rule.LinkedACLs) == 0 {
		return ""
	}
	separator := " "
	if rule.Operator == RuleOperatorOr {
		separator = " or "
	}
	return " " + rule.TestType + " " + strings.Join(rule.LinkedACLs, separator)
}

// renderCustomOptions turns a verbatim option fragment into indented block
// lines. Blank lines are discarded so the block stays canonical.
func renderCustomOptions(options string) []string {
	if strings.TrimSpace(options) == "" {
		return nil
	}

	var lines []string
	for _, line := range strings.Split(options, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// formatBlock renders a block header followed by its tab-indented lines.
func formatBlock(header string, lines []string) string {
	var builder strings.Builder
	builder.WriteString(header)
	builder.WriteByte('\n')
	for _, line := range lines {
		builder.WriteString("\t")
		builder.WriteString(line)
		builder.WriteByte('\n')
	}
	return builder.String()
}
