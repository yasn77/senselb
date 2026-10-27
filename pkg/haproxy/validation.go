package haproxy

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// ValidationError is the error returned by Model.Validate. It aggregates every
// problem found, so a caller can report them in a single pass.
type ValidationError struct {
	errs []error
}

// Error implements the error interface. Problems are rendered one per line.
func (e *ValidationError) Error() string {
	noun := "problems"
	if len(e.errs) == 1 {
		noun = "problem"
	}
	return fmt.Sprintf("invalid HAProxy model: %d %s:\n%v", len(e.errs), noun, errors.Join(e.errs...))
}

// Errors returns the individual problems. The returned slice is a copy.
func (e *ValidationError) Errors() []error {
	return slices.Clone(e.errs)
}

// Unwrap exposes the problems to errors.Is and errors.As.
func (e *ValidationError) Unwrap() []error {
	return e.errs
}

// Allowed values for the model's string enums. They mirror the option values
// published by the os-haproxy plugin model.
var (
	serverModes    = []string{ServerModeActive, ServerModeBackup, ServerModeDisabled}
	serverTypes    = []string{ServerTypeStatic, ServerTypeTemplate, ServerTypeUnix}
	aclExpressions = []string{
		ACLExpressionHdr,
		ACLExpressionHdrBeg,
		ACLExpressionHdrEnd,
		ACLExpressionHdrReg,
		ACLExpressionHdrSub,
		ACLExpressionPathBeg,
		ACLExpressionPath,
		ACLExpressionPathReg,
		ACLExpressionSrc,
		ACLExpressionSSLFcSNI,
	}
	ruleTypes = []string{
		RuleTypeUseBackend,
		RuleTypeUseServer,
		RuleTypeHTTPRequest,
		RuleTypeHTTPResponse,
		RuleTypeTCPRequest,
		RuleTypeTCPResponse,
		RuleTypeCustom,
	}
	ruleTestTypes = []string{RuleTestTypeIf, RuleTestTypeUnless}
	ruleOperators = []string{RuleOperatorAnd, RuleOperatorOr}
	algorithms    = []string{
		AlgorithmRoundRobin,
		AlgorithmSource,
		AlgorithmLeastConn,
		AlgorithmStaticRoundRobin,
		AlgorithmURI,
		AlgorithmRandom,
	}
	healthCheckTypes = []string{
		HealthCheckTypeTCP,
		HealthCheckTypeHTTP,
		HealthCheckTypeAgent,
		HealthCheckTypeLDAP,
		HealthCheckTypeMySQL,
		HealthCheckTypePostgreSQL,
		HealthCheckTypeRedis,
		HealthCheckTypeSMTP,
		HealthCheckTypeESMTP,
		HealthCheckTypeSSL,
	}
	frontendModes = []string{string(ModeHTTP), string(ModeTCP), string(ModeSSL)}
	backendModes  = []string{string(ModeHTTP), string(ModeTCP)}
)

// Validate reports every problem in the model. It returns nil when the model
// is valid, and a *ValidationError enumerating all problems otherwise.
func (m *Model) Validate() error {
	backendNames := make(map[string]struct{}, len(m.Backends))
	for _, backend := range m.Backends {
		if backend.Name != "" {
			backendNames[backend.Name] = struct{}{}
		}
	}

	var problems []error
	problems = append(problems, m.validateFrontends(backendNames)...)
	problems = append(problems, m.validateBackends(backendNames)...)
	problems = append(problems, m.validateListeners(backendNames)...)

	if len(problems) == 0 {
		return nil
	}
	return &ValidationError{errs: problems}
}

func (m *Model) validateFrontends(backendNames map[string]struct{}) []error {
	var problems []error
	seen := make(map[string]struct{}, len(m.Frontends))

	for i, frontend := range m.Frontends {
		scope := fmt.Sprintf("frontend %q", frontend.Name)
		if frontend.Name == "" {
			scope = fmt.Sprintf("frontend[%d]", i)
			problems = append(problems, fmt.Errorf("%s: name must not be empty", scope))
		} else {
			if _, duplicate := seen[frontend.Name]; duplicate {
				problems = append(problems, fmt.Errorf("%s: duplicate name", scope))
			}
			seen[frontend.Name] = struct{}{}
		}
		if err := checkText(scope, "name", frontend.Name); err != nil {
			problems = append(problems, err)
		}

		// A frontend the model creates must accept connections somewhere;
		// rendering it bind-less leaves HAProxy warning about its usefulness.
		if len(frontend.Bind) == 0 {
			problems = append(problems, fmt.Errorf("%s: requires at least one bind address", scope))
		}
		for _, bind := range frontend.Bind {
			if err := checkText(scope, "bind", bind); err != nil {
				problems = append(problems, err)
			}
		}

		if err := checkEnum(scope, "mode", string(frontend.Mode), frontendModes); err != nil {
			problems = append(problems, err)
		}

		if err := checkOptionLines(scope, "custom options", frontend.CustomOptions); err != nil {
			problems = append(problems, err)
		}

		aclNames, aclProblems := validateACLs(scope, frontend.ACLs)
		problems = append(problems, aclProblems...)
		problems = append(problems, validateRules(scope, "frontend", frontend.Rules, aclNames, backendNames)...)

		if frontend.DefaultBackend != "" {
			if _, declared := backendNames[frontend.DefaultBackend]; !declared {
				problems = append(problems, fmt.Errorf("%s: default backend %q is not declared", scope, frontend.DefaultBackend))
			}
		}
	}
	return problems
}

func (m *Model) validateBackends(backendNames map[string]struct{}) []error {
	var problems []error
	seen := make(map[string]struct{}, len(m.Backends))

	for i, backend := range m.Backends {
		scope := fmt.Sprintf("backend %q", backend.Name)
		if backend.Name == "" {
			scope = fmt.Sprintf("backend[%d]", i)
			problems = append(problems, fmt.Errorf("%s: name must not be empty", scope))
		} else {
			if _, duplicate := seen[backend.Name]; duplicate {
				problems = append(problems, fmt.Errorf("%s: duplicate name", scope))
			}
			seen[backend.Name] = struct{}{}
		}
		if err := checkText(scope, "name", backend.Name); err != nil {
			problems = append(problems, err)
		}
		if err := checkOptionLines(scope, "custom options", backend.CustomOptions); err != nil {
			problems = append(problems, err)
		}

		if err := checkEnum(scope, "mode", string(backend.Mode), backendModes); err != nil {
			problems = append(problems, err)
		}
		if err := checkEnum(scope, "algorithm", backend.Algorithm, algorithms); err != nil {
			problems = append(problems, err)
		}

		problems = append(problems, validateServers(scope, backend.Servers)...)

		aclNames, aclProblems := validateACLs(scope, backend.ACLs)
		problems = append(problems, aclProblems...)
		problems = append(problems, validateRules(scope, "backend", backend.Rules, aclNames, backendNames)...)

		if backend.HealthCheck != nil && backend.HealthCheck.Enabled {
			// A disabled check is inert: the renderer emits no health-check
			// keyword for it, so its fields are not validated either.
			if err := checkEnum(scope, "health check type", backend.HealthCheck.Type, healthCheckTypes); err != nil {
				problems = append(problems, err)
			}
			// The path is rendered into the option httpchk directive.
			if err := checkText(scope, "health check path", backend.HealthCheck.Path); err != nil {
				problems = append(problems, err)
			}
			problems = append(problems, validateHealthCheck(scope, *backend.HealthCheck)...)
		}
	}
	return problems
}

func (m *Model) validateListeners(backendNames map[string]struct{}) []error {
	var problems []error
	seen := make(map[string]struct{}, len(m.Listeners))

	for i, listener := range m.Listeners {
		scope := fmt.Sprintf("listener %q", listener.Name)
		if listener.Name == "" {
			scope = fmt.Sprintf("listener[%d]", i)
			problems = append(problems, fmt.Errorf("%s: name must not be empty", scope))
		} else {
			if _, duplicate := seen[listener.Name]; duplicate {
				problems = append(problems, fmt.Errorf("%s: duplicate name", scope))
			}
			seen[listener.Name] = struct{}{}
		}
		if err := checkText(scope, "name", listener.Name); err != nil {
			problems = append(problems, err)
		}

		// An adopted frontend defines its own mode, so the listener may omit
		// it. A listener that creates a frontend must state the mode.
		if !listener.Adopt || listener.Mode != "" {
			if err := checkEnum(scope, "mode", string(listener.Mode), frontendModes); err != nil {
				problems = append(problems, err)
			}
		}

		if listener.Adopt {
			if listener.ExistingFrontend == "" {
				problems = append(problems, fmt.Errorf("%s: adopting requires an existing frontend", scope))
			}
		} else if len(listener.Bind) == 0 {
			problems = append(problems, fmt.Errorf("%s: creating a frontend requires at least one bind address", scope))
		}

		if listener.DefaultBackend != "" {
			if _, declared := backendNames[listener.DefaultBackend]; !declared {
				problems = append(problems, fmt.Errorf("%s: default backend %q is not declared", scope, listener.DefaultBackend))
			}
		}
	}
	return problems
}

// validateACLs checks one ACL collection and returns the declared names for
// rule resolution.
func validateACLs(scope string, acls []ACL) (map[string]struct{}, []error) {
	var problems []error
	names := make(map[string]struct{}, len(acls))

	for i, acl := range acls {
		aclScope := fmt.Sprintf("%s ACL %q", scope, acl.Name)
		if acl.Name == "" {
			aclScope = fmt.Sprintf("%s ACL[%d]", scope, i)
			problems = append(problems, fmt.Errorf("%s: name must not be empty", aclScope))
		} else {
			if _, duplicate := names[acl.Name]; duplicate {
				problems = append(problems, fmt.Errorf("%s: duplicate name", aclScope))
			}
			names[acl.Name] = struct{}{}
		}
		if err := checkText(aclScope, "name", acl.Name); err != nil {
			problems = append(problems, err)
		}
		if err := checkACLParameters(aclScope, acl); err != nil {
			problems = append(problems, err)
		}

		if err := checkEnum(aclScope, "expression", acl.Expression, aclExpressions); err != nil {
			problems = append(problems, err)
		}
	}
	return names, problems
}

// validateRules checks one rule list. kind names the parent collection in
// errors about unresolved ACL references.
func validateRules(scope, kind string, rules []Rule, aclNames, backendNames map[string]struct{}) []error {
	var problems []error
	seen := make(map[string]struct{}, len(rules))

	for i, rule := range rules {
		ruleScope := fmt.Sprintf("%s rule %q", scope, rule.Name)
		if rule.Name == "" {
			ruleScope = fmt.Sprintf("%s rule[%d]", scope, i)
			problems = append(problems, fmt.Errorf("%s: name must not be empty", ruleScope))
		} else {
			if _, duplicate := seen[rule.Name]; duplicate {
				problems = append(problems, fmt.Errorf("%s: duplicate name", ruleScope))
			}
			seen[rule.Name] = struct{}{}
		}
		if err := checkText(ruleScope, "name", rule.Name); err != nil {
			problems = append(problems, err)
		}
		if err := checkText(ruleScope, "custom", rule.Custom); err != nil {
			problems = append(problems, err)
		}
		if err := checkText(ruleScope, "action", rule.HTTPRequestAction); err != nil {
			problems = append(problems, err)
		}
		if err := checkText(ruleScope, "use_server", rule.UseServer); err != nil {
			problems = append(problems, err)
		}

		if err := checkEnum(ruleScope, "type", rule.Type, ruleTypes); err != nil {
			problems = append(problems, err)
		}
		if err := checkEnum(ruleScope, "test type", rule.TestType, ruleTestTypes); err != nil {
			problems = append(problems, err)
		}
		if err := checkEnum(ruleScope, "operator", rule.Operator, ruleOperators); err != nil {
			problems = append(problems, err)
		}

		// use_backend is a frontend keyword and use_server a backend keyword.
		// The payload checks below only make sense in the scope that owns the
		// keyword, so a misplaced rule reports the scope error alone.
		inScope := true
		switch {
		case kind == "frontend" && rule.Type == RuleTypeUseServer:
			problems = append(problems, fmt.Errorf("%s: use_server is only valid in a backend", ruleScope))
			inScope = false
		case kind == "backend" && rule.Type == RuleTypeUseBackend:
			problems = append(problems, fmt.Errorf("%s: use_backend is only valid in a frontend", ruleScope))
			inScope = false
		}

		if inScope {
			switch rule.Type {
			case RuleTypeUseBackend:
				if rule.UseBackend == "" {
					problems = append(problems, fmt.Errorf("%s: use_backend requires a backend", ruleScope))
				} else if _, declared := backendNames[rule.UseBackend]; !declared {
					problems = append(problems, fmt.Errorf("%s: backend %q is not declared", ruleScope, rule.UseBackend))
				}
			case RuleTypeUseServer:
				if rule.UseServer == "" {
					problems = append(problems, fmt.Errorf("%s: use_server requires a server", ruleScope))
				}
			case RuleTypeHTTPRequest, RuleTypeHTTPResponse, RuleTypeTCPRequest, RuleTypeTCPResponse:
				// A rule without its action renders no directive at all, so it
				// would silently disappear from the configuration.
				if rule.HTTPRequestAction == "" {
					problems = append(problems, fmt.Errorf("%s: %s requires an action", ruleScope, rule.Type))
				}
			case RuleTypeCustom:
				if rule.Custom == "" {
					problems = append(problems, fmt.Errorf("%s: custom requires a directive", ruleScope))
				}
			}
		}

		for _, linked := range rule.LinkedACLs {
			if _, declared := aclNames[linked]; !declared {
				problems = append(problems, fmt.Errorf("%s: ACL %q is not declared in this %s", ruleScope, linked, kind))
			}
		}
	}
	return problems
}

func validateServers(scope string, servers []Server) []error {
	var problems []error
	seen := make(map[string]struct{}, len(servers))

	for i, server := range servers {
		serverScope := fmt.Sprintf("%s server %q", scope, server.Name)
		if server.Name == "" {
			serverScope = fmt.Sprintf("%s server[%d]", scope, i)
			problems = append(problems, fmt.Errorf("%s: name must not be empty", serverScope))
		} else {
			if _, duplicate := seen[server.Name]; duplicate {
				problems = append(problems, fmt.Errorf("%s: duplicate name", serverScope))
			}
			seen[server.Name] = struct{}{}
		}

		if err := checkEnum(serverScope, "mode", server.Mode, serverModes); err != nil {
			problems = append(problems, err)
		}
		if err := checkEnum(serverScope, "type", server.Type, serverTypes); err != nil {
			problems = append(problems, err)
		}
		if err := checkText(serverScope, "name", server.Name); err != nil {
			problems = append(problems, err)
		}
		if err := checkText(serverScope, "address", server.Address); err != nil {
			problems = append(problems, err)
		}
		if err := checkText(serverScope, "source", server.Source); err != nil {
			problems = append(problems, err)
		}
		problems = append(problems, validateServerNumbers(serverScope, server)...)
	}
	return problems
}

// validateServerNumbers bounds the numeric server fields that HAProxy accepts
// only within a fixed range.
func validateServerNumbers(scope string, server Server) []error {
	var problems []error

	// Weight 0 means "unset", which renders no weight keyword; HAProxy's
	// documented maximum is 256.
	if server.Weight < 0 || server.Weight > 256 {
		problems = append(problems, fmt.Errorf("%s: weight %d must be between 0 and 256", scope, server.Weight))
	}

	if server.Type == ServerTypeUnix {
		// A unix server names a socket path; a port would be ignored.
		if server.Port != 0 {
			problems = append(problems, fmt.Errorf("%s: port must be 0 for a unix server", scope))
		}
	} else if server.Port < 1 || server.Port > 65535 {
		problems = append(problems, fmt.Errorf("%s: port %d must be between 1 and 65535", scope, server.Port))
	}

	// CheckPort 0 means "use the server port", so only a set value is bounded.
	if server.CheckPort != 0 && (server.CheckPort < 1 || server.CheckPort > 65535) {
		problems = append(problems, fmt.Errorf("%s: check port %d must be between 1 and 65535", scope, server.CheckPort))
	}

	for _, field := range []struct {
		name  string
		value int
	}{
		{"maxconn", server.MaxConn},
		{"check interval", server.CheckInterval},
		{"check down interval", server.CheckDownInterval},
	} {
		if field.value < 0 {
			problems = append(problems, fmt.Errorf("%s: %s %d must not be negative", scope, field.name, field.value))
		}
	}

	return problems
}

// validateHealthCheck bounds the numeric fields of an enabled health check.
func validateHealthCheck(scope string, healthCheck HealthCheck) []error {
	var problems []error
	for _, field := range []struct {
		name  string
		value int
	}{
		{"health check interval", healthCheck.Interval},
		{"health check fall", healthCheck.Fall},
		{"health check rise", healthCheck.Rise},
	} {
		if field.value < 0 {
			problems = append(problems, fmt.Errorf("%s: %s %d must not be negative", scope, field.name, field.value))
		}
	}
	return problems
}

// checkACLParameters enforces the ACL.Parameters contract: non-empty raw
// tokens, function-style for an hdr-family expression only, plain for every
// other expression, and free of characters that cannot appear in a rendered
// directive.
func checkACLParameters(scope string, acl ACL) error {
	if strings.TrimSpace(acl.Parameters) == "" {
		return fmt.Errorf("%s: parameters must not be empty", scope)
	}
	parenthesised := strings.HasPrefix(acl.Parameters, "(")
	if strings.HasPrefix(acl.Expression, "hdr") {
		if !parenthesised {
			return fmt.Errorf(`%s: %s requires a parenthesised header argument, for example "(host) -i example.com"`, scope, acl.Expression)
		}
	} else if parenthesised {
		// renderACLs joins a parenthesised argument with no separating space,
		// which only an hdr-family fetch accepts; anywhere else it would
		// produce an unknown fetch such as path_reg(^/api).
		return fmt.Errorf("%s: %s takes a plain argument, not a parenthesised one", scope, acl.Expression)
	}
	return checkText(scope, "parameters", acl.Parameters)
}

// checkText rejects text carrying control characters or a comment marker. Such
// text cannot appear in a rendered directive: a newline or carriage return
// would start a new configuration line, other control characters are never
// valid syntax, and a '#' truncates the directive from that point on, so a
// server line could lose its port.
func checkText(scope, field, value string) error {
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s: %s contains control character %q", scope, field, r)
		}
	}
	if strings.ContainsRune(value, '#') {
		return fmt.Errorf("%s: %s contains '#', which starts an HAProxy comment", scope, field)
	}
	return nil
}

// checkOptionLines applies checkText to a verbatim option fragment one line at
// a time. A newline is the block-line separator renderCustomOptions honours, so
// it is structural rather than injectable; every other control character,
// including a carriage return, is rejected.
func checkOptionLines(scope, field, value string) error {
	for _, line := range strings.Split(value, "\n") {
		if err := checkText(scope, field, line); err != nil {
			return err
		}
	}
	return nil
}

// checkEnum returns an error when value is empty or absent from allowed.
func checkEnum(scope, field, value string, allowed []string) error {
	if value == "" {
		return fmt.Errorf("%s: %s must not be empty; expected one of %s", scope, field, quotedList(allowed))
	}
	if !slices.Contains(allowed, value) {
		return fmt.Errorf("%s: %s %q is not valid; expected one of %s", scope, field, value, quotedList(allowed))
	}
	return nil
}

// quotedList renders the allowed values as a comma-separated, quoted list.
func quotedList(values []string) string {
	quoted := make([]string, len(values))
	for i, value := range values {
		quoted[i] = fmt.Sprintf("%q", value)
	}
	return strings.Join(quoted, ", ")
}
