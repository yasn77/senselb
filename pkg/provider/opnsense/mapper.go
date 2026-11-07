package opnsense

import (
	"cmp"
	"fmt"
	"math"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/yasn77/senselb/pkg/haproxy"
)

// Form values for the plugin's BooleanField.
const (
	formTrue  = "1"
	formFalse = "0"
)

// MalformedSettingsError reports a settings/get payload whose shape differs
// from the os-haproxy plugin model. Path is the dotted location of the
// offending value, for example
// haproxy.servers.server.<uuid>.port.
type MalformedSettingsError struct {
	// Path is the dotted JSON path of the offending value.
	Path string
	// Reason states what the mapper expected and what it found.
	Reason string
}

// Error implements error.
func (e *MalformedSettingsError) Error() string {
	return fmt.Sprintf("opnsense: malformed settings at %s: %s", e.Path, e.Reason)
}

// FromSettings maps a settings/get payload onto the canonical model.
//
// The plugin stores every collection as an object keyed by uuid (for example
// haproxy.backends.backend.<uuid>) and encodes enum fields as select objects
// whose selected key is the stored value. FromSettings records each uuid in the
// model object's UUID field, flattens the selects, and resolves the uuid-keyed
// linkage (a frontend's defaultBackend, a backend's linkedServers, and so on)
// into the names the model uses.
//
// The plugin keeps ACLs and servers in global collections and links them from
// actions and backends. A server reaches the model through a backend's
// linkedServers, and an ACL through the actions a frontend or backend links, so
// a live object that nothing links is invisible to the model.
//
// A relation that names a uuid no collection declares is a dangling reference:
// live configuration can acquire one when a foreign object was deleted
// out-of-band. Such a reference is skipped and reported in the second return
// value as a dotted path, for example
// haproxy.backends.backend.<uuid>.linkedServers.<ref>; only a structural defect
// in the payload is returned as a *MalformedSettingsError. Reading therefore
// survives a partially broken live configuration, and the provider's next
// relation write drops the dangling reference.
//
// Output is deterministic: collections are ordered by uuid and each parent's
// children by name. The plugin stores linkage as an unordered multi-select, so
// rule order within a frontend or backend follows the rule name.
//
// The model is not validated here: Get must report the live configuration even
// when it contains objects senselb would never create.
func FromSettings(s Settings) (*haproxy.Model, []string, error) {
	root, err := rootObject(s)
	if err != nil {
		return nil, nil, err
	}

	frontends, err := readCollection(root, "frontends", "frontend")
	if err != nil {
		return nil, nil, err
	}
	backends, err := readCollection(root, "backends", "backend")
	if err != nil {
		return nil, nil, err
	}
	servers, err := readCollection(root, "servers", "server")
	if err != nil {
		return nil, nil, err
	}
	acls, err := readCollection(root, "acls", "acl")
	if err != nil {
		return nil, nil, err
	}
	actions, err := readCollection(root, "actions", "action")
	if err != nil {
		return nil, nil, err
	}
	healthchecks, err := readCollection(root, "healthchecks", "healthcheck")
	if err != nil {
		return nil, nil, err
	}

	var dangling danglingRefs

	serversByUUID := make(map[string]haproxy.Server, len(servers))
	serverNames := make(map[string]string, len(servers))
	for _, object := range servers {
		server, err := decodeServer(object)
		if err != nil {
			return nil, nil, err
		}
		serversByUUID[object.uuid] = server
		serverNames[object.uuid] = server.Name
	}

	aclsByName := make(map[string]haproxy.ACL, len(acls))
	aclNames := make(map[string]string, len(acls))
	for _, object := range acls {
		acl, err := decodeACL(object)
		if err != nil {
			return nil, nil, err
		}
		aclsByName[acl.Name] = acl
		aclNames[object.uuid] = acl.Name
	}

	// Actions resolve names, so the backend names must be known before the
	// actions are decoded; their payloads are decoded after the actions.
	backendNames := make(map[string]string, len(backends))
	for _, object := range backends {
		name, err := objectName(object)
		if err != nil {
			return nil, nil, err
		}
		backendNames[object.uuid] = name
	}

	rulesByUUID := make(map[string]haproxy.Rule, len(actions))
	for _, object := range actions {
		rule, err := decodeAction(object, aclNames, backendNames, serverNames, &dangling)
		if err != nil {
			return nil, nil, err
		}
		rulesByUUID[object.uuid] = rule
	}

	healthchecksByUUID := make(map[string]settingsObject, len(healthchecks))
	for _, object := range healthchecks {
		healthchecksByUUID[object.uuid] = object
	}

	model := &haproxy.Model{}
	for _, object := range backends {
		backend, err := decodeBackend(
			object, serversByUUID, rulesByUUID, healthchecksByUUID, aclsByName, &dangling,
		)
		if err != nil {
			return nil, nil, err
		}
		model.Backends = append(model.Backends, backend)
	}
	for _, object := range frontends {
		frontend, err := decodeFrontend(object, backendNames, rulesByUUID, aclsByName, &dangling)
		if err != nil {
			return nil, nil, err
		}
		model.Frontends = append(model.Frontends, frontend)
	}
	return model, dangling.paths, nil
}

// danglingRefs collects the relation references a tolerant read skips.
type danglingRefs struct {
	paths []string
}

// skip records one dangling reference in dotted path notation.
func (d *danglingRefs) skip(object settingsObject, field, uuid string) {
	if d == nil {
		return
	}
	d.paths = append(d.paths, object.path+"."+field+"."+uuid)
}

// flattenSelect returns the key of a plugin select object's selected entry, the
// value itself for a plain string, and "" for a nil or unrecognised value. The
// selected key is the stored value (http, roundrobin, src); the entry's value
// is only the display label.
func flattenSelect(v any) string {
	switch value := v.(type) {
	case nil:
		return ""
	case string:
		return value
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			if key != "" && isSelected(value[key]) {
				return key
			}
		}
		return ""
	default:
		return ""
	}
}

// selectedKeys returns the sorted keys of a select object whose entries are
// selected. A plain string is a single selected value; an empty string selects
// nothing.
func selectedKeys(v any) ([]string, error) {
	switch value := v.(type) {
	case nil:
		return nil, nil
	case string:
		if value == "" {
			return nil, nil
		}
		return []string{value}, nil
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key, entry := range value {
			if key != "" && isSelected(entry) {
				keys = append(keys, key)
			}
		}
		slices.Sort(keys)
		return keys, nil
	default:
		return nil, fmt.Errorf("want select object, got %T", v)
	}
}

// isSelected reports whether one select entry is flagged as selected. The plugin
// encodes the flag as a JSON number, and occasionally as a string.
func isSelected(entry any) bool {
	values, ok := entry.(map[string]any)
	if !ok {
		return false
	}
	return truthy(values["selected"])
}

// truthy interprets a plugin boolean flag.
func truthy(v any) bool {
	switch value := v.(type) {
	case bool:
		return value
	case string:
		return value == "1" || strings.EqualFold(value, "true")
	case float64:
		return value != 0
	default:
		return false
	}
}

// rootObject returns the payload's root "haproxy" object.
func rootObject(s Settings) (map[string]any, error) {
	raw, ok := s["haproxy"]
	if !ok {
		return nil, &MalformedSettingsError{Path: "haproxy", Reason: "missing root object"}
	}
	root, ok := asObjectMap(raw)
	if !ok {
		return nil, &MalformedSettingsError{Path: "haproxy", Reason: fmt.Sprintf("want object, got %T", raw)}
	}
	return root, nil
}

// settingsObject is one entry of a plugin collection: its uuid, the values of
// the object, and the dotted path used in malformed-payload errors.
type settingsObject struct {
	uuid   string
	path   string
	values map[string]any
}

// readCollection returns the objects of one plugin collection in uuid order.
// The outer collection key must exist; an absent singular container is an empty
// collection.
func readCollection(root map[string]any, name, item string) ([]settingsObject, error) {
	path := "haproxy." + name
	raw, ok := root[name]
	if !ok {
		return nil, &MalformedSettingsError{Path: path, Reason: "missing collection"}
	}
	container, ok := asObjectMap(raw)
	if !ok {
		return nil, &MalformedSettingsError{Path: path, Reason: fmt.Sprintf("want object, got %T", raw)}
	}

	inner, ok := container[item]
	if !ok {
		return nil, nil
	}
	objects, ok := asObjectMap(inner)
	if !ok {
		return nil, &MalformedSettingsError{
			Path:   path + "." + item,
			Reason: fmt.Sprintf("want object, got %T", inner),
		}
	}

	uuids := make([]string, 0, len(objects))
	for uuid := range objects {
		uuids = append(uuids, uuid)
	}
	slices.Sort(uuids)

	entries := make([]settingsObject, 0, len(uuids))
	for _, uuid := range uuids {
		values, ok := objects[uuid].(map[string]any)
		if !ok {
			return nil, &MalformedSettingsError{
				Path:   path + "." + item + "." + uuid,
				Reason: fmt.Sprintf("want object, got %T", objects[uuid]),
			}
		}
		entries = append(entries, settingsObject{
			uuid:   uuid,
			path:   path + "." + item + "." + uuid,
			values: values,
		})
	}
	return entries, nil
}

// asObjectMap accepts a decoded JSON object. An empty array is tolerated because
// OPNsense serialises an empty model container as [] rather than {}.
func asObjectMap(v any) (map[string]any, bool) {
	switch value := v.(type) {
	case map[string]any:
		return value, true
	case []any:
		if len(value) == 0 {
			return map[string]any{}, true
		}
	}
	return nil, false
}

// fieldReader decodes the fields of one plugin object, recording the first
// shape error together with its JSON path. A read after a failure yields the
// zero value.
type fieldReader struct {
	values map[string]any
	path   string
	err    error
}

// newFieldReader returns a reader for one plugin object.
func newFieldReader(values map[string]any, path string) *fieldReader {
	return &fieldReader{values: values, path: path}
}

// fail records the first shape error, scoped to field.
func (r *fieldReader) fail(field, reason string) {
	if r.err == nil {
		r.err = &MalformedSettingsError{Path: r.path + "." + field, Reason: reason}
	}
}

// raw returns a field's non-nil value unless the reader already failed.
func (r *fieldReader) raw(field string) (any, bool) {
	if r.err != nil {
		return nil, false
	}
	value, ok := r.values[field]
	if !ok || value == nil {
		return nil, false
	}
	return value, true
}

// str reads a text field.
func (r *fieldReader) str(field string) string {
	value, ok := r.raw(field)
	if !ok {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		r.fail(field, fmt.Sprintf("want string, got %T", value))
		return ""
	}
	return text
}

// integer reads an integer field. The plugin keeps some durations in a text
// field, so a numeric prefix is accepted and its HAProxy unit suffix dropped:
// the canonical model stores integers only.
func (r *fieldReader) integer(field string) int {
	value, ok := r.raw(field)
	if !ok {
		return 0
	}
	switch number := value.(type) {
	case float64:
		if math.Trunc(number) != number {
			r.fail(field, fmt.Sprintf("want integer, got %v", number))
			return 0
		}
		return int(number)
	case string:
		if number == "" {
			return 0
		}
		parsed, ok := leadingInteger(number)
		if !ok {
			r.fail(field, fmt.Sprintf("want integer, got %q", number))
			return 0
		}
		return parsed
	default:
		r.fail(field, fmt.Sprintf("want integer, got %T", value))
		return 0
	}
}

// leadingInteger parses the leading decimal digits of s, ignoring an optional
// suffix such as the "s" in "2s".
func leadingInteger(s string) (int, bool) {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false
	}
	parsed, err := strconv.Atoi(s[:end])
	if err != nil {
		return 0, false
	}
	return parsed, true
}

// boolean reads a BooleanField, which the plugin encodes as "1" or "0".
func (r *fieldReader) boolean(field string) bool {
	value, ok := r.raw(field)
	if !ok {
		return false
	}
	switch flag := value.(type) {
	case bool:
		return flag
	case float64:
		return flag != 0
	case string:
		switch flag {
		case "1", "true":
			return true
		case "0", "false", "":
			return false
		}
	}
	r.fail(field, fmt.Sprintf("want boolean, got %v", value))
	return false
}

// enum reads an OptionField and returns the selected option key.
func (r *fieldReader) enum(field string) string {
	value, ok := r.raw(field)
	if !ok {
		return ""
	}
	return flattenSelect(value)
}

// keys reads a multi-select and returns the sorted keys of its selected entries.
func (r *fieldReader) keys(field string) []string {
	value, ok := r.raw(field)
	if !ok {
		return nil
	}
	keys, err := selectedKeys(value)
	if err != nil {
		r.fail(field, err.Error())
		return nil
	}
	return keys
}

// key reads a single-select and returns the key of its one selected entry.
func (r *fieldReader) key(field string) string {
	keys := r.keys(field)
	switch len(keys) {
	case 0:
		return ""
	case 1:
		return keys[0]
	default:
		r.fail(field, fmt.Sprintf("single relation has %d selected entries", len(keys)))
		return ""
	}
}

// decodeServer maps one server object.
func decodeServer(object settingsObject) (haproxy.Server, error) {
	reader := newFieldReader(object.values, object.path)
	server := haproxy.Server{
		UUID:              object.uuid,
		Name:              reader.str("name"),
		Address:           reader.str("address"),
		Port:              reader.integer("port"),
		CheckPort:         reader.integer("checkport"),
		Mode:              reader.enum("mode"),
		Type:              reader.enum("type"),
		Weight:            reader.integer("weight"),
		MaxConn:           reader.integer("maxConnections"),
		CheckInterval:     reader.integer("checkInterval"),
		CheckDownInterval: reader.integer("checkDownInterval"),
		Source:            reader.str("source"),
	}
	if reader.err != nil {
		return haproxy.Server{}, reader.err
	}
	return server, nil
}

// decodeACL maps one acl object.
//
// The plugin stores an ACL's argument in the TextField named after the
// expression (hdr_beg, path_beg, cust_hdr_beg) rather than in a single
// parameters value; see aclParametersFromExpression.
func decodeACL(object settingsObject) (haproxy.ACL, error) {
	reader := newFieldReader(object.values, object.path)
	expression := reader.enum("expression")
	acl := haproxy.ACL{
		UUID:        object.uuid,
		Name:        reader.str("name"),
		Description: reader.str("description"),
		Expression:  modelACLExpression(expression),
	}
	if reader.err != nil {
		return haproxy.ACL{}, reader.err
	}
	acl.Parameters = aclParametersFromExpression(reader, expression)
	if reader.err != nil {
		return haproxy.ACL{}, reader.err
	}
	return acl, nil
}

// modelACLExpression converts a plugin expression key into the canonical model
// expression. The plugin's cust_hdr* options match a named header with the
// corresponding hdr* expression; the model carries the header name in
// Parameters instead.
func modelACLExpression(expression string) string {
	return strings.TrimPrefix(expression, "cust_")
}

// aclParametersFromExpression rebuilds an ACL's arguments from the plugin's
// per-expression fields. The plugin renders hdr_beg(host) -i example.com for
// the hdr_beg expression, and hdr_beg(X-Header) -i value for cust_hdr_beg with
// cust_hdr_beg_name, so the canonical parameters are "(host) -i example.com"
// and "(X-Header) -i value" respectively.
func aclParametersFromExpression(reader *fieldReader, expression string) string {
	value := reader.str(expression)
	if value == "" {
		return ""
	}
	modifier := ""
	if !reader.boolean("caseSensitive") {
		modifier = "-i "
	}
	if strings.HasPrefix(expression, "cust_hdr") {
		header := reader.str(expression + "_name")
		if header == "" {
			return ""
		}
		return "(" + header + ") " + modifier + value
	}
	switch expression {
	case "hdr", "hdr_beg", "hdr_end", "hdr_reg", "hdr_sub":
		return "(host) " + modifier + value
	case "path_beg", "path", "path_reg", "src", "ssl_fc_sni":
		return modifier + value
	default:
		return ""
	}
}

// objectName reads an object's name, used to build lookup maps before the
// object itself is decoded.
func objectName(object settingsObject) (string, error) {
	reader := newFieldReader(object.values, object.path)
	name := reader.str("name")
	if reader.err != nil {
		return "", reader.err
	}
	return name, nil
}

// decodeAction maps one action object onto a rule. A dangling relation is
// skipped and recorded in dangling rather than failing the read.
func decodeAction(
	object settingsObject,
	aclNames, backendNames, serverNames map[string]string,
	dangling *danglingRefs,
) (haproxy.Rule, error) {
	reader := newFieldReader(object.values, object.path)
	rule := haproxy.Rule{
		UUID:              object.uuid,
		Name:              reader.str("name"),
		Type:              reader.enum("type"),
		TestType:          reader.enum("testType"),
		Operator:          reader.enum("operator"),
		// The plugin serialises this as an OptionField ({"<action>": {"value":..,
		// "selected":0|1}}), not a plain string; reading it with str() rejects
		// every live configuration that carries a use_backend rule.
		HTTPRequestAction: reader.enum("http_request_action"),
		Custom:            reader.str("custom"),
	}

	for _, uuid := range reader.keys("linkedAcls") {
		name, ok := aclNames[uuid]
		if !ok {
			dangling.skip(object, "linkedAcls", uuid)
			continue
		}
		rule.LinkedACLs = append(rule.LinkedACLs, name)
	}
	slices.Sort(rule.LinkedACLs)

	rule.UseBackend = resolveRelation(
		dangling, object, "use_backend", reader.key("use_backend"), backendNames,
	)
	rule.UseServer = resolveRelation(
		dangling, object, "use_server", reader.key("use_server"), serverNames,
	)

	if reader.err != nil {
		return haproxy.Rule{}, reader.err
	}
	return rule, nil
}

// decodeBackend maps one backend object, pulling its servers, rules and health
// check in from the collections they live in. The health check's uuid is not
// retained: the canonical model has no field for it, and the provider matches a
// check by its backend instead.
func decodeBackend(
	object settingsObject,
	servers map[string]haproxy.Server,
	rules map[string]haproxy.Rule,
	healthchecks map[string]settingsObject,
	aclsByName map[string]haproxy.ACL,
	dangling *danglingRefs,
) (haproxy.Backend, error) {
	reader := newFieldReader(object.values, object.path)
	backend := haproxy.Backend{
		UUID:          object.uuid,
		Name:          reader.str("name"),
		Mode:          haproxy.Mode(reader.enum("mode")),
		Algorithm:     reader.enum("algorithm"),
		Sticky:        reader.enum("persistence") == "sticktable",
		CustomOptions: reader.str("customOptions"),
	}

	for _, uuid := range reader.keys("linkedServers") {
		server, ok := servers[uuid]
		if !ok {
			dangling.skip(object, "linkedServers", uuid)
			continue
		}
		backend.Servers = append(backend.Servers, server)
	}
	slices.SortFunc(backend.Servers, func(a, b haproxy.Server) int { return cmp.Compare(a.Name, b.Name) })

	for _, uuid := range reader.keys("linkedActions") {
		rule, ok := rules[uuid]
		if !ok {
			dangling.skip(object, "linkedActions", uuid)
			continue
		}
		backend.Rules = append(backend.Rules, rule)
	}
	slices.SortFunc(backend.Rules, func(a, b haproxy.Rule) int { return cmp.Compare(a.Name, b.Name) })

	backend.ACLs = aclsForRules(backend.Rules, aclsByName)

	if uuid := reader.key("healthCheck"); uuid != "" {
		healthcheck, ok := healthchecks[uuid]
		if !ok {
			dangling.skip(object, "healthCheck", uuid)
		} else {
			decoded, err := decodeHealthCheck(
				healthcheck,
				reader.boolean("healthCheckEnabled"),
				reader.integer("healthCheckFall"),
				reader.integer("healthCheckRise"),
				reader.enum("healthCheckProxyProto") == "enable",
			)
			if err != nil {
				return haproxy.Backend{}, err
			}
			backend.HealthCheck = decoded
		}
	}

	if reader.err != nil {
		return haproxy.Backend{}, reader.err
	}
	return backend, nil
}

// decodeFrontend maps one frontend object, pulling its rules in from the actions
// collection. SSL certificates are recorded by their plugin reference id, which
// is the key of the certificate select.
func decodeFrontend(
	object settingsObject,
	backendNames map[string]string,
	rules map[string]haproxy.Rule,
	aclsByName map[string]haproxy.ACL,
	dangling *danglingRefs,
) (haproxy.Frontend, error) {
	reader := newFieldReader(object.values, object.path)
	frontend := haproxy.Frontend{
		UUID:            object.uuid,
		Name:            reader.str("name"),
		Bind:            reader.keys("bind"),
		Mode:            haproxy.Mode(reader.enum("mode")),
		SSLEnabled:      reader.boolean("ssl_enabled"),
		SSLCertificates: reader.keys("ssl_certificates"),
		SSLDefaultCert:  reader.key("ssl_default_certificate"),
		CustomOptions:   reader.str("customOptions"),
	}

	frontend.DefaultBackend = resolveRelation(
		dangling, object, "defaultBackend", reader.key("defaultBackend"), backendNames,
	)

	for _, uuid := range reader.keys("linkedActions") {
		rule, ok := rules[uuid]
		if !ok {
			dangling.skip(object, "linkedActions", uuid)
			continue
		}
		frontend.Rules = append(frontend.Rules, rule)
	}
	slices.SortFunc(frontend.Rules, func(a, b haproxy.Rule) int { return cmp.Compare(a.Name, b.Name) })

	frontend.ACLs = aclsForRules(frontend.Rules, aclsByName)

	if reader.err != nil {
		return haproxy.Frontend{}, reader.err
	}
	return frontend, nil
}

// decodeHealthCheck maps a referenced healthcheck object, together with the
// per-backend settings that also shape the check.
func decodeHealthCheck(object settingsObject, enabled bool, fall, rise int, proxyProto bool) (*haproxy.HealthCheck, error) {
	reader := newFieldReader(object.values, object.path)
	healthCheck := &haproxy.HealthCheck{
		Enabled:    enabled,
		Type:       reader.enum("type"),
		Path:       reader.str("http_uri"),
		Interval:   reader.integer("interval"),
		Fall:       fall,
		Rise:       rise,
		ProxyProto: proxyProto,
	}
	if reader.err != nil {
		return nil, reader.err
	}
	return healthCheck, nil
}

// aclsForRules collects the ACLs the rules reference, in name order. The plugin
// stores ACLs globally and links them from actions, so a parent's ACL scope is
// the set its rules use.
func aclsForRules(rules []haproxy.Rule, aclsByName map[string]haproxy.ACL) []haproxy.ACL {
	seen := make(map[string]struct{})
	collected := make([]haproxy.ACL, 0)
	for _, rule := range rules {
		for _, name := range rule.LinkedACLs {
			if _, duplicate := seen[name]; duplicate {
				continue
			}
			acl, ok := aclsByName[name]
			if !ok {
				continue
			}
			seen[name] = struct{}{}
			collected = append(collected, acl)
		}
	}
	slices.SortFunc(collected, func(a, b haproxy.ACL) int { return cmp.Compare(a.Name, b.Name) })
	return collected
}

// resolveRelation resolves one uuid-keyed relation to its name. A uuid that the
// collection does not declare is a dangling reference: live configuration can
// acquire one when a foreign object was removed out-of-band, so it is skipped
// and recorded rather than failing the read.
func resolveRelation(
	dangling *danglingRefs,
	object settingsObject,
	field, uuid string,
	names map[string]string,
) string {
	if uuid == "" {
		return ""
	}
	name, ok := names[uuid]
	if !ok {
		dangling.skip(object, field, uuid)
		return ""
	}
	return name
}

// ToServerForm returns the form that creates or updates server, keyed with the
// plugin's server prefix.
//
// The form carries the object's own scalar and enum fields. Linkage is the
// provider's job: a backend's linkedServers relation must be written there
// because the provider merges the identifiers of servers it does not own. The
// model has no administrative enabled flag, so enabled is always posted as set.
//
// checkInterval and checkDownInterval are TextFields the plugin passes to
// HAProxy verbatim, and HAProxy reads a bare number as milliseconds; the form
// therefore always posts them in seconds ("3s").
func ToServerForm(server haproxy.Server) url.Values {
	prefix := objectKinds[kindServer]
	form := url.Values{}
	form.Set(formKey(prefix, "enabled"), formTrue)
	form.Set(formKey(prefix, "name"), server.Name)
	form.Set(formKey(prefix, "address"), server.Address)
	form.Set(formKey(prefix, "port"), integerValue(server.Port))
	form.Set(formKey(prefix, "checkport"), integerValue(server.CheckPort))
	setIfNotEmpty(form, formKey(prefix, "mode"), server.Mode)
	setIfNotEmpty(form, formKey(prefix, "type"), server.Type)
	form.Set(formKey(prefix, "weight"), integerValue(server.Weight))
	form.Set(formKey(prefix, "maxConnections"), integerValue(server.MaxConn))
	form.Set(formKey(prefix, "checkInterval"), durationValue(server.CheckInterval))
	form.Set(formKey(prefix, "checkDownInterval"), durationValue(server.CheckDownInterval))
	form.Set(formKey(prefix, "source"), server.Source)
	return form
}

// ToBackendForm returns the form that creates or updates backend, keyed with the
// plugin's backend prefix.
//
// The form carries the object's own scalar and enum fields. Linkage and the
// health check relation are the provider's job, because they must merge the
// identifiers of objects the reconciler does not own. Persistence is posted as
// sticktable when Sticky is set and cleared otherwise.
func ToBackendForm(backend haproxy.Backend) url.Values {
	prefix := objectKinds[kindBackend]
	form := url.Values{}
	form.Set(formKey(prefix, "enabled"), formTrue)
	form.Set(formKey(prefix, "name"), backend.Name)
	setIfNotEmpty(form, formKey(prefix, "mode"), string(backend.Mode))
	setIfNotEmpty(form, formKey(prefix, "algorithm"), backend.Algorithm)
	persistence := ""
	if backend.Sticky {
		persistence = "sticktable"
	}
	form.Set(formKey(prefix, "persistence"), persistence)
	form.Set(formKey(prefix, "customOptions"), backend.CustomOptions)
	return form
}

// ToFrontendForm returns the form that creates or updates frontend, keyed with
// the plugin's frontend prefix.
//
// The form carries the object's own scalar and enum fields. Linkage is the
// provider's job: defaultBackend and linkedActions must be written there because
// the provider merges the identifiers of objects it does not own. Binds and
// certificates are repeated array fields.
func ToFrontendForm(frontend haproxy.Frontend) url.Values {
	prefix := objectKinds[kindFrontend]
	form := url.Values{}
	form.Set(formKey(prefix, "enabled"), formTrue)
	form.Set(formKey(prefix, "name"), frontend.Name)
	for _, bind := range frontend.Bind {
		form.Add(formListKey(prefix, "bind"), bind)
	}
	setIfNotEmpty(form, formKey(prefix, "mode"), string(frontend.Mode))
	form.Set(formKey(prefix, "ssl_enabled"), booleanValue(frontend.SSLEnabled))
	for _, certificate := range frontend.SSLCertificates {
		form.Add(formListKey(prefix, "ssl_certificates"), certificate)
	}
	form.Set(formKey(prefix, "ssl_default_certificate"), frontend.SSLDefaultCert)
	form.Set(formKey(prefix, "customOptions"), frontend.CustomOptions)
	return form
}

// ToACLForm returns the form that creates or updates acl, keyed with the
// plugin's acl prefix. The form carries the object's own fields; an ACL has no
// enabled flag.
//
// The plugin's ACL model has no "parameters" field: the expression OptionField
// names the fetch and the argument lives in the TextField of the same name
// (HAProxy.xml). A host-header expression is stored under the expression's own
// name; any other header is stored under cust_<expression>, with the header name
// in cust_<expression>_name. caseSensitive carries the "-i" modifier, which
// HAProxy spells as case-insensitivity and the plugin therefore stores inverted.
func ToACLForm(acl haproxy.ACL) url.Values {
	prefix := objectKinds[kindACL]
	form := url.Values{}
	form.Set(formKey(prefix, "name"), acl.Name)
	form.Set(formKey(prefix, "description"), acl.Description)

	target := aclFormTarget(acl)
	form.Set(formKey(prefix, "expression"), target.expression)
	form.Set(formKey(prefix, target.field), target.value)
	if target.header != "" {
		form.Set(formKey(prefix, target.field+"_name"), target.header)
	}
	form.Set(formKey(prefix, "caseSensitive"), booleanValue(target.caseSensitive))
	return form
}

// aclForm is the plugin encoding of one canonical ACL argument.
type aclForm struct {
	// expression is the plugin's expression option key.
	expression string
	// field is the TextField that carries the argument.
	field string
	// value is the argument, without the fetch and modifier.
	value string
	// header is the matched header name, empty for the host header.
	header string
	// caseSensitive inverts the canonical "-i" modifier.
	caseSensitive bool
}

// aclFormTarget maps a canonical ACL onto the plugin's per-expression fields.
// The inverse is aclParametersFromExpression.
func aclFormTarget(acl haproxy.ACL) aclForm {
	fetch, value, caseSensitive := splitACLParameters(acl.Parameters)
	target := aclForm{
		expression:    acl.Expression,
		field:         acl.Expression,
		value:         value,
		caseSensitive: caseSensitive,
	}
	if !strings.HasPrefix(acl.Expression, "hdr") || strings.EqualFold(fetch, "host") {
		return target
	}
	target.expression = "cust_" + acl.Expression
	target.field = target.expression
	target.header = fetch
	return target
}

// splitACLParameters separates the canonical parameters into the optional
// parenthesised fetch argument, the argument itself, and the case sensitivity
// the "-i" modifier implies. HAProxy's -i applies to every pattern, so the
// canonical form carries it directly after the fetch argument.
func splitACLParameters(parameters string) (fetch, value string, caseSensitive bool) {
	rest := strings.TrimSpace(parameters)
	if strings.HasPrefix(rest, "(") {
		if end := strings.IndexByte(rest, ')'); end > 0 {
			fetch = rest[1:end]
			rest = strings.TrimSpace(rest[end+1:])
		}
	}
	caseSensitive = true
	if argument, found := strings.CutPrefix(rest, "-i "); found {
		rest = argument
		caseSensitive = false
	} else if rest == "-i" {
		rest = ""
		caseSensitive = false
	}
	return fetch, strings.TrimSpace(rest), caseSensitive
}

// ToRuleForm returns the form that creates or updates rule, keyed with the
// plugin's action prefix.
//
// The form carries the object's own scalar and enum fields. Linkage is the
// provider's job: linkedAcls, use_backend and use_server must be written there
// because the provider merges the identifiers of objects it does not own.
func ToRuleForm(rule haproxy.Rule) url.Values {
	prefix := objectKinds[kindAction]
	form := url.Values{}
	form.Set(formKey(prefix, "enabled"), formTrue)
	form.Set(formKey(prefix, "name"), rule.Name)
	setIfNotEmpty(form, formKey(prefix, "type"), rule.Type)
	setIfNotEmpty(form, formKey(prefix, "testType"), rule.TestType)
	setIfNotEmpty(form, formKey(prefix, "operator"), rule.Operator)
	form.Set(formKey(prefix, "http_request_action"), rule.HTTPRequestAction)
	form.Set(formKey(prefix, "custom"), rule.Custom)
	return form
}

// formKey renders one form field under an object's prefix.
func formKey(prefix, field string) string {
	return prefix + "[" + field + "]"
}

// formListKey renders the key of a repeated (array-valued) form field.
func formListKey(prefix, field string) string {
	return prefix + "[" + field + "][]"
}

// integerValue renders an optional integer form value; zero clears the field.
func integerValue(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

// durationValue renders a whole number of seconds as the plugin's duration text
// ("3s"); zero clears the field. A bare number would reach HAProxy as
// milliseconds.
func durationValue(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n) + "s"
}

// booleanValue renders a BooleanField value.
func booleanValue(flag bool) string {
	if flag {
		return formTrue
	}
	return formFalse
}

// setIfNotEmpty posts a value only when it is set, so a required enum keeps the
// plugin default instead of receiving an empty value.
func setIfNotEmpty(form url.Values, key, value string) {
	if value != "" {
		form.Set(key, value)
	}
}

// Compile-time assertion that the malformed-payload error satisfies error.
var _ error = (*MalformedSettingsError)(nil)
