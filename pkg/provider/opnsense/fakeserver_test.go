package opnsense

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/yasn77/senselb/pkg/haproxy"
)

// UUIDs used by the fake store beyond the mapper fixture's own.
const (
	uuidFakeForeignAction = "00000000-0000-0000-0000-00000000000f"
	uuidFakeOwnedBackend  = "00000000-0000-0000-0000-0000000000a1"
	uuidFakeOwnedServer   = "00000000-0000-0000-0000-0000000000a2"
)

// fakeObject is one plugin object in the fake store: each field mapped to the
// values a form write posted, or to the keys a seeded select had selected.
type fakeObject map[string][]string

// fakeRequest captures one request the fake server received.
type fakeRequest struct {
	Method        string
	Path          string
	ContentType   string
	Authorization string
	Body          string
}

// fakeServer is an in-memory OPNsense os-haproxy plugin: it renders its store
// in the plugin's settings/get shape, accepts the add/set/del forms, and
// records every request so a test can assert on ordering and bodies.
type fakeServer struct {
	t      *testing.T
	server *httptest.Server

	mu             sync.Mutex
	objects        map[string]map[string]fakeObject // collection -> uuid -> object
	recorded       []fakeRequest
	failConfigTest bool
	configTests    int
	reconfigures   int
	nextUUID       int
}

// newFakeServer starts a fake plugin and returns its API base URL, which
// already includes the /api/haproxy path.
func newFakeServer(t *testing.T) (string, *fakeServer) {
	t.Helper()

	fake := &fakeServer{
		t:       t,
		objects: make(map[string]map[string]fakeObject),
	}
	for _, kind := range []string{kindFrontend, kindBackend, kindServer, kindACL, kindAction, kindHealthcheck} {
		fake.objects[fakeCollection(kind)] = make(map[string]fakeObject)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/haproxy/settings/get", fake.handleGet)
	mux.HandleFunc("POST /api/haproxy/settings/{action}", fake.handleWrite)
	mux.HandleFunc("POST /api/haproxy/settings/{action}/{uuid}", fake.handleWrite)
	mux.HandleFunc("POST /api/haproxy/service/configtest", fake.handleConfigTest)
	mux.HandleFunc("POST /api/haproxy/service/reconfigure", fake.handleReconfigure)

	fake.server = httptest.NewServer(fake.recorder(mux))
	t.Cleanup(fake.server.Close)
	return fake.server.URL + "/api/haproxy", fake
}

// recorder records each request before the mux handles it, restoring the body
// so the handler can parse it.
func (s *fakeServer) recorder(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			s.t.Errorf("read request body: %v", err)
		}
		s.mu.Lock()
		s.recorded = append(s.recorded, fakeRequest{
			Method:        r.Method,
			Path:          r.URL.Path,
			ContentType:   r.Header.Get("Content-Type"),
			Authorization: r.Header.Get("Authorization"),
			Body:          string(body),
		})
		s.mu.Unlock()

		r.Body = io.NopCloser(strings.NewReader(string(body)))
		next.ServeHTTP(w, r)
	})
}

// handleGet renders the store as the plugin's settings/get payload.
func (s *fakeServer) handleGet(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	payload := map[string]any{"haproxy": s.renderLocked()}
	s.mu.Unlock()
	writeJSONValue(w, http.StatusOK, payload)
}

// handleWrite implements add/set/del: it parses the form, mutates the store and
// answers with the plugin's result envelope.
func (s *fakeServer) handleWrite(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	uuid := r.PathValue("uuid")

	verb, kind := splitWriteAction(action)
	prefix, err := formPrefix(kind)
	if err != nil {
		s.t.Errorf("write %s: %v", r.URL.Path, err)
		http.Error(w, "unknown object kind", http.StatusBadRequest)
		return
	}
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		s.t.Errorf("write %s: Content-Type = %q, want form encoding", r.URL.Path, r.Header.Get("Content-Type"))
	}
	if err := r.ParseForm(); err != nil {
		s.t.Errorf("write %s: parse form: %v", r.URL.Path, err)
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}

	switch verb {
	case "del":
		existed, err := s.deleteObject(kind, uuid)
		if errors.Is(err, errItemInUse) {
			// The plugin's safe-delete raises a user exception, which the
			// framework renders as an HTTP 500 rather than a result envelope.
			http.Error(w, "Item in use by: "+uuid, http.StatusInternalServerError)
			return
		}
		if !existed {
			writeJSONValue(w, http.StatusOK, map[string]string{"result": resultNotFound})
			return
		}
		writeJSONValue(w, http.StatusOK, map[string]string{"result": resultDeleted})
	case "add":
		object, err := formObject(prefix, r.PostForm)
		if err != nil {
			s.t.Errorf("write %s: %v", r.URL.Path, err)
			http.Error(w, "malformed form", http.StatusBadRequest)
			return
		}
		uuid = s.addObject(kind, object)
		writeJSONValue(w, http.StatusOK, map[string]string{"result": resultSaved, "uuid": uuid})
	case "set":
		if uuid == "" {
			s.t.Errorf("write %s: set without a uuid", r.URL.Path)
			http.Error(w, "missing uuid", http.StatusBadRequest)
			return
		}
		object, err := formObject(prefix, r.PostForm)
		if err != nil {
			s.t.Errorf("write %s: %v", r.URL.Path, err)
			http.Error(w, "malformed form", http.StatusBadRequest)
			return
		}
		// The plugin rebuilds the object from the submitted form, so a Set
		// replaces the stored object rather than merging into it.
		s.putObject(kind, uuid, object)
		writeJSONValue(w, http.StatusOK, map[string]string{"result": resultSaved, "uuid": uuid})
	default:
		s.t.Errorf("write %s: unknown action %q", r.URL.Path, action)
		http.Error(w, "unknown action", http.StatusBadRequest)
	}
}

// splitWriteAction splits "setFrontend" into its verb and object kind.
func splitWriteAction(action string) (string, string) {
	for _, verb := range []string{"add", "set", "del"} {
		if strings.HasPrefix(action, verb) {
			return verb, strings.TrimPrefix(action, verb)
		}
	}
	return "", ""
}

// formObject converts a posted form into the object to store.
func formObject(prefix string, form url.Values) (fakeObject, error) {
	object := fakeObject{}
	for key, values := range form {
		field, err := formField(prefix, key)
		if err != nil {
			return nil, err
		}
		// The plugin stores a CSV-valued field (bind, the linked* relations) as
		// a list, even though it takes the value as one comma-separated string.
		if csvFormFields[field] && len(values) == 1 {
			object[field] = splitCSV(values[0])
			continue
		}
		object[field] = slices.Clone(values)
	}
	return object, nil
}

// splitCSV mirrors the plugin's storage of a CSV-valued field: an empty value
// clears the field.
func splitCSV(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

// formField strips a "prefix[field]" or "prefix[field][]" form key down to the
// bare field name.
func formField(prefix, key string) (string, error) {
	open := strings.IndexByte(key, '[')
	if open < 0 || !strings.HasSuffix(key, "]") || key[:open] != prefix {
		return "", fmt.Errorf("form key %q does not belong to the %s[...] family", key, prefix)
	}
	field := strings.TrimSuffix(key[open+1:], "[]")
	field = strings.TrimSuffix(field, "]")
	return field, nil
}

// handleConfigTest reports the configured outcome and counts the call.
func (s *fakeServer) handleConfigTest(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.configTests++
	failure := s.failConfigTest
	s.mu.Unlock()

	result := "Configuration file is valid"
	if failure {
		result = "Fatal errors found in configuration"
	}
	writeJSONValue(w, http.StatusOK, map[string]string{"result": result})
}

// handleReconfigure counts the reload.
func (s *fakeServer) handleReconfigure(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.reconfigures++
	s.mu.Unlock()
	writeJSONValue(w, http.StatusOK, map[string]string{"result": "ok"})
}

// renderLocked renders the store in the plugin's settings/get shape. The
// caller holds the lock.
func (s *fakeServer) renderLocked() map[string]any {
	root := map[string]any{
		"general": map[string]any{"enabled": formTrue},
	}
	for _, kind := range []string{kindFrontend, kindBackend, kindServer, kindACL, kindAction, kindHealthcheck} {
		prefix, err := formPrefix(kind)
		if err != nil {
			continue
		}
		objects := map[string]any{}
		for uuid, object := range s.objects[fakeCollection(kind)] {
			objects[uuid] = s.renderObjectLocked(object)
		}
		root[prefix+"s"] = map[string]any{prefix: objects}
	}
	return root
}

// renderObjectLocked renders one object with enum and relation fields encoded
// as the plugin's select objects.
func (s *fakeServer) renderObjectLocked(object fakeObject) map[string]any {
	rendered := make(map[string]any, len(object))
	for field, values := range object {
		switch {
		case fakeListFields[field]:
			selects := make(map[string]any, len(values))
			for _, value := range values {
				if value == "" {
					continue
				}
				selects[value] = map[string]any{
					"value":    s.displayValueLocked(field, value),
					"selected": 1,
				}
			}
			rendered[field] = selects
		case fakeScalarSelectFields[field]:
			value := ""
			if len(values) > 0 {
				value = values[0]
			}
			if value == "" {
				rendered[field] = map[string]any{"": map[string]any{"value": "", "selected": 0}}
				continue
			}
			rendered[field] = map[string]any{
				value: map[string]any{"value": s.displayValueLocked(field, value), "selected": 1},
			}
		default:
			if len(values) == 1 {
				rendered[field] = values[0]
				continue
			}
			rendered[field] = slices.Clone(values)
		}
	}
	return rendered
}

// displayValueLocked renders a relation's display label, which is the
// referenced object's name.
func (s *fakeServer) displayValueLocked(field, value string) string {
	kind := relationKind(field)
	if kind == "" {
		return value
	}
	object, found := s.objectLocked(kind, value)
	if !found {
		return value
	}
	if names := object["name"]; len(names) > 0 {
		return names[0]
	}
	return value
}

// fakeListFields are the fields the plugin renders as a multi-select.
var fakeListFields = map[string]bool{
	"bind":             true,
	"ssl_certificates": true,
	"linkedActions":    true,
	"linkedAcls":       true,
	"linkedServers":    true,
	"linkedErrorfiles": true,
}

// fakeScalarSelectFields are the fields the plugin renders as a single-select:
// enums and one-to-one relations.
var fakeScalarSelectFields = map[string]bool{
	"mode":                    true,
	"algorithm":               true,
	"type":                    true,
	"expression":              true,
	"testType":                true,
	"operator":                true,
	"persistence":             true,
	"healthCheckProxyProto":   true,
	"defaultBackend":          true,
	"use_backend":             true,
	"use_server":              true,
	"healthCheck":             true,
	"ssl_default_certificate": true,
}

// relationKind names the object kind a relation field points at, or "" when the
// field is not a relation.
func relationKind(field string) string {
	switch field {
	case "linkedActions":
		return kindAction
	case "linkedAcls":
		return kindACL
	case "linkedServers", "use_server":
		return kindServer
	case "defaultBackend", "use_backend":
		return kindBackend
	case "healthCheck":
		return kindHealthcheck
	default:
		return ""
	}
}

// addObject stores an object under a server-assigned uuid and returns it.
func (s *fakeServer) addObject(kind string, object fakeObject) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextUUID++
	uuid := fmt.Sprintf("00000000-0000-0000-0000-%012d", s.nextUUID)
	s.objects[fakeCollection(kind)][uuid] = object
	return uuid
}

// putObject replaces an object.
func (s *fakeServer) putObject(kind, uuid string, object fakeObject) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[fakeCollection(kind)][uuid] = object
}

// errItemInUse reports the plugin's safe-delete refusal.
var errItemInUse = errors.New("item in use by")

// deleteObject removes an object, reporting whether it existed. It mirrors the
// plugin's safe-delete ($internalModelUseSafeDelete is enabled in
// Api/SettingsController.php): a uuid any other stored object still references
// is refused.
func (s *fakeServer) deleteObject(kind, uuid string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	target := fakeCollection(kind)
	if _, found := s.objects[target][uuid]; !found {
		return false, nil
	}
	if s.referencedLocked(uuid) {
		return true, errItemInUse
	}
	delete(s.objects[target], uuid)
	return true, nil
}

// referencedLocked reports whether any stored object holds uuid as a field
// value. The caller holds the lock.
func (s *fakeServer) referencedLocked(uuid string) bool {
	for _, objects := range s.objects {
		for _, object := range objects {
			for _, values := range object {
				if slices.Contains(values, uuid) {
					return true
				}
			}
		}
	}
	return false
}

// objectLocked returns a copy of one stored object; the caller holds the lock.
func (s *fakeServer) objectLocked(kind, uuid string) (fakeObject, bool) {
	object, found := s.objects[fakeCollection(kind)][uuid]
	return object, found
}

// fakeCollection maps an object kind onto its collection name.
func fakeCollection(kind string) string {
	prefix, err := formPrefix(kind)
	if err != nil {
		return ""
	}
	return prefix + "s"
}

// writeJSONValue writes one JSON response.
func writeJSONValue(w http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	//nolint:gosec // body is a test response, never external input.
	_, _ = w.Write(body)
}

// ---- test helpers -------------------------------------------------------

// seedFixture loads the representative foreign live configuration the mapper
// tests use.
func (s *fakeServer) seedFixture() {
	s.t.Helper()
	s.seedSettings(decodeFixtureSettings(s.t))
}

// seedAdoptionFixture loads the fixture plus a foreign action linked from
// ingress-HTTPS, the shape an adopted listener meets in the field.
func (s *fakeServer) seedAdoptionFixture() {
	s.t.Helper()
	s.seedFixture()
	s.put(kindAction, uuidFakeForeignAction, fakeObject{
		"name":                {"legacy_redirect"},
		"description":         {""},
		"enabled":             {formTrue},
		"type":                {haproxy.RuleTypeHTTPRequest},
		"testType":            {haproxy.RuleTestTypeIf},
		"operator":            {haproxy.RuleOperatorAnd},
		"http_request_action": {"set-header X-Legacy yes"},
		"custom":              {""},
	})
	s.appendField(kindFrontend, uuidFrontendHTTPS, "linkedActions", uuidFakeForeignAction)
}

// seedOwnedBackend stores a backend senselb already owns, for update and
// rollback tests.
func (s *fakeServer) seedOwnedBackend(name, uuid string) {
	s.t.Helper()
	s.put(kindBackend, uuid, fakeObject{
		"name":               {name},
		"description":        {OwnedDescription},
		"enabled":            {formTrue},
		"mode":               {"http"},
		"algorithm":          {"roundrobin"},
		"linkedServers":      nil,
		"linkedActions":      nil,
		"healthCheckEnabled": {"0"},
		"healthCheck":        nil,
		"persistence":        {""},
		"customOptions":      {"option forwardfor"},
	})
}

// seedOwnedServer stores a server senselb already owns and links it from a
// backend.
func (s *fakeServer) seedOwnedServer(backendName, name, uuid string) {
	s.t.Helper()

	s.put(kindServer, uuid, fakeObject{
		"name":              {name},
		"description":       {OwnedDescription},
		"enabled":           {formTrue},
		"address":           {"10.0.0.1"},
		"port":              {"30080"},
		"checkport":         {""},
		"mode":              {"active"},
		"type":              {"static"},
		"weight":            {"0"},
		"maxConnections":    {"0"},
		"checkInterval":     {""},
		"checkDownInterval": {""},
		"source":            {""},
	})
	backendUUID, _, found := s.findObject(kindBackend, backendName)
	if !found {
		s.t.Fatalf("seed owned server: no backend %q", backendName)
	}
	s.appendField(kindBackend, backendUUID, "linkedServers", uuid)
}

// seedSettings copies a decoded settings payload into the store.
func (s *fakeServer) seedSettings(settings Settings) {
	s.t.Helper()

	root, err := rootObject(settings)
	if err != nil {
		s.t.Fatalf("seed settings: %v", err)
	}
	for _, kind := range []string{kindFrontend, kindBackend, kindServer, kindACL, kindAction, kindHealthcheck} {
		prefix, err := formPrefix(kind)
		if err != nil {
			continue
		}
		container, _ := asObjectMap(root[prefix+"s"])
		objects, _ := asObjectMap(container[prefix])
		for uuid, raw := range objects {
			values, ok := raw.(map[string]any)
			if !ok {
				s.t.Fatalf("seed settings: %s object %s is %T", kind, uuid, raw)
			}
			s.putObject(kind, uuid, fakeObjectFromValues(values))
		}
	}
}

// fakeObjectFromValues flattens one plugin object into the store shape.
func fakeObjectFromValues(values map[string]any) fakeObject {
	object := make(fakeObject, len(values))
	for field, raw := range values {
		switch value := raw.(type) {
		case string:
			object[field] = []string{value}
		case bool:
			object[field] = []string{booleanValue(value)}
		case float64:
			object[field] = []string{strconv.FormatFloat(value, 'f', -1, 64)}
		case map[string]any:
			keys, err := selectedKeys(value)
			if err != nil {
				object[field] = nil
				continue
			}
			object[field] = keys
		default:
			object[field] = nil
		}
	}
	return object
}

// put stores an object verbatim.
func (s *fakeServer) put(kind, uuid string, object fakeObject) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[fakeCollection(kind)][uuid] = object
}

// appendField appends values to one stored field.
func (s *fakeServer) appendField(kind, uuid, field string, values ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	object, found := s.objects[fakeCollection(kind)][uuid]
	if !found {
		s.t.Fatalf("append field: no %s object %s", kind, uuid)
	}
	object[field] = append(object[field], values...)
}

// object returns a copy of one stored object.
func (s *fakeServer) object(kind, uuid string) (fakeObject, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	object, found := s.objectLocked(kind, uuid)
	if !found {
		return nil, false
	}
	return cloneFakeObject(object), true
}

// findObject returns the uuid and a copy of the object with the given name.
func (s *fakeServer) findObject(kind, name string) (string, fakeObject, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	objects := s.objects[fakeCollection(kind)]
	uuids := make([]string, 0, len(objects))
	for uuid := range objects {
		uuids = append(uuids, uuid)
	}
	slices.Sort(uuids)
	for _, uuid := range uuids {
		if names := objects[uuid]["name"]; len(names) > 0 && names[0] == name {
			return uuid, cloneFakeObject(objects[uuid]), true
		}
	}
	return "", nil, false
}

// cloneFakeObject copies an object so a test cannot mutate the store.
func cloneFakeObject(object fakeObject) fakeObject {
	clone := make(fakeObject, len(object))
	for field, values := range object {
		clone[field] = slices.Clone(values)
	}
	return clone
}

// setConfigTestFailure makes the next configtest fail or succeed.
func (s *fakeServer) setConfigTestFailure(fail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failConfigTest = fail
}

// counters returns the configtest and reconfigure call counts.
func (s *fakeServer) counters() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.configTests, s.reconfigures
}

// requests returns a copy of every recorded request.
func (s *fakeServer) requests() []fakeRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.recorded)
}

// writeRequests returns the recorded settings mutations.
func (s *fakeServer) writeRequests() []fakeRequest {
	var writes []fakeRequest
	for _, request := range s.requests() {
		if strings.HasPrefix(request.Path, "/api/haproxy/settings/") && request.Method == http.MethodPost {
			writes = append(writes, request)
		}
	}
	return writes
}
