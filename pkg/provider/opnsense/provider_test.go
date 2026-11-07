package opnsense

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yasn77/senselb/pkg/haproxy"
	"github.com/yasn77/senselb/pkg/provider"
)

// newTestProvider returns a provider pointed at a fresh fake plugin.
func newTestProvider(t *testing.T) (*Provider, *fakeServer) {
	t.Helper()

	baseURL, fake := newFakeServer(t)
	prov, err := New(ClientConfig{
		URL:     baseURL,
		Key:     testKey,
		Secret:  testSecret,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return prov, fake
}

// TestProviderGetRoundTrip proves Get maps a live configuration onto the
// canonical model with the plugin's UUIDs attached.
func TestProviderGetRoundTrip(t *testing.T) {
	t.Parallel()

	prov, fake := newTestProvider(t)
	fake.seedFixture()

	model, err := prov.Get()
	if err != nil {
		t.Fatalf("Get(): %v", err)
	}

	frontend := findFrontend(t, model, "ingress-HTTPS")
	if frontend.UUID != uuidFrontendHTTPS {
		t.Errorf("frontend uuid = %q, want %q", frontend.UUID, uuidFrontendHTTPS)
	}
	if !slices.Equal(frontend.Bind, []string{"0.0.0.0:443"}) {
		t.Errorf("frontend bind = %v, want [0.0.0.0:443]", frontend.Bind)
	}

	backend := findBackend(t, model, "k8s-ingress-HTTP")
	if backend.UUID != uuidBackendHTTP {
		t.Errorf("backend uuid = %q, want %q", backend.UUID, uuidBackendHTTP)
	}
	if len(backend.Servers) != 1 || backend.Servers[0].Name != "k8s_HTTP" {
		t.Fatalf("backend servers = %+v, want k8s_HTTP", backend.Servers)
	}

	acme := findFrontend(t, model, "HTTP")
	if len(acme.Rules) != 1 || acme.Rules[0].UUID != uuidActionACME {
		t.Fatalf("frontend HTTP rules = %+v, want the ACME action", acme.Rules)
	}
}

// TestApplyWritesFormEncodedWithSingularPrefix pins assertion (a): every write
// is form-encoded and every field carries the object's singular prefix.
func TestApplyWritesFormEncodedWithSingularPrefix(t *testing.T) {
	t.Parallel()

	prov, fake := newTestProvider(t)
	fake.seedFixture()

	plan := haproxy.Plan{Ordered: true, Operations: []haproxy.Operation{
		{
			Kind:   haproxy.OpCreate,
			Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectBackend, Name: "senselb-app"},
			Object: haproxy.NewBackend("senselb-app", haproxy.ModeHTTP),
		},
		{
			Kind:   haproxy.OpCreate,
			Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectServer, Parent: "senselb-app", Name: "senselb-app-1"},
			Object: haproxy.NewServer("senselb-app-1", "10.0.0.1", 30080),
		},
	}}
	if err := prov.Apply(plan); err != nil {
		t.Fatalf("Apply(): %v", err)
	}

	writes := fake.writeRequests()
	if len(writes) == 0 {
		t.Fatal("no write request recorded")
	}
	for _, request := range writes {
		if request.ContentType != "application/x-www-form-urlencoded" {
			t.Errorf("%s Content-Type = %q, want form encoding", request.Path, request.ContentType)
		}
		if request.Authorization != expectedBasicAuth() {
			t.Errorf("%s Authorization = %q, want the Basic credentials", request.Path, request.Authorization)
		}
		form, err := url.ParseQuery(request.Body)
		if err != nil {
			t.Fatalf("ParseQuery(%q): %v", request.Body, err)
		}
		if len(form) == 0 {
			t.Errorf("%s carries an empty form", request.Path)
		}
		prefix := writeKindPrefix(request.Path)
		if prefix == "" {
			t.Fatalf("%s names no object kind", request.Path)
		}
		for key := range form {
			if !strings.HasPrefix(key, prefix+"[") {
				t.Errorf("%s field %q does not use the %s[...] prefix", request.Path, key, prefix)
			}
		}
	}
}

// TestApplyCreateUpsertsClientChosenUUID pins assertion (b): a create posts a
// Set on a UUID the provider chose, and the plugin's upsert creates it.
func TestApplyCreateUpsertsClientChosenUUID(t *testing.T) {
	t.Parallel()

	prov, fake := newTestProvider(t)
	fake.seedFixture()

	const chosen = "00000000-0000-0000-0000-0000000000fe"
	backend := haproxy.NewBackend("senselb-app", haproxy.ModeHTTP)
	backend.UUID = chosen

	plan := haproxy.Plan{Ordered: true, Operations: []haproxy.Operation{{
		Kind:   haproxy.OpCreate,
		Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectBackend, Name: "senselb-app"},
		Object: backend,
	}}}
	if err := prov.Apply(plan); err != nil {
		t.Fatalf("Apply(): %v", err)
	}

	if _, found := fake.object(kindBackend, chosen); !found {
		t.Fatalf("backend %s was not upserted into the store", chosen)
	}
	paths := make([]string, 0, len(fake.writeRequests()))
	for _, request := range fake.writeRequests() {
		paths = append(paths, request.Path)
	}
	want := "/api/haproxy/settings/setBackend/" + chosen
	if !slices.Contains(paths, want) {
		t.Fatalf("recorded writes = %v, want %s", paths, want)
	}
	if _, _, found := fake.findObject(kindBackend, "senselb-app"); !found {
		t.Fatal("the created backend does not render back by name")
	}
}

// TestApplyConfigTestPrecedesReconfigure pins assertion (c): the batch writes,
// then runs exactly one configtest, then exactly one reconfigure.
func TestApplyConfigTestPrecedesReconfigure(t *testing.T) {
	t.Parallel()

	prov, fake := newTestProvider(t)
	fake.seedFixture()

	plan := haproxy.Plan{Ordered: true, Operations: []haproxy.Operation{
		{
			Kind:   haproxy.OpCreate,
			Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectBackend, Name: "senselb-app"},
			Object: haproxy.NewBackend("senselb-app", haproxy.ModeHTTP),
		},
		{
			Kind:   haproxy.OpCreate,
			Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectServer, Parent: "senselb-app", Name: "senselb-app-1"},
			Object: haproxy.NewServer("senselb-app-1", "10.0.0.1", 30080),
		},
	}}
	if err := prov.Apply(plan); err != nil {
		t.Fatalf("Apply(): %v", err)
	}

	lastWrite, configTest, reconfigure := -1, -1, -1
	for i, request := range fake.requests() {
		switch {
		case request.Path == "/api/haproxy/service/configtest":
			configTest = i
		case request.Path == "/api/haproxy/service/reconfigure":
			reconfigure = i
		case request.Method == http.MethodPost && strings.HasPrefix(request.Path, "/api/haproxy/settings/"):
			lastWrite = i
		}
	}
	if lastWrite < 0 || configTest < 0 || reconfigure < 0 {
		t.Fatalf("sequence incomplete: lastWrite=%d configtest=%d reconfigure=%d", lastWrite, configTest, reconfigure)
	}
	if lastWrite >= configTest || configTest >= reconfigure {
		t.Fatalf("order = write@%d, configtest@%d, reconfigure@%d; want write < configtest < reconfigure",
			lastWrite, configTest, reconfigure)
	}
	if tests, reloads := fake.counters(); tests != 1 || reloads != 1 {
		t.Fatalf("configtest/reconfigure calls = %d/%d, want 1/1", tests, reloads)
	}
}

// TestApplyRollsBackOnConfigTestFailure pins assertion (d): a failed configtest
// restores the snapshot, including the adopted frontend's foreign rules, and
// returns a typed error.
func TestApplyRollsBackOnConfigTestFailure(t *testing.T) {
	t.Parallel()

	prov, fake := newTestProvider(t)
	fake.seedAdoptionFixture()
	fake.seedOwnedBackend("senselb-app", uuidFakeOwnedBackend)
	fake.setConfigTestFailure(true)

	updated := haproxy.NewBackend("senselb-app", haproxy.ModeHTTP)
	updated.CustomOptions = "option httpclose"

	rule := haproxy.NewRule("senselb-rule", haproxy.RuleTypeHTTPRequest)
	rule.HTTPRequestAction = "set-header X-Senselb yes"

	plan := haproxy.Plan{Ordered: true, Operations: []haproxy.Operation{
		{
			Kind:   haproxy.OpCreate,
			Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectRule, Parent: "ingress-HTTPS", Name: "senselb-rule"},
			Object: rule,
		},
		{
			Kind:   haproxy.OpCreate,
			Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectServer, Parent: "senselb-app", Name: "senselb-app-1"},
			Object: haproxy.NewServer("senselb-app-1", "10.0.0.1", 30080),
		},
		{
			Kind:   haproxy.OpUpdate,
			Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectBackend, Name: "senselb-app"},
			Object: updated,
		},
	}}

	err := prov.Apply(plan)
	var configErr *provider.ErrConfigTest
	if !errors.As(err, &configErr) {
		t.Fatalf("Apply() = %v, want *provider.ErrConfigTest", err)
	}
	for _, credential := range []string{testKey, testSecret} {
		if strings.Contains(err.Error(), credential) {
			t.Fatalf("Apply() error discloses credential %q", credential)
		}
	}

	if _, _, found := fake.findObject(kindAction, "senselb-rule"); found {
		t.Error("created action survived the rollback")
	}
	if _, _, found := fake.findObject(kindServer, "senselb-app-1"); found {
		t.Error("created server survived the rollback")
	}

	_, backend, found := fake.findObject(kindBackend, "senselb-app")
	if !found {
		t.Fatal("the pre-existing owned backend was deleted")
	}
	if got := firstValue(backend["customOptions"]); got != "option forwardfor" {
		t.Errorf("backend customOptions = %q, want the snapshot value", got)
	}
	if got := backend["linkedServers"]; len(got) != 0 {
		t.Errorf("backend linkedServers = %v, want the snapshot value (empty)", got)
	}

	_, frontend, found := fake.findObject(kindFrontend, "ingress-HTTPS")
	if !found {
		t.Fatal("the adopted frontend was deleted")
	}
	if got := frontend["linkedActions"]; !slices.Equal(got, []string{uuidFakeForeignAction}) {
		t.Errorf("adopted frontend linkedActions = %v, want only the foreign action", got)
	}
	if got := frontend["bind"]; !slices.Equal(got, []string{"0.0.0.0:443"}) {
		t.Errorf("adopted frontend bind = %v, want the untouched live value", got)
	}
}

// TestApplyRejectsForeignTargets pins assertion (e): a plan step that would
// mutate or delete a foreign object fails before any write.
func TestApplyRejectsForeignTargets(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		op   haproxy.Operation
		ref  string
	}{
		{
			name: "update an adopted frontend",
			op: haproxy.Operation{
				Kind:   haproxy.OpUpdate,
				Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectFrontend, Name: "ingress-HTTPS"},
				Object: haproxy.NewFrontend("ingress-HTTPS", haproxy.ModeHTTP, "0.0.0.0:443"),
			},
			ref: "frontend ingress-HTTPS",
		},
		{
			name: "delete a foreign backend",
			op: haproxy.Operation{
				Kind: haproxy.OpDelete,
				Ref:  haproxy.ObjectRef{Kind: haproxy.ObjectBackend, Name: "k8s-ingress-HTTPS"},
			},
			ref: "backend k8s-ingress-HTTPS",
		},
		{
			name: "create an unowned name",
			op: haproxy.Operation{
				Kind:   haproxy.OpCreate,
				Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectBackend, Name: "k8s-app"},
				Object: haproxy.NewBackend("k8s-app", haproxy.ModeHTTP),
			},
			ref: "backend k8s-app",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prov, fake := newTestProvider(t)
			fake.seedFixture()

			err := prov.Apply(haproxy.Plan{Ordered: true, Operations: []haproxy.Operation{tt.op}})
			var conflict *provider.ErrOwnershipConflict
			if !errors.As(err, &conflict) {
				t.Fatalf("Apply() = %v, want *provider.ErrOwnershipConflict", err)
			}
			if !slices.Contains(conflict.Refs, tt.ref) {
				t.Errorf("Refs = %v, want %q", conflict.Refs, tt.ref)
			}
			if writes := fake.writeRequests(); len(writes) != 0 {
				t.Errorf("writes = %d, want none on an ownership conflict", len(writes))
			}
			if tests, reloads := fake.counters(); tests != 0 || reloads != 0 {
				t.Errorf("configtest/reconfigure calls = %d/%d, want 0/0", tests, reloads)
			}
		})
	}
}

// TestApplyRejectsCreateNameCollision covers the name-collision gate: a live
// object of the same kind already holding the create's name conflicts even when
// its description is foreign and the name carries the senselb prefix.
func TestApplyRejectsCreateNameCollision(t *testing.T) {
	t.Parallel()

	prov, fake := newTestProvider(t)
	fake.seedFixture()
	fake.put(kindFrontend, "00000000-0000-0000-0000-0000000000f0", fakeObject{
		"name":        {"senselb-web-prod-80"},
		"description": {"owned by hand"},
		"enabled":     {formTrue},
		"bind":        {"0.0.0.0:80"},
		"mode":        {"http"},
	})

	plan := haproxy.Plan{Ordered: true, Operations: []haproxy.Operation{{
		Kind:   haproxy.OpCreate,
		Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectFrontend, Name: "senselb-web-prod-80"},
		Object: haproxy.NewFrontend("senselb-web-prod-80", haproxy.ModeHTTP, "0.0.0.0:8099"),
	}}}

	err := prov.Apply(plan)
	var conflict *provider.ErrOwnershipConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("Apply() = %v, want *provider.ErrOwnershipConflict", err)
	}
	if !slices.Contains(conflict.Refs, "frontend senselb-web-prod-80") {
		t.Errorf("Refs = %v, want the colliding frontend", conflict.Refs)
	}
	if writes := fake.writeRequests(); len(writes) != 0 {
		t.Errorf("writes = %d, want none on a name collision", len(writes))
	}
	if tests, reloads := fake.counters(); tests != 0 || reloads != 0 {
		t.Errorf("configtest/reconfigure calls = %d/%d, want 0/0", tests, reloads)
	}
}

// TestApplyDeletesServerAfterUnlink pins the safe-delete ordering: the plugin
// refuses to delete a uuid another object still references, so the backend is
// rewritten before the server delete is issued.
func TestApplyDeletesServerAfterUnlink(t *testing.T) {
	t.Parallel()

	prov, fake := newTestProvider(t)
	fake.seedFixture()
	fake.seedOwnedBackend("senselb-app", uuidFakeOwnedBackend)
	fake.seedOwnedServer("senselb-app", "senselb-app-1", uuidFakeOwnedServer)

	plan := haproxy.Plan{Ordered: true, Operations: []haproxy.Operation{{
		Kind: haproxy.OpDelete,
		Ref:  haproxy.ObjectRef{Kind: haproxy.ObjectServer, Parent: "senselb-app", Name: "senselb-app-1"},
	}}}
	if err := prov.Apply(plan); err != nil {
		t.Fatalf("Apply(): %v", err)
	}

	unlink, del := -1, -1
	for i, request := range fake.writeRequests() {
		switch request.Path {
		case "/api/haproxy/settings/setBackend/" + uuidFakeOwnedBackend:
			unlink = i
		case "/api/haproxy/settings/delServer/" + uuidFakeOwnedServer:
			del = i
		}
	}
	if unlink < 0 || del < 0 {
		t.Fatalf("sequence incomplete: unlink=%d delete=%d", unlink, del)
	}
	if unlink >= del {
		t.Errorf("order = unlink@%d, delete@%d; want the unlink first", unlink, del)
	}
}

// TestFormFromSettingsRepeatsMultiSelects covers rollback fidelity: a stored
// multi-select with more than one selected key must survive as repeated
// field[] entries, not collapse to the first.
func TestFormFromSettingsRepeatsMultiSelects(t *testing.T) {
	t.Parallel()

	settings := minimalSettings()
	collection(t, settings, "frontends", "frontend")[uuidFrontendHTTPS] = map[string]any{
		"name":        "ingress-HTTPS",
		"description": "",
		"enabled":     formTrue,
		"bind":        map[string]any{"0.0.0.0:443": map[string]any{"value": "0.0.0.0:443", "selected": float64(1)}},
		"mode":        map[string]any{"http": map[string]any{"value": "HTTP", "selected": float64(1)}},
		"linkedErrorfiles": map[string]any{
			"00000000-0000-0000-0000-0000000000e1": map[string]any{"value": "errors-1", "selected": float64(1)},
			"00000000-0000-0000-0000-0000000000e2": map[string]any{"value": "errors-2", "selected": float64(1)},
			"00000000-0000-0000-0000-0000000000e3": map[string]any{"value": "errors-3", "selected": float64(0)},
		},
	}

	form, found := formFromSettings(settings, kindFrontend, uuidFrontendHTTPS)
	if !found {
		t.Fatal("formFromSettings: frontend not found")
	}
	want := []string{"00000000-0000-0000-0000-0000000000e1", "00000000-0000-0000-0000-0000000000e2"}
	if got := form["frontend[linkedErrorfiles][]"]; !slices.Equal(got, want) {
		t.Errorf("linkedErrorfiles = %v, want %v", got, want)
	}
	if got := form.Get("frontend[mode]"); got != "http" {
		t.Errorf("mode = %q, want the single-value form", got)
	}
	if form.Has("frontend[mode][]") {
		t.Error("mode is a scalar select but was posted as a repeated field")
	}
}

// TestApplyAdoptionUnion pins assertion (f): adding an owned action to an
// adopted frontend keeps the foreign action and places the owned UUID first.
func TestApplyAdoptionUnion(t *testing.T) {
	t.Parallel()

	prov, fake := newTestProvider(t)
	fake.seedAdoptionFixture()

	rule := haproxy.NewRule("senselb-rule", haproxy.RuleTypeHTTPRequest)
	rule.HTTPRequestAction = "set-header X-Senselb yes"

	plan := haproxy.Plan{Ordered: true, Operations: []haproxy.Operation{{
		Kind:   haproxy.OpCreate,
		Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectRule, Parent: "ingress-HTTPS", Name: "senselb-rule"},
		Object: rule,
	}}}
	if err := prov.Apply(plan); err != nil {
		t.Fatalf("Apply(): %v", err)
	}

	ownedUUID, _, found := fake.findObject(kindAction, "senselb-rule")
	if !found {
		t.Fatal("the created action is missing from the store")
	}

	var relationForm url.Values
	for _, request := range fake.writeRequests() {
		if request.Path != "/api/haproxy/settings/setFrontend/"+uuidFrontendHTTPS {
			continue
		}
		form, err := url.ParseQuery(request.Body)
		if err != nil {
			t.Fatalf("ParseQuery(%q): %v", request.Body, err)
		}
		if form.Has("frontend[linkedActions]") {
			relationForm = form
		}
	}
	if relationForm == nil {
		t.Fatal("no frontend relation write recorded")
	}
	// A relation is posted as one comma-separated value, matching the plugin's
	// ModelRelationField binding.
	want := ownedUUID + "," + uuidFakeForeignAction
	if got := relationForm.Get("frontend[linkedActions]"); got != want {
		t.Errorf("linkedActions = %q, want %q (owned first, foreign preserved)", got, want)
	}

	_, frontend, found := fake.findObject(kindFrontend, "ingress-HTTPS")
	if !found {
		t.Fatal("the adopted frontend was deleted")
	}
	if got := firstValue(frontend["name"]); got != "ingress-HTTPS" {
		t.Errorf("frontend name = %q, want ingress-HTTPS", got)
	}
	if got := frontend["bind"]; !slices.Equal(got, []string{"0.0.0.0:443"}) {
		t.Errorf("frontend bind = %v, want the untouched live value", got)
	}
	if got := firstValue(frontend["description"]); got != "" {
		t.Errorf("frontend description = %q, want the foreign value", got)
	}
}

// TestApplyCreatesBackendAndServers covers the happy path: a backend, its
// servers and the relation that ties them together.
func TestApplyCreatesBackendAndServers(t *testing.T) {
	t.Parallel()

	prov, fake := newTestProvider(t)
	fake.seedFixture()

	plan := haproxy.Plan{Ordered: true, Operations: []haproxy.Operation{
		{
			Kind:   haproxy.OpCreate,
			Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectBackend, Name: "senselb-app"},
			Object: haproxy.NewBackend("senselb-app", haproxy.ModeHTTP),
		},
		{
			Kind:   haproxy.OpCreate,
			Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectServer, Parent: "senselb-app", Name: "senselb-app-2"},
			Object: haproxy.NewServer("senselb-app-2", "10.0.0.2", 30080),
		},
		{
			Kind:   haproxy.OpCreate,
			Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectServer, Parent: "senselb-app", Name: "senselb-app-1"},
			Object: haproxy.NewServer("senselb-app-1", "10.0.0.1", 30080),
		},
	}}
	if err := prov.Apply(plan); err != nil {
		t.Fatalf("Apply(): %v", err)
	}

	firstUUID, _, found := fake.findObject(kindServer, "senselb-app-1")
	if !found {
		t.Fatal("server senselb-app-1 is missing")
	}
	secondUUID, _, found := fake.findObject(kindServer, "senselb-app-2")
	if !found {
		t.Fatal("server senselb-app-2 is missing")
	}

	_, backend, found := fake.findObject(kindBackend, "senselb-app")
	if !found {
		t.Fatal("backend senselb-app is missing")
	}
	if got, want := backend["linkedServers"], []string{firstUUID, secondUUID}; !slices.Equal(got, want) {
		t.Errorf("linkedServers = %v, want %v (owned, name order)", got, want)
	}
	if got := firstValue(backend["description"]); got != OwnedDescription {
		t.Errorf("backend description = %q, want the ownership marker", got)
	}

	model, err := prov.Get()
	if err != nil {
		t.Fatalf("Get(): %v", err)
	}
	created := findBackend(t, model, "senselb-app")
	if len(created.Servers) != 2 {
		t.Fatalf("round-tripped servers = %d, want 2", len(created.Servers))
	}
	if created.Servers[0].Name != "senselb-app-1" || created.Servers[1].Name != "senselb-app-2" {
		t.Errorf("round-tripped server order = %s, %s", created.Servers[0].Name, created.Servers[1].Name)
	}
}

// TestApplyLinksRuleACLsAndDefaultBackend covers the relations the mapper's
// forms omit: a rule's ACLs and backend, and a frontend's default backend.
func TestApplyLinksRuleACLsAndDefaultBackend(t *testing.T) {
	t.Parallel()

	prov, fake := newTestProvider(t)
	fake.seedFixture()

	rule := haproxy.NewRule("senselb-rule", haproxy.RuleTypeUseBackend)
	rule.LinkedACLs = []string{"senselb-acl"}
	rule.UseBackend = "senselb-app"

	frontend := haproxy.NewFrontend("senselb-web", haproxy.ModeHTTP, "0.0.0.0:8080")
	frontend.DefaultBackend = "senselb-app"

	plan := haproxy.Plan{Ordered: true, Operations: []haproxy.Operation{
		{
			Kind:   haproxy.OpCreate,
			Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectACL, Parent: "senselb-web", Name: "senselb-acl"},
			Object: haproxy.NewACL("senselb-acl", haproxy.ACLExpressionPathBeg, "/app"),
		},
		{
			Kind:   haproxy.OpCreate,
			Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectRule, Parent: "senselb-web", Name: "senselb-rule"},
			Object: rule,
		},
		{
			Kind:   haproxy.OpCreate,
			Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectBackend, Name: "senselb-app"},
			Object: haproxy.NewBackend("senselb-app", haproxy.ModeHTTP),
		},
		{
			Kind:   haproxy.OpCreate,
			Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectFrontend, Name: "senselb-web"},
			Object: frontend,
		},
	}}
	if err := prov.Apply(plan); err != nil {
		t.Fatalf("Apply(): %v", err)
	}

	aclUUID, _, found := fake.findObject(kindACL, "senselb-acl")
	if !found {
		t.Fatal("ACL senselb-acl is missing")
	}
	backendUUID, _, found := fake.findObject(kindBackend, "senselb-app")
	if !found {
		t.Fatal("backend senselb-app is missing")
	}
	ruleUUID, action, found := fake.findObject(kindAction, "senselb-rule")
	if !found {
		t.Fatal("action senselb-rule is missing")
	}
	if got := action["linkedAcls"]; !slices.Equal(got, []string{aclUUID}) {
		t.Errorf("action linkedAcls = %v, want [%s]", got, aclUUID)
	}
	if got := action["use_backend"]; !slices.Equal(got, []string{backendUUID}) {
		t.Errorf("action use_backend = %v, want [%s]", got, backendUUID)
	}

	_, created, found := fake.findObject(kindFrontend, "senselb-web")
	if !found {
		t.Fatal("frontend senselb-web is missing")
	}
	if got := created["linkedActions"]; !slices.Equal(got, []string{ruleUUID}) {
		t.Errorf("frontend linkedActions = %v, want [%s]", got, ruleUUID)
	}
	if got := created["defaultBackend"]; !slices.Equal(got, []string{backendUUID}) {
		t.Errorf("frontend defaultBackend = %v, want [%s]", got, backendUUID)
	}
}

// TestApplyEmptyPlanIsInert asserts an empty plan performs no request at all.
func TestApplyEmptyPlanIsInert(t *testing.T) {
	t.Parallel()

	prov, fake := newTestProvider(t)
	fake.seedFixture()

	if err := prov.Apply(haproxy.Plan{}); err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	if got := len(fake.requests()); got != 0 {
		t.Fatalf("requests = %d, want none for an empty plan", got)
	}
}

// TestRollbackAfterSuccessfulApplyIsNoop covers the retained-snapshot lifetime:
// a live batch clears it, so a stray Rollback cannot revert good configuration.
func TestRollbackAfterSuccessfulApplyIsNoop(t *testing.T) {
	t.Parallel()

	prov, fake := newTestProvider(t)
	fake.seedFixture()

	plan := haproxy.Plan{Ordered: true, Operations: []haproxy.Operation{
		{
			Kind:   haproxy.OpCreate,
			Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectBackend, Name: "senselb-app"},
			Object: haproxy.NewBackend("senselb-app", haproxy.ModeHTTP),
		},
		{
			Kind:   haproxy.OpCreate,
			Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectServer, Parent: "senselb-app", Name: "senselb-app-1"},
			Object: haproxy.NewServer("senselb-app-1", "10.0.0.1", 30080),
		},
	}}
	if err := prov.Apply(plan); err != nil {
		t.Fatalf("Apply(): %v", err)
	}

	if err := prov.Rollback(); err != nil {
		t.Fatalf("Rollback(): %v", err)
	}
	if _, _, found := fake.findObject(kindBackend, "senselb-app"); !found {
		t.Error("rollback reverted a batch that already reached the data plane")
	}
	if _, _, found := fake.findObject(kindServer, "senselb-app-1"); !found {
		t.Error("rollback removed the server of a batch that already reached the data plane")
	}
}

// TestRollbackAfterFailedApplyKeepsSnapshot covers the retained snapshot a failed
// batch leaves behind: the controller may call Rollback explicitly, and a second
// restore is harmless.
func TestRollbackAfterFailedApplyKeepsSnapshot(t *testing.T) {
	t.Parallel()

	prov, fake := newTestProvider(t)
	fake.seedFixture()
	fake.setConfigTestFailure(true)

	plan := haproxy.Plan{Ordered: true, Operations: []haproxy.Operation{{
		Kind:   haproxy.OpCreate,
		Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectBackend, Name: "senselb-app"},
		Object: haproxy.NewBackend("senselb-app", haproxy.ModeHTTP),
	}}}
	var configErr *provider.ErrConfigTest
	if err := prov.Apply(plan); !errors.As(err, &configErr) {
		t.Fatalf("Apply() = %v, want *provider.ErrConfigTest", err)
	}

	if err := prov.Rollback(); err != nil {
		t.Fatalf("Rollback() after a failed apply: %v", err)
	}
	if _, _, found := fake.findObject(kindBackend, "senselb-app"); found {
		t.Error("rollback of the failed batch left the created backend behind")
	}
}

// TestApplyDeletesOwnedServer covers the delete path: the object is removed and
// its parent stops linking it.
func TestApplyDeletesOwnedServer(t *testing.T) {
	t.Parallel()

	prov, fake := newTestProvider(t)
	fake.seedFixture()
	fake.seedOwnedBackend("senselb-app", uuidFakeOwnedBackend)
	fake.seedOwnedServer("senselb-app", "senselb-app-1", uuidFakeOwnedServer)

	plan := haproxy.Plan{Ordered: true, Operations: []haproxy.Operation{{
		Kind: haproxy.OpDelete,
		Ref:  haproxy.ObjectRef{Kind: haproxy.ObjectServer, Parent: "senselb-app", Name: "senselb-app-1"},
	}}}
	if err := prov.Apply(plan); err != nil {
		t.Fatalf("Apply(): %v", err)
	}

	if _, _, found := fake.findObject(kindServer, "senselb-app-1"); found {
		t.Error("the deleted server is still in the store")
	}
	_, backend, found := fake.findObject(kindBackend, "senselb-app")
	if !found {
		t.Fatal("the backend was deleted with its server")
	}
	if got := backend["linkedServers"]; len(got) != 0 {
		t.Errorf("backend linkedServers = %v, want none after the delete", got)
	}
	if tests, reloads := fake.counters(); tests != 1 || reloads != 1 {
		t.Errorf("configtest/reconfigure calls = %d/%d, want 1/1", tests, reloads)
	}
}

// TestConfigTestFailureRecreatesDeletedObject asserts rollback restores a
// deleted object and re-links it.
func TestConfigTestFailureRecreatesDeletedObject(t *testing.T) {
	t.Parallel()

	prov, fake := newTestProvider(t)
	fake.seedFixture()
	fake.seedOwnedBackend("senselb-app", uuidFakeOwnedBackend)
	fake.seedOwnedServer("senselb-app", "senselb-app-1", uuidFakeOwnedServer)
	fake.setConfigTestFailure(true)

	plan := haproxy.Plan{Ordered: true, Operations: []haproxy.Operation{{
		Kind: haproxy.OpDelete,
		Ref:  haproxy.ObjectRef{Kind: haproxy.ObjectServer, Parent: "senselb-app", Name: "senselb-app-1"},
	}}}

	var configErr *provider.ErrConfigTest
	if err := prov.Apply(plan); !errors.As(err, &configErr) {
		t.Fatalf("Apply() = %v, want *provider.ErrConfigTest", err)
	}

	_, server, found := fake.findObject(kindServer, "senselb-app-1")
	if !found {
		t.Fatal("rollback did not recreate the deleted server")
	}
	if got := firstValue(server["address"]); got != "10.0.0.1" {
		t.Errorf("restored server address = %q, want the snapshot value", got)
	}
	if got := firstValue(server["description"]); got != OwnedDescription {
		t.Errorf("restored server description = %q, want the ownership marker", got)
	}
	_, backend, found := fake.findObject(kindBackend, "senselb-app")
	if !found {
		t.Fatal("the backend is missing after rollback")
	}
	if got := backend["linkedServers"]; !slices.Equal(got, []string{uuidFakeOwnedServer}) {
		t.Errorf("backend linkedServers = %v, want [%s]", got, uuidFakeOwnedServer)
	}
}

// TestValidateAndReload exercises the thin wrapper methods.
func TestValidateAndReload(t *testing.T) {
	t.Parallel()

	prov, fake := newTestProvider(t)

	fake.setConfigTestFailure(true)
	var configErr *provider.ErrConfigTest
	if err := prov.Validate(); !errors.As(err, &configErr) {
		t.Fatalf("Validate() = %v, want *provider.ErrConfigTest", err)
	}

	fake.setConfigTestFailure(false)
	if err := prov.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	if err := prov.Reload(); err != nil {
		t.Fatalf("Reload() = %v, want nil", err)
	}
	if tests, reloads := fake.counters(); tests != 2 || reloads != 1 {
		t.Fatalf("configtest/reconfigure calls = %d/%d, want 2/1", tests, reloads)
	}
}

// TestApplyRollbackKeepsMultiSelectFields covers rollback fidelity for a field
// the canonical model does not carry: both stored linkedErrorfiles survive the
// restore as repeated form entries instead of collapsing to the first.
func TestApplyRollbackKeepsMultiSelectFields(t *testing.T) {
	t.Parallel()

	prov, fake := newTestProvider(t)
	fake.seedFixture()

	const (
		frontendUUID = "00000000-0000-0000-0000-0000000000b1"
		firstErrors  = "00000000-0000-0000-0000-0000000000e1"
		secondErrors = "00000000-0000-0000-0000-0000000000e2"
	)
	fake.put(kindFrontend, frontendUUID, fakeObject{
		"name":             {"senselb-web"},
		"description":      {OwnedDescription},
		"enabled":          {formTrue},
		"bind":             {"0.0.0.0:8080"},
		"mode":             {"http"},
		"linkedActions":    nil,
		"linkedErrorfiles": {firstErrors, secondErrors},
	})
	fake.setConfigTestFailure(true)

	frontend := haproxy.NewFrontend("senselb-web", haproxy.ModeHTTP, "0.0.0.0:8080")
	frontend.CustomOptions = "option httplog"
	plan := haproxy.Plan{Ordered: true, Operations: []haproxy.Operation{{
		Kind:   haproxy.OpUpdate,
		Ref:    haproxy.ObjectRef{Kind: haproxy.ObjectFrontend, Name: "senselb-web"},
		Object: frontend,
	}}}

	var configErr *provider.ErrConfigTest
	if err := prov.Apply(plan); !errors.As(err, &configErr) {
		t.Fatalf("Apply() = %v, want *provider.ErrConfigTest", err)
	}

	want := []string{firstErrors, secondErrors}
	restored := false
	for _, request := range fake.writeRequests() {
		if request.Path != "/api/haproxy/settings/setFrontend/"+frontendUUID {
			continue
		}
		form, err := url.ParseQuery(request.Body)
		if err != nil {
			t.Fatalf("ParseQuery(%q): %v", request.Body, err)
		}
		if got := form["frontend[linkedErrorfiles][]"]; slices.Equal(got, want) {
			restored = true
		}
	}
	if !restored {
		t.Error("no frontend write carried both linkedErrorfiles entries")
	}
}

// firstValue returns the first stored value of a field, or "".
func firstValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// writeKindPrefix derives the singular object prefix from a settings write
// path, for example setBackend/<uuid> -> backend.
func writeKindPrefix(path string) string {
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, segment := range segments {
		if segment != "settings" || i+1 >= len(segments) {
			continue
		}
		action := segments[i+1]
		for _, verb := range []string{"add", "set", "del"} {
			if suffix, found := strings.CutPrefix(action, verb); found {
				return strings.ToLower(suffix)
			}
		}
	}
	return ""
}
