package haproxy_test

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/yasn77/senselb/pkg/haproxy"
)

// routingModel returns a model with one HTTP frontend that routes to one
// backend through an ACL and a rule.
func routingModel() *haproxy.Model {
	frontend := haproxy.NewFrontend("external", haproxy.ModeHTTP, "0.0.0.0:80")
	frontend.DefaultBackend = "app"
	frontend.ACLs = []haproxy.ACL{
		haproxy.NewACL("host-app", haproxy.ACLExpressionHdr, "(host) -i app.example.com"),
	}

	route := haproxy.NewRule("route-app", haproxy.RuleTypeUseBackend)
	route.LinkedACLs = []string{"host-app"}
	route.UseBackend = "app"
	frontend.Rules = []haproxy.Rule{route}

	backend := haproxy.NewBackend("app", haproxy.ModeHTTP)
	backend.Servers = []haproxy.Server{haproxy.NewServer("node-1", "10.0.0.11", 30080)}

	return &haproxy.Model{
		Frontends: []haproxy.Frontend{frontend},
		Backends:  []haproxy.Backend{backend},
	}
}

// multiObjectModel returns a model with two frontends and two backends so a
// plan exercises several objects of each kind.
func multiObjectModel() *haproxy.Model {
	model := routingModel()

	worker := haproxy.NewBackend("worker", haproxy.ModeHTTP)
	worker.Servers = []haproxy.Server{
		haproxy.NewServer("node-3", "10.0.0.13", 30081),
		haproxy.NewServer("node-4", "10.0.0.14", 30082),
	}
	model.Backends = append(model.Backends, worker)

	internal := haproxy.NewFrontend("internal", haproxy.ModeTCP, "0.0.0.0:5432")
	internal.DefaultBackend = "worker"
	model.Frontends = append(model.Frontends, internal)

	return model
}

// describeOperations renders a plan for a test failure message.
func describeOperations(operations []haproxy.Operation) string {
	rendered := make([]string, len(operations))
	for i, operation := range operations {
		rendered[i] = fmt.Sprintf("%s %s/%s/%s", operation.Kind, operation.Ref.Kind, operation.Ref.Parent, operation.Ref.Name)
	}
	return strings.Join(rendered, ", ")
}

func TestDiffIdenticalModelsIsEmpty(t *testing.T) {
	model := validModel()

	plan, err := haproxy.Diff(model, model)
	if err != nil {
		t.Fatalf("Diff returned an error: %v", err)
	}
	if !plan.IsEmpty() {
		t.Fatalf("Diff of identical models returned %d operations: %s", len(plan.Operations), describeOperations(plan.Operations))
	}
	if !plan.Ordered {
		t.Fatal("Diff did not mark the plan as ordered")
	}
}

func TestDiffAcceptsEmptyModels(t *testing.T) {
	plan, err := haproxy.Diff(&haproxy.Model{}, &haproxy.Model{})
	if err != nil {
		t.Fatalf("Diff returned an error: %v", err)
	}
	if !plan.IsEmpty() {
		t.Fatalf("Diff of empty models returned %d operations: %s", len(plan.Operations), describeOperations(plan.Operations))
	}
}

func TestDiffIgnoresUUIDs(t *testing.T) {
	desired := validModel()
	live := validModel()
	live.Frontends[0].UUID = "frontend-uuid"
	live.Backends[0].UUID = "backend-uuid"
	live.Backends[0].Servers[0].UUID = "server-uuid"
	live.Backends[1].ACLs[0].UUID = "acl-uuid"
	live.Backends[1].Rules[0].UUID = "rule-uuid"

	plan, err := haproxy.Diff(desired, live)
	if err != nil {
		t.Fatalf("Diff returned an error: %v", err)
	}
	if !plan.IsEmpty() {
		t.Fatalf("Diff treated live UUIDs as a change: %s", describeOperations(plan.Operations))
	}
}

func TestDiffTreatsNilAndEmptySlicesAsEqual(t *testing.T) {
	desired := routingModel()
	desired.Frontends[0].Bind = nil
	desired.Frontends[0].SSLCertificates = nil
	desired.Frontends[0].Rules[0].LinkedACLs = nil

	live := routingModel()
	live.Frontends[0].Bind = []string{}
	live.Frontends[0].SSLCertificates = []string{}
	live.Frontends[0].Rules[0].LinkedACLs = []string{}
	live.Backends[0].ACLs = []haproxy.ACL{}

	plan, err := haproxy.Diff(desired, live)
	if err != nil {
		t.Fatalf("Diff returned an error: %v", err)
	}
	if !plan.IsEmpty() {
		t.Fatalf("Diff treated nil and empty slices as different: %s", describeOperations(plan.Operations))
	}
}

func TestDiffPlansCreateUpdateAndDelete(t *testing.T) {
	ref := func(kind haproxy.ObjectKind, parent, name string) haproxy.ObjectRef {
		return haproxy.ObjectRef{Kind: kind, Parent: parent, Name: name}
	}

	hostApp := haproxy.NewACL("host-app", haproxy.ACLExpressionHdr, "(host) -i app.example.com")
	routeApp := haproxy.NewRule("route-app", haproxy.RuleTypeUseBackend)
	routeApp.LinkedACLs = []string{"host-app"}
	routeApp.UseBackend = "app"

	plannedFrontend := haproxy.NewFrontend("external", haproxy.ModeHTTP, "0.0.0.0:80")
	plannedFrontend.DefaultBackend = "app"

	updatedBackend := haproxy.NewBackend("app", haproxy.ModeHTTP)
	updatedBackend.Algorithm = haproxy.AlgorithmLeastConn

	tests := []struct {
		name    string
		desired func() *haproxy.Model
		live    func() *haproxy.Model
		want    []haproxy.Operation
	}{
		{
			name: "create server in an existing backend",
			desired: func() *haproxy.Model {
				model := routingModel()
				model.Backends[0].Servers = append(model.Backends[0].Servers, haproxy.NewServer("node-2", "10.0.0.12", 30080))
				return model
			},
			live: routingModel,
			want: []haproxy.Operation{{
				Kind:   haproxy.OpCreate,
				Ref:    ref(haproxy.ObjectServer, "app", "node-2"),
				Object: haproxy.NewServer("node-2", "10.0.0.12", 30080),
			}},
		},
		{
			name: "create backend with its server",
			desired: func() *haproxy.Model {
				model := routingModel()
				worker := haproxy.NewBackend("worker", haproxy.ModeHTTP)
				worker.Servers = []haproxy.Server{haproxy.NewServer("node-3", "10.0.0.13", 30081)}
				model.Backends = append(model.Backends, worker)
				return model
			},
			live: routingModel,
			want: []haproxy.Operation{
				{
					Kind:   haproxy.OpCreate,
					Ref:    ref(haproxy.ObjectServer, "worker", "node-3"),
					Object: haproxy.NewServer("node-3", "10.0.0.13", 30081),
				},
				{
					Kind:   haproxy.OpCreate,
					Ref:    ref(haproxy.ObjectBackend, "", "worker"),
					Object: haproxy.NewBackend("worker", haproxy.ModeHTTP),
				},
			},
		},
		{
			name:    "create frontend with its ACL and rule",
			desired: routingModel,
			live: func() *haproxy.Model {
				model := routingModel()
				model.Frontends = nil
				return model
			},
			want: []haproxy.Operation{
				{
					Kind:   haproxy.OpCreate,
					Ref:    ref(haproxy.ObjectACL, "external", "host-app"),
					Object: hostApp,
				},
				{
					Kind:   haproxy.OpCreate,
					Ref:    ref(haproxy.ObjectRule, "external", "route-app"),
					Object: routeApp,
				},
				{
					Kind:   haproxy.OpCreate,
					Ref:    ref(haproxy.ObjectFrontend, "", "external"),
					Object: plannedFrontend,
				},
			},
		},
		{
			name: "update backend algorithm",
			desired: func() *haproxy.Model {
				model := routingModel()
				model.Backends[0].Algorithm = haproxy.AlgorithmLeastConn
				return model
			},
			live: routingModel,
			want: []haproxy.Operation{{
				Kind:   haproxy.OpUpdate,
				Ref:    ref(haproxy.ObjectBackend, "", "app"),
				Object: updatedBackend,
			}},
		},
		{
			name: "update frontend rule",
			desired: func() *haproxy.Model {
				model := routingModel()
				model.Frontends[0].Rules[0].UseBackend = "worker"
				return model
			},
			live: routingModel,
			want: []haproxy.Operation{{
				Kind: haproxy.OpUpdate,
				Ref:  ref(haproxy.ObjectRule, "external", "route-app"),
				Object: func() haproxy.Rule {
					rule := haproxy.NewRule("route-app", haproxy.RuleTypeUseBackend)
					rule.LinkedACLs = []string{"host-app"}
					rule.UseBackend = "worker"
					return rule
				}(),
			}},
		},
		{
			name: "delete server from an existing backend",
			desired: func() *haproxy.Model {
				model := routingModel()
				model.Backends[0].Servers = nil
				return model
			},
			live: routingModel,
			want: []haproxy.Operation{{
				Kind: haproxy.OpDelete,
				Ref:  ref(haproxy.ObjectServer, "app", "node-1"),
			}},
		},
		{
			name: "delete backend with its server",
			desired: func() *haproxy.Model {
				model := routingModel()
				model.Backends = nil
				return model
			},
			live: routingModel,
			want: []haproxy.Operation{
				{
					Kind: haproxy.OpDelete,
					Ref:  ref(haproxy.ObjectBackend, "", "app"),
				},
				{
					Kind: haproxy.OpDelete,
					Ref:  ref(haproxy.ObjectServer, "app", "node-1"),
				},
			},
		},
		{
			name: "delete frontend with its children",
			desired: func() *haproxy.Model {
				model := routingModel()
				model.Frontends = nil
				return model
			},
			live: routingModel,
			want: []haproxy.Operation{
				{
					Kind: haproxy.OpDelete,
					Ref:  ref(haproxy.ObjectFrontend, "", "external"),
				},
				{
					Kind: haproxy.OpDelete,
					Ref:  ref(haproxy.ObjectRule, "external", "route-app"),
				},
				{
					Kind: haproxy.OpDelete,
					Ref:  ref(haproxy.ObjectACL, "external", "host-app"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := haproxy.Diff(test.desired(), test.live())
			if err != nil {
				t.Fatalf("Diff returned an error: %v", err)
			}
			if !plan.Ordered {
				t.Error("Diff did not mark the plan as ordered")
			}
			if !reflect.DeepEqual(plan.Operations, test.want) {
				t.Fatalf("operations mismatch\n got: %s\nwant: %s", describeOperations(plan.Operations), describeOperations(test.want))
			}
			for _, operation := range plan.Operations {
				if operation.Kind == haproxy.OpDelete && operation.Object != nil {
					t.Errorf("delete of %s/%s/%s carries a payload", operation.Ref.Kind, operation.Ref.Parent, operation.Ref.Name)
				}
			}
		})
	}
}

func TestDiffIsDeterministic(t *testing.T) {
	desired := multiObjectModel()
	live := &haproxy.Model{}

	first, err := haproxy.Diff(desired, live)
	if err != nil {
		t.Fatalf("Diff returned an error: %v", err)
	}
	second, err := haproxy.Diff(desired, live)
	if err != nil {
		t.Fatalf("Diff returned an error: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("repeated Diff runs differ\nfirst:  %s\nsecond: %s", describeOperations(first.Operations), describeOperations(second.Operations))
	}

	// Equal inputs ordered differently must still produce the same canonical
	// plan.
	reordered := multiObjectModel()
	slices.Reverse(reordered.Frontends)
	slices.Reverse(reordered.Backends)
	for i := range reordered.Backends {
		slices.Reverse(reordered.Backends[i].Servers)
	}

	third, err := haproxy.Diff(reordered, live)
	if err != nil {
		t.Fatalf("Diff returned an error: %v", err)
	}
	if !reflect.DeepEqual(first, third) {
		t.Fatalf("reordered inputs produced a different plan\nfirst:   %s\nreorder: %s", describeOperations(first.Operations), describeOperations(third.Operations))
	}
}

func TestDiffOrdersCreatesTargetsBeforeLinkers(t *testing.T) {
	plan, err := haproxy.Diff(multiObjectModel(), &haproxy.Model{})
	if err != nil {
		t.Fatalf("Diff returned an error: %v", err)
	}

	position := make(map[haproxy.ObjectRef]int, len(plan.Operations))
	for i, operation := range plan.Operations {
		if operation.Kind != haproxy.OpCreate {
			t.Fatalf("operation %d is %s, want create", i, operation.Kind)
		}
		position[operation.Ref] = i
	}

	ordered := []struct {
		target, linker haproxy.ObjectRef
	}{
		{
			target: haproxy.ObjectRef{Kind: haproxy.ObjectServer, Parent: "app", Name: "node-1"},
			linker: haproxy.ObjectRef{Kind: haproxy.ObjectBackend, Name: "app"},
		},
		{
			target: haproxy.ObjectRef{Kind: haproxy.ObjectServer, Parent: "worker", Name: "node-3"},
			linker: haproxy.ObjectRef{Kind: haproxy.ObjectBackend, Name: "worker"},
		},
		{
			target: haproxy.ObjectRef{Kind: haproxy.ObjectACL, Parent: "external", Name: "host-app"},
			linker: haproxy.ObjectRef{Kind: haproxy.ObjectRule, Parent: "external", Name: "route-app"},
		},
		{
			target: haproxy.ObjectRef{Kind: haproxy.ObjectRule, Parent: "external", Name: "route-app"},
			linker: haproxy.ObjectRef{Kind: haproxy.ObjectFrontend, Name: "external"},
		},
		{
			target: haproxy.ObjectRef{Kind: haproxy.ObjectBackend, Name: "app"},
			linker: haproxy.ObjectRef{Kind: haproxy.ObjectFrontend, Name: "external"},
		},
		{
			target: haproxy.ObjectRef{Kind: haproxy.ObjectBackend, Name: "worker"},
			linker: haproxy.ObjectRef{Kind: haproxy.ObjectFrontend, Name: "internal"},
		},
	}

	for _, pair := range ordered {
		targetAt, targetFound := position[pair.target]
		linkerAt, linkerFound := position[pair.linker]
		if !targetFound || !linkerFound {
			t.Fatalf("plan lacks %v or %v: %s", pair.target, pair.linker, describeOperations(plan.Operations))
		}
		if targetAt >= linkerAt {
			t.Errorf("target %v is at %d, linker %v at %d: a target must precede its linker", pair.target, targetAt, pair.linker, linkerAt)
		}
	}
}

func TestDiffOrdersDeletesLinkersBeforeTargets(t *testing.T) {
	plan, err := haproxy.Diff(&haproxy.Model{}, multiObjectModel())
	if err != nil {
		t.Fatalf("Diff returned an error: %v", err)
	}

	position := make(map[haproxy.ObjectRef]int, len(plan.Operations))
	for i, operation := range plan.Operations {
		if operation.Kind != haproxy.OpDelete {
			t.Fatalf("operation %d is %s, want delete", i, operation.Kind)
		}
		position[operation.Ref] = i
	}

	ordered := []struct {
		linker, target haproxy.ObjectRef
	}{
		{
			linker: haproxy.ObjectRef{Kind: haproxy.ObjectFrontend, Name: "external"},
			target: haproxy.ObjectRef{Kind: haproxy.ObjectBackend, Name: "app"},
		},
		{
			linker: haproxy.ObjectRef{Kind: haproxy.ObjectBackend, Name: "app"},
			target: haproxy.ObjectRef{Kind: haproxy.ObjectServer, Parent: "app", Name: "node-1"},
		},
		{
			linker: haproxy.ObjectRef{Kind: haproxy.ObjectFrontend, Name: "external"},
			target: haproxy.ObjectRef{Kind: haproxy.ObjectRule, Parent: "external", Name: "route-app"},
		},
		{
			linker: haproxy.ObjectRef{Kind: haproxy.ObjectRule, Parent: "external", Name: "route-app"},
			target: haproxy.ObjectRef{Kind: haproxy.ObjectACL, Parent: "external", Name: "host-app"},
		},
	}

	for _, pair := range ordered {
		linkerAt, linkerFound := position[pair.linker]
		targetAt, targetFound := position[pair.target]
		if !linkerFound || !targetFound {
			t.Fatalf("plan lacks %v or %v: %s", pair.linker, pair.target, describeOperations(plan.Operations))
		}
		if linkerAt >= targetAt {
			t.Errorf("linker %v is at %d, target %v at %d: a linker must be deleted first", pair.linker, linkerAt, pair.target, targetAt)
		}
	}
}

func TestDiffRejectsMalformedModels(t *testing.T) {
	tests := []struct {
		name    string
		desired *haproxy.Model
		live    *haproxy.Model
		want    string
	}{
		{
			name:    "nil desired model",
			desired: nil,
			live:    &haproxy.Model{},
			want:    "desired model is nil",
		},
		{
			name:    "nil live model",
			desired: &haproxy.Model{},
			live:    nil,
			want:    "live model is nil",
		},
		{
			name:    "empty frontend name",
			desired: &haproxy.Model{Frontends: []haproxy.Frontend{{}}},
			live:    &haproxy.Model{},
			want:    "frontend[0] has an empty name",
		},
		{
			name: "duplicate frontend name",
			desired: &haproxy.Model{Frontends: []haproxy.Frontend{
				{Name: "fe"},
				{Name: "fe"},
			}},
			live: &haproxy.Model{},
			want: `duplicate frontend name "fe"`,
		},
		{
			name:    "empty backend name",
			desired: &haproxy.Model{Backends: []haproxy.Backend{{}}},
			live:    &haproxy.Model{},
			want:    "backend[0] has an empty name",
		},
		{
			name: "duplicate backend name",
			desired: &haproxy.Model{Backends: []haproxy.Backend{
				{Name: "be"},
				{Name: "be"},
			}},
			live: &haproxy.Model{},
			want: `duplicate backend name "be"`,
		},
		{
			name: "empty server name",
			desired: &haproxy.Model{Backends: []haproxy.Backend{{
				Name:    "be",
				Servers: []haproxy.Server{{}},
			}}},
			live: &haproxy.Model{},
			want: `backend "be": server[0] has an empty name`,
		},
		{
			name: "duplicate server name",
			desired: &haproxy.Model{Backends: []haproxy.Backend{{
				Name: "be",
				Servers: []haproxy.Server{
					{Name: "node"},
					{Name: "node"},
				},
			}}},
			live: &haproxy.Model{},
			want: `backend "be": duplicate server name "node"`,
		},
		{
			name: "duplicate ACL name in a frontend",
			desired: &haproxy.Model{Frontends: []haproxy.Frontend{{
				Name: "fe",
				ACLs: []haproxy.ACL{
					{Name: "acl"},
					{Name: "acl"},
				},
			}}},
			live: &haproxy.Model{},
			want: `frontend "fe": duplicate acl name "acl"`,
		},
		{
			name: "duplicate rule name in a backend",
			desired: &haproxy.Model{Backends: []haproxy.Backend{{
				Name: "be",
				Rules: []haproxy.Rule{
					{Name: "rule"},
					{Name: "rule"},
				},
			}}},
			live: &haproxy.Model{},
			want: `backend "be": duplicate rule name "rule"`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := haproxy.Diff(test.desired, test.live)
			if err == nil {
				t.Fatalf("Diff accepted a malformed model and returned %s", describeOperations(plan.Operations))
			}
			if plan != nil {
				t.Fatalf("Diff returned a plan alongside the error: %s", describeOperations(plan.Operations))
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error %q does not contain %q", err, test.want)
			}
		})
	}
}
