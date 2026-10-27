package haproxy

import (
	"cmp"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// OpKind classifies one step of a reconciliation plan.
type OpKind int

const (
	// OpCreate adds an object that exists only in the desired model.
	OpCreate OpKind = iota
	// OpUpdate rewrites an object whose desired payload differs from the live
	// one.
	OpUpdate
	// OpDelete removes an object that exists only in the live model.
	OpDelete
)

// String renders the operation kind for logs and diagnostics.
func (k OpKind) String() string {
	switch k {
	case OpCreate:
		return "create"
	case OpUpdate:
		return "update"
	case OpDelete:
		return "delete"
	default:
		return fmt.Sprintf("OpKind(%d)", int(k))
	}
}

// ObjectKind names the model collection an operation targets.
type ObjectKind string

// Object kinds that can appear in a plan. Listeners are configuration inputs
// that resolve to frontends before reconciliation, so they are never plan
// objects.
const (
	ObjectFrontend ObjectKind = "frontend"
	ObjectBackend  ObjectKind = "backend"
	ObjectServer   ObjectKind = "server"
	ObjectACL      ObjectKind = "acl"
	ObjectRule     ObjectKind = "rule"
)

// ObjectRef identifies one model object. Parent names the owning frontend or
// backend for servers, ACLs and rules; it is empty for frontends and backends.
// Names are matched within their parent scope only, mirroring how the platform
// names objects.
type ObjectRef struct {
	Kind   ObjectKind
	Parent string
	Name   string
}

// Operation is one CRUD step of a Plan. Object carries the desired payload for
// OpCreate and OpUpdate, and is nil for OpDelete.
type Operation struct {
	Kind   OpKind
	Ref    ObjectRef
	Object any
}

// Plan is the set of operations that turns the live model into the desired one.
//
// A plan is a minimal object-level diff. It strips child collections from every
// parent payload and emits no parent operation when only a parent's children
// changed, so it never carries parent-to-child linkage. A provider that stores
// linkage on the parent must recompute it while applying; see
// provider.Provider.Apply.
type Plan struct {
	Operations []Operation
	// Ordered reports whether Operations are in apply-safe order: creates
	// precede updates, updates precede deletes, and link targets precede the
	// objects that link them. Diff always produces an ordered plan.
	Ordered bool
}

// IsEmpty reports whether the plan holds no operations, so the live model
// already matches the desired one.
func (p Plan) IsEmpty() bool {
	return len(p.Operations) == 0
}

// Diff compares the desired model with the live configuration and returns the
// minimal plan that reconciles them. Frontends and backends match by name at
// the top level; servers, ACLs and rules match by name within their parent
// object.
//
// An object present in both models produces an operation only when its payload
// differs, so a no-op change disappears from the plan. Comparison ignores the
// UUID field, which identifies live objects only, and treats a nil slice as
// equal to an empty one. Owned child collections are excluded from a parent's
// payload because each child is planned as its own operation: that keeps the
// plan minimal and stops a provider applying a child twice.
//
// Diff is pure and platform-agnostic. It performs no ownership filtering and
// assumes no naming convention; ownership checks belong to the provider. A
// parent that exists only in the live model is deleted together with its
// children, each as its own operation.
//
// Diff returns an error when either model is nil or fails structural sanity:
// every object must have a non-empty name, and names must be unique within
// their scope.
func Diff(desired, live *Model) (*Plan, error) {
	if desired == nil {
		return nil, errors.New("diff: desired model is nil")
	}
	if live == nil {
		return nil, errors.New("diff: live model is nil")
	}
	if err := checkStructure("desired", desired); err != nil {
		return nil, err
	}
	if err := checkStructure("live", live); err != nil {
		return nil, err
	}

	desiredFrontends := indexByName(desired.Frontends, frontendName)
	desiredBackends := indexByName(desired.Backends, backendName)
	liveFrontends := indexByName(live.Frontends, frontendName)
	liveBackends := indexByName(live.Backends, backendName)

	var set operationSet

	set.add(diffNamed(ObjectFrontend, "", desired.Frontends, live.Frontends, frontendName, planFrontend))
	for _, frontend := range desired.Frontends {
		liveFrontend := liveFrontends[frontend.Name]
		set.add(diffNamed(ObjectACL, frontend.Name, frontend.ACLs, liveFrontend.ACLs, aclName, planACL))
		set.add(diffNamed(ObjectRule, frontend.Name, frontend.Rules, liveFrontend.Rules, ruleName, planRule))
	}
	for _, frontend := range live.Frontends {
		if _, declared := desiredFrontends[frontend.Name]; declared {
			continue
		}
		// The frontend is deleted, so its children are deleted with it.
		set.add(diffNamed(ObjectACL, frontend.Name, nil, frontend.ACLs, aclName, planACL))
		set.add(diffNamed(ObjectRule, frontend.Name, nil, frontend.Rules, ruleName, planRule))
	}

	set.add(diffNamed(ObjectBackend, "", desired.Backends, live.Backends, backendName, planBackend))
	for _, backend := range desired.Backends {
		liveBackend := liveBackends[backend.Name]
		set.add(diffNamed(ObjectServer, backend.Name, backend.Servers, liveBackend.Servers, serverName, planServer))
		set.add(diffNamed(ObjectACL, backend.Name, backend.ACLs, liveBackend.ACLs, aclName, planACL))
		set.add(diffNamed(ObjectRule, backend.Name, backend.Rules, liveBackend.Rules, ruleName, planRule))
	}
	for _, backend := range live.Backends {
		if _, declared := desiredBackends[backend.Name]; declared {
			continue
		}
		// The backend is deleted, so its children are deleted with it.
		set.add(diffNamed(ObjectServer, backend.Name, nil, backend.Servers, serverName, planServer))
		set.add(diffNamed(ObjectACL, backend.Name, nil, backend.ACLs, aclName, planACL))
		set.add(diffNamed(ObjectRule, backend.Name, nil, backend.Rules, ruleName, planRule))
	}

	return set.plan(), nil
}

// diffNamed compares two collections of one object kind matched by name within
// a parent scope. payloadOf returns an object in the form that is both planned
// and compared with its live counterpart.
func diffNamed[T any](
	kind ObjectKind,
	parent string,
	desired, live []T,
	nameOf func(T) string,
	payloadOf func(T) T,
) operationSet {
	liveByName := make(map[string]T, len(live))
	for _, object := range live {
		liveByName[nameOf(object)] = object
	}

	var set operationSet
	matched := make(map[string]struct{}, len(desired))
	for _, want := range desired {
		name := nameOf(want)
		matched[name] = struct{}{}
		ref := ObjectRef{Kind: kind, Parent: parent, Name: name}

		have, exists := liveByName[name]
		switch {
		case !exists:
			set.creates = append(set.creates, Operation{Kind: OpCreate, Ref: ref, Object: payloadOf(want)})
		case !reflect.DeepEqual(payloadOf(want), payloadOf(have)):
			set.updates = append(set.updates, Operation{Kind: OpUpdate, Ref: ref, Object: payloadOf(want)})
		}
	}

	for _, object := range live {
		name := nameOf(object)
		if _, exists := matched[name]; exists {
			continue
		}
		set.deletes = append(set.deletes, Operation{
			Kind: OpDelete,
			Ref:  ObjectRef{Kind: kind, Parent: parent, Name: name},
		})
	}
	return set
}

// operationSet collects operations per phase before they are sorted into a
// plan.
type operationSet struct {
	creates []Operation
	updates []Operation
	deletes []Operation
}

// add appends the operations of another set.
func (s *operationSet) add(other operationSet) {
	s.creates = append(s.creates, other.creates...)
	s.updates = append(s.updates, other.updates...)
	s.deletes = append(s.deletes, other.deletes...)
}

// plan sorts each phase canonically and concatenates them in apply order.
func (s operationSet) plan() *Plan {
	byApplyOrder := func(a, b Operation) int { return compareOperations(a, b, false) }
	slices.SortStableFunc(s.creates, byApplyOrder)
	slices.SortStableFunc(s.updates, byApplyOrder)
	slices.SortStableFunc(s.deletes, func(a, b Operation) int { return compareOperations(a, b, true) })

	operations := make([]Operation, 0, len(s.creates)+len(s.updates)+len(s.deletes))
	operations = append(operations, s.creates...)
	operations = append(operations, s.updates...)
	operations = append(operations, s.deletes...)
	return &Plan{Operations: operations, Ordered: true}
}

// dependencyDepth counts the link hops between an object and a leaf object:
// servers, ACLs and rules are leaves, a backend links leaves, and a frontend
// links rules and backends.
func dependencyDepth(kind ObjectKind) int {
	switch kind {
	case ObjectBackend:
		return 1
	case ObjectFrontend:
		return 2
	default:
		return 0
	}
}

// kindRank orders object kinds alphabetically, which is the canonical
// within-depth order for creates and updates. Deleting reverses it, so a rule
// is removed before the ACLs it links.
func kindRank(kind ObjectKind) int {
	switch kind {
	case ObjectACL:
		return 0
	case ObjectBackend:
		return 1
	case ObjectFrontend:
		return 2
	case ObjectRule:
		return 3
	case ObjectServer:
		return 4
	default:
		return 5
	}
}

// compareOperations orders two operations of the same phase. Creates and
// updates place link targets before the objects that link them; deletes reverse
// both the dependency depth and the kind rank, so a linker is removed before its
// targets.
func compareOperations(a, b Operation, deleting bool) int {
	depthA, depthB := dependencyDepth(a.Ref.Kind), dependencyDepth(b.Ref.Kind)
	rankA, rankB := kindRank(a.Ref.Kind), kindRank(b.Ref.Kind)
	if deleting {
		depthA, depthB = -depthA, -depthB
		rankA, rankB = -rankA, -rankB
	}
	return cmp.Or(
		cmp.Compare(depthA, depthB),
		cmp.Compare(rankA, rankB),
		strings.Compare(a.Ref.Parent, b.Ref.Parent),
		strings.Compare(a.Ref.Name, b.Ref.Name),
	)
}

// indexByName maps each object's name to the object. checkStructure has already
// rejected duplicate names, so the index is lossless.
func indexByName[T any](objects []T, nameOf func(T) string) map[string]T {
	index := make(map[string]T, len(objects))
	for _, object := range objects {
		index[nameOf(object)] = object
	}
	return index
}

func frontendName(frontend Frontend) string { return frontend.Name }
func backendName(backend Backend) string    { return backend.Name }
func serverName(server Server) string       { return server.Name }
func aclName(acl ACL) string                { return acl.Name }
func ruleName(rule Rule) string             { return rule.Name }

// planFrontend returns the payload planned for a frontend and the form used to
// compare it with live configuration. The UUID is live state, and child
// collections are separate operations.
func planFrontend(frontend Frontend) Frontend {
	frontend.UUID = ""
	frontend.Bind = normaliseSlice(frontend.Bind)
	frontend.SSLCertificates = normaliseSlice(frontend.SSLCertificates)
	frontend.ACLs = nil
	frontend.Rules = nil
	return frontend
}

// planBackend returns the payload planned for a backend and the form used to
// compare it with live configuration.
func planBackend(backend Backend) Backend {
	backend.UUID = ""
	backend.Servers = nil
	backend.ACLs = nil
	backend.Rules = nil
	return backend
}

// planServer returns the payload planned for a server.
func planServer(server Server) Server {
	server.UUID = ""
	return server
}

// planACL returns the payload planned for an ACL.
func planACL(acl ACL) ACL {
	acl.UUID = ""
	return acl
}

// planRule returns the payload planned for a rule.
func planRule(rule Rule) Rule {
	rule.UUID = ""
	rule.LinkedACLs = normaliseSlice(rule.LinkedACLs)
	return rule
}

// normaliseSlice maps a nil and an empty slice to the same value, so a caller
// can compare models without distinguishing the two spellings of "no items".
func normaliseSlice[T any](values []T) []T {
	if len(values) == 0 {
		return nil
	}
	return values
}

// checkStructure rejects names that matching cannot resolve: an empty name or a
// name repeated within its scope.
func checkStructure(side string, model *Model) error {
	if err := checkTopLevelNames(side, ObjectFrontend, model.Frontends, frontendName); err != nil {
		return err
	}
	for _, frontend := range model.Frontends {
		scope := fmt.Sprintf("frontend %q", frontend.Name)
		if err := checkChildNames(side, scope, frontend.ACLs, frontend.Rules, nil); err != nil {
			return err
		}
	}

	if err := checkTopLevelNames(side, ObjectBackend, model.Backends, backendName); err != nil {
		return err
	}
	for _, backend := range model.Backends {
		scope := fmt.Sprintf("backend %q", backend.Name)
		if err := checkChildNames(side, scope, backend.ACLs, backend.Rules, backend.Servers); err != nil {
			return err
		}
	}
	return nil
}

// checkTopLevelNames checks the names of frontends or backends.
func checkTopLevelNames[T any](side string, kind ObjectKind, objects []T, nameOf func(T) string) error {
	seen := make(map[string]struct{}, len(objects))
	for i, object := range objects {
		name := nameOf(object)
		if name == "" {
			return fmt.Errorf("diff: %s model: %s[%d] has an empty name", side, kind, i)
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("diff: %s model: duplicate %s name %q", side, kind, name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

// checkChildNames checks the names of the children owned by one parent.
func checkChildNames(side, scope string, acls []ACL, rules []Rule, servers []Server) error {
	if err := checkNames(side, scope, ObjectACL, len(acls), func(i int) string { return acls[i].Name }); err != nil {
		return err
	}
	if err := checkNames(side, scope, ObjectRule, len(rules), func(i int) string { return rules[i].Name }); err != nil {
		return err
	}
	return checkNames(side, scope, ObjectServer, len(servers), func(i int) string { return servers[i].Name })
}

// checkNames checks one child collection.
func checkNames(side, scope string, kind ObjectKind, count int, nameAt func(int) string) error {
	seen := make(map[string]struct{}, count)
	for i := range count {
		name := nameAt(i)
		if name == "" {
			return fmt.Errorf("diff: %s model: %s: %s[%d] has an empty name", side, scope, kind, i)
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("diff: %s model: %s: duplicate %s name %q", side, scope, kind, name)
		}
		seen[name] = struct{}{}
	}
	return nil
}
