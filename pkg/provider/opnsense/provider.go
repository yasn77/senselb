package opnsense

import (
	"cmp"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"sync"

	"github.com/yasn77/senselb/pkg/haproxy"
	"github.com/yasn77/senselb/pkg/provider"
)

// Provider implements provider.Provider and provider.Rollbacker for one
// OPNsense os-haproxy plugin instance.
//
// Apply is single-flight: the complete read-validate-write sequence runs inside
// Client.WithLock, so overlapping calls cannot interleave. A snapshot of the
// live configuration is taken before the first write and retained, so Rollback
// can undo the last batch.
//
// The provider owns the object relations the plugin stores on a parent. A plan
// deliberately omits them (see provider.Provider.Apply), so Apply recomputes
// each affected parent's linkedActions, linkedServers, defaultBackend and rule
// relations after the object writes. Ownership is enforced before the first
// write: a plan step that would touch a foreign object returns
// *provider.ErrOwnershipConflict with no request sent.
type Provider struct {
	c *Client

	mu   sync.Mutex
	last *applySnapshot
}

// Compile-time assertions that Provider satisfies the backend contract and its
// optional rollback capability.
var (
	_ provider.Provider   = (*Provider)(nil)
	_ provider.Rollbacker = (*Provider)(nil)
)

// New returns a provider for the OPNsense firewall described by cfg.
func New(cfg ClientConfig) (*Provider, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Provider{c: client}, nil
}

// Get reads the live configuration and returns it as the canonical model.
//
// A live relation that names a uuid the plugin no longer holds is skipped, so
// Get still reports a configuration a foreign deletion left partially dangling.
// The skipped references are not logged: the provider carries no logger, and the
// omission is not an error. The next Apply rewrites each touched parent's
// relations from the live object and drops the dangling reference there; until
// then the model simply lacks that link, which is what the live plugin renders.
func (p *Provider) Get() (*haproxy.Model, error) {
	settings, err := p.c.Get()
	if err != nil {
		return nil, err
	}
	model, _, err := FromSettings(settings)
	if err != nil {
		return nil, err
	}
	return model, nil
}

// Apply applies a diff plan.
//
// An empty plan performs no read, no write and no reload. Otherwise the call
// runs in four stages inside the client's mutation lock:
//
//  1. Read the live configuration into a snapshot and validate ownership of
//     every operation against it. A conflict returns
//     *provider.ErrOwnershipConflict before any write.
//  2. Execute the plan's creates and updates in order. A create is written with
//     Set on a UUID the provider chooses (from the payload when set, otherwise
//     generated once), rather than with Add, whose server-assigned identifier a
//     lost response would hide from rollback. Each direct write posts the
//     mapper's own fields plus the ownership description.
//  3. Rewrite the relations of every parent the plan touched: the plugin keeps
//     linkedActions on frontends and backends, linkedServers and the health
//     check on backends, and linkedAcls on actions. The parent is read afresh
//     and its relation fields are replaced with the union of foreign entries
//     and owned entries, owned entries first in name order, so an adopted
//     frontend keeps every foreign rule while gaining senselb's.
//  4. Delete the plan's deleted objects, after stage 3 has removed every link
//     that pointed at them: the plugin's settings endpoints enable safe-delete,
//     which refuses to delete an object another object still references.
//
// A failed write or configtest restores the snapshot before returning. A
// successful batch ends with exactly one reconfigure.
//
// Every write goes through setBase, the plugin's upsert endpoint (see
// Set), and setBase runs whole-model validation server-side rather than
// validating only the submitted object. A pre-existing invalid FOREIGN object
// anywhere in the HAProxy model therefore fails every senselb create with a
// *ValidationError whose Fields map names foreign field paths rather than
// senselb's own. That signature is the diagnostic: the rejected plan is not at
// fault, and the foreign object must be repaired before a reconcile can
// succeed.
func (p *Provider) Apply(plan haproxy.Plan) error {
	if plan.IsEmpty() {
		return nil
	}
	return p.c.WithLock(func() error { return p.apply(plan) })
}

// Validate runs the plugin's configuration syntax check.
func (p *Provider) Validate() error {
	return p.c.ConfigTest()
}

// Reload regenerates the configuration and gracefully reloads HAProxy.
func (p *Provider) Reload() error {
	return p.c.Reconfigure()
}

// Rollback restores the snapshot taken before the last Apply.
//
// It is best-effort: every object is attempted, failures are collected, and a
// joined error reports them. No reconfigure is issued: the controller calls
// Rollback for a batch whose configtest failed, and that batch never reached
// the data plane. A successful Apply clears the retained snapshot, so Rollback
// after a good batch is a no-op and cannot revert configuration that is already
// serving traffic.
func (p *Provider) Rollback() error {
	p.mu.Lock()
	snapshot := p.last
	p.mu.Unlock()

	if snapshot == nil {
		return nil
	}
	return p.c.WithLock(func() error { return p.restore(snapshot) })
}

// apply runs one batch; the caller holds the client's mutation lock.
func (p *Provider) apply(plan haproxy.Plan) error {
	settings, err := p.c.Get()
	if err != nil {
		return fmt.Errorf("opnsense: apply: read current configuration: %w", err)
	}
	model, _, err := FromSettings(settings)
	if err != nil {
		return fmt.Errorf("opnsense: apply: %w", err)
	}

	snapshot := &applySnapshot{
		settings:    settings,
		model:       model,
		creates:     make(map[int]string, len(plan.Operations)),
		created:     make(map[string]bool, len(plan.Operations)),
		deleted:     make(map[string]bool, len(plan.Operations)),
		parentKinds: make(map[string]string, len(plan.Operations)),
	}
	if err := snapshot.assignCreateUUIDs(plan.Operations); err != nil {
		return err
	}
	p.setLast(snapshot)

	conflicts, err := preflight(snapshot, plan)
	if err != nil {
		return err
	}
	if len(conflicts) > 0 {
		return &provider.ErrOwnershipConflict{Refs: conflicts}
	}

	if err := p.execute(plan, snapshot); err != nil {
		return errors.Join(err, p.restore(snapshot))
	}
	if err := p.writeRelations(plan, snapshot); err != nil {
		return errors.Join(err, p.restore(snapshot))
	}
	if err := p.deleteObjects(plan, snapshot); err != nil {
		return errors.Join(err, p.restore(snapshot))
	}
	if err := p.c.ConfigTest(); err != nil {
		return errors.Join(fmt.Errorf("opnsense: apply: %w", err), p.restore(snapshot))
	}
	if err := p.c.Reconfigure(); err != nil {
		return fmt.Errorf("opnsense: apply: reconfigure: %w", err)
	}
	// The batch is live: a later Rollback must not revert it.
	p.setLast(nil)
	return nil
}

// setLast records the snapshot a later Rollback restores; nil clears it.
func (p *Provider) setLast(snapshot *applySnapshot) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.last = snapshot
}

// applySnapshot is the pre-apply state of one batch together with the writes it
// made, so rollback can undo exactly those writes.
type applySnapshot struct {
	// settings and model are the live configuration read before the first
	// write.
	settings Settings
	model    *haproxy.Model

	// creates maps an operation index to the UUID a create writes.
	creates map[int]string
	// ops holds the object kind and UUID each operation resolved to; delete
	// operations resolve to an empty UUID when the object is already absent.
	ops []resolvedOp
	// created marks the "kind/uuid" keys this batch brought into existence.
	created map[string]bool
	// deleted marks the "kind/uuid" keys this batch removed, so rollback can
	// recreate them before a parent's relations point at them again.
	deleted map[string]bool
	// parentKinds records the kind of a frontend or backend the plan writes,
	// including one created by the same batch, which the snapshot model cannot
	// know yet.
	parentKinds map[string]string
	// writes lists every mutation in the order it was made.
	writes []writeRecord
}

// resolvedOp is one plan operation after the provider resolved its live target.
type resolvedOp struct {
	kind    string
	uuid    string
	payload planPayload
}

// writeRecord is one mutation, used to replay the opposite write on rollback.
type writeRecord struct {
	kind string
	uuid string
}

// recordWrite appends one mutation to the rollback journal.
func (s *applySnapshot) recordWrite(kind, uuid string) {
	s.writes = append(s.writes, writeRecord{kind: kind, uuid: uuid})
}

// assignCreateUUIDs chooses the UUID of every create once, before any write:
// a payload that carries a UUID keeps it, every other create gets a fresh
// random identifier.
func (s *applySnapshot) assignCreateUUIDs(operations []haproxy.Operation) error {
	for i, op := range operations {
		if op.Kind != haproxy.OpCreate {
			continue
		}
		if payload, err := newPlanPayload(op.Object); err == nil && payload.uuid != "" {
			s.creates[i] = payload.uuid
			continue
		}
		uuid, err := newUUID()
		if err != nil {
			return err
		}
		s.creates[i] = uuid
	}
	return nil
}

// planPayload is the decoded payload of a create or update operation.
type planPayload struct {
	kind   string
	name   string
	uuid   string
	form   url.Values
	object any
}

// newPlanPayload maps an operation payload onto its object kind, name and
// mapper form.
func newPlanPayload(object any) (planPayload, error) {
	switch payload := object.(type) {
	case haproxy.Frontend:
		return planPayload{
			kind:   kindFrontend,
			name:   payload.Name,
			uuid:   payload.UUID,
			form:   ToFrontendForm(payload),
			object: payload,
		}, nil
	case haproxy.Backend:
		return planPayload{
			kind:   kindBackend,
			name:   payload.Name,
			uuid:   payload.UUID,
			form:   ToBackendForm(payload),
			object: payload,
		}, nil
	case haproxy.Server:
		return planPayload{
			kind:   kindServer,
			name:   payload.Name,
			uuid:   payload.UUID,
			form:   ToServerForm(payload),
			object: payload,
		}, nil
	case haproxy.ACL:
		return planPayload{
			kind:   kindACL,
			name:   payload.Name,
			uuid:   payload.UUID,
			form:   ToACLForm(payload),
			object: payload,
		}, nil
	case haproxy.Rule:
		return planPayload{
			kind:   kindAction,
			name:   payload.Name,
			uuid:   payload.UUID,
			form:   ToRuleForm(payload),
			object: payload,
		}, nil
	default:
		return planPayload{}, fmt.Errorf("opnsense: apply: unsupported operation payload %T", object)
	}
}

// stampOwnership posts the managed description alongside an object's own
// fields, so a later reconcile recognises the object as senselb's. The plugin
// only accepts the marker through the description field, which the canonical
// model does not carry for every kind. An unsupported kind is an error: the
// caller has already resolved the payload, so this cannot happen in practice.
func stampOwnership(kind string, form url.Values) error {
	prefix, err := formPrefix(kind)
	if err != nil {
		return err
	}
	form.Set(formKey(prefix, "description"), OwnedDescription)
	return nil
}

// preflight validates a plan against the snapshot without writing anything. The
// returned references name every operation that would touch an object senselb
// does not own; a structural defect in the plan is returned as an error
// instead.
func preflight(snapshot *applySnapshot, plan haproxy.Plan) ([]string, error) {
	var conflicts []string
	for _, op := range plan.Operations {
		switch op.Kind {
		case haproxy.OpCreate:
			payload, err := newPlanPayload(op.Object)
			if err != nil {
				return nil, err
			}
			if payload.name != op.Ref.Name {
				return nil, fmt.Errorf(
					"opnsense: apply: create %s: payload names %q", refString(op.Ref), payload.name,
				)
			}
			// senselb only creates objects in its own namespace.
			if !IsOwned(payload.name, OwnedDescription) {
				conflicts = append(conflicts, refString(op.Ref))
				continue
			}
			// A client-chosen UUID must not overwrite an existing object.
			if payload.uuid != "" {
				if _, exists := settingsObjectValues(snapshot.settings, payload.kind, payload.uuid); exists {
					conflicts = append(conflicts, refString(op.Ref))
					continue
				}
			}
			// The name must be free as well: the plugin holds names per
			// collection, so a live object of the same kind - owned or foreign -
			// with this name would be overwritten or duplicated by the create.
			if _, exists := settingsUUIDByName(snapshot.settings, payload.kind, payload.name); exists {
				conflicts = append(conflicts, refString(op.Ref))
			}
		case haproxy.OpUpdate:
			payload, err := newPlanPayload(op.Object)
			if err != nil {
				return nil, err
			}
			if payload.name != op.Ref.Name {
				return nil, fmt.Errorf(
					"opnsense: apply: update %s: payload names %q", refString(op.Ref), payload.name,
				)
			}
			live, found := locate(snapshot.model, snapshot.settings, op.Ref)
			if !found {
				return nil, fmt.Errorf("opnsense: apply: update %s: live object not found", refString(op.Ref))
			}
			if !IsOwned(live.name, live.description) {
				conflicts = append(conflicts, refString(op.Ref))
			}
		case haproxy.OpDelete:
			live, found := locate(snapshot.model, snapshot.settings, op.Ref)
			if !found {
				// The desired state already holds; the delete is a no-op.
				continue
			}
			if !IsOwned(live.name, live.description) {
				conflicts = append(conflicts, refString(op.Ref))
			}
		}
	}
	slices.Sort(conflicts)
	return conflicts, nil
}

// execute resolves every operation and writes the plan's creates and updates in
// order. Deletes are resolved here too, so the relation phase can see them, but
// they run later in deleteObjects, once the links to them are gone.
func (p *Provider) execute(plan haproxy.Plan, snapshot *applySnapshot) error {
	snapshot.ops = make([]resolvedOp, len(plan.Operations))
	for i, op := range plan.Operations {
		resolved, err := snapshot.resolve(i, op)
		if err != nil {
			return err
		}
		snapshot.ops[i] = resolved
		if op.Kind == haproxy.OpDelete || resolved.uuid == "" {
			continue
		}
		if err := p.c.Set(resolved.kind, resolved.uuid, resolved.payload.form); err != nil {
			return fmt.Errorf("opnsense: apply: %w", err)
		}
		snapshot.recordWrite(resolved.kind, resolved.uuid)
	}
	return nil
}

// deleteObjects removes the plan's deleted objects.
//
// It runs after writeRelations because the plugin's settings endpoints enable
// safe-delete (Api/SettingsController.php sets $internalModelUseSafeDelete), and
// ApiMutableModelControllerBase::delBase then refuses any uuid that still
// appears anywhere in the configuration with "Item in use by". Unlinking the
// parents first leaves nothing pointing at the object, so the delete is accepted.
func (p *Provider) deleteObjects(plan haproxy.Plan, snapshot *applySnapshot) error {
	for i, op := range plan.Operations {
		if op.Kind != haproxy.OpDelete {
			continue
		}
		resolved := snapshot.ops[i]
		if resolved.uuid == "" {
			// The object was already absent; nothing to delete.
			continue
		}
		if err := p.c.Del(resolved.kind, resolved.uuid); err != nil {
			return fmt.Errorf("opnsense: apply: %w", err)
		}
		snapshot.deleted[resolved.kind+"/"+resolved.uuid] = true
		snapshot.recordWrite(resolved.kind, resolved.uuid)
	}
	return nil
}

// resolve maps one operation onto the object kind and UUID it addresses.
func (s *applySnapshot) resolve(index int, op haproxy.Operation) (resolvedOp, error) {
	switch op.Kind {
	case haproxy.OpCreate:
		payload, err := newPlanPayload(op.Object)
		if err != nil {
			return resolvedOp{}, err
		}
		if err := stampOwnership(payload.kind, payload.form); err != nil {
			return resolvedOp{}, err
		}
		uuid := s.creates[index]
		key := payload.kind + "/" + uuid
		s.created[key] = true
		s.noteParent(op.Ref)
		return resolvedOp{kind: payload.kind, uuid: uuid, payload: payload}, nil
	case haproxy.OpUpdate:
		payload, err := newPlanPayload(op.Object)
		if err != nil {
			return resolvedOp{}, err
		}
		if err := stampOwnership(payload.kind, payload.form); err != nil {
			return resolvedOp{}, err
		}
		live, found := locate(s.model, s.settings, op.Ref)
		if !found {
			return resolvedOp{}, fmt.Errorf("opnsense: apply: update %s: live object not found", refString(op.Ref))
		}
		s.noteParent(op.Ref)
		return resolvedOp{kind: payload.kind, uuid: live.uuid, payload: payload}, nil
	case haproxy.OpDelete:
		kind := kindForObject(op.Ref.Kind)
		live, found := locate(s.model, s.settings, op.Ref)
		if !found {
			return resolvedOp{kind: kind}, nil
		}
		return resolvedOp{kind: kind, uuid: live.uuid}, nil
	default:
		return resolvedOp{}, fmt.Errorf("opnsense: apply: unknown operation kind %v", op.Kind)
	}
}

// noteParent remembers the kind of a frontend or backend the plan writes, so a
// child operation can find its parent even when the same batch created it.
func (s *applySnapshot) noteParent(ref haproxy.ObjectRef) {
	switch ref.Kind {
	case haproxy.ObjectFrontend:
		s.parentKinds[ref.Name] = kindFrontend
	case haproxy.ObjectBackend:
		s.parentKinds[ref.Name] = kindBackend
	}
}

// parentKey resolves the parent of a child operation to its kind and name.
func (s *applySnapshot) parentKey(name string) (parentKey, error) {
	if kind, known := s.parentKinds[name]; known {
		return parentKey{kind: kind, name: name}, nil
	}
	for _, frontend := range s.model.Frontends {
		if frontend.Name == name {
			return parentKey{kind: kindFrontend, name: name}, nil
		}
	}
	for _, backend := range s.model.Backends {
		if backend.Name == name {
			return parentKey{kind: kindBackend, name: name}, nil
		}
	}
	return parentKey{}, fmt.Errorf("opnsense: apply: child operation names unknown parent %q", name)
}

// writeRelations rewrites the relation fields of every parent the plan touched.
// It rereads the configuration inside the lock, so an adopted frontend is
// modified from its current live object and only through its relation fields.
func (p *Provider) writeRelations(plan haproxy.Plan, snapshot *applySnapshot) error {
	fresh, err := p.c.Get()
	if err != nil {
		return fmt.Errorf("opnsense: apply: reread configuration for relations: %w", err)
	}
	if err := p.writeRuleRelations(plan, snapshot, fresh); err != nil {
		return err
	}
	return p.writeParentRelations(plan, snapshot, fresh)
}

// writeRuleRelations restores the ACL and backend relations the mapper's rule
// form deliberately omits. It runs after every object write, so a referenced
// ACL or backend created by the batch is already present.
func (p *Provider) writeRuleRelations(plan haproxy.Plan, snapshot *applySnapshot, fresh Settings) error {
	prefix, err := formPrefix(kindAction)
	if err != nil {
		return err
	}
	for i, op := range plan.Operations {
		if op.Ref.Kind != haproxy.ObjectRule || op.Kind == haproxy.OpDelete {
			continue
		}
		resolved := snapshot.ops[i]
		rule, ok := resolved.payload.object.(haproxy.Rule)
		if !ok || resolved.uuid == "" {
			continue
		}
		form, found := formFromSettings(fresh, kindAction, resolved.uuid)
		if !found {
			continue
		}

		acls := make([]string, 0, len(rule.LinkedACLs))
		for _, name := range rule.LinkedACLs {
			uuid, err := relationUUID(fresh, kindACL, name)
			if err != nil {
				return fmt.Errorf("opnsense: apply: rule %q: %w", rule.Name, err)
			}
			acls = append(acls, uuid)
		}
		slices.Sort(acls)

		backend, err := relationUUID(fresh, kindBackend, rule.UseBackend)
		if err != nil {
			return fmt.Errorf("opnsense: apply: rule %q: %w", rule.Name, err)
		}

		server, err := relationUUID(fresh, kindServer, rule.UseServer)
		if err != nil {
			return fmt.Errorf("opnsense: apply: rule %q: %w", rule.Name, err)
		}

		// The form was read after the object's own write, so a rule with nothing
		// to relate and no stored relation is already complete: skip the
		// redundant second write.
		listKey := formListKey(prefix, "linkedAcls")
		backendKey := formKey(prefix, "use_backend")
		serverKey := formKey(prefix, "use_server")
		if slices.Equal(form[listKey], acls) &&
			form.Get(backendKey) == backend &&
			form.Get(serverKey) == server {
			continue
		}

		setListField(form, listKey, acls)
		setScalarField(form, backendKey, backend)
		setScalarField(form, serverKey, server)

		if err := p.c.Set(kindAction, resolved.uuid, form); err != nil {
			return fmt.Errorf("opnsense: apply: relate rule %q: %w", rule.Name, err)
		}
		snapshot.recordWrite(kindAction, resolved.uuid)
	}
	return nil
}

// parentKey identifies one frontend or backend whose relation fields the plan
// changes.
type parentKey struct {
	kind string
	name string
}

// parentDelta is the child membership one parent gains and loses in a batch,
// together with the payload of a parent the same batch creates or updates and
// whose own relation field the plan therefore decides.
type parentDelta struct {
	actionAdds    []string
	serverAdds    []string
	actionRemoves []string
	serverRemoves []string
	frontend      *haproxy.Frontend
}

// writeParentRelations merges the plan's child-linkage delta into each touched
// parent. The pre-apply snapshot supplies the base list, so a foreign entry is
// preserved even when the parent's own scalar fields were rewritten first.
func (p *Provider) writeParentRelations(plan haproxy.Plan, snapshot *applySnapshot, fresh Settings) error {
	deltas := map[parentKey]*parentDelta{}
	deltaFor := func(key parentKey) *parentDelta {
		delta, known := deltas[key]
		if !known {
			delta = &parentDelta{}
			deltas[key] = delta
		}
		return delta
	}

	for i, op := range plan.Operations {
		resolved := snapshot.ops[i]
		switch op.Kind {
		case haproxy.OpCreate, haproxy.OpUpdate:
			switch op.Ref.Kind {
			case haproxy.ObjectFrontend:
				delta := deltaFor(parentKey{kind: kindFrontend, name: op.Ref.Name})
				if frontend, ok := resolved.payload.object.(haproxy.Frontend); ok {
					delta.frontend = &frontend
				}
			case haproxy.ObjectBackend:
				// Only a parent's own write rewrites its form; a child write
				// leaves the parent's membership alone.
				deltaFor(parentKey{kind: kindBackend, name: op.Ref.Name})
			case haproxy.ObjectRule:
				if op.Kind != haproxy.OpCreate {
					continue
				}
				parent, err := snapshot.parentKey(op.Ref.Parent)
				if err != nil {
					return err
				}
				delta := deltaFor(parent)
				delta.actionAdds = append(delta.actionAdds, resolved.uuid)
			case haproxy.ObjectServer:
				if op.Kind != haproxy.OpCreate {
					continue
				}
				delta := deltaFor(parentKey{kind: kindBackend, name: op.Ref.Parent})
				delta.serverAdds = append(delta.serverAdds, resolved.uuid)
			}
		case haproxy.OpDelete:
			switch op.Ref.Kind {
			case haproxy.ObjectRule:
				if resolved.uuid == "" {
					continue
				}
				parent, err := snapshot.parentKey(op.Ref.Parent)
				if err != nil {
					return err
				}
				delta := deltaFor(parent)
				delta.actionRemoves = append(delta.actionRemoves, resolved.uuid)
			case haproxy.ObjectServer:
				if resolved.uuid == "" {
					continue
				}
				delta := deltaFor(parentKey{kind: kindBackend, name: op.Ref.Parent})
				delta.serverRemoves = append(delta.serverRemoves, resolved.uuid)
			}
		}
	}

	parents := make([]parentKey, 0, len(deltas))
	for key := range deltas {
		parents = append(parents, key)
	}
	slices.SortFunc(parents, func(a, b parentKey) int {
		return cmp.Or(cmp.Compare(a.kind, b.kind), cmp.Compare(a.name, b.name))
	})

	for _, key := range parents {
		if err := p.applyParentDelta(key, snapshot, fresh, deltas[key]); err != nil {
			return err
		}
	}
	return nil
}

// applyParentDelta rewrites one parent's relation fields. An empty delta still
// rewrites the parent's own relation form, which is what a freshly created or
// updated frontend or backend needs.
func (p *Provider) applyParentDelta(
	key parentKey,
	snapshot *applySnapshot,
	fresh Settings,
	delta *parentDelta,
) error {
	uuid, found := settingsUUIDByName(fresh, key.kind, key.name)
	if !found {
		// The parent was deleted by this batch; it has no relations to write.
		return nil
	}
	form, found := formFromSettings(fresh, key.kind, uuid)
	if !found {
		return nil
	}
	prefix, err := formPrefix(key.kind)
	if err != nil {
		return err
	}
	base, _ := settingsObjectValues(snapshot.settings, key.kind, uuid)

	actions := mergeLinkage(selectedField(base, "linkedActions"), delta.actionAdds, delta.actionRemoves)
	setListField(form, formListKey(prefix, "linkedActions"), orderedLinkage(actions, fresh, kindAction))

	switch key.kind {
	case kindBackend:
		servers := mergeLinkage(selectedField(base, "linkedServers"), delta.serverAdds, delta.serverRemoves)
		setListField(form, formListKey(prefix, "linkedServers"), orderedLinkage(servers, fresh, kindServer))
		// A health check is a shared object the canonical model does not name,
		// so the live relation is preserved rather than provisioned.
		setScalarField(form, formKey(prefix, "healthCheck"), selectedValue(base, "healthCheck"))
	case kindFrontend:
		defaultBackend := selectedValue(base, "defaultBackend")
		if delta.frontend != nil {
			defaultBackend, err = relationUUID(fresh, kindBackend, delta.frontend.DefaultBackend)
			if err != nil {
				return fmt.Errorf("opnsense: apply: frontend %q: %w", key.name, err)
			}
		}
		setScalarField(form, formKey(prefix, "defaultBackend"), defaultBackend)
	}

	if err := p.c.Set(key.kind, uuid, form); err != nil {
		return fmt.Errorf("opnsense: apply: relate %s %q: %w", key.kind, key.name, err)
	}
	snapshot.recordWrite(key.kind, uuid)
	return nil
}

// mergeLinkage unions the base membership with the batch's additions and
// removes its deletions, keeping each UUID once.
func mergeLinkage(base, add, remove []string) []string {
	removed := make(map[string]bool, len(remove))
	for _, uuid := range remove {
		removed[uuid] = true
	}
	seen := make(map[string]bool, len(base)+len(add))
	merged := make([]string, 0, len(base)+len(add))
	for _, uuid := range base {
		if uuid == "" || removed[uuid] || seen[uuid] {
			continue
		}
		seen[uuid] = true
		merged = append(merged, uuid)
	}
	for _, uuid := range add {
		if uuid == "" || seen[uuid] {
			continue
		}
		seen[uuid] = true
		merged = append(merged, uuid)
	}
	return merged
}

// orderedLinkage orders a parent's linked objects: owned objects first, in name
// order, then foreign objects in UUID order. Owned rules therefore evaluate
// ahead of a listener's catch-all foreign rules, which is the routing
// precedence senselb promises.
func orderedLinkage(uuids []string, fresh Settings, kind string) []string {
	type entry struct {
		uuid  string
		name  string
		owned bool
	}
	entries := make([]entry, 0, len(uuids))
	for _, uuid := range uuids {
		values, found := settingsObjectValues(fresh, kind, uuid)
		if !found {
			continue
		}
		name, _ := values["name"].(string)
		description, _ := values["description"].(string)
		entries = append(entries, entry{uuid: uuid, name: name, owned: IsOwned(name, description)})
	}
	slices.SortFunc(entries, func(a, b entry) int {
		if a.owned != b.owned {
			if a.owned {
				return -1
			}
			return 1
		}
		if a.owned {
			return cmp.Compare(a.name, b.name)
		}
		return cmp.Compare(a.uuid, b.uuid)
	})

	ordered := make([]string, len(entries))
	for i, item := range entries {
		ordered[i] = item.uuid
	}
	return ordered
}

// restore replays the snapshot over the writes a batch made. Objects the batch
// deleted are recreated first, so a parent restored afterwards can link them;
// every other written object is then set back to its snapshot values, which
// also drops the links to objects the batch created; those created objects are
// deleted last, because the plugin's safe-delete refuses any uuid a parent still
// references. It attempts every write and joins the failures.
func (p *Provider) restore(snapshot *applySnapshot) error {
	var errs []error
	errs = append(errs, p.replay(snapshot, func(key string) bool {
		return snapshot.deleted[key] && !snapshot.created[key]
	})...)
	errs = append(errs, p.replay(snapshot, func(key string) bool {
		return !snapshot.created[key] && !snapshot.deleted[key]
	})...)
	errs = append(errs, p.replay(snapshot, func(key string) bool {
		return snapshot.created[key]
	})...)
	return errors.Join(errs...)
}

// replay restores the journal entries of one class, newest first and once per
// object.
func (p *Provider) replay(snapshot *applySnapshot, include func(key string) bool) []error {
	seen := make(map[string]bool, len(snapshot.writes))
	var errs []error
	for i := len(snapshot.writes) - 1; i >= 0; i-- {
		record := snapshot.writes[i]
		key := record.kind + "/" + record.uuid
		if seen[key] || !include(key) {
			continue
		}
		seen[key] = true

		if snapshot.created[key] {
			if err := p.c.Del(record.kind, record.uuid); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		form, found := formFromSettings(snapshot.settings, record.kind, record.uuid)
		if !found {
			errs = append(errs, fmt.Errorf(
				"opnsense: rollback: snapshot has no %s object %s", record.kind, record.uuid,
			))
			continue
		}
		if err := p.c.Set(record.kind, record.uuid, form); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// liveObject is one object resolved from the snapshot.
type liveObject struct {
	uuid        string
	name        string
	description string
}

// locate resolves an object reference against the live model, scoping children
// to their parent, and reads its description from the raw settings so
// ownership can be decided.
func locate(model *haproxy.Model, settings Settings, ref haproxy.ObjectRef) (liveObject, bool) {
	var uuid, name string
	switch ref.Kind {
	case haproxy.ObjectFrontend:
		for _, frontend := range model.Frontends {
			if frontend.Name == ref.Name {
				uuid, name = frontend.UUID, frontend.Name
			}
		}
	case haproxy.ObjectBackend:
		for _, backend := range model.Backends {
			if backend.Name == ref.Name {
				uuid, name = backend.UUID, backend.Name
			}
		}
	case haproxy.ObjectServer:
		for _, backend := range model.Backends {
			if backend.Name != ref.Parent {
				continue
			}
			for _, server := range backend.Servers {
				if server.Name == ref.Name {
					uuid, name = server.UUID, server.Name
				}
			}
		}
	case haproxy.ObjectACL:
		uuid, name = locateACL(model, ref)
	case haproxy.ObjectRule:
		uuid, name = locateRule(model, ref)
	}
	if uuid == "" {
		return liveObject{}, false
	}
	return liveObject{
		uuid:        uuid,
		name:        name,
		description: settingsDescription(settings, kindForObject(ref.Kind), uuid),
	}, true
}

// locateACL finds an ACL among the children of the referenced parent.
func locateACL(model *haproxy.Model, ref haproxy.ObjectRef) (string, string) {
	for _, frontend := range model.Frontends {
		if frontend.Name != ref.Parent {
			continue
		}
		for _, acl := range frontend.ACLs {
			if acl.Name == ref.Name {
				return acl.UUID, acl.Name
			}
		}
	}
	for _, backend := range model.Backends {
		if backend.Name != ref.Parent {
			continue
		}
		for _, acl := range backend.ACLs {
			if acl.Name == ref.Name {
				return acl.UUID, acl.Name
			}
		}
	}
	return "", ""
}

// locateRule finds a rule among the children of the referenced parent.
func locateRule(model *haproxy.Model, ref haproxy.ObjectRef) (string, string) {
	for _, frontend := range model.Frontends {
		if frontend.Name != ref.Parent {
			continue
		}
		for _, rule := range frontend.Rules {
			if rule.Name == ref.Name {
				return rule.UUID, rule.Name
			}
		}
	}
	for _, backend := range model.Backends {
		if backend.Name != ref.Parent {
			continue
		}
		for _, rule := range backend.Rules {
			if rule.Name == ref.Name {
				return rule.UUID, rule.Name
			}
		}
	}
	return "", ""
}

// kindForObject maps a plan object kind onto the client's object kind.
func kindForObject(kind haproxy.ObjectKind) string {
	switch kind {
	case haproxy.ObjectFrontend:
		return kindFrontend
	case haproxy.ObjectBackend:
		return kindBackend
	case haproxy.ObjectServer:
		return kindServer
	case haproxy.ObjectACL:
		return kindACL
	case haproxy.ObjectRule:
		return kindAction
	default:
		return ""
	}
}

// refString renders an object reference for an error or a diagnostic.
func refString(ref haproxy.ObjectRef) string {
	if ref.Parent == "" {
		return string(ref.Kind) + " " + ref.Name
	}
	return string(ref.Kind) + " " + ref.Parent + "/" + ref.Name
}

// listFormFields are the plugin fields the API accepts as a repeated form
// field. They carry a multi-valued relation, so a snapshot form repeats them
// rather than collapsing them into one value.
var listFormFields = map[string]bool{
	"bind":             true,
	"ssl_certificates": true,
	"linkedActions":    true,
	"linkedAcls":       true,
	"linkedServers":    true,
}

// scalarSelectFields are the plugin fields that hold a single selection: enums
// and one-to-one relations. Every other select object in the plugin model is a
// multi-select, so a stored object with more than one selected key must be
// posted as repeated field[] entries or the plugin keeps only the first.
var scalarSelectFields = map[string]bool{
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

// formFromSettings renders one live plugin object as the complete form that
// recreates it. It is the rollback path and the read-modify-write base for a
// relation merge: every stored field is posted, including fields the canonical
// model does not carry, so the write is a faithful restore.
func formFromSettings(settings Settings, kind, uuid string) (url.Values, bool) {
	object, found := settingsObjectValues(settings, kind, uuid)
	if !found {
		return nil, false
	}
	prefix, err := formPrefix(kind)
	if err != nil {
		return nil, false
	}
	form := url.Values{}
	for _, field := range slices.Sorted(maps.Keys(object)) {
		if listFormFields[field] {
			values, err := selectedKeys(object[field])
			if err != nil {
				continue
			}
			for _, value := range values {
				form.Add(formListKey(prefix, field), value)
			}
			continue
		}
		if values, isSelect := selectedFieldValues(object[field]); isSelect &&
			!scalarSelectFields[field] && len(values) > 1 {
			for _, value := range values {
				form.Add(formListKey(prefix, field), value)
			}
			continue
		}
		setRawValue(form, formKey(prefix, field), object[field])
	}
	return form, true
}

// selectedFieldValues returns a stored field's selected keys and reports whether
// the field is a select object at all.
func selectedFieldValues(raw any) ([]string, bool) {
	if _, ok := raw.(map[string]any); !ok {
		return nil, false
	}
	keys, err := selectedKeys(raw)
	if err != nil {
		return nil, false
	}
	return keys, true
}

// setRawValue renders one stored field value as a scalar form value.
func setRawValue(form url.Values, key string, raw any) {
	switch value := raw.(type) {
	case nil:
	case string:
		form.Set(key, value)
	case bool:
		form.Set(key, booleanValue(value))
	case float64:
		form.Set(key, strconv.FormatFloat(value, 'f', -1, 64))
	case map[string]any:
		form.Set(key, flattenSelect(value))
	}
}

// setListField replaces a repeated form field with values, in order.
func setListField(form url.Values, key string, values []string) {
	form.Del(key)
	for _, value := range values {
		form.Add(key, value)
	}
}

// setScalarField replaces a scalar relation, clearing it when value is empty.
func setScalarField(form url.Values, key, value string) {
	if value == "" {
		form.Del(key)
		return
	}
	form.Set(key, value)
}

// selectedField returns the selected keys of a stored relation.
func selectedField(values map[string]any, field string) []string {
	if values == nil {
		return nil
	}
	keys, err := selectedKeys(values[field])
	if err != nil {
		return nil
	}
	return keys
}

// selectedValue returns the single selected key of a stored relation.
func selectedValue(values map[string]any, field string) string {
	if values == nil {
		return ""
	}
	return flattenSelect(values[field])
}

// settingsCollection returns one collection's uuid-keyed objects.
func settingsCollection(settings Settings, kind string) (map[string]any, bool) {
	root, err := rootObject(settings)
	if err != nil {
		return nil, false
	}
	prefix, err := formPrefix(kind)
	if err != nil {
		return nil, false
	}
	container, ok := asObjectMap(root[prefix+"s"])
	if !ok {
		return nil, false
	}
	return asObjectMap(container[prefix])
}

// settingsObjectValues returns one stored object's fields.
func settingsObjectValues(settings Settings, kind, uuid string) (map[string]any, bool) {
	objects, ok := settingsCollection(settings, kind)
	if !ok {
		return nil, false
	}
	values, ok := objects[uuid].(map[string]any)
	return values, ok
}

// settingsDescription returns one stored object's description.
func settingsDescription(settings Settings, kind, uuid string) string {
	values, found := settingsObjectValues(settings, kind, uuid)
	if !found {
		return ""
	}
	description, _ := values["description"].(string)
	return description
}

// settingsUUIDByName resolves an object's name to its UUID, deterministically
// when malformed live data repeats a name.
func settingsUUIDByName(settings Settings, kind, name string) (string, bool) {
	objects, ok := settingsCollection(settings, kind)
	if !ok || name == "" {
		return "", false
	}
	for _, uuid := range slices.Sorted(maps.Keys(objects)) {
		values, ok := objects[uuid].(map[string]any)
		if !ok {
			continue
		}
		if objectName, _ := values["name"].(string); objectName == name {
			return uuid, true
		}
	}
	return "", false
}

// relationUUID resolves a relation target by name; an empty name clears the
// relation and an unknown name is an error, because writing a dangling
// reference would leave a configuration that cannot load.
func relationUUID(settings Settings, kind, name string) (string, error) {
	if name == "" {
		return "", nil
	}
	uuid, found := settingsUUIDByName(settings, kind, name)
	if !found {
		return "", fmt.Errorf("relation target %s %q not found", kind, name)
	}
	return uuid, nil
}

// newUUID returns a random RFC 4122 version 4 identifier.
func newUUID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("opnsense: generate uuid: %w", err)
	}
	bytes[6] = bytes[6]&0x0f | 0x40 // version 4
	bytes[8] = bytes[8]&0x3f | 0x80 // RFC 4122 variant
	return fmt.Sprintf(
		"%x-%x-%x-%x-%x",
		bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16],
	), nil
}
