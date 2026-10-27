// Package provider defines the backend contract that isolates the controller
// from any concrete load balancer implementation.
//
// A Provider reads the live configuration into the canonical model, applies a
// diff plan, syntax-checks the result, and reloads the data plane. The concrete
// implementations (OPNsense, later OpenWrt) live in their own packages; the
// controller depends only on the interfaces and error types declared here, so it
// never imports a specific backend.
package provider

import (
	"strings"

	"github.com/yasn77/senselb/pkg/haproxy"
)

// Provider is the backend contract: read live config into the canonical model,
// apply a diff plan, syntax-check, and reload.
//
// Apply must be atomic with respect to its own snapshot: a failed write leaves
// the backend either untouched or restorable through Rollbacker.
type Provider interface {
	// Get reads the live configuration and returns it as the canonical model.
	Get() (*haproxy.Model, error)
	// Apply applies a diff plan. Writes are made atomically with respect to
	// the snapshot taken for the operation.
	//
	// The plan is object-level and deliberately omits linkage. A parent payload
	// has its child collections stripped, and a change confined to children
	// emits no parent operation at all. Platforms that store the link on the
	// parent (the OPNsense plugin keeps linkedActions on a frontend and
	// linkedServers on a backend) therefore never receive that linkage from the
	// plan. Apply MUST recompute it while applying: after the create and delete
	// operations for a parent's children, rewrite that parent's link list from
	// the live model Get returned, correlating children by ObjectRef.Parent, and
	// persist the update itself. Apply owns that parent write; Diff will not
	// emit one.
	Apply(plan haproxy.Plan) error
	// Validate runs the backend's configuration syntax check.
	Validate() error
	// Reload reconfigures the backend and performs a graceful reload.
	Reload() error
}

// Rollbacker is an optional capability, asserted by the reconciler for rollback
// support. A provider that implements it can restore the snapshot it captured
// before Apply.
type Rollbacker interface {
	// Rollback restores the pre-Apply snapshot.
	Rollback() error
}

// ErrConfigTest reports a failed configuration syntax check. The controller
// treats it as a change-related failure and rolls back, unlike a transport
// error, which leaves the backend state unknown but unmodified by intent.
type ErrConfigTest struct {
	// Message is the diagnostic reported by the configuration test.
	Message string
}

// Error implements error.
func (e *ErrConfigTest) Error() string {
	if e.Message == "" {
		return "configtest failed"
	}
	return "configtest failed: " + e.Message
}

// ErrOwnershipConflict reports a plan step that would touch an object senselb
// does not own, or an adopted frontend beyond the linked-list merge. The
// controller detects it without importing a concrete provider package.
type ErrOwnershipConflict struct {
	// Refs lists the offending object references, for example
	// "frontend ingress-HTTPS".
	Refs []string
}

// Error implements error.
func (e *ErrOwnershipConflict) Error() string {
	if len(e.Refs) == 0 {
		return "ownership conflict"
	}
	return "ownership conflict: " + strings.Join(e.Refs, ", ")
}

// Compile-time assertions that the error types satisfy error.
var (
	_ error = (*ErrConfigTest)(nil)
	_ error = (*ErrOwnershipConflict)(nil)
)
