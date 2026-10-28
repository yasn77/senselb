package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/yasn77/senselb/pkg/config"
	"github.com/yasn77/senselb/pkg/haproxy"
	"github.com/yasn77/senselb/pkg/provider"
)

// OwnedPrefix starts the name of every top-level object senselb manages.
//
// It deliberately duplicates opnsense.OwnedPrefix: this package must not import
// a concrete provider, so the naming convention is part of the
// provider-agnostic contract. Ownership itself is decided in two layers. The
// queue only uses the name prefix, together with its own inventory, to decide
// which live objects are in scope. provider.Apply's preflight enforces the full
// check - prefix and description - before it writes anything. A name collision
// that passes the first layer is therefore rejected, not clobbered, by the
// second.
const OwnedPrefix = "senselb-"

// DefaultDebounce is how long the pipeline waits for the enqueue stream to go
// quiet before it drains, so a burst of Service updates becomes one apply.
const DefaultDebounce = 2 * time.Second

// Backoff bounds for a failed batch. A transport failure leaves the backend
// state unknown, so the whole batch is retried after an exponentially growing
// delay rather than hammering a firewall that is down.
const (
	defaultBackoffBase = time.Second
	maxBackoff         = 5 * time.Minute
)

// notifyCapacity is one: a notification only says "there is work", so a burst
// of enqueues collapses into one wake-up.
const notifyCapacity = 1

// Pipeline metrics, served by controller-runtime's metrics server on the
// registry it already exposes. They are deliberately queue-level counters: a
// drain is one apply, whatever number of Services it covers.
var (
	appliesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "senselb_applies_total",
		Help: "Number of successful apply cycles.",
	})
	apiErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "senselb_api_errors_total",
		Help: "Number of failed provider or Kubernetes API calls in the apply pipeline.",
	})
	configTestFailuresTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "senselb_configtest_failures_total",
		Help: "Number of apply cycles rolled back because the provider configuration test failed.",
	})
)

func init() {
	metrics.Registry.MustRegister(appliesTotal, apiErrorsTotal, configTestFailuresTotal)
}

// RebuildAllKey asks the apply queue to rebuild the whole desired model from the
// ownership store. It is the zero NamespacedName, which no real Service can
// carry, and is never itself built into a contribution. The cleanup paths
// enqueue it after removing a Service's store entries, so the next drain no
// longer contains that Service and the diff prunes its HAProxy objects.
var RebuildAllKey = types.NamespacedName{}

// ContributionFunc builds one Service's desired fragment: it fetches the
// Service, reads its annotations and targets, and calls BuildContribution. A
// Service that no longer exists, is not a LoadBalancer, or is disabled yields a
// nil model and no issues.
type ContributionFunc func(ctx context.Context, key types.NamespacedName) (*haproxy.Model, []error)

// ApplyQueue is the single-flight apply pipeline.
//
// One worker coalesces every enqueue into one apply cycle: it enumerates the
// managed Services (the store's inventory plus any pending key), builds one
// desired model, reads the live configuration, diffs, applies, and only then
// publishes status and the name-to-UUID inventory. It is leader-only: a
// non-leader replica must never touch the firewall, so Run's leader-election
// hook reports true and the manager starts it only on the elected replica.
//
// The desired model is rebuilt in full on every drain from the store and the
// pending set, and the diff is idempotent. A crash between the provider writes
// and the reconfigure therefore converges on the next drain: the same desired
// state is computed again and only the remaining difference is applied.
//
// Orphaned objects are a deliberate exception. A live object with senselb's
// name prefix that no inventory accounts for is left untouched, so a lost store
// cannot make the controller delete work it cannot attribute. The inventory is
// the store's contents plus, for one drain, the contents observed at the last
// successful drain: that is what lets a Service the reconciler just removed from
// the store still have its objects deleted. The residual risk is a stale object
// surviving until an operator removes it.
type ApplyQueue struct {
	Provider provider.Provider
	Client   client.Client
	Store    *Store
	Recorder record.EventRecorder
	Config   *config.Config

	// BuildContribution is injected so the queue and the reconciler share one
	// build path; see ServiceReconciler.BuildForService.
	BuildContribution ContributionFunc

	// Debounce is the quiet window that collapses a burst of enqueues. A zero
	// value selects DefaultDebounce.
	Debounce time.Duration

	mu      sync.Mutex
	pending map[types.NamespacedName]struct{}
	notify  chan struct{}
	backoff time.Duration
	// inventory is the object names the store held at the last successful
	// drain. It keeps a just-removed Service's objects in scope for the drain
	// that must delete them: the reconciler deletes the inventory entries
	// before it enqueues the rebuild, so the current store alone cannot
	// authorise that delete.
	inventory map[string]struct{}

	// backoffBase is the first retry delay. It is a field so tests can shrink
	// it without waiting a second per attempt; a zero value selects
	// defaultBackoffBase.
	backoffBase time.Duration
}

// NewApplyQueue returns an empty queue with the default debounce window. The
// exported fields are set after construction by the caller that wires the
// manager.
func NewApplyQueue() *ApplyQueue {
	queue := &ApplyQueue{Debounce: DefaultDebounce}
	queue.mu.Lock()
	queue.ensureLocked()
	queue.mu.Unlock()
	return queue
}

// Enqueue records key for the next apply cycle and wakes the worker. It never
// blocks: the notification channel holds at most one token and the key set
// deduplicates, so a burst of Service events costs one wake-up and one entry.
func (q *ApplyQueue) Enqueue(key types.NamespacedName) {
	q.mu.Lock()
	q.ensureLocked()
	q.pending[key] = struct{}{}
	notify := q.notify
	q.mu.Unlock()

	select {
	case notify <- struct{}{}:
	default:
	}
}

// Run drains the queue until ctx is cancelled. It is the manager.Runnable body;
// Start calls it.
func (q *ApplyQueue) Run(ctx context.Context) error {
	q.mu.Lock()
	q.ensureLocked()
	q.mu.Unlock()

	// Startup drift reconcile: the first drain rebuilds the desired model from
	// the whole store, so a change made while the controller was down is
	// corrected without waiting for a Service event.
	q.Enqueue(RebuildAllKey)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-q.notify:
		}

		if !q.waitForQuiet(ctx) {
			return nil
		}

		batch := q.takePending()
		err := q.drain(ctx, batch)
		if err == nil {
			q.resetBackoff()
			continue
		}
		if ctx.Err() != nil {
			return nil
		}

		delay := q.nextBackoff()
		slog.WarnContext(ctx, "apply cycle failed; retrying after backoff",
			"error", err, "retryIn", delay.String(), "services", len(batch))

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}

		q.requeue(batch)
	}
}

// Start implements manager.Runnable.
func (q *ApplyQueue) Start(ctx context.Context) error { return q.Run(ctx) }

// NeedLeaderElection implements manager.LeaderElectionRunnable. The firewall is
// a single shared target, so only the elected replica may program it.
func (q *ApplyQueue) NeedLeaderElection() bool { return true }

// Keys returns the keys waiting for the next drain, sorted. It is the observable
// contract the reconciler tests rely on: Enqueue records a request and Keys
// reports it without a provider call.
func (q *ApplyQueue) Keys() []types.NamespacedName {
	q.mu.Lock()
	defer q.mu.Unlock()

	keys := make([]types.NamespacedName, 0, len(q.pending))
	for key := range q.pending {
		keys = append(keys, key)
	}
	sortKeys(keys)
	return keys
}

// ensureLocked initialises the zero-value fields. The caller holds q.mu.
func (q *ApplyQueue) ensureLocked() {
	if q.pending == nil {
		q.pending = make(map[types.NamespacedName]struct{})
	}
	if q.notify == nil {
		q.notify = make(chan struct{}, notifyCapacity)
	}
	if q.Debounce <= 0 {
		q.Debounce = DefaultDebounce
	}
	if q.backoffBase <= 0 {
		q.backoffBase = defaultBackoffBase
	}
}

// waitForQuiet debounces: it returns true once no notification has arrived for
// one full Debounce window, and false when ctx is cancelled first. Each new
// notification restarts the window, so only the end of a burst drains.
func (q *ApplyQueue) waitForQuiet(ctx context.Context) bool {
	q.mu.Lock()
	window := q.Debounce
	if window <= 0 {
		window = DefaultDebounce
	}
	notify := q.notify
	q.mu.Unlock()

	for {
		timer := time.NewTimer(window)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-notify:
			timer.Stop()
		case <-timer.C:
			return true
		}
	}
}

// takePending atomically snapshots and clears the pending set.
func (q *ApplyQueue) takePending() []types.NamespacedName {
	q.mu.Lock()
	defer q.mu.Unlock()

	keys := make([]types.NamespacedName, 0, len(q.pending))
	for key := range q.pending {
		keys = append(keys, key)
	}
	clear(q.pending)
	sortKeys(keys)
	return keys
}

// requeue puts a failed batch back on the queue after the backoff delay. An
// empty batch still needs a retry, so the rebuild sentinel is used.
func (q *ApplyQueue) requeue(batch []types.NamespacedName) {
	if len(batch) == 0 {
		q.Enqueue(RebuildAllKey)
		return
	}
	for _, key := range batch {
		q.Enqueue(key)
	}
}

// resetBackoff clears the failure delay after a successful cycle.
func (q *ApplyQueue) resetBackoff() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.backoff = 0
}

// nextBackoff returns the delay for the next retry and records it: the base
// delay on the first failure, then doubling, capped at maxBackoff.
func (q *ApplyQueue) nextBackoff() time.Duration {
	q.mu.Lock()
	defer q.mu.Unlock()

	base := q.backoffBase
	if base <= 0 {
		base = defaultBackoffBase
	}
	switch {
	case q.backoff <= 0:
		q.backoff = base
	case q.backoff >= maxBackoff:
		q.backoff = maxBackoff
	default:
		q.backoff = min(q.backoff*2, maxBackoff)
	}
	return q.backoff
}

// currentBackoff reports the delay the next failure would use. It exists for
// tests and diagnostics.
func (q *ApplyQueue) currentBackoff() time.Duration {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.backoff
}

// drain runs one apply cycle over the whole managed set.
//
// The returned error is retryable: it is a transport or API failure, and Run
// backs off and retries the batch. A settled outcome - a rolled-back config
// test or an ownership conflict - is published as a condition and returns nil,
// because retrying cannot change it until the desired state changes.
func (q *ApplyQueue) drain(ctx context.Context, batch []types.NamespacedName) error {
	if q.Provider == nil || q.Store == nil || q.Client == nil {
		return errors.New("apply queue: provider, store and client are required")
	}
	if q.BuildContribution == nil {
		return errors.New("apply queue: build function is required")
	}

	services, err := q.managedServices(ctx, batch)
	if err != nil {
		apiErrorsTotal.Inc()
		return err
	}
	// Nothing is managed and no inventory is remembered: there is no desired
	// state to compare, so the provider is not called at all. The remembered
	// inventory is the exception, because it may hold a deleted Service's
	// objects that still need removing.
	if len(services) == 0 && !q.hasInventory() {
		return nil
	}

	contributions := make([]serviceContribution, 0, len(services))
	for _, key := range services {
		model, issues := q.BuildContribution(ctx, key)
		var retry *RetryableBuildError
		for _, issue := range issues {
			if errors.As(issue, &retry) {
				return retry
			}
		}
		if model == nil {
			continue
		}
		contributions = append(contributions, serviceContribution{key: key, model: model, issues: issues})
	}

	desired, failures := mergeContributions(q.Config, contributions)
	for _, key := range sortedKeys(failures) {
		if err := q.publishProblem(ctx, key, ReasonConfigError, failures[key]); err != nil {
			apiErrorsTotal.Inc()
			return err
		}
	}

	applied := make([]serviceContribution, 0, len(contributions))
	for _, contribution := range contributions {
		if _, failed := failures[contribution.key]; failed {
			continue
		}
		applied = append(applied, contribution)
	}

	live, err := q.Provider.Get()
	if err != nil {
		apiErrorsTotal.Inc()
		return fmt.Errorf("read live configuration: %w", err)
	}
	if live == nil {
		live = &haproxy.Model{}
	}

	inventory, err := q.inventoryNames(ctx)
	if err != nil {
		apiErrorsTotal.Inc()
		return err
	}

	desiredNames := topLevelNames(desired)
	filtered := filterLive(live, desiredNames, q.scope(inventory), q.declaredFrontends())
	hydrateAdoptedFrontends(desired, live)

	plan, err := haproxy.Diff(desired, filtered)
	if err != nil {
		return fmt.Errorf("diff desired and live configuration: %w", err)
	}

	return q.apply(ctx, plan, applied)
}

// apply runs the plan and publishes its outcome.
func (q *ApplyQueue) apply(ctx context.Context, plan *haproxy.Plan, applied []serviceContribution) error {
	applyErr := q.Provider.Apply(*plan)

	var configTest *provider.ErrConfigTest
	var conflict *provider.ErrOwnershipConflict
	switch {
	case applyErr == nil:
		return q.commit(ctx, applied)
	case errors.As(applyErr, &configTest):
		configTestFailuresTotal.Inc()
		retry, rollbackErr := q.rollback(ctx)
		message := "configtest failed after apply; rolled back: " + configTest.Error()
		if rollbackErr != nil {
			message = "configtest failed after apply; " + rollbackErr.Error()
		}
		failErr := q.fail(ctx, applied, message)
		if retry {
			return errors.Join(rollbackErr, failErr)
		}
		return failErr
	case errors.As(applyErr, &conflict):
		return q.fail(ctx, applied, "ownership conflict: "+conflict.Error())
	default:
		apiErrorsTotal.Inc()
		return fmt.Errorf("apply plan: %w", applyErr)
	}
}

// rollback restores the pre-apply snapshot when the provider supports it.
//
// retry reports whether the batch must be attempted again: a rollback that
// itself failed leaves the backend in an unknown state. A provider without the
// optional capability cannot undo the batch; that is reported once, as a
// warning, and is not retried because no retry can change it.
func (q *ApplyQueue) rollback(ctx context.Context) (retry bool, err error) {
	rollbacker, ok := q.Provider.(provider.Rollbacker)
	if !ok {
		slog.WarnContext(ctx, "provider does not implement rollback; a failed config test cannot be undone")
		return false, errors.New("the provider cannot roll back")
	}
	if err := rollbacker.Rollback(); err != nil {
		slog.ErrorContext(ctx, "rollback of a failed apply did not complete", "error", err)
		return true, fmt.Errorf("rollback did not complete: %w", err)
	}
	return false, nil
}

// commit publishes a successful batch: it rereads the live configuration,
// refreshes the name-to-UUID inventory, prunes stale entries, and sets each
// Service's status.
func (q *ApplyQueue) commit(ctx context.Context, applied []serviceContribution) error {
	live, err := q.Provider.Get()
	if err != nil {
		apiErrorsTotal.Inc()
		return fmt.Errorf("read live configuration after apply: %w", err)
	}
	if live == nil {
		live = &haproxy.Model{}
	}

	// The cycle counts as applied once the post-apply read that confirms the
	// objects' UUIDs has succeeded; a failed refresh leaves the cycle
	// incomplete and retryable.
	appliesTotal.Inc()

	for _, contribution := range applied {
		if err := q.recordInventory(ctx, contribution, live); err != nil {
			apiErrorsTotal.Inc()
			return err
		}
	}

	// Remember what the store now authorises, after this batch's prune. The
	// next drain scopes the live model to this inventory, so an object this
	// batch deleted stays out of scope while an object the reconciler removed
	// between drains stays in scope for exactly the drain that deletes it.
	inventory, err := q.inventoryNames(ctx)
	if err != nil {
		apiErrorsTotal.Inc()
		return err
	}
	q.rememberInventory(inventory)

	for _, contribution := range applied {
		if len(contribution.issues) > 0 {
			issue := contribution.issues[0]
			if err := q.publishProblem(ctx, contribution.key, issueReason(issue), issue.Error()); err != nil {
				apiErrorsTotal.Inc()
				return err
			}
			continue
		}
		if err := q.publishReady(ctx, contribution, live); err != nil {
			apiErrorsTotal.Inc()
			return err
		}
	}
	return nil
}

// fail marks every Service in the batch with the same problem.
func (q *ApplyQueue) fail(ctx context.Context, applied []serviceContribution, message string) error {
	for _, contribution := range applied {
		if err := q.publishProblem(ctx, contribution.key, ReasonConfigError, message); err != nil {
			apiErrorsTotal.Inc()
			return err
		}
	}
	return nil
}

// publishProblem records a warning event and an Error condition on one Service.
//
// reason classifies the problem and is the caller's, not a constant: a Service
// whose TCP ports applied while a UDP port was rejected keeps its
// UnsupportedProtocol reason after the drain, and only a genuine configuration
// problem is reported as ConfigError.
func (q *ApplyQueue) publishProblem(ctx context.Context, key types.NamespacedName, reason, message string) error {
	svc, err := q.service(ctx, key)
	if err != nil || svc == nil {
		return err
	}
	if q.Recorder != nil {
		q.Recorder.Event(svc, corev1.EventTypeWarning, reason, message)
	}
	return SetErrorWithReason(ctx, q.Client, svc, svc.Generation, reason, message)
}

// publishReady marks one Service programmed and publishes its ingress.
func (q *ApplyQueue) publishReady(ctx context.Context, contribution serviceContribution, live *haproxy.Model) error {
	svc, err := q.service(ctx, contribution.key)
	if err != nil || svc == nil {
		return err
	}
	addresses := q.ingressAddresses(contribution, live)
	return SetReady(ctx, q.Client, svc, LoadBalancerIngress(addresses), svc.Generation, "programmed")
}

// service reads the Service a status update targets. A Service that has gone is
// not an error: it simply has no status left to publish.
func (q *ApplyQueue) service(ctx context.Context, key types.NamespacedName) (*corev1.Service, error) {
	var svc corev1.Service
	if err := q.Client.Get(ctx, key, &svc); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get Service %s: %w", key, err)
	}
	return &svc, nil
}

// managedServices returns the store's inventory plus any pending key, sorted. A
// key that is only pending is still attempted: it was enqueued before its
// inventory entry existed, and the first successful drain records it. The
// rebuild sentinel is not a Service and is skipped.
func (q *ApplyQueue) managedServices(ctx context.Context, batch []types.NamespacedName) ([]types.NamespacedName, error) {
	stored, err := q.Store.ManagedServices(ctx)
	if err != nil {
		return nil, fmt.Errorf("list managed Services: %w", err)
	}

	seen := make(map[types.NamespacedName]struct{}, len(stored)+len(batch))
	for _, key := range stored {
		seen[key] = struct{}{}
	}
	for _, key := range batch {
		if key == RebuildAllKey {
			continue
		}
		seen[key] = struct{}{}
	}

	services := make([]types.NamespacedName, 0, len(seen))
	for key := range seen {
		services = append(services, key)
	}
	sortKeys(services)
	return services, nil
}

// inventoryNames collects the top-level object names the store records, so the
// live filter keeps an object this controller created even when the desired
// model no longer declares it. That is what lets cleanup delete it.
func (q *ApplyQueue) inventoryNames(ctx context.Context) (map[string]struct{}, error) {
	services, err := q.Store.ManagedServices(ctx)
	if err != nil {
		return nil, fmt.Errorf("list managed Services: %w", err)
	}

	names := make(map[string]struct{}, len(services))
	for _, key := range services {
		entries, err := q.Store.ForService(ctx, key.Namespace, key.Name)
		if err != nil {
			return nil, fmt.Errorf("list inventory of Service %s: %w", key, err)
		}
		for _, entry := range entries {
			names[objectNameOf(entry)] = struct{}{}
		}
	}
	return names, nil
}

// scope unions the store's current inventory with the previous drain's, so a
// Service whose entries the reconciler just removed is still in scope for the
// apply that deletes its objects.
func (q *ApplyQueue) scope(inventory map[string]struct{}) map[string]struct{} {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.inventory) == 0 {
		return inventory
	}
	scoped := make(map[string]struct{}, len(inventory)+len(q.inventory))
	for name := range inventory {
		scoped[name] = struct{}{}
	}
	for name := range q.inventory {
		scoped[name] = struct{}{}
	}
	return scoped
}

// rememberInventory records what the store authorises after a successful
// drain.
func (q *ApplyQueue) rememberInventory(inventory map[string]struct{}) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.inventory = inventory
}

// hasInventory reports whether the previous drain left object names that still
// need to be reconciled.
func (q *ApplyQueue) hasInventory() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.inventory) > 0
}

// recordInventory writes the Service's current objects into the store and prunes
// the entries whose objects it no longer declares.
func (q *ApplyQueue) recordInventory(ctx context.Context, contribution serviceContribution, live *haproxy.Model) error {
	liveUUIDs := make(map[string]string, len(live.Frontends)+len(live.Backends))
	for _, frontend := range live.Frontends {
		liveUUIDs[frontend.Name] = frontend.UUID
	}
	for _, backend := range live.Backends {
		liveUUIDs[backend.Name] = backend.UUID
	}

	desired := make(map[string]struct{}, len(contribution.model.Frontends)+len(contribution.model.Backends))
	record := func(kind, name string) error {
		if !strings.HasPrefix(name, OwnedPrefix) {
			return nil
		}
		entry := kind + ":" + name
		desired[entry] = struct{}{}

		uuid := liveUUIDs[name]
		if uuid == "" {
			return nil
		}
		if err := q.Store.Put(ctx, storeKey(contribution.key, entry), uuid); err != nil {
			return fmt.Errorf("record %s of Service %s: %w", entry, contribution.key, err)
		}
		return nil
	}

	for _, frontend := range contribution.model.Frontends {
		if err := record("frontend", frontend.Name); err != nil {
			return err
		}
	}
	for _, backend := range contribution.model.Backends {
		if err := record("backend", backend.Name); err != nil {
			return err
		}
	}

	existing, err := q.Store.ForService(ctx, contribution.key.Namespace, contribution.key.Name)
	if err != nil {
		return fmt.Errorf("list inventory of Service %s: %w", contribution.key, err)
	}
	for _, entry := range existing {
		if _, keep := desired[inventoryEntryOf(entry)]; keep {
			continue
		}
		if err := q.Store.Delete(ctx, entry); err != nil {
			return fmt.Errorf("prune inventory entry %q: %w", entry, err)
		}
	}
	return nil
}

// ingressAddresses derives the Service's published addresses from the listeners
// it uses. A created listener contributes its configured bind hosts; an adopted
// listener contributes the host of its live frontend's binds, because the
// frontend belongs to the platform and only the live object knows where it
// listens. When neither yields a usable host, the provider's own host is the
// fallback, since that is where the traffic arrives.
func (q *ApplyQueue) ingressAddresses(contribution serviceContribution, live *haproxy.Model) []string {
	var addresses []string
	seen := make(map[string]struct{})

	add := func(bind string) {
		host := bindHost(bind)
		if host == "" {
			return
		}
		if _, duplicate := seen[host]; duplicate {
			return
		}
		seen[host] = struct{}{}
		addresses = append(addresses, host)
	}

	for _, frontend := range contribution.model.Frontends {
		listener, ok := q.listenerFor(frontend.Name)
		if !ok {
			continue
		}
		if !listener.Adopt {
			for _, bind := range listener.Bind {
				add(bind)
			}
			continue
		}
		for _, liveFrontend := range live.Frontends {
			if liveFrontend.Name != listener.ExistingFrontend {
				continue
			}
			// The platform owns the adopted frontend, so the first usable
			// bind it reports is where traffic for this Service arrives.
			if host := firstBindHost(liveFrontend.Bind); host != "" {
				add(host)
			}
		}
	}

	if len(addresses) == 0 {
		if host := q.providerHost(); host != "" {
			addresses = append(addresses, host)
		}
	}
	return addresses
}

// listenerFor resolves a frontend name back to its configured listener: a
// created listener owns CreatedFrontendName of its name, and an adopted listener
// attaches to the frontend it names.
func (q *ApplyQueue) listenerFor(frontend string) (config.ListenerConfig, bool) {
	if q.Config == nil {
		return config.ListenerConfig{}, false
	}
	for _, listener := range q.Config.Listeners {
		if listener.Adopt {
			if listener.ExistingFrontend == frontend {
				return listener, true
			}
			continue
		}
		if CreatedFrontendName(listener.Name) == frontend {
			return listener, true
		}
	}
	return config.ListenerConfig{}, false
}

// declaredFrontends names every frontend the controller configuration declares:
// the frontends created listeners own, and the platform frontends adopted
// listeners attach to. They are managed by declaration, whatever their name.
func (q *ApplyQueue) declaredFrontends() map[string]struct{} {
	names := make(map[string]struct{})
	if q.Config == nil {
		return names
	}
	for _, listener := range q.Config.Listeners {
		if listener.Adopt {
			if listener.ExistingFrontend != "" {
				names[listener.ExistingFrontend] = struct{}{}
			}
			continue
		}
		names[CreatedFrontendName(listener.Name)] = struct{}{}
	}
	return names
}

// providerHost returns the host of the configured provider URL, which is the
// address traffic reaches when no listener bind can be used.
func (q *ApplyQueue) providerHost() string {
	if q.Config == nil {
		return ""
	}
	parsed, err := url.Parse(q.Config.Provider.URL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// serviceContribution is one Service's desired fragment together with the
// issues its build reported.
type serviceContribution struct {
	key    types.NamespacedName
	model  *haproxy.Model
	issues []error
}

// mergeContributions unions every contribution into one desired model.
//
// Backends are owned by exactly one Service, so two Services that name the same
// backend conflict even when the payloads look identical: merging them would
// silently point one Service's traffic at the other's servers. Both are
// reported and excluded, while the rest of the batch still applies.
//
// Frontends are shared. A created listener's frontend is the same object for
// every Service that names the listener, so equal payloads merge and their
// rules and ACLs are unioned. A differing payload means the Services disagree
// about the listener itself, which is also a conflict.
//
// Created-listener frontends are added even when no Service uses them, so a
// configured listener always exists and its default backend keeps serving. The
// always-present union names them through CreatedFrontendName, exactly as
// BuildContribution does, so the two paths cannot drift. The default backend
// itself is referenced, never created: it names the platform's own catch-all,
// which senselb does not own.
func mergeContributions(cfg *config.Config, contributions []serviceContribution) (*haproxy.Model, map[types.NamespacedName]string) {
	failures := make(map[types.NamespacedName]string)

	type frontendEntry struct {
		base   haproxy.Frontend
		source types.NamespacedName
	}
	frontends := make(map[string]frontendEntry, len(contributions))
	for _, contribution := range contributions {
		for _, frontend := range contribution.model.Frontends {
			base := frontendBase(frontend)
			existing, seen := frontends[frontend.Name]
			if !seen {
				frontends[frontend.Name] = frontendEntry{base: base, source: contribution.key}
				continue
			}
			if reflect.DeepEqual(existing.base, base) {
				continue
			}
			message := fmt.Sprintf("frontend %q is configured inconsistently by Services %s and %s",
				frontend.Name, existing.source, contribution.key)
			failures[existing.source] = message
			failures[contribution.key] = message
		}
	}

	backends := make(map[string]types.NamespacedName, len(contributions))
	for _, contribution := range contributions {
		for _, backend := range contribution.model.Backends {
			owner, taken := backends[backend.Name]
			if taken && owner != contribution.key {
				message := fmt.Sprintf("backend %q is claimed by Services %s and %s",
					backend.Name, owner, contribution.key)
				failures[owner] = message
				failures[contribution.key] = message
				continue
			}
			backends[backend.Name] = contribution.key
		}
	}

	model := &haproxy.Model{}
	frontendIndex := make(map[string]int, len(frontends))
	backendIndex := make(map[string]int, len(backends))

	for _, contribution := range contributions {
		if _, failed := failures[contribution.key]; failed {
			continue
		}
		for _, frontend := range contribution.model.Frontends {
			if index, seen := frontendIndex[frontend.Name]; seen {
				model.Frontends[index] = unionFrontend(model.Frontends[index], frontend)
				continue
			}
			frontendIndex[frontend.Name] = len(model.Frontends)
			model.Frontends = append(model.Frontends, frontend)
		}
		for _, backend := range contribution.model.Backends {
			if index, seen := backendIndex[backend.Name]; seen {
				model.Backends[index] = unionBackend(model.Backends[index], backend)
				continue
			}
			backendIndex[backend.Name] = len(model.Backends)
			model.Backends = append(model.Backends, backend)
		}
	}

	if cfg != nil {
		for _, listener := range cfg.Listeners {
			if !listener.Adopt {
				name := CreatedFrontendName(listener.Name)
				if _, present := frontendIndex[name]; !present {
					frontendIndex[name] = len(model.Frontends)
					model.Frontends = append(model.Frontends, contributedFrontend(listener))
				}
			}
			model.Listeners = append(model.Listeners, modelListener(listener))
		}
	}
	return model, failures
}

// frontendBase returns the part of a frontend that identifies the shared
// listener. Rules and ACLs are per-Service children and are unioned separately.
func frontendBase(frontend haproxy.Frontend) haproxy.Frontend {
	frontend.UUID = ""
	frontend.ACLs = nil
	frontend.Rules = nil
	frontend.Bind = slices.Clone(frontend.Bind)
	frontend.SSLCertificates = slices.Clone(frontend.SSLCertificates)
	return frontend
}

// unionFrontend adds another Service's rules and ACLs to a shared frontend,
// keeping one object per name.
func unionFrontend(destination, source haproxy.Frontend) haproxy.Frontend {
	destination.ACLs = unionACLs(destination.ACLs, source.ACLs)
	destination.Rules = unionRules(destination.Rules, source.Rules)
	return destination
}

// unionBackend adds another contribution's children to a backend, keeping one
// object per name. Two Services never reach it with the same backend name; the
// union is defensive.
func unionBackend(destination, source haproxy.Backend) haproxy.Backend {
	destination.Servers = unionServers(destination.Servers, source.Servers)
	destination.ACLs = unionACLs(destination.ACLs, source.ACLs)
	destination.Rules = unionRules(destination.Rules, source.Rules)
	return destination
}

func unionACLs(destination, source []haproxy.ACL) []haproxy.ACL {
	seen := make(map[string]struct{}, len(destination))
	for _, acl := range destination {
		seen[acl.Name] = struct{}{}
	}
	for _, acl := range source {
		if _, duplicate := seen[acl.Name]; duplicate {
			continue
		}
		seen[acl.Name] = struct{}{}
		destination = append(destination, acl)
	}
	return destination
}

func unionRules(destination, source []haproxy.Rule) []haproxy.Rule {
	seen := make(map[string]struct{}, len(destination))
	for _, rule := range destination {
		seen[rule.Name] = struct{}{}
	}
	for _, rule := range source {
		if _, duplicate := seen[rule.Name]; duplicate {
			continue
		}
		seen[rule.Name] = struct{}{}
		destination = append(destination, rule)
	}
	return destination
}

func unionServers(destination, source []haproxy.Server) []haproxy.Server {
	seen := make(map[string]struct{}, len(destination))
	for _, server := range destination {
		seen[server.Name] = struct{}{}
	}
	for _, server := range source {
		if _, duplicate := seen[server.Name]; duplicate {
			continue
		}
		seen[server.Name] = struct{}{}
		destination = append(destination, server)
	}
	return destination
}

// modelListener converts a configured listener into the model's input form.
func modelListener(listener config.ListenerConfig) haproxy.Listener {
	return haproxy.Listener{
		Name:             listener.Name,
		Adopt:            listener.Adopt,
		ExistingFrontend: listener.ExistingFrontend,
		Bind:             slices.Clone(listener.Bind),
		Mode:             haproxy.Mode(listener.Mode),
		DefaultBackend:   listener.DefaultBackend,
	}
}

// topLevelNames returns the names of a model's frontends and backends.
func topLevelNames(model *haproxy.Model) map[string]struct{} {
	names := make(map[string]struct{}, len(model.Frontends)+len(model.Backends))
	for _, frontend := range model.Frontends {
		names[frontend.Name] = struct{}{}
	}
	for _, backend := range model.Backends {
		names[backend.Name] = struct{}{}
	}
	return names
}

// filterLive reduces the live model to the objects senselb may plan against.
//
// A top-level object is in scope when its name is senselb's or is declared by
// the controller configuration, and it is either desired or in the inventory
// (the store plus the previous drain's contents). The second condition is the
// safety rule: an owned-looking object that no inventory accounts for is left
// alone, so a wiped store cannot make the controller delete configuration it
// cannot attribute. Children follow their parent, but only owned children are
// kept, so a foreign rule on an adopted frontend is never planned for deletion.
func filterLive(live *haproxy.Model, desired, inventory, declared map[string]struct{}) *haproxy.Model {
	filtered := &haproxy.Model{}

	inScope := func(name string) bool {
		owned := strings.HasPrefix(name, OwnedPrefix)
		if !owned {
			if _, isDeclared := declared[name]; !isDeclared {
				return false
			}
		}
		if _, ok := desired[name]; ok {
			return true
		}
		_, ok := inventory[name]
		return ok
	}
	ownedChild := func(name string) bool { return strings.HasPrefix(name, OwnedPrefix) }

	for _, frontend := range live.Frontends {
		if !inScope(frontend.Name) {
			continue
		}
		frontend.ACLs = filterNamed(frontend.ACLs, func(acl haproxy.ACL) string { return acl.Name }, ownedChild)
		frontend.Rules = filterNamed(frontend.Rules, func(rule haproxy.Rule) string { return rule.Name }, ownedChild)
		filtered.Frontends = append(filtered.Frontends, frontend)
	}
	for _, backend := range live.Backends {
		if !inScope(backend.Name) {
			continue
		}
		backend.ACLs = filterNamed(backend.ACLs, func(acl haproxy.ACL) string { return acl.Name }, ownedChild)
		backend.Rules = filterNamed(backend.Rules, func(rule haproxy.Rule) string { return rule.Name }, ownedChild)
		backend.Servers = filterNamed(backend.Servers, func(server haproxy.Server) string { return server.Name }, ownedChild)
		filtered.Backends = append(filtered.Backends, backend)
	}
	return filtered
}

// filterNamed keeps the objects whose name passes keep.
func filterNamed[T any](objects []T, nameOf func(T) string, keep func(string) bool) []T {
	kept := make([]T, 0, len(objects))
	for _, object := range objects {
		if keep(nameOf(object)) {
			kept = append(kept, object)
		}
	}
	return kept
}

// hydrateAdoptedFrontends completes an adopted listener's partial frontend from
// the live object it attaches to.
//
// A contribution can only name an adopted frontend: its bind, mode, TLS and
// default backend belong to the platform, which owns the object. Copying those
// fields from the live frontend makes the desired payload equal to the live one,
// so the diff plans only the owned rules and never rewrites a foreign object's
// own configuration. An absent live frontend is left partial, and the provider's
// preflight then rejects the resulting create.
func hydrateAdoptedFrontends(desired, live *haproxy.Model) {
	liveFrontends := make(map[string]haproxy.Frontend, len(live.Frontends))
	for _, frontend := range live.Frontends {
		liveFrontends[frontend.Name] = frontend
	}

	for i, frontend := range desired.Frontends {
		if len(frontend.Bind) > 0 {
			continue
		}
		liveFrontend, ok := liveFrontends[frontend.Name]
		if !ok {
			continue
		}
		frontend.Bind = slices.Clone(liveFrontend.Bind)
		frontend.Mode = liveFrontend.Mode
		frontend.DefaultBackend = liveFrontend.DefaultBackend
		frontend.SSLEnabled = liveFrontend.SSLEnabled
		frontend.SSLCertificates = slices.Clone(liveFrontend.SSLCertificates)
		frontend.SSLDefaultCert = liveFrontend.SSLDefaultCert
		frontend.CustomOptions = liveFrontend.CustomOptions
		desired.Frontends[i] = frontend
	}
}

// firstBindHost returns the host of the first bind address that is publishable,
// skipping wildcards and blanks.
func firstBindHost(binds []string) string {
	for _, bind := range binds {
		if host := bindHost(bind); host != "" {
			return host
		}
	}
	return ""
}

// bindHost returns the host part of a bind address, or "" when the address is
// wildcard (0.0.0.0, ::, *) or empty and therefore not publishable.
func bindHost(bind string) string {
	bind = strings.TrimSpace(bind)
	if bind == "" {
		return ""
	}

	host := bind
	if parsed, _, err := net.SplitHostPort(bind); err == nil {
		host = parsed
	} else if strings.HasPrefix(bind, "[") && strings.HasSuffix(bind, "]") {
		host = strings.Trim(bind, "[]")
	}

	host = strings.TrimSpace(host)
	switch host {
	case "", "0.0.0.0", "::", "*":
		return ""
	}
	return host
}

// storeKey renders the inventory key of one object: the owning Service's prefix
// followed by the object's kind and name.
func storeKey(service types.NamespacedName, object string) string {
	return service.Namespace + "/" + service.Name + "/" + object
}

// inventoryEntryOf strips the Service prefix from an inventory key, leaving the
// "<kind>:<name>" entry the store records.
func inventoryEntryOf(key string) string {
	if index := strings.LastIndex(key, "/"); index >= 0 {
		return key[index+1:]
	}
	return key
}

// objectNameOf returns the provider object name from an inventory key: the
// "<kind>:<name>" entry with its kind removed.
func objectNameOf(key string) string {
	entry := inventoryEntryOf(key)
	if index := strings.Index(entry, ":"); index >= 0 {
		return entry[index+1:]
	}
	return entry
}

// sortedKeys returns the map's keys in a deterministic order.
func sortedKeys(values map[types.NamespacedName]string) []types.NamespacedName {
	keys := make([]types.NamespacedName, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sortKeys(keys)
	return keys
}

// sortKeys orders Service keys by namespace and then name.
func sortKeys(keys []types.NamespacedName) {
	slices.SortFunc(keys, func(a, b types.NamespacedName) int {
		if a.Namespace != b.Namespace {
			return strings.Compare(a.Namespace, b.Namespace)
		}
		return strings.Compare(a.Name, b.Name)
	})
}

// Compile-time assertions that the queue satisfies the manager contracts.
var (
	_ manager.Runnable               = (*ApplyQueue)(nil)
	_ manager.LeaderElectionRunnable = (*ApplyQueue)(nil)
)
