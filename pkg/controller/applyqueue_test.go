package controller

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/yasn77/senselb/pkg/config"
	"github.com/yasn77/senselb/pkg/haproxy"
	"github.com/yasn77/senselb/pkg/provider"
)

// fakeProvider is a provider.Provider that records every call and can be told
// to fail in one of the ways the queue distinguishes.
type fakeProvider struct {
	mu sync.Mutex

	live *haproxy.Model
	// after is the live model a successful Apply leaves behind, so the queue's
	// post-apply Get can observe the created UUIDs.
	after *haproxy.Model
	// applyErr is returned from Apply; nil means success.
	applyErr error
	// failures makes the next Apply calls fail with a transport error before
	// applyErr is consulted.
	failures int

	gets      int
	applies   int
	rollbacks int
	plans     []haproxy.Plan
	appliedAt []time.Time
}

func (p *fakeProvider) Get() (*haproxy.Model, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gets++
	return p.live, nil
}

func (p *fakeProvider) Apply(plan haproxy.Plan) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.applies++
	p.plans = append(p.plans, plan)
	p.appliedAt = append(p.appliedAt, time.Now())

	if p.failures > 0 {
		p.failures--
		return errors.New("connection refused")
	}
	if p.applyErr != nil {
		return p.applyErr
	}
	if p.after != nil {
		p.live = p.after
	}
	return nil
}

func (p *fakeProvider) Validate() error { return nil }
func (p *fakeProvider) Reload() error   { return nil }

func (p *fakeProvider) Rollback() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rollbacks++
	return nil
}

func (p *fakeProvider) counts() (gets, applies, rollbacks int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.gets, p.applies, p.rollbacks
}

func (p *fakeProvider) applyTimes() []time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]time.Time(nil), p.appliedAt...)
}

func (p *fakeProvider) planAt(index int) haproxy.Plan {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.plans[index]
}

// staticBuilder returns a ContributionFunc over a fixed key-to-model map. A key
// with no model contributes nothing, which is what a deleted Service does.
func staticBuilder(models map[types.NamespacedName]*haproxy.Model) ContributionFunc {
	return func(_ context.Context, key types.NamespacedName) (*haproxy.Model, []error) {
		return models[key], nil
	}
}

// newPipeline builds an ApplyQueue over the fake client and provider with a
// debounce window short enough for a test.
func newPipeline(t *testing.T, cl client.Client, cfg *config.Config, p *fakeProvider, build ContributionFunc) (*ApplyQueue, *record.FakeRecorder) {
	t.Helper()
	store := &Store{Client: cl, Namespace: "senselb-system", Name: "senselb-store"}
	recorder := record.NewFakeRecorder(100)
	queue := &ApplyQueue{
		Provider:          p,
		Client:            cl,
		Store:             store,
		Recorder:          recorder,
		Config:            cfg,
		BuildContribution: build,
		Debounce:          15 * time.Millisecond,
		backoffBase:       20 * time.Millisecond,
	}
	return queue, recorder
}

// startPipeline runs the queue until the test ends.
func startPipeline(t *testing.T, queue *ApplyQueue) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- queue.Run(ctx) }()

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("queue stopped with %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("queue did not stop after cancellation")
		}
	})
}

// waitForApplies blocks until the provider has seen count apply calls.
func waitForApplies(t *testing.T, p *fakeProvider, count int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, applies, _ := p.counts(); applies >= count {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	_, applies, _ := p.counts()
	t.Fatalf("apply calls = %d, want %d", applies, count)
}

// pipelineClient builds a fake client holding the named LoadBalancer Services.
func pipelineClient(t *testing.T, names ...string) client.Client {
	t.Helper()
	objects := make([]client.Object, 0, len(names))
	for _, name := range names {
		objects = append(objects, lbService(name, nil))
	}
	return fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithStatusSubresource(&corev1.Service{}).
		WithObjects(objects...).
		Build()
}

// serviceModel is a minimal contribution: one frontend on the named listener and
// one backend with one server.
func serviceModel(listener, backend string) *haproxy.Model {
	frontend := haproxy.NewFrontend(listener, haproxy.ModeHTTP, "172.16.16.1:80")
	backendModel := haproxy.NewBackend(backend, haproxy.ModeHTTP)
	backendModel.Servers = []haproxy.Server{haproxy.NewServer("senselb-node-80", "10.0.0.1", 30080)}
	return &haproxy.Model{
		Frontends: []haproxy.Frontend{frontend},
		Backends:  []haproxy.Backend{backendModel},
	}
}

// liveModel returns a live configuration carrying the passed frontend and
// backend UUIDs.
func liveModel(frontends map[string]string, backends map[string]string) *haproxy.Model {
	model := &haproxy.Model{}
	for _, name := range sortedNames(frontends) {
		frontend := haproxy.NewFrontend(name, haproxy.ModeHTTP, "172.16.16.1:80")
		frontend.UUID = frontends[name]
		model.Frontends = append(model.Frontends, frontend)
	}
	for _, name := range sortedNames(backends) {
		backendModel := haproxy.NewBackend(name, haproxy.ModeHTTP)
		backendModel.UUID = backends[name]
		model.Backends = append(model.Backends, backendModel)
	}
	return model
}

func sortedNames(values map[string]string) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// requireCondition waits for a condition on a Service to reach status and carry
// messageFragment.
func requireCondition(t *testing.T, cl client.Client, name, conditionType string, status metav1.ConditionStatus, messageFragment string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var last *metav1.Condition
	for time.Now().Before(deadline) {
		var svc corev1.Service
		if err := cl.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: name}, &svc); err == nil {
			last = meta.FindStatusCondition(svc.Status.Conditions, conditionType)
			if last != nil && last.Status == status && strings.Contains(last.Message, messageFragment) {
				return
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("condition %s on Service %s = %+v, want status %s containing %q", conditionType, name, last, status, messageFragment)
}

func TestApplyQueueCoalescesEnqueues(t *testing.T) {
	names := []string{"one", "two", "three", "four", "five"}
	cl := pipelineClient(t, names...)

	models := make(map[types.NamespacedName]*haproxy.Model, len(names))
	for _, name := range names {
		key := types.NamespacedName{Namespace: "default", Name: name}
		models[key] = serviceModel("senselb-web", "senselb-default-"+name+"-80")
	}

	p := &fakeProvider{live: &haproxy.Model{}, after: liveModel(
		map[string]string{"senselb-web": "uuid-web"},
		map[string]string{
			"senselb-default-one-80":   "uuid-one",
			"senselb-default-two-80":   "uuid-two",
			"senselb-default-three-80": "uuid-three",
			"senselb-default-four-80":  "uuid-four",
			"senselb-default-five-80":  "uuid-five",
		},
	)}
	queue, _ := newPipeline(t, cl, buildConfig(), p, staticBuilder(models))
	startPipeline(t, queue)

	for _, name := range names {
		queue.Enqueue(types.NamespacedName{Namespace: "default", Name: name})
		time.Sleep(time.Millisecond)
	}

	waitForApplies(t, p, 1)

	// One drain is one Get before the diff and one after the apply.
	gets, applies, _ := p.counts()
	if gets != 2 {
		t.Errorf("Get calls = %d, want 2 (one before the diff, one after the apply)", gets)
	}
	if applies != 1 {
		t.Errorf("Apply calls = %d, want 1", applies)
	}

	// No second cycle follows: the burst was coalesced, not replayed.
	time.Sleep(6 * queue.Debounce)
	if _, applies, _ := p.counts(); applies != 1 {
		t.Errorf("Apply calls after settling = %d, want 1", applies)
	}
}

func TestApplyQueueRollsBackOnConfigTest(t *testing.T) {
	cl := pipelineClient(t, "app")
	key := types.NamespacedName{Namespace: "default", Name: "app"}
	p := &fakeProvider{
		live:     &haproxy.Model{},
		applyErr: &provider.ErrConfigTest{Message: "frontend web: invalid"},
	}
	queue, recorder := newPipeline(t, cl, buildConfig(), p, staticBuilder(map[types.NamespacedName]*haproxy.Model{
		key: serviceModel("senselb-web", "senselb-default-app-80"),
	}))
	startPipeline(t, queue)

	queue.Enqueue(key)
	waitForApplies(t, p, 1)

	if _, _, rollbacks := p.counts(); rollbacks != 1 {
		t.Errorf("Rollback calls = %d, want 1", rollbacks)
	}
	requireCondition(t, cl, "app", ConditionError, metav1.ConditionTrue, "rolled back")

	events := drainEvents(recorder)
	eventContaining(t, events, "rolled back")
}

func TestApplyQueueKeepsUnsupportedProtocolReason(t *testing.T) {
	cl := pipelineClient(t, "app")
	key := types.NamespacedName{Namespace: "default", Name: "app"}
	p := &fakeProvider{
		live: &haproxy.Model{},
		after: liveModel(
			map[string]string{"senselb-web": "uuid-web"},
			map[string]string{"senselb-default-app-80": "uuid-backend"},
		),
	}
	queue, recorder := newPipeline(t, cl, buildConfig(), p,
		func(_ context.Context, _ types.NamespacedName) (*haproxy.Model, []error) {
			return serviceModel("senselb-web", "senselb-default-app-80"),
				[]error{&UDPUnsupportedError{Port: 53, Protocol: "UDP"}}
		})
	startPipeline(t, queue)

	queue.Enqueue(key)
	waitForApplies(t, p, 1)

	// The TCP port applied successfully, so the drain publishes the Service's
	// real problem. It must keep the reconciler's classification instead of
	// being flattened into a generic configuration error.
	deadline := time.Now().Add(3 * time.Second)
	var last *metav1.Condition
	for time.Now().Before(deadline) {
		var svc corev1.Service
		if err := cl.Get(context.Background(), key, &svc); err == nil {
			last = meta.FindStatusCondition(svc.Status.Conditions, ConditionError)
			if last != nil && last.Status == metav1.ConditionTrue &&
				last.Reason == ReasonUnsupportedProtocol && strings.Contains(last.Message, "UDP") {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	if last == nil || last.Reason != ReasonUnsupportedProtocol || !strings.Contains(last.Message, "UDP") {
		t.Fatalf("Error condition = %+v, want reason %s with the UDP message", last, ReasonUnsupportedProtocol)
	}
	eventContaining(t, drainEvents(recorder), ReasonUnsupportedProtocol)
}

func TestApplyQueueOwnershipConflictMarksEveryService(t *testing.T) {
	cl := pipelineClient(t, "app", "other")
	appKey := types.NamespacedName{Namespace: "default", Name: "app"}
	otherKey := types.NamespacedName{Namespace: "default", Name: "other"}
	p := &fakeProvider{
		live:     &haproxy.Model{},
		applyErr: &provider.ErrOwnershipConflict{Refs: []string{"frontend ingress-HTTPS"}},
	}
	queue, _ := newPipeline(t, cl, buildConfig(), p, staticBuilder(map[types.NamespacedName]*haproxy.Model{
		appKey:   serviceModel("senselb-web", "senselb-default-app-80"),
		otherKey: serviceModel("senselb-web", "senselb-default-other-80"),
	}))
	startPipeline(t, queue)

	queue.Enqueue(appKey)
	queue.Enqueue(otherKey)
	waitForApplies(t, p, 1)

	if _, _, rollbacks := p.counts(); rollbacks != 0 {
		t.Errorf("Rollback calls = %d, want 0: nothing was written before the preflight rejected the plan", rollbacks)
	}
	requireCondition(t, cl, "app", ConditionError, metav1.ConditionTrue, "ownership conflict")
	requireCondition(t, cl, "other", ConditionError, metav1.ConditionTrue, "ownership conflict")
}

func TestApplyQueueBacksOffThenResets(t *testing.T) {
	cl := pipelineClient(t, "app")
	key := types.NamespacedName{Namespace: "default", Name: "app"}
	p := &fakeProvider{
		live:     &haproxy.Model{},
		after:    liveModel(map[string]string{"senselb-web": "uuid-web"}, map[string]string{"senselb-default-app-80": "uuid-backend"}),
		failures: 1,
	}
	queue, _ := newPipeline(t, cl, buildConfig(), p, staticBuilder(map[types.NamespacedName]*haproxy.Model{
		key: serviceModel("senselb-web", "senselb-default-app-80"),
	}))
	startPipeline(t, queue)

	queue.Enqueue(key)
	waitForApplies(t, p, 1)

	// A second drain must wait for the backoff window.
	time.Sleep(queue.backoffBase / 2)
	if _, applies, _ := p.counts(); applies != 1 {
		t.Fatalf("Apply calls before the backoff elapsed = %d, want 1", applies)
	}
	if backoff := queue.currentBackoff(); backoff != queue.backoffBase {
		t.Errorf("backoff after one failure = %v, want %v", backoff, queue.backoffBase)
	}

	waitForApplies(t, p, 2)

	times := p.applyTimes()
	if gap := times[1].Sub(times[0]); gap < queue.backoffBase {
		t.Errorf("retry after %v, want at least the %v backoff", gap, queue.backoffBase)
	}

	// The reset follows the successful commit, which runs after Apply returns.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && queue.currentBackoff() != 0 {
		time.Sleep(2 * time.Millisecond)
	}
	if backoff := queue.currentBackoff(); backoff != 0 {
		t.Errorf("backoff after a successful retry = %v, want 0", backoff)
	}

	// The first failure was retried, so the Service is programmed and there is
	// no Error condition left.
	requireCondition(t, cl, "app", ConditionReady, metav1.ConditionTrue, "programmed")
}

func TestApplyQueueDebouncesBurst(t *testing.T) {
	cl := pipelineClient(t, "app")
	key := types.NamespacedName{Namespace: "default", Name: "app"}
	p := &fakeProvider{
		live:  &haproxy.Model{},
		after: liveModel(map[string]string{"senselb-web": "uuid-web"}, map[string]string{"senselb-default-app-80": "uuid-backend"}),
	}
	queue, _ := newPipeline(t, cl, buildConfig(), p, staticBuilder(map[types.NamespacedName]*haproxy.Model{
		key: serviceModel("senselb-web", "senselb-default-app-80"),
	}))
	queue.Debounce = 25 * time.Millisecond
	startPipeline(t, queue)

	for range 5 {
		queue.Enqueue(key)
		time.Sleep(3 * time.Millisecond)
	}

	waitForApplies(t, p, 1)
	time.Sleep(4 * queue.Debounce)
	if _, applies, _ := p.counts(); applies != 1 {
		t.Errorf("Apply calls = %d, want 1 for a burst inside the debounce window", applies)
	}
}

func TestApplyQueueExcludesConflictingBackendClaimants(t *testing.T) {
	cl := pipelineClient(t, "a", "b", "c")
	aKey := types.NamespacedName{Namespace: "default", Name: "a"}
	bKey := types.NamespacedName{Namespace: "default", Name: "b"}
	cKey := types.NamespacedName{Namespace: "default", Name: "c"}

	p := &fakeProvider{
		live:  &haproxy.Model{},
		after: liveModel(map[string]string{"senselb-web": "uuid-web"}, map[string]string{"senselb-default-c-80": "uuid-c"}),
	}
	queue, _ := newPipeline(t, cl, buildConfig(), p, staticBuilder(map[types.NamespacedName]*haproxy.Model{
		aKey: serviceModel("senselb-web", "shared-backend"),
		bKey: serviceModel("senselb-web", "shared-backend"),
		cKey: serviceModel("senselb-web", "senselb-default-c-80"),
	}))
	startPipeline(t, queue)

	queue.Enqueue(aKey)
	queue.Enqueue(bKey)
	queue.Enqueue(cKey)
	waitForApplies(t, p, 1)

	plan := p.planAt(0)
	for _, operation := range plan.Operations {
		if operation.Ref.Name == "shared-backend" {
			t.Errorf("plan touches the conflicting backend: %+v", operation)
		}
	}

	requireCondition(t, cl, "a", ConditionError, metav1.ConditionTrue, "claimed by")
	requireCondition(t, cl, "b", ConditionError, metav1.ConditionTrue, "claimed by")
	requireCondition(t, cl, "c", ConditionReady, metav1.ConditionTrue, "programmed")
}

func TestApplyQueueRefreshesAndPrunesStore(t *testing.T) {
	cl := pipelineClient(t, "app")
	key := types.NamespacedName{Namespace: "default", Name: "app"}
	p := &fakeProvider{
		live:  &haproxy.Model{},
		after: liveModel(map[string]string{"senselb-web": "uuid-web"}, map[string]string{"senselb-default-app-80": "uuid-backend"}),
	}
	queue, _ := newPipeline(t, cl, buildConfig(), p, staticBuilder(map[types.NamespacedName]*haproxy.Model{
		key: serviceModel("senselb-web", "senselb-default-app-80"),
	}))

	ctx := context.Background()
	if err := queue.Store.Put(ctx, "default/app/backend:stale-backend", "uuid-stale"); err != nil {
		t.Fatalf("seed stale entry: %v", err)
	}
	startPipeline(t, queue)

	// The seeded entry makes the Service known to the store, so a plain drain
	// picks it up even before any key is enqueued.
	queue.Enqueue(RebuildAllKey)
	waitForApplies(t, p, 1)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		uuid, ok, err := queue.Store.Get(ctx, "default/app/backend:senselb-default-app-80")
		_, stale, staleErr := queue.Store.Get(ctx, "default/app/backend:stale-backend")
		if err == nil && staleErr == nil && ok && uuid == "uuid-backend" && !stale {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	if uuid, ok, err := queue.Store.Get(ctx, "default/app/backend:senselb-default-app-80"); err != nil || !ok || uuid != "uuid-backend" {
		t.Errorf("inventory entry = %q, %t, %v; want uuid-backend", uuid, ok, err)
	}
	if _, ok, err := queue.Store.Get(ctx, "default/app/backend:stale-backend"); err != nil || ok {
		t.Errorf("stale entry survived the refresh: present = %t, err = %v", ok, err)
	}
}

func TestApplyQueueDeletesAfterInventoryRemoval(t *testing.T) {
	cl := pipelineClient(t, "app")
	key := types.NamespacedName{Namespace: "default", Name: "app"}
	p := &fakeProvider{
		live:  &haproxy.Model{},
		after: liveModel(map[string]string{"senselb-web": "uuid-web"}, map[string]string{"senselb-default-app-80": "uuid-backend"}),
	}
	queue, _ := newPipeline(t, cl, buildConfig(), p, staticBuilder(map[types.NamespacedName]*haproxy.Model{
		key: serviceModel("senselb-web", "senselb-default-app-80"),
	}))

	// The drains are driven directly rather than through Run: the assertion is
	// about inventory remembered between two cycles, and a live worker could
	// take the pending key at any point and rebuild the contribution.
	ctx := context.Background()
	if err := queue.drain(ctx, []types.NamespacedName{key}); err != nil {
		t.Fatalf("first drain: %v", err)
	}

	// The reconciler deletes the inventory before it asks for a rebuild, so the
	// queue must remember the previous drain's inventory to authorise the
	// delete.
	entries, err := queue.Store.ForService(ctx, "default", "app")
	if err != nil {
		t.Fatalf("list inventory: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("the inventory was not recorded after the first drain")
	}
	for _, entry := range entries {
		if err := queue.Store.Delete(ctx, entry); err != nil {
			t.Fatalf("delete inventory entry: %v", err)
		}
	}

	if err := queue.drain(ctx, []types.NamespacedName{RebuildAllKey}); err != nil {
		t.Fatalf("rebuild drain: %v", err)
	}

	plan := p.planAt(1)
	deleted := false
	for _, operation := range plan.Operations {
		if operation.Kind == haproxy.OpDelete && operation.Ref.Name == "senselb-default-app-80" {
			deleted = true
		}
	}
	if !deleted {
		t.Errorf("plan does not delete the removed Service's backend: %+v", plan.Operations)
	}
}

func TestApplyQueueIngressFromCreatedListener(t *testing.T) {
	cl := pipelineClient(t, "app")
	key := types.NamespacedName{Namespace: "default", Name: "app"}
	p := &fakeProvider{
		live:  &haproxy.Model{},
		after: liveModel(map[string]string{"senselb-web": "uuid-web"}, map[string]string{"senselb-default-app-80": "uuid-backend"}),
	}
	cfg := buildConfig()
	cfg.Provider.URL = "https://firewall.example.net:8443/api/haproxy"

	queue, _ := newPipeline(t, cl, cfg, p, staticBuilder(map[types.NamespacedName]*haproxy.Model{
		key: serviceModel("senselb-web", "senselb-default-app-80"),
	}))
	startPipeline(t, queue)

	queue.Enqueue(key)
	waitForApplies(t, p, 1)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var svc corev1.Service
		if err := cl.Get(context.Background(), key, &svc); err == nil &&
			len(svc.Status.LoadBalancer.Ingress) == 1 &&
			svc.Status.LoadBalancer.Ingress[0].IP == "172.16.16.1" {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	var svc corev1.Service
	if err := cl.Get(context.Background(), key, &svc); err != nil {
		t.Fatalf("get Service: %v", err)
	}
	t.Errorf("ingress = %+v, want the created listener's bind host 172.16.16.1", svc.Status.LoadBalancer.Ingress)
}

func TestApplyQueueIngressFallsBackToProviderHost(t *testing.T) {
	cl := pipelineClient(t, "app")
	key := types.NamespacedName{Namespace: "default", Name: "app"}

	live := liveModel(map[string]string{"acme-frontend": "uuid-acme"}, nil)
	// A wildcard bind is not publishable, so the provider host is the fallback.
	live.Frontends[0].Bind = []string{"0.0.0.0:443"}

	p := &fakeProvider{live: &haproxy.Model{}}
	// Apply succeeds and leaves the adopted frontend in place; no backend UUID
	// is needed for the ingress assertion.
	p.after = live

	cfg := buildConfig()
	cfg.Provider.URL = "https://firewall.example.net:8443/api/haproxy"
	model := &haproxy.Model{Frontends: []haproxy.Frontend{{Name: "acme-frontend"}}}

	queue, _ := newPipeline(t, cl, cfg, p, staticBuilder(map[types.NamespacedName]*haproxy.Model{
		key: model,
	}))
	startPipeline(t, queue)

	queue.Enqueue(key)
	waitForApplies(t, p, 1)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var svc corev1.Service
		if err := cl.Get(context.Background(), key, &svc); err == nil &&
			len(svc.Status.LoadBalancer.Ingress) == 1 &&
			svc.Status.LoadBalancer.Ingress[0].IP == "firewall.example.net" {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	var svc corev1.Service
	if err := cl.Get(context.Background(), key, &svc); err != nil {
		t.Fatalf("get Service: %v", err)
	}
	t.Errorf("ingress = %+v, want the provider host firewall.example.net", svc.Status.LoadBalancer.Ingress)
}

func TestIngressAddresses(t *testing.T) {
	cfg := buildConfig()
	cfg.Provider.URL = "https://firewall.example.net:8443/api/haproxy"

	cases := []struct {
		name  string
		model *haproxy.Model
		live  *haproxy.Model
		want  []string
	}{
		{
			name:  "created listener bind",
			model: &haproxy.Model{Frontends: []haproxy.Frontend{{Name: "senselb-web"}}},
			want:  []string{"172.16.16.1"},
		},
		{
			name:  "adopted frontend bind",
			model: &haproxy.Model{Frontends: []haproxy.Frontend{{Name: "acme-frontend"}}},
			live:  liveModel(map[string]string{"acme-frontend": "uuid-acme"}, nil),
			want:  []string{"172.16.16.1"},
		},
		{
			name:  "adopted frontend wildcard bind falls back to the provider host",
			model: &haproxy.Model{Frontends: []haproxy.Frontend{{Name: "acme-frontend"}}},
			live: func() *haproxy.Model {
				model := liveModel(map[string]string{"acme-frontend": "uuid-acme"}, nil)
				model.Frontends[0].Bind = []string{"0.0.0.0:443"}
				return model
			}(),
			want: []string{"firewall.example.net"},
		},
		{
			name:  "adopted frontend skips a wildcard bind before a usable one",
			model: &haproxy.Model{Frontends: []haproxy.Frontend{{Name: "acme-frontend"}}},
			live: func() *haproxy.Model {
				model := liveModel(map[string]string{"acme-frontend": "uuid-acme"}, nil)
				model.Frontends[0].Bind = []string{"0.0.0.0:443", "172.16.16.2:443"}
				return model
			}(),
			want: []string{"172.16.16.2"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			queue := &ApplyQueue{Config: cfg}
			live := tc.live
			if live == nil {
				live = &haproxy.Model{}
			}
			got := queue.ingressAddresses(serviceContribution{
				key:   types.NamespacedName{Namespace: "default", Name: "app"},
				model: tc.model,
			}, live)
			if len(got) != len(tc.want) {
				t.Fatalf("addresses = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("addresses = %v, want %v", got, tc.want)
					break
				}
			}
		})
	}
}

func TestFilterLiveDropsForeignChildren(t *testing.T) {
	live := &haproxy.Model{
		Frontends: []haproxy.Frontend{{
			Name: "acme-frontend",
			Bind: []string{"0.0.0.0:443"},
			Rules: []haproxy.Rule{
				{Name: "acme-challenge"},
				{Name: "senselb-default-app-80"},
			},
		}},
	}
	desired := map[string]struct{}{"acme-frontend": {}}
	declared := map[string]struct{}{"acme-frontend": {}}

	filtered := filterLive(live, desired, map[string]struct{}{}, declared)
	if len(filtered.Frontends) != 1 {
		t.Fatalf("frontends = %+v, want the adopted frontend", filtered.Frontends)
	}
	rules := filtered.Frontends[0].Rules
	if len(rules) != 1 || rules[0].Name != "senselb-default-app-80" {
		t.Errorf("rules = %+v, want only the owned rule", rules)
	}
}

func TestApplyQueueNeedsLeaderElection(t *testing.T) {
	queue := NewApplyQueue()
	if !queue.NeedLeaderElection() {
		t.Error("NeedLeaderElection = false, want true: a non-leader replica must not program the firewall")
	}
}

func TestApplyQueueRecordsKeys(t *testing.T) {
	queue := NewApplyQueue()
	queue.Enqueue(types.NamespacedName{Namespace: "default", Name: "b"})
	queue.Enqueue(types.NamespacedName{Namespace: "default", Name: "a"})
	queue.Enqueue(types.NamespacedName{Namespace: "default", Name: "a"})

	keys := queue.Keys()
	want := []types.NamespacedName{
		{Namespace: "default", Name: "a"},
		{Namespace: "default", Name: "b"},
	}
	if len(keys) != len(want) {
		t.Fatalf("Keys = %v, want %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Errorf("Keys[%d] = %v, want %v", i, keys[i], want[i])
		}
	}
}

func TestBindHost(t *testing.T) {
	cases := []struct {
		bind string
		want string
	}{
		{"172.16.16.1:443", "172.16.16.1"},
		{"172.16.16.1", "172.16.16.1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"0.0.0.0:443", ""},
		{"[::]:443", ""},
		{"*:443", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := bindHost(tc.bind); got != tc.want {
			t.Errorf("bindHost(%q) = %q, want %q", tc.bind, got, tc.want)
		}
	}
}
