package controller

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1 to scheme: %v", err)
	}
	if err := discoveryv1.AddToScheme(scheme); err != nil {
		t.Fatalf("add discoveryv1 to scheme: %v", err)
	}
	return scheme
}

// newTestReconciler builds a reconciler over the controller-runtime fake client.
// The client is configured with the Service status subresource, so status
// writes behave like a real API server without needing envtest.
func newTestReconciler(t *testing.T, objects ...client.Object) (*ServiceReconciler, client.Client, *ApplyQueue, *record.FakeRecorder) {
	t.Helper()
	cl := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithStatusSubresource(&corev1.Service{}).
		WithObjects(objects...).
		Build()
	queue := NewApplyQueue()
	recorder := record.NewFakeRecorder(100)
	reconciler := &ServiceReconciler{
		Client:   cl,
		Scheme:   testScheme(t),
		Config:   buildConfig(),
		Store:    &Store{Client: cl, Namespace: "senselb-system", Name: "senselb-store"},
		Recorder: recorder,
		Queue:    queue,
	}
	return reconciler, cl, queue, recorder
}

func lbService(name string, annotations map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, Annotations: annotations},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{tcpPort(80, 30080)},
		},
	}
}

func requestFor(svc *corev1.Service) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}}
}

func getService(t *testing.T, cl client.Client, name string) *corev1.Service {
	t.Helper()
	var svc corev1.Service
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: name}, &svc); err != nil {
		t.Fatalf("get Service %s: %v", name, err)
	}
	return &svc
}

func drainEvents(recorder *record.FakeRecorder) []string {
	var events []string
	for {
		select {
		case message := <-recorder.Events:
			events = append(events, message)
		default:
			return events
		}
	}
}

func eventContaining(t *testing.T, events []string, fragment string) {
	t.Helper()
	for _, message := range events {
		if strings.Contains(message, fragment) {
			return
		}
	}
	t.Fatalf("no event contains %q: %v", fragment, events)
}

func TestReconcileAddsFinalizerAndEnqueues(t *testing.T) {
	svc := lbService("app", map[string]string{
		"senselb.io/listeners": "web",
		"senselb.io/host":      "app.example.com",
	})
	reconciler, cl, queue, _ := newTestReconciler(t, svc)

	result, err := reconciler.Reconcile(context.Background(), requestFor(svc))
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !result.IsZero() {
		t.Errorf("result = %+v, want an immediate success", result)
	}

	got := getService(t, cl, "app")
	if !containsFinalizer(got) {
		t.Errorf("finalizers = %v, want %q", got.Finalizers, FinalizerName)
	}
	want := []types.NamespacedName{{Namespace: "default", Name: "app"}}
	if keys := queue.Keys(); len(keys) != 1 || keys[0] != want[0] {
		t.Errorf("enqueued = %v, want %v", keys, want)
	}
	if condition := meta.FindStatusCondition(got.Status.Conditions, ConditionError); condition != nil {
		t.Errorf("unexpected Error condition: %+v", condition)
	}
}

func containsFinalizer(svc *corev1.Service) bool {
	for _, finalizer := range svc.Finalizers {
		if finalizer == FinalizerName {
			return true
		}
	}
	return false
}

func TestReconcileBadAnnotations(t *testing.T) {
	svc := lbService("app", map[string]string{"senselb.io/mode": "sideways"})
	reconciler, cl, queue, recorder := newTestReconciler(t, svc)

	result, err := reconciler.Reconcile(context.Background(), requestFor(svc))
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if result.RequeueAfter != annotationRetryDelay {
		t.Errorf("requeue after = %v, want %v", result.RequeueAfter, annotationRetryDelay)
	}
	if len(queue.Keys()) != 0 {
		t.Errorf("enqueued = %v, want nothing", queue.Keys())
	}

	got := getService(t, cl, "app")
	condition := meta.FindStatusCondition(got.Status.Conditions, ConditionError)
	if condition == nil || condition.Status != metav1.ConditionTrue || condition.Reason != ReasonAnnotationError {
		t.Fatalf("Error condition = %+v", condition)
	}
	if condition.ObservedGeneration != got.Generation {
		t.Errorf("observed generation = %d, want %d", condition.ObservedGeneration, got.Generation)
	}
	eventContaining(t, drainEvents(recorder), ReasonAnnotationError)
}

func TestReconcileDisabled(t *testing.T) {
	svc := lbService("app", map[string]string{
		"senselb.io/enabled":   "false",
		"senselb.io/listeners": "web",
	})
	svc.Finalizers = []string{FinalizerName}
	reconciler, cl, queue, _ := newTestReconciler(t, svc)
	if err := reconciler.Store.Put(context.Background(), "default/app/backend:senselb-default-app-80", "uuid-1"); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	if _, err := reconciler.Reconcile(context.Background(), requestFor(svc)); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	got := getService(t, cl, "app")
	if containsFinalizer(got) {
		t.Error("finalizer must be removed when the Service is disabled")
	}
	if condition := meta.FindStatusCondition(got.Status.Conditions, ConditionReady); condition == nil ||
		condition.Status != metav1.ConditionFalse || condition.Reason != ReasonDisabled {
		t.Errorf("Ready condition = %+v", condition)
	}
	if condition := meta.FindStatusCondition(got.Status.Conditions, ConditionError); condition == nil ||
		condition.Status != metav1.ConditionFalse || condition.Reason != ReasonDisabled {
		t.Errorf("Error condition = %+v, want the Error-less Disabled state", condition)
	}
	if keys, err := reconciler.Store.ForService(context.Background(), "default", "app"); err != nil || len(keys) != 0 {
		t.Errorf("store keys = %v, err %v", keys, err)
	}
	if keys := queue.Keys(); len(keys) != 1 || keys[0] != RebuildAllKey {
		t.Errorf("enqueued = %v, want the rebuild key", keys)
	}
}

func TestReconcileIgnoresNonLoadBalancer(t *testing.T) {
	svc := lbService("app", nil)
	svc.Spec.Type = corev1.ServiceTypeClusterIP
	reconciler, _, queue, _ := newTestReconciler(t, svc)

	if _, err := reconciler.Reconcile(context.Background(), requestFor(svc)); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(queue.Keys()) != 0 {
		t.Errorf("enqueued = %v, want nothing", queue.Keys())
	}
}

func TestReconcileTypeChangedAwayFromLoadBalancer(t *testing.T) {
	svc := lbService("app", nil)
	svc.Spec.Type = corev1.ServiceTypeClusterIP
	svc.Finalizers = []string{FinalizerName}
	reconciler, cl, queue, _ := newTestReconciler(t, svc)
	if err := reconciler.Store.Put(context.Background(), "default/app/backend:senselb-default-app-80", "uuid-1"); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	if _, err := reconciler.Reconcile(context.Background(), requestFor(svc)); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	got := getService(t, cl, "app")
	if containsFinalizer(got) {
		t.Error("finalizer must be removed when the Service leaves LoadBalancer")
	}
	if len(got.Status.Conditions) != 0 {
		t.Errorf("conditions = %v, want cleared", got.Status.Conditions)
	}
	if keys, err := reconciler.Store.ForService(context.Background(), "default", "app"); err != nil || len(keys) != 0 {
		t.Errorf("store keys = %v, err %v", keys, err)
	}
	if keys := queue.Keys(); len(keys) != 1 || keys[0] != RebuildAllKey {
		t.Errorf("enqueued = %v, want the rebuild key", keys)
	}
}

func TestReconcileDeletion(t *testing.T) {
	svc := lbService("app", nil)
	svc.Finalizers = []string{FinalizerName}
	now := metav1.Now()
	svc.DeletionTimestamp = &now
	reconciler, cl, queue, _ := newTestReconciler(t, svc)
	if err := reconciler.Store.Put(context.Background(), "default/app/backend:senselb-default-app-80", "uuid-1"); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	if _, err := reconciler.Reconcile(context.Background(), requestFor(svc)); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if keys, err := reconciler.Store.ForService(context.Background(), "default", "app"); err != nil || len(keys) != 0 {
		t.Errorf("store keys = %v, err %v", keys, err)
	}
	if keys := queue.Keys(); len(keys) != 1 || keys[0] != RebuildAllKey {
		t.Errorf("enqueued = %v, want the rebuild key", keys)
	}
	var got corev1.Service
	err := cl.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "app"}, &got)
	if err == nil && containsFinalizer(&got) {
		t.Error("the finalizer must be released on deletion")
	}
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("get Service: %v", err)
	}
}

func TestReconcileUnknownListener(t *testing.T) {
	svc := lbService("app", map[string]string{"senselb.io/listeners": "missing"})
	reconciler, cl, queue, recorder := newTestReconciler(t, svc)

	if _, err := reconciler.Reconcile(context.Background(), requestFor(svc)); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	got := getService(t, cl, "app")
	condition := meta.FindStatusCondition(got.Status.Conditions, ConditionError)
	if condition == nil || condition.Reason != ReasonConfigError {
		t.Fatalf("Error condition = %+v, want ConfigError", condition)
	}
	if !strings.Contains(condition.Message, "missing") {
		t.Errorf("message = %q", condition.Message)
	}
	if len(queue.Keys()) != 0 {
		t.Errorf("enqueued = %v, want nothing without a contribution", queue.Keys())
	}
	eventContaining(t, drainEvents(recorder), "missing")
}

func TestReconcileUnsupportedProtocolKeepsTCP(t *testing.T) {
	svc := lbService("app", map[string]string{"senselb.io/listeners": "web"})
	svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Name: "dns", Port: 53, Protocol: corev1.ProtocolUDP})
	reconciler, cl, queue, recorder := newTestReconciler(t, svc)

	if _, err := reconciler.Reconcile(context.Background(), requestFor(svc)); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	want := types.NamespacedName{Namespace: "default", Name: "app"}
	if keys := queue.Keys(); len(keys) != 1 || keys[0] != want {
		t.Errorf("enqueued = %v, want the TCP contribution", keys)
	}
	got := getService(t, cl, "app")
	condition := meta.FindStatusCondition(got.Status.Conditions, ConditionError)
	if condition == nil || condition.Reason != ReasonUnsupportedProtocol {
		t.Fatalf("Error condition = %+v, want UnsupportedProtocol", condition)
	}
	if !strings.Contains(strings.ToUpper(condition.Message), "UDP") {
		t.Errorf("message = %q", condition.Message)
	}
	eventContaining(t, drainEvents(recorder), "UDP")
}

func TestReconcileEndpointMode(t *testing.T) {
	svc := lbService("app", map[string]string{
		"senselb.io/listeners":   "web",
		"senselb.io/target-mode": "endpoint",
	})
	ready := true
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "app-abc",
			Labels:    map[string]string{endpointSliceServiceLabel: "app"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{"10.244.0.5"},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		}},
		Ports: []discoveryv1.EndpointPort{{Name: ptr("http"), Port: ptr(int32(8080))}},
	}
	reconciler, cl, queue, _ := newTestReconciler(t, svc, slice)

	if _, err := reconciler.Reconcile(context.Background(), requestFor(svc)); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(queue.Keys()) != 1 {
		t.Errorf("enqueued = %v, want one key", queue.Keys())
	}
	got := getService(t, cl, "app")
	if condition := meta.FindStatusCondition(got.Status.Conditions, ConditionError); condition != nil {
		t.Errorf("unexpected Error condition: %+v", condition)
	}
}

func ptr[T any](value T) *T {
	return &value
}

func TestNodesToServices(t *testing.T) {
	reconciler, _, _, _ := newTestReconciler(t)
	ctx := context.Background()
	for _, key := range []string{
		"default/beta/backend:b",
		"prod/alpha/backend:a",
		"default/alpha/backend:a",
	} {
		if err := reconciler.Store.Put(ctx, key, "uuid"); err != nil {
			t.Fatalf("seed store: %v", err)
		}
	}

	requests := reconciler.nodesToServices(ctx, &corev1.Node{})
	want := []types.NamespacedName{
		{Namespace: "default", Name: "alpha"},
		{Namespace: "default", Name: "beta"},
		{Namespace: "prod", Name: "alpha"},
	}
	if len(requests) != len(want) {
		t.Fatalf("requests = %v, want %v", requests, want)
	}
	for i, request := range requests {
		if request.NamespacedName != want[i] {
			t.Errorf("request[%d] = %v, want %v", i, request.NamespacedName, want[i])
		}
	}
}

func TestEndpointSlicesToServices(t *testing.T) {
	reconciler, _, _, _ := newTestReconciler(t)
	ctx := context.Background()

	byLabel := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "app-abc",
			Labels:    map[string]string{endpointSliceServiceLabel: "app"},
		},
	}
	requests := reconciler.endpointSlicesToServices(ctx, byLabel)
	if len(requests) != 1 || requests[0].NamespacedName != (types.NamespacedName{Namespace: "default", Name: "app"}) {
		t.Errorf("label mapping = %v", requests)
	}

	byOwner := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "default",
			Name:            "app-def",
			OwnerReferences: []metav1.OwnerReference{{Kind: "Service", Name: "app"}},
		},
	}
	requests = reconciler.endpointSlicesToServices(ctx, byOwner)
	if len(requests) != 1 || requests[0].Name != "app" {
		t.Errorf("owner mapping = %v", requests)
	}

	unmapped := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "orphan"}}
	if requests := reconciler.endpointSlicesToServices(ctx, unmapped); len(requests) != 0 {
		t.Errorf("orphan mapping = %v, want none", requests)
	}
}

func TestServicePredicate(t *testing.T) {
	predicate := servicePredicate()

	loadBalancer := lbService("app", nil)
	clusterIP := lbService("other", nil)
	clusterIP.Spec.Type = corev1.ServiceTypeClusterIP
	finalised := lbService("legacy", nil)
	finalised.Spec.Type = corev1.ServiceTypeClusterIP
	finalised.Finalizers = []string{FinalizerName}

	cases := []struct {
		name string
		got  bool
		want bool
	}{
		{"create LoadBalancer", predicate.Create(event.CreateEvent{Object: loadBalancer}), true},
		{"create ClusterIP", predicate.Create(event.CreateEvent{Object: clusterIP}), false},
		{"create finalised ClusterIP", predicate.Create(event.CreateEvent{Object: finalised}), true},
		{"update LoadBalancer to ClusterIP", predicate.Update(event.UpdateEvent{ObjectOld: loadBalancer, ObjectNew: clusterIP}), true},
		{"update ClusterIP", predicate.Update(event.UpdateEvent{ObjectOld: clusterIP, ObjectNew: clusterIP}), false},
		{"delete LoadBalancer", predicate.Delete(event.DeleteEvent{Object: loadBalancer}), true},
		{"delete ClusterIP", predicate.Delete(event.DeleteEvent{Object: clusterIP}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("predicate = %t, want %t", tc.got, tc.want)
			}
		})
	}
}

func TestStatusSetters(t *testing.T) {
	svc := lbService("app", nil)
	_, cl, _, _ := newTestReconciler(t, svc)
	ctx := context.Background()

	got := getService(t, cl, "app")
	if err := SetReady(ctx, cl, got, LoadBalancerIngress([]string{"192.168.1.10"}), 3, "programmed"); err != nil {
		t.Fatalf("SetReady: %v", err)
	}
	got = getService(t, cl, "app")
	if condition := meta.FindStatusCondition(got.Status.Conditions, ConditionReady); condition == nil ||
		condition.Status != metav1.ConditionTrue || condition.ObservedGeneration != 3 {
		t.Errorf("Ready condition = %+v", condition)
	}
	if len(got.Status.LoadBalancer.Ingress) != 1 || got.Status.LoadBalancer.Ingress[0].IP != "192.168.1.10" {
		t.Errorf("ingress = %+v", got.Status.LoadBalancer.Ingress)
	}

	if err := SetError(ctx, cl, got, 4, "cannot reach the provider"); err != nil {
		t.Fatalf("SetError: %v", err)
	}
	got = getService(t, cl, "app")
	if condition := meta.FindStatusCondition(got.Status.Conditions, ConditionReady); condition == nil ||
		condition.Status != metav1.ConditionFalse || condition.Reason != ReasonConfigError {
		t.Errorf("Ready condition = %+v", condition)
	}
	if condition := meta.FindStatusCondition(got.Status.Conditions, ConditionError); condition == nil ||
		condition.Status != metav1.ConditionTrue || condition.Message != "cannot reach the provider" {
		t.Errorf("Error condition = %+v", condition)
	}
	if len(got.Status.LoadBalancer.Ingress) != 1 {
		t.Errorf("SetError must leave ingress untouched, got %+v", got.Status.LoadBalancer.Ingress)
	}

	// Repeating an identical status write must not touch the object: a write
	// would bump the resource version and wake the Service watch again.
	resourceVersion := got.ResourceVersion
	if err := SetError(ctx, cl, got, 4, "cannot reach the provider"); err != nil {
		t.Fatalf("repeat SetError: %v", err)
	}
	if got.ResourceVersion != resourceVersion {
		t.Errorf("repeat SetError wrote the status: resource version %q -> %q", resourceVersion, got.ResourceVersion)
	}

	if err := SetDisabled(ctx, cl, got, 5); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}
	got = getService(t, cl, "app")
	if len(got.Status.LoadBalancer.Ingress) != 0 {
		t.Errorf("SetDisabled must clear ingress, got %+v", got.Status.LoadBalancer.Ingress)
	}
	if condition := meta.FindStatusCondition(got.Status.Conditions, ConditionError); condition == nil ||
		condition.Status != metav1.ConditionFalse || condition.Reason != ReasonDisabled {
		t.Errorf("Error condition = %+v", condition)
	}

	if err := ClearStatus(ctx, cl, got); err != nil {
		t.Fatalf("ClearStatus: %v", err)
	}
	got = getService(t, cl, "app")
	if len(got.Status.Conditions) != 0 {
		t.Errorf("conditions = %v, want cleared", got.Status.Conditions)
	}
}

func TestLoadBalancerIngressDropsBlanks(t *testing.T) {
	ingress := LoadBalancerIngress([]string{"192.168.1.10", " ", ""})
	if len(ingress) != 1 || ingress[0].IP != "192.168.1.10" {
		t.Errorf("ingress = %+v", ingress)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()
	store := &Store{Client: cl, Namespace: "senselb-system", Name: "senselb-store"}
	ctx := context.Background()

	if uuid, ok, err := store.Get(ctx, "default/app/backend:one"); err != nil || ok || uuid != "" {
		t.Fatalf("empty store Get = %q, %t, %v", uuid, ok, err)
	}

	if err := store.Put(ctx, "default/app/backend:one", "uuid-1"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if uuid, ok, err := store.Get(ctx, "default/app/backend:one"); err != nil || !ok || uuid != "uuid-1" {
		t.Fatalf("Get = %q, %t, %v", uuid, ok, err)
	}

	if err := store.Put(ctx, "prod/app/backend:one", "uuid-2"); err != nil {
		t.Fatalf("Put second Service: %v", err)
	}
	keys, err := store.ForService(ctx, "default", "app")
	if err != nil || len(keys) != 1 || keys[0] != "default/app/backend:one" {
		t.Fatalf("ForService = %v, %v", keys, err)
	}

	services, err := store.ManagedServices(ctx)
	if err != nil {
		t.Fatalf("ManagedServices: %v", err)
	}
	want := []types.NamespacedName{{Namespace: "default", Name: "app"}, {Namespace: "prod", Name: "app"}}
	if len(services) != 2 || services[0] != want[0] || services[1] != want[1] {
		t.Errorf("ManagedServices = %v, want %v", services, want)
	}

	if err := store.Delete(ctx, "default/app/backend:one"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := store.Delete(ctx, "default/app/backend:one"); err != nil {
		t.Fatalf("Delete absent key: %v", err)
	}
	if _, ok, err := store.Get(ctx, "default/app/backend:one"); err != nil || ok {
		t.Errorf("deleted key still present: %t, %v", ok, err)
	}

	// A malformed key cannot be attributed to a Service and is skipped.
	if err := store.Put(ctx, "malformed", "uuid-3"); err != nil {
		t.Fatalf("Put malformed: %v", err)
	}
	if services, err := store.ManagedServices(ctx); err != nil || len(services) != 1 {
		t.Errorf("ManagedServices with a malformed key = %v, %v", services, err)
	}
}

func TestStoreConcurrentPut(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()
	store := &Store{Client: cl, Namespace: "senselb-system", Name: "senselb-store"}
	ctx := context.Background()

	const writers = 25
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			key := "default/app/backend:" + strconv.Itoa(index)
			errs <- store.Put(ctx, key, "uuid")
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Put: %v", err)
		}
	}

	keys, err := store.ForService(ctx, "default", "app")
	if err != nil {
		t.Fatalf("ForService: %v", err)
	}
	if len(keys) != writers {
		t.Errorf("entries = %d, want %d", len(keys), writers)
	}
}

// conflictOnceClient injects one update conflict before delegating, so the
// store's bounded optimistic retry is exercised without racing goroutines.
type conflictOnceClient struct {
	client.Client
	remaining int
}

func (c *conflictOnceClient) Update(ctx context.Context, object client.Object, opts ...client.UpdateOption) error {
	if c.remaining > 0 {
		c.remaining--
		return apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, object.GetName(), errors.New("injected conflict"))
	}
	return c.Client.Update(ctx, object, opts...)
}

func TestStoreRetriesOnConflict(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()
	store := &Store{Client: cl, Namespace: "senselb-system", Name: "senselb-store"}
	ctx := context.Background()
	if err := store.Put(ctx, "default/app/backend:one", "uuid-1"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	retrying := &Store{
		Client:    &conflictOnceClient{Client: cl, remaining: 1},
		Namespace: store.Namespace,
		Name:      store.Name,
	}
	if err := retrying.Put(ctx, "default/app/backend:two", "uuid-2"); err != nil {
		t.Fatalf("Put after a conflict: %v", err)
	}

	for _, key := range []string{"default/app/backend:one", "default/app/backend:two"} {
		if _, ok, err := store.Get(ctx, key); err != nil || !ok {
			t.Errorf("key %q missing after retry: %t, %v", key, ok, err)
		}
	}
}

func TestStoreIgnoresEmptyConfigMapState(t *testing.T) {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "senselb-system", Name: "senselb-store"},
	}
	cl := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(configMap).Build()
	store := &Store{Client: cl, Namespace: "senselb-system", Name: "senselb-store"}

	if services, err := store.ManagedServices(context.Background()); err != nil || len(services) != 0 {
		t.Errorf("ManagedServices = %v, %v", services, err)
	}
}

func TestAnnotationRetryDelayIsBounded(t *testing.T) {
	if annotationRetryDelay <= 0 || annotationRetryDelay > time.Minute {
		t.Errorf("retry delay = %v, want a positive delay of at most a minute", annotationRetryDelay)
	}
}
