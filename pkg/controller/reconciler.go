package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yasn77/senselb/pkg/annotations"
	"github.com/yasn77/senselb/pkg/config"
	"github.com/yasn77/senselb/pkg/haproxy"
	"github.com/yasn77/senselb/pkg/provider"
)

// FinalizerName keeps a Service around until senselb has cleaned up after it.
const FinalizerName = "senselb.io/finalizer"

// reconcilesTotal counts Service reconcile requests, including the ones that
// short-circuit because the Service does not need senselb.
var reconcilesTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "senselb_reconciles_total",
	Help: "Number of Service reconcile requests handled.",
})

func init() {
	metrics.Registry.MustRegister(reconcilesTotal)
}

// annotationRetryDelay is how long a Service with unreadable annotations waits
// before the reconciler tries again. The watch on the Service also wakes it as
// soon as the annotations change.
const annotationRetryDelay = 60 * time.Second

// endpointSliceServiceLabel is the well-known label that ties an EndpointSlice
// to its Service.
const endpointSliceServiceLabel = discoveryv1.LabelServiceName

// ServiceReconciler turns Services, Nodes and EndpointSlices into desired
// HAProxy contributions.
//
// It deliberately does not apply anything: the apply pipeline (Task 4.4) owns
// the provider calls, and this reconciler only validates, builds and enqueues.
// It depends on provider.Provider for the interface type only, never on a
// concrete provider package.
type ServiceReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Provider provider.Provider
	Config   *config.Config
	Store    *Store
	Recorder record.EventRecorder
	Queue    *ApplyQueue
}

// Reconcile handles one Service.
//
// The flow is deliberately short-circuiting: a missing Service, a non-LoadBalancer
// Service and a disabled Service leave the cluster untouched beyond the cleanup
// path, while a managed Service gains its finalizer, has its targets read, and
// is turned into a contribution. Problems are published as conditions and
// events, never as a provider call.
func (r *ServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reconcilesTotal.Inc()

	var svc corev1.Service
	if err := r.Get(ctx, req.NamespacedName, &svc); err != nil {
		if apierrors.IsNotFound(err) {
			// Without a finalizer there is nothing to clean up. Store entries
			// left behind are pruned by the apply pipeline's rebuild.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get Service %s: %w", req.NamespacedName, err)
	}

	// Deletion: publish nothing new, drop the inventory, and let the finalizer
	// release the object.
	if !svc.DeletionTimestamp.IsZero() {
		if err := ClearStatus(ctx, r.Client, &svc); err != nil {
			return ctrl.Result{}, fmt.Errorf("clear status of Service %s: %w", req.NamespacedName, err)
		}
		return r.cleanup(ctx, &svc, ReasonDeleted, "Service is being deleted")
	}

	// A Service that is not a LoadBalancer is only interesting when senselb
	// previously managed it: its type changed away, so the contributions go.
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		if !controllerutil.ContainsFinalizer(&svc, FinalizerName) {
			return ctrl.Result{}, nil
		}
		if err := ClearStatus(ctx, r.Client, &svc); err != nil {
			return ctrl.Result{}, fmt.Errorf("clear status of Service %s: %w", req.NamespacedName, err)
		}
		return r.cleanup(ctx, &svc, ReasonDisabled, "Service is no longer a LoadBalancer")
	}

	values, err := annotations.Parse(svc.Annotations, r.annotationDefaults(), r.annotationPrefix())
	if err != nil {
		return r.reportProblem(ctx, &svc, ReasonAnnotationError, err.Error())
	}

	if !values.Enabled {
		if controllerutil.ContainsFinalizer(&svc, FinalizerName) ||
			len(svc.Status.Conditions) > 0 || len(svc.Status.LoadBalancer.Ingress) > 0 {
			if err := SetDisabled(ctx, r.Client, &svc, svc.Generation); err != nil {
				return ctrl.Result{}, fmt.Errorf("mark Service %s disabled: %w", req.NamespacedName, err)
			}
		}
		return r.cleanup(ctx, &svc, ReasonDisabled, "senselb management is disabled for this Service")
	}

	if !controllerutil.ContainsFinalizer(&svc, FinalizerName) {
		controllerutil.AddFinalizer(&svc, FinalizerName)
		if err := r.Update(ctx, &svc); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer to Service %s: %w", req.NamespacedName, err)
		}
	}

	model, issues, err := r.contribution(ctx, &svc, values)
	if err != nil {
		return ctrl.Result{}, err
	}

	if len(issues) > 0 {
		for _, issue := range issues {
			r.event(&svc, corev1.EventTypeWarning, issueReason(issue), issue.Error())
		}
		reason := issueReason(issues[0])
		if err := SetErrorWithReason(ctx, r.Client, &svc, svc.Generation, reason, issues[0].Error()); err != nil {
			return ctrl.Result{}, fmt.Errorf("set error condition on Service %s: %w", req.NamespacedName, err)
		}
	} else if err := ClearError(ctx, r.Client, &svc); err != nil {
		return ctrl.Result{}, fmt.Errorf("clear error condition on Service %s: %w", req.NamespacedName, err)
	}

	// A nil model means the Service contributes nothing at all; a non-nil one
	// is enqueued even when some of its ports were rejected.
	if model != nil {
		r.enqueue(req.NamespacedName)
	}
	return ctrl.Result{}, nil
}

// BuildForService implements ContributionFunc. It is the single build path the
// reconciler and the apply queue share, so both decide from the same annotations
// and the same model rules.
//
// A Service that is gone, is being deleted, is not a LoadBalancer or is disabled
// contributes nothing and reports no issue. A Kubernetes read failure is wrapped
// in *RetryableBuildError, which the queue treats as a transport failure and
// retries with backoff; everything else is a build issue that becomes a
// condition.
func (r *ServiceReconciler) BuildForService(ctx context.Context, key types.NamespacedName) (*haproxy.Model, []error) {
	var svc corev1.Service
	if err := r.Get(ctx, key, &svc); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, []error{&RetryableBuildError{Err: fmt.Errorf("get Service %s: %w", key, err)}}
	}
	if !svc.DeletionTimestamp.IsZero() || svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return nil, nil
	}

	values, err := annotations.Parse(svc.Annotations, r.annotationDefaults(), r.annotationPrefix())
	if err != nil {
		return nil, []error{err}
	}
	if !values.Enabled {
		return nil, nil
	}

	model, issues, err := r.contribution(ctx, &svc, values)
	if err != nil {
		return nil, []error{&RetryableBuildError{Err: err}}
	}
	return model, issues
}

// contribution builds one Service's desired fragment from its parsed
// annotations. The returned error is a Kubernetes read failure, not a build
// problem; build problems are the issues.
func (r *ServiceReconciler) contribution(ctx context.Context, svc *corev1.Service, values annotations.Values) (*haproxy.Model, []error, error) {
	nodes, endpoints, err := r.targets(ctx, svc, values)
	if err != nil {
		return nil, nil, err
	}
	name := types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}
	model, issues := BuildContribution(r.Config, values, name, svc.Spec.Ports, nodes, endpoints)
	return model, issues, nil
}

// RetryableBuildError reports that a contribution could not be built because a
// Kubernetes read failed. The apply queue retries it with backoff instead of
// publishing a condition for a transient failure.
type RetryableBuildError struct {
	Err error
}

// Error implements error.
func (e *RetryableBuildError) Error() string { return "build contribution: " + e.Err.Error() }

// Unwrap exposes the underlying read failure.
func (e *RetryableBuildError) Unwrap() error { return e.Err }

// cleanup releases senselb's hold on a Service.
//
// It deletes the Service's ownership entries, asks the apply queue for a full
// rebuild (the store no longer lists the Service, so the next diff deletes its
// objects), and removes the finalizer immediately. HAProxy object removal is
// therefore best-effort and asynchronous.
//
// A successful drain prunes the objects while the queue still remembers the
// pre-cleanup inventory. A crash between the store-key deletion and that drain,
// or a restart during a persistently failing drain, leaves a residual the
// startup drift reconcile cannot repair: the in-memory inventory dies with the
// process, the store no longer lists the Service's objects, and filterLive
// therefore keeps them out of scope. An operator removes such orphans from
// OPNsense; leaving them is the deliberate price of never deleting an object
// senselb cannot attribute (see the ApplyQueue orphan rule).
func (r *ServiceReconciler) cleanup(ctx context.Context, svc *corev1.Service, reason, message string) (ctrl.Result, error) {
	if r.Store != nil {
		keys, err := r.Store.ForService(ctx, svc.Namespace, svc.Name)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("list ownership entries of Service %s/%s: %w", svc.Namespace, svc.Name, err)
		}
		for _, key := range keys {
			if err := r.Store.Delete(ctx, key); err != nil {
				return ctrl.Result{}, fmt.Errorf("delete ownership entry %q: %w", key, err)
			}
		}
	}

	r.enqueue(RebuildAllKey)

	if controllerutil.ContainsFinalizer(svc, FinalizerName) {
		controllerutil.RemoveFinalizer(svc, FinalizerName)
		if err := r.Update(ctx, svc); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("remove finalizer from Service %s/%s: %w", svc.Namespace, svc.Name, err)
		}
	}

	r.event(svc, corev1.EventTypeNormal, reason, message)
	return ctrl.Result{}, nil
}

// reportProblem publishes an unrecoverable annotation error and retries later.
// It never enqueues: there is nothing trustworthy to apply.
func (r *ServiceReconciler) reportProblem(ctx context.Context, svc *corev1.Service, reason, message string) (ctrl.Result, error) {
	r.event(svc, corev1.EventTypeWarning, reason, message)
	if err := SetErrorWithReason(ctx, r.Client, svc, svc.Generation, reason, message); err != nil {
		return ctrl.Result{}, fmt.Errorf("set error condition on Service %s/%s: %w", svc.Namespace, svc.Name, err)
	}
	return ctrl.Result{RequeueAfter: annotationRetryDelay}, nil
}

// targets reads the nodes or endpoints that back the Service's ports, according
// to its target-mode. Nodeport mode asks for ready nodes; endpoint mode asks for
// the Service's ready EndpointSlice addresses.
func (r *ServiceReconciler) targets(ctx context.Context, svc *corev1.Service, values annotations.Values) ([]NodeInfo, []EndpointInfo, error) {
	if values.TargetMode == "endpoint" {
		endpoints, err := r.readEndpoints(ctx, svc)
		return nil, endpoints, err
	}
	nodes, err := r.readNodes(ctx)
	return nodes, nil, err
}

// readNodes lists the ready nodes that pass the configured node selector,
// sorted by name so the resulting server list is deterministic.
func (r *ServiceReconciler) readNodes(ctx context.Context) ([]NodeInfo, error) {
	var list corev1.NodeList
	if err := r.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list Nodes: %w", err)
	}

	nodes := make([]NodeInfo, 0, len(list.Items))
	for i := range list.Items {
		node := &list.Items[i]
		if !nodeIsReady(node) || !r.nodeSelected(node) {
			continue
		}
		nodes = append(nodes, NodeInfo{Name: node.Name, Addresses: nodeAddresses(node)})
	}
	slices.SortFunc(nodes, func(a, b NodeInfo) int { return strings.Compare(a.Name, b.Name) })
	return nodes, nil
}

// readEndpoints lists the ready addresses of the Service's EndpointSlices.
//
// The result is flat: EndpointInfo cannot say which Service port an address
// belongs to, so endpoint mode is only unambiguous for a single TCP port.
// BuildContribution rejects a multi-port Service in endpoint mode instead of
// feeding every backend the same flattened address list; nothing later in the
// pipeline resolves per-port endpoints.
func (r *ServiceReconciler) readEndpoints(ctx context.Context, svc *corev1.Service) ([]EndpointInfo, error) {
	var list discoveryv1.EndpointSliceList
	err := r.List(ctx, &list,
		client.InNamespace(svc.Namespace),
		client.MatchingLabels{endpointSliceServiceLabel: svc.Name},
	)
	if err != nil {
		return nil, fmt.Errorf("list EndpointSlices of Service %s/%s: %w", svc.Namespace, svc.Name, err)
	}

	var endpoints []EndpointInfo
	seen := make(map[string]struct{})
	for _, slice := range list.Items {
		for _, endpoint := range slice.Endpoints {
			// A nil Ready condition means "unknown", which Kubernetes treats
			// as ready.
			if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
				continue
			}
			for _, port := range slice.Ports {
				if port.Port == nil || *port.Port <= 0 {
					continue
				}
				for _, address := range endpoint.Addresses {
					if address == "" {
						continue
					}
					key := address + ":" + strconv.Itoa(int(*port.Port))
					if _, duplicate := seen[key]; duplicate {
						continue
					}
					seen[key] = struct{}{}
					endpoints = append(endpoints, EndpointInfo{IP: address, Port: *port.Port})
				}
			}
		}
	}
	slices.SortFunc(endpoints, func(a, b EndpointInfo) int {
		if c := strings.Compare(a.IP, b.IP); c != 0 {
			return c
		}
		return int(a.Port - b.Port)
	})
	return endpoints, nil
}

// nodeIsReady reports whether the node's Ready condition is true.
func nodeIsReady(node *corev1.Node) bool {
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

// nodeSelected reports whether the node's labels satisfy the configured node
// selector. An empty selector accepts every node.
func (r *ServiceReconciler) nodeSelected(node *corev1.Node) bool {
	if r.Config == nil {
		return true
	}
	for key, value := range r.Config.NodeSelector {
		if node.Labels[key] != value {
			return false
		}
	}
	return true
}

// nodeAddresses returns the node's InternalIP and ExternalIP addresses, internal
// first, in status order. Hostname entries are not routable from the provider
// and are dropped.
func nodeAddresses(node *corev1.Node) []string {
	var internal, external []string
	for _, address := range node.Status.Addresses {
		switch address.Type {
		case corev1.NodeInternalIP:
			if address.Address != "" {
				internal = append(internal, address.Address)
			}
		case corev1.NodeExternalIP:
			if address.Address != "" {
				external = append(external, address.Address)
			}
		}
	}
	return append(internal, external...)
}

// SetupWithManager registers the Service, Node and EndpointSlice watches.
func (r *ServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return errors.New("setup ServiceReconciler: manager is nil")
	}
	if r.Store == nil {
		return errors.New("setup ServiceReconciler: Store is required")
	}
	if r.Config == nil {
		return errors.New("setup ServiceReconciler: Config is required")
	}
	if r.Recorder == nil {
		// The plan fixes Recorder's type as the classic client-go recorder;
		// the replacement (GetEventRecorder) speaks the events.k8s.io API and
		// has a different method signature, so the deprecated constructor is
		// deliberate until that migration is planned.
		r.Recorder = mgr.GetEventRecorderFor("senselb") //nolint:staticcheck // see above
	}
	if r.Queue == nil {
		r.Queue = NewApplyQueue()
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}, builder.WithPredicates(servicePredicate())).
		Watches(&corev1.Node{}, handler.EnqueueRequestsFromMapFunc(r.nodesToServices)).
		Watches(&discoveryv1.EndpointSlice{}, handler.EnqueueRequestsFromMapFunc(r.endpointSlicesToServices)).
		Complete(r)
}

// servicePredicate admits LoadBalancer Services and any Service still carrying
// senselb's finalizer, so a type change away from LoadBalancer still reaches the
// cleanup path.
func servicePredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return managesObject(e.Object) },
		UpdateFunc:  func(e event.UpdateEvent) bool { return managesObject(e.ObjectOld) || managesObject(e.ObjectNew) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return managesObject(e.Object) },
		GenericFunc: func(e event.GenericEvent) bool { return managesObject(e.Object) },
	}
}

// managesObject reports whether an object is a Service senselb must reconcile.
func managesObject(object client.Object) bool {
	svc, ok := object.(*corev1.Service)
	if !ok {
		return false
	}
	return svc.Spec.Type == corev1.ServiceTypeLoadBalancer || controllerutil.ContainsFinalizer(svc, FinalizerName)
}

// nodesToServices fans a Node event out to every Service the store knows about.
// Node membership and addresses affect nodeport-mode backends only, but the
// store does not record target mode, so every managed Service is enqueued.
func (r *ServiceReconciler) nodesToServices(ctx context.Context, _ client.Object) []reconcile.Request {
	if r.Store == nil {
		return nil
	}
	services, err := r.Store.ManagedServices(ctx)
	if err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0, len(services))
	for _, service := range services {
		requests = append(requests, reconcile.Request{NamespacedName: service})
	}
	return requests
}

// endpointSlicesToServices maps an EndpointSlice event to its Service, first by
// the well-known service-name label and then, as a fallback, by an owner
// reference of kind Service.
func (r *ServiceReconciler) endpointSlicesToServices(_ context.Context, object client.Object) []reconcile.Request {
	slice, ok := object.(*discoveryv1.EndpointSlice)
	if !ok {
		return nil
	}

	name := slice.Labels[endpointSliceServiceLabel]
	if name == "" {
		for _, owner := range slice.OwnerReferences {
			if owner.Kind == "Service" && owner.Name != "" {
				name = owner.Name
				break
			}
		}
	}
	if name == "" {
		return nil
	}
	return []reconcile.Request{{
		NamespacedName: types.NamespacedName{Namespace: slice.Namespace, Name: name},
	}}
}

// enqueue records a key on the stub apply queue, tolerating a nil queue so a
// partially wired reconciler still reconciles.
func (r *ServiceReconciler) enqueue(key types.NamespacedName) {
	if r.Queue == nil {
		return
	}
	r.Queue.Enqueue(key)
}

// event records an event when a recorder is configured.
func (r *ServiceReconciler) event(svc *corev1.Service, eventType, reason, message string) {
	if r.Recorder == nil {
		return
	}
	r.Recorder.Event(svc, eventType, reason, message)
}

// annotationDefaults returns the ConfigMap defaults layer.
func (r *ServiceReconciler) annotationDefaults() annotations.Values {
	if r.Config == nil {
		return annotations.Values{}
	}
	return r.Config.Defaults
}

// annotationPrefix returns the configured annotation prefix; an empty value
// makes Parse use its default.
func (r *ServiceReconciler) annotationPrefix() string {
	if r.Config == nil {
		return ""
	}
	return r.Config.AnnotationPrefix
}

// issueReason maps a build issue onto the condition reason that classifies it.
func issueReason(err error) string {
	var unknownListener *UnknownListenerError
	var unsupportedProtocol *UDPUnsupportedError
	var annotationError *AnnotationError
	switch {
	case errors.As(err, &unknownListener):
		return ReasonConfigError
	case errors.As(err, &unsupportedProtocol):
		return ReasonUnsupportedProtocol
	case errors.As(err, &annotationError):
		return ReasonAnnotationError
	default:
		return ReasonConfigError
	}
}

// Compile-time assertion that the reconciler satisfies the controller-runtime
// contract.
var _ reconcile.Reconciler = (*ServiceReconciler)(nil)
