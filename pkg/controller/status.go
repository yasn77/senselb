package controller

import (
	"context"
	"reflect"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Status condition types senselb maintains on a Service. Both ride in
// ServiceStatus.Conditions, which is available in the pinned k8s.io/api.
const (
	// ConditionReady reports whether the Service's HAProxy objects are
	// programmed.
	ConditionReady = "Ready"
	// ConditionError reports whether the last reconcile found a problem.
	ConditionError = "Error"
)

// Condition reasons, one per outcome an operator can act on.
const (
	// ReasonReconciled is the reason on a healthy condition.
	ReasonReconciled = "Reconciled"
	// ReasonConfigError reports a problem with the controller configuration,
	// such as an unknown listener.
	ReasonConfigError = "ConfigError"
	// ReasonAnnotationError reports an annotation senselb cannot honour.
	ReasonAnnotationError = "AnnotationError"
	// ReasonUnsupportedProtocol reports a Service port senselb does not proxy.
	ReasonUnsupportedProtocol = "UnsupportedProtocol"
	// ReasonDisabled reports that senselb management is switched off.
	ReasonDisabled = "Disabled"
	// ReasonDeleted reports that the Service is being removed.
	ReasonDeleted = "Deleted"
)

// SetReady marks the Service as programmed and publishes its load-balancer
// ingress addresses. generation is the Service generation the reconcile
// observed, so a stale status is detectable. The Error condition is cleared.
//
// The ingress slice replaces whatever the Service carried; a caller that has no
// new addresses should pass the previous ones rather than nil.
func SetReady(ctx context.Context, c client.Client, svc *corev1.Service, ingress []corev1.LoadBalancerIngress, generation int64, message string) error {
	return updateStatus(ctx, c, svc, func() {
		meta.SetStatusCondition(&svc.Status.Conditions, metav1.Condition{
			Type:               ConditionReady,
			Status:             metav1.ConditionTrue,
			Reason:             ReasonReconciled,
			Message:            message,
			ObservedGeneration: generation,
		})
		meta.SetStatusCondition(&svc.Status.Conditions, metav1.Condition{
			Type:               ConditionError,
			Status:             metav1.ConditionFalse,
			Reason:             ReasonReconciled,
			ObservedGeneration: generation,
		})
		svc.Status.LoadBalancer.Ingress = ingress
	})
}

// SetError marks the Service as not ready for the given reason. Existing
// ingress entries are left untouched, so an address published by an earlier
// successful reconcile survives a transient failure.
func SetError(ctx context.Context, c client.Client, svc *corev1.Service, generation int64, message string) error {
	return SetErrorWithReason(ctx, c, svc, generation, ReasonConfigError, message)
}

// SetErrorWithReason is SetError with an explicit condition reason, for the
// caller that knows the failure class (AnnotationError, UnsupportedProtocol,
// ConfigError).
func SetErrorWithReason(ctx context.Context, c client.Client, svc *corev1.Service, generation int64, reason, message string) error {
	return updateStatus(ctx, c, svc, func() {
		meta.SetStatusCondition(&svc.Status.Conditions, metav1.Condition{
			Type:               ConditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             reason,
			Message:            message,
			ObservedGeneration: generation,
		})
		meta.SetStatusCondition(&svc.Status.Conditions, metav1.Condition{
			Type:               ConditionError,
			Status:             metav1.ConditionTrue,
			Reason:             reason,
			Message:            message,
			ObservedGeneration: generation,
		})
	})
}

// SetDisabled records that senselb no longer manages the Service. Both
// conditions are false, so the object carries no Error state, and the ingress
// addresses are cleared.
func SetDisabled(ctx context.Context, c client.Client, svc *corev1.Service, generation int64) error {
	return updateStatus(ctx, c, svc, func() {
		meta.SetStatusCondition(&svc.Status.Conditions, metav1.Condition{
			Type:               ConditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             ReasonDisabled,
			Message:            "senselb management is disabled for this Service",
			ObservedGeneration: generation,
		})
		meta.SetStatusCondition(&svc.Status.Conditions, metav1.Condition{
			Type:               ConditionError,
			Status:             metav1.ConditionFalse,
			Reason:             ReasonDisabled,
			ObservedGeneration: generation,
		})
		svc.Status.LoadBalancer.Ingress = nil
	})
}

// updateStatus applies mutate and writes the status only when it changed. An
// unchanged write would bump the resource version, wake the Service watch and
// reconcile the same state again, so the guard is what keeps a reconcile loop
// from spinning on its own status.
func updateStatus(ctx context.Context, c client.Client, svc *corev1.Service, mutate func()) error {
	before := svc.Status.DeepCopy()
	mutate()
	if reflect.DeepEqual(*before, svc.Status) {
		return nil
	}
	return c.Status().Update(ctx, svc)
}

// ClearError removes the Error condition after a successful reconcile without
// touching ingress or the Ready condition, which only the apply pipeline can
// set. The status is written only when the condition was present.
func ClearError(ctx context.Context, c client.Client, svc *corev1.Service) error {
	if !meta.RemoveStatusCondition(&svc.Status.Conditions, ConditionError) {
		return nil
	}
	return c.Status().Update(ctx, svc)
}

// ClearStatus removes every condition and ingress entry. It is used on the
// deletion path, where the Service is about to disappear.
func ClearStatus(ctx context.Context, c client.Client, svc *corev1.Service) error {
	if len(svc.Status.Conditions) == 0 && len(svc.Status.LoadBalancer.Ingress) == 0 {
		return nil
	}
	svc.Status.Conditions = nil
	svc.Status.LoadBalancer.Ingress = nil
	return c.Status().Update(ctx, svc)
}

// LoadBalancerIngress converts addresses into Service ingress entries, dropping
// blanks. The address is published in the IP field, which is what a hostname
// would also be for a Service whose names are the platform's addresses.
func LoadBalancerIngress(addresses []string) []corev1.LoadBalancerIngress {
	ingress := make([]corev1.LoadBalancerIngress, 0, len(addresses))
	for _, address := range addresses {
		if address = strings.TrimSpace(address); address == "" {
			continue
		}
		ingress = append(ingress, corev1.LoadBalancerIngress{IP: address})
	}
	return ingress
}
