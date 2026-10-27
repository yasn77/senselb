# ADR 0006: Reconciliation and rollback

## Status

Accepted.

## Context

HAProxy on OPNsense is reconfigured through an API that validates a candidate
configuration and then applies it. Each apply is a real change to a live
firewall that carries production traffic. A naive controller would issue one
`configtest` and one `reconfigure` per object it reconciles; a burst of Service
changes would then mean a burst of applies, and a failure midway could leave
the firewall in a configuration it cannot load.

Two further questions follow from having a live, shared datastore. How do we
recompute only what changed, rather than re-sending everything? And what do we
do if the candidate configuration is rejected after we have already written
part of it?

## Decision

Reconciliation is an incremental diff — desired model against live, filtered to
senselb-owned objects — with a debounced, single-flight apply: one `configtest`
and one `reconfigure` per batch, never per object.

Before writes, a pre-apply snapshot is taken. If `configtest` fails after a
write, senselb rolls back its own last change — including restoring foreign
frontends' linked-list fields to their snapshot values, the one sanctioned
foreign-object write — and never leaves HAProxy broken.

There is a single active replica via leader election; the apply queue is a
leader-only runnable. Cleanup on Service deletion uses a finalizer. Status is
reported through Ready and Error conditions on the status subresource.
Behaviour is idempotent and at-least-once: a crash mid-apply converges on the
next reconcile.

## Consequences

- Batching keeps the number of firewall reconfigurations proportional to bursts
  of change rather than to the number of objects, which is what makes a busy
  cluster tolerable for a small firewall.
- The diff against live state, not against a cached model, means external drift
  is corrected on the next reconcile rather than ignored.
- The snapshot and rollback path means a failed `configtest` returns the
  firewall to a loadable state instead of leaving it half-written, and the
  at-least-once design means a crash is recoverable by simply reconciling again.
- Honest negative consequence: a single active replica with a leader-only apply
  queue means the controller is not horizontally scalable for writes. Extra
  replicas add availability, not throughput; all applies funnel through one
  leader.
- Honest negative consequence: rollback writes to a foreign frontend's
  linked-list fields, contradicting the otherwise absolute read-only rule for
  foreign objects. It is sanctioned narrowly — restoring the snapshot values —
  but it is a real exception that must be justified in review.
- Honest negative consequence: taking a pre-apply snapshot costs an extra read
  of live state before each batch, and the snapshot is only as good as the
  moment it was taken; a change made by another tool between snapshot and
  rollback is outside what senselb can restore.
