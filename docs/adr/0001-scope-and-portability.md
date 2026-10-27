# ADR 0001: Scope and portability

## Status

Accepted.

## Context

senselb exists to make `Service type=LoadBalancer` work on bare metal. That is
the job it must do well, and a tightly scoped first version is easier to build
correctly and to verify. At the same time, the repository will eventually need
a provider for a second platform: an OpenWrt router running HAProxy. If the
rendering core grows a dependency on OPNsense, or on the OPNsense-shaped way of
describing HAProxy, the second provider cannot reuse it and the model must be
written twice.

We therefore had to choose two things at once: what the v1 controller watches,
and where the platform boundary sits within the code.

## Decision

The v1 scope is `Service type=LoadBalancer` only. There is no Ingress
mirroring.

The `pkg/haproxy` package — the canonical model, the renderer and the diff —
must not preclude adding Ingress support later, and must stay platform-agnostic.
It carries zero platform imports, so a future OpenWrt+HAProxy provider reuses
it unmodified.

## Consequences

- The platform boundary is a real interface: the controller depends on the
  provider, and `pkg/haproxy` depends on nothing platform-specific. A second
  provider can be added without editing the rendering core.
- Reviewers gain a crisp test: if a change to `pkg/haproxy` imports anything
  from `pkg/provider/opnsense`, it is wrong by construction.
- Honest negative consequence: by keeping the model free of any one platform's
  assumptions, it can only describe the HAProxy constructs that every planned
  platform shares. A capability unique to OPNsense has no natural home in the
  canonical model and must be expressed through the provider layer, which is
  more indirect than reaching for the OPNsense API directly.
- Honest negative consequence: users who want Ingress handled by senselb today
  cannot have it. They must keep a separate Ingress controller until Ingress
  support is designed, and duplicating routing between that controller and
  senselb is a real operational cost.
