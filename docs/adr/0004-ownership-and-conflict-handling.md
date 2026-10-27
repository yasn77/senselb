# ADR 0004: Ownership and conflict handling

## Status

Accepted.

## Context

senselb writes into an HAProxy configuration it does not own end to end. The
same OPNsense instance runs frontends, backends, ACLs and rules created by
other tools: a certificate manager's ACME-challenge rules, a reverse proxy's
backends, hand-written configuration. A controller that treats the live
configuration as its own will eventually delete or overwrite something a human
depends on.

Two questions follow. How does senselb tell its own objects apart from foreign
ones, and how does it remember the mapping between the Kubernetes names it
reconciles and the opaque identifiers the API hands back? And what should it do
when two Services, or a Service and a foreign object, want the same thing?

## Decision

Every object senselb creates carries a `senselb-` name prefix and the
description "managed by senselb — do not edit". Foreign objects — for example
Traefik backends and ACME-challenge rules — are strictly read-only; senselb
never mutates or deletes them.

A name-to-UUID map is persisted in a ConfigMap store (`senselb-store`).

senselb's ACLs and rules are inserted ahead of the listener's default backend,
so that more-specific routing wins.

On conflict — two Services claiming the same `host:port`, or a collision with a
foreign object — senselb does not clobber. It writes an Error condition and a
Kubernetes Event, and skips.

## Consequences

- Foreign configuration survives senselb entirely: the ownership rule makes the
  read-only guarantee mechanical, so a foreign frontend's rules cannot be
  deleted by a reconcile that does not know about them.
- The name-to-UUID map lets senselb translate a stable Kubernetes-derived name
  into the identifier the API expects, and lets a later reconcile find what an
  earlier one created.
- Inserting ahead of the default backend means senselb's more-specific routes
  take effect without disturbing the catch-all behaviour configured by hand.
- Honest negative consequence: skipping on conflict keeps the firewall safe at
  the cost of surfacing the problem somewhere the operator must look. A
  colliding Service is not load-balanced until a human resolves the overlap,
  and the only signal is the condition and event.
- Honest negative consequence: the persisted map is cluster state that must
  survive restarts, so the ConfigMap store is a dependency, and a lost or
  corrupted store degrades senselb's ability to recognise its own prior work.
- Honest negative consequence: the `senselb-` prefix and the description string
  are the ownership contract. An operator who edits a senselb object by hand,
  or renames it, removes it from the set senselb recognises and can leave it
  orphaned.
