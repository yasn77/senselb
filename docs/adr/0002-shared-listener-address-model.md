# ADR 0002: Shared listener address model

## Status

Accepted.

## Context

A LoadBalancer controller must decide what IP addresses it reports on
`status.loadBalancer.ingress`, and how a Service maps onto a listening socket.
Two shapes were available. The first gives every Service its own dedicated
frontend and address, which is simple to reason about but consumes an address
and a port per Service and rapidly exhausts a home or small-office firewall.
The second shares a small number of frontends between many Services, which is
how HAProxy is normally deployed but requires a way to say which Services share
which frontend.

We chose the shared model, and had to define how a Service attaches to a shared
frontend and what happens to configuration that frontend already carries.

## Decision

The address model is multiple named shared "listeners", each being one shared
HAProxy frontend — for example `external` on the WAN `0.0.0.0:443` with TLS,
`external-http` on `0.0.0.0:80`, and `internal` on a LAN IP.

Services attach to one or more listeners via annotation. Each listener is
either `adopt` — bind senselb's routing rules to an existing frontend by name,
preserving all its foreign configuration such as ACME-challenge rules — or
`create` — senselb creates the frontend.

Each listener's bind IP becomes a `status.loadBalancer.ingress` entry.

## Consequences

- A handful of listeners serve an arbitrary number of Services, so the address
  model scales with Services rather than with ports.
- Owner-managed frontends such as an ACME-terminating HTTPS frontend can be
  reused through `adopt`, which means existing certificate automation keeps
  working alongside senselb.
- Because a listener reports its bind IP on the status of every Service that
  attaches to it, several Services legitimately share one ingress address. That
  is the model, not an error.
- Honest negative consequence: shared listeners mean several Services can claim
  the same `host:port` on one listener, and those claims collide. The address
  model alone cannot resolve a collision, so senselb must detect it and refuse
  to clobber a sibling; that conflict handling exists precisely because of this
  decision.
- Honest negative consequence: `adopt` binds senselb to frontend names chosen
  outside its control, so renaming or restructuring the firewall's frontends is
  a change that ripples into listener configuration.
