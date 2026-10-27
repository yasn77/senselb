# ADR 0007: Annotation precedence

## Status

Accepted.

## Context

A Service needs to express how it should be load-balanced: which listeners it
attaches to, which host and path it answers, which backend algorithm and target
mode to use, whether TLS applies, and so on. That configuration has to live
somewhere, and wherever it lives, the controller must be able to answer a
simple question unambiguously: when two sources disagree about a value, which
one wins?

There are three natural sources. Per-Service annotation is the most specific
and travels with the Service. A ConfigMap offers cluster-wide defaults an
operator can set once. Built-ins ensure the controller has an answer even when
nothing is configured.

## Decision

Configuration precedence is Service annotations > ConfigMap defaults >
built-ins.

The annotation prefix is `senselb.io/` and is configurable.

The core annotation set is: `enabled`, `listeners` (comma-separated), `host`,
`path`, `sni`, `mode`, `algorithm`, `target-mode`, `healthcheck`,
`healthcheck-path`, `proxy-protocol`, `timeout-connect`, `timeout-server`,
`timeout-client`, `maxconn`, `weight`, `sticky`, `tls`, `tls-cert`,
`tls-passthrough`, `backend-custom`, `backend-name`.

## Consequences

- The most specific source wins, which matches operator intuition: a Service
  that states its own value is never silently overridden by a cluster default.
- A ConfigMap lets an operator set sensible cluster-wide values once, so most
  Services only annotate what is genuinely different about them.
- Built-ins mean the controller always has a value for every setting, so a
  Service with no annotations beyond `enabled` and `listeners` still produces a
  complete configuration.
- Making the prefix configurable avoids clashing with an organisation that
  already uses `senselb.io/` for something else.
- Honest negative consequence: a broad annotation surface is a broad API to
  keep stable. Every one of the core annotations is a compatibility promise,
  and changing a value's meaning later is a breaking change for users.
- Honest negative consequence: with precedence stacked three deep, the
  effective value of a setting can come from a place the operator is not
  looking. A Service with no `algorithm` annotation may silently inherit a
  ConfigMap default that differs from the built-in, and debugging that requires
  knowing the whole precedence order.
- Honest negative consequence: because configuration travels with each Service,
  changing a shared behaviour means editing many Services or adding a ConfigMap
  default that only applies where no annotation overrides it. There is no
  single point of change for a value that some Services already set explicitly.
