# ADR 0005: OPNsense connectivity and secret hygiene

## Status

Accepted.

## Context

senselb talks to the OPNsense REST API, which means it needs a base URL, a key
and a secret. Those credentials are powerful: the API user can rewrite the
firewall's HAProxy configuration. How senselb stores and uses them determines
the blast radius of a leaked credential and the ease of pointing the controller
at the right firewall.

OPNsense deployments also shape the transport. The API is normally reached on a
management port rather than 443, and the firewall typically presents a
self-signed certificate on that port, so certificate verification cannot always
succeed against the same URL a browser would warn about.

Finally, the number of firewalls a single controller programs affects the whole
design: identity, configuration and reconciliation all key off it.

## Decision

Exactly one OPNsense per controller instance.

Credentials live in an in-cluster Secret with fields `key`, `secret` and `url`.
Authentication is HTTP Basic. Because the API lives on a non-443 management
port with a self-signed certificate in typical deployments, the client offers
an `insecureSkipVerify` toggle plus an optional CA.

URL precedence: a non-empty Secret `url` field overrides the config URL.

The key and secret are never logged; the client redacts them.

No secrets in the repository.

## Consequences

- The one-firewall-per-instance rule keeps the provider's identity simple: the
  controller knows a single target, and no per-Service routing of writes is
  needed.
- Putting `url` in the Secret alongside the credentials lets one deployment
  target a different firewall without editing the chart, and the precedence
  rule makes the effective URL predictable when both are set.
- Redaction in the client means a debug log does not become a credential leak,
  and the no-secrets-in-the-repository rule keeps credentials out of the
  GitOps manifests repository that consumes the chart.
- Honest negative consequence: the `insecureSkipVerify` toggle is a genuine
  weakening of transport security when it is used, and it exists because
  self-signed management endpoints are normal. Operators who enable it accept
  that the channel is not authenticated against a trusted certificate.
- Honest negative consequence: one controller instance programs one firewall,
  so a deployment with two OPNsense firewalls runs two controller instances,
  each with its own replica and its own store.
