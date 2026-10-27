# senselb

`senselb` is a Kubernetes LoadBalancer controller that gives bare-metal
clusters first-class `Service type=LoadBalancer` support by programming the
HAProxy plugin on an OPNsense firewall through its REST API.

On a managed cloud, a LoadBalancer Service is fulfilled by the platform's
load-balancer controller. On bare metal there is no such controller by default,
so `LoadBalancer` Services sit with an empty `status.loadBalancer` forever.
senselb fills that gap: it watches `Service type=LoadBalancer`, renders the
matching HAProxy frontends, backends, ACLs and rules, applies them to OPNsense,
and reports the listener addresses back on the Service status.

One OPNsense firewall is programmed per controller instance. senselb runs a
single active replica, elected as leader, so that writes to the firewall are
serialised through one apply queue.

> **Status: work in progress.** The controller is not implemented yet. This
> repository currently holds the project scaffold, the design record (the
> ADRs) and this documentation seed. Nothing here will configure your firewall.

## Scope

**senselb manages `Service type=LoadBalancer` only. There is no Ingress
mirroring in v1.** The `pkg/haproxy` layer is written so that Ingress support
could be added later without reshaping it, but that is a design constraint, not
a current feature. Do not rely on any Ingress behaviour.

## Architecture overview

senselb is split into a platform-agnostic rendering layer and a provider that
knows how to talk to one firewall platform. The controller reconciles
Kubernetes state into a canonical HAProxy model, diffs that model against the
live configuration filtered to senselb-owned objects, and applies the
difference in a single debounced batch.

- `cmd/senselb-controller` — the controller entrypoint: flags, provider wiring,
  manager startup and signal handling.
- `pkg/haproxy` — the platform-agnostic core: the canonical HAProxy model, the
  renderer that turns Kubernetes Services into that model, and the diff that
  computes what to change. It carries **zero platform imports**, so a future
  OpenWrt+HAProxy provider can reuse it unmodified.
- `pkg/provider` — the provider interface that the controller depends on, so
  that a platform implementation is swappable.
- `pkg/provider/opnsense` — the OPNsense implementation: REST client, secret
  handling, and translation between the canonical model and OPNsense's API.
- `pkg/annotations` — parsing and validation of the `senselb.io/` annotation
  set and its precedence rules.
- `pkg/config` — controller-level configuration: listener definitions,
  ConfigMap defaults and built-in values.
- `pkg/controller` — the controller-runtime reconcilers, the debounced
  single-flight apply queue and the finalizer-based cleanup.
- `charts/senselb` — the Helm chart, consumed by a GitOps-managed manifests
  repository (arrives in Phase 5).
- `docs/adr` — the architecture decision records.
- `GLOSSARY.md` — the project vocabulary.

## Example: an annotated LoadBalancer Service

The following manifest is **illustrative only**. The controller is not
implemented yet, so applying this today has no effect beyond creating the
Service. It shows the shape of the core annotations.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: default
  annotations:
    senselb.io/enabled: "true"
    senselb.io/listeners: "external,external-http"
    senselb.io/host: "web.example.com"
    senselb.io/target-mode: "nodeport"
    senselb.io/algorithm: "roundrobin"
    senselb.io/healthcheck: "true"
    senselb.io/healthcheck-path: "/healthz"
    senselb.io/tls: "true"
spec:
  type: LoadBalancer
  selector:
    app: web
  ports:
    - name: http
      port: 80
      targetPort: 8080
      protocol: TCP
```

Here the Service attaches to two listeners — `external` on the WAN address on
port 443 with TLS, and `external-http` on port 80 — and routes requests for
`web.example.com` to the cluster, one backend server per ready Node addressed
by node IP and the Service's `nodePort`.

## Documentation

- [`docs/adr/`](docs/adr/) — the architecture decision records that fix the
  design: scope and portability, the shared-listener address model, backend
  target modes, ownership and conflict handling, OPNsense connectivity and
  secret hygiene, reconciliation and rollback, and annotation precedence.
- [`GLOSSARY.md`](GLOSSARY.md) — definitions for the vocabulary used across
  the code and the ADRs.

## Work in progress

Two pieces of documentation arrive with the final docs in Phase 5 and are
intentionally absent for now:

- **Annotation reference** — the full table of `senselb.io/` annotations, their
  values, defaults and precedence.
- **Deployment steps** — installing the Helm chart and configuring the
  controller against an OPNsense firewall.

Until then, the ADRs in [`docs/adr/`](docs/adr/) are the authoritative record
of the design.
