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

> **Status: early release.** The controller, the OPNsense provider and the Helm
> chart are implemented. The chart is not yet published to a Helm repository,
> so install it from this repository; see [Deploying](#deploying).

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
- `charts/senselb` — the Helm chart, consumed by an ArgoCD-managed manifests
  repository.
- `config/samples` — reference ConfigMap, Secret and LoadBalancer Service
  manifests.
- `docs/adr` — the architecture decision records.
- `GLOSSARY.md` — the project vocabulary.

## Example: an annotated LoadBalancer Service

The following manifest is a complete example. It attaches one Service to two
adopted listeners and shows the shape of the core annotations.

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
port 443 and `external-http` on port 80 — and routes requests for
`web.example.com` to the cluster, one backend server per ready Node addressed
by node IP and the Service's `nodePort`.

Both listeners are adopted, so the example sets no `senselb.io/tls` annotation:
the existing `ingress-HTTPS` frontend already carries the TLS certificate, and
`tls` is rejected on an adopted listener. To terminate TLS on a listener
senselb creates, set `tls: "true"` together with `tls-cert`.

A listener that is created rather than adopted is rendered as the frontend
`senselb-<listener>`, so a listener called `internal` becomes
`senselb-internal`. The configured name stays the logical handle used in the
`listeners` annotation.

## Annotations

Annotation keys carry the configured prefix, `senselb.io/` by default. An
unknown key under that prefix is an error, so a misspelt annotation stops the
Service's reconcile instead of being ignored; keys with another prefix belong
to other controllers and are ignored.

Values resolve in three layers: the Service annotation, then the ConfigMap
`defaults`, then the built-ins. A Service annotation always wins, including a
blank value that clears an inherited default (annotations that require a value,
such as `listeners` and the timeouts, still reject a blank value). A ConfigMap
boolean default can only raise a flag to `true`, never lower it.

| Annotation | Accepted values | Default | Effect |
| --- | --- | --- | --- |
| `enabled` | `"true"`, `"false"` | `true` | `"false"` stops management and triggers cleanup. |
| `listeners` | comma-separated listener names | none, required | Logical listeners from the controller ConfigMap. |
| `host` | hostname | none | Case-insensitive `Host` header prefix match. |
| `path` | path prefix | none | Path prefix match. |
| `sni` | hostname | none | TLS SNI match. |
| `mode` | `http`, `tcp` | `http` | Backend proxy mode. |
| `algorithm` | `roundrobin`, `source`, `leastconn`, `static-rr`, `uri`, `random` | `roundrobin` | Backend load-balancing algorithm. |
| `target-mode` | `nodeport`, `endpoint` | `nodeport` | Where backend servers come from. `endpoint` supports one port only. |
| `healthcheck` | boolean | `false` | HTTP health check per backend server. |
| `healthcheck-path` | path | empty | Path for the HTTP health check. |
| `proxy-protocol` | boolean | `false` | Recorded on the backend health check. |
| `timeout-connect` | duration, for example `5s` | empty | Parsed, then reported as unmodelled; use `backend-custom`. |
| `timeout-server` | duration | empty | Parsed, then reported as unmodelled; use `backend-custom`. |
| `timeout-client` | duration | empty | Parsed, then reported as unmodelled; use `backend-custom`. |
| `maxconn` | integer, at least 1 | unset | Per-server connection limit. |
| `weight` | integer, at least 0 | unset | Server weight; 0 means no traffic. |
| `sticky` | boolean | `false` | Sticky sessions. |
| `tls` | boolean | `false` | TLS on a created listener's frontend; requires `tls-cert`. Rejected on an adopted listener. |
| `tls-cert` | certificate reference | empty | Certificate for a created TLS frontend. |
| `tls-passthrough` | boolean | `false` | Not implemented in v1; setting it reports an error. |
| `backend-custom` | verbatim directives, one per line | empty | Extra backend directives, such as `timeout connect 5s`. |
| `backend-name` | name starting with `senselb-` | derived | Custom backend name; multi-port Services get a `-<port>` suffix. |

## Deploying

senselb is deployed GitOps-only: the chart and its non-secret values are
committed to an ArgoCD-managed manifests repository, and credentials are
created by your secret manager, never committed.

- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — prerequisites, routing, site
  values, the ArgoCD Application, verification, safety and uninstalling.
- [`charts/senselb`](charts/senselb) — the Helm chart. It is not yet published
  to a Helm repository; vendor it into your manifests repository.
- [`config/samples`](config/samples) — reference ConfigMap, Secret and
  LoadBalancer Service manifests.

## Documentation

- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — how to deploy and operate the
  controller against an OPNsense firewall.
- [`docs/adr/`](docs/adr/) — the architecture decision records that fix the
  design: scope and portability, the shared-listener address model, backend
  target modes, ownership and conflict handling, OPNsense connectivity and
  secret hygiene, reconciliation and rollback, and annotation precedence.
- [`GLOSSARY.md`](GLOSSARY.md) — definitions for the vocabulary used across
  the code and the ADRs.
