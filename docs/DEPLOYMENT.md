# Deploying senselb

This guide takes you from an OPNsense firewall with the HAProxy plugin to a
`LoadBalancer` Service whose traffic is served through it. It assumes the
GitOps deployment model senselb is shipped under: the chart and its values live
in a git repository that ArgoCD reconciles, and nothing is applied to the
cluster by hand.

## 1. Overview

senselb watches `Service type=LoadBalancer` objects and programs the HAProxy
plugin on one OPNsense firewall. For each Service it creates or extends:

- a shared **frontend** per listener the Service attaches to;
- one **backend** per Service port, populated with cluster Nodes (nodeport
  mode) or pod addresses (endpoint mode);
- the **ACLs** and **rules** that route matching requests to that backend.

It then publishes the listener addresses on `status.loadBalancer.ingress` and
keeps the firewall converged by diffing the desired model against the live
configuration filtered to objects it owns.

Two operating rules shape everything below:

- **One firewall per controller instance.** A second OPNsense means a second
  senselb installation with its own release, namespace and ownership store.
- **GitOps only.** The chart, the values and the non-secret configuration are
  committed to your manifests repository and synced by ArgoCD. Credentials come
  from your secret manager. Do not `helm install` into the cluster by hand and
  do not edit live objects.

The controller reads its ConfigMap and provider Secret **once at startup**.
Configuration and credential changes therefore take effect on a new pod, not
on a watch event.

## 2. Prerequisites

### Firewall

- OPNsense 26.7 or later with the HAProxy plugin (`os-haproxy`) installed and
  enabled. Frontends, backends, ACLs and rules are managed through the
  plugin's REST endpoints.
- An API key pair for senselb. Create a dedicated user under
  **System → Access → Users**, give it only the HAProxy privileges senselb
  needs, then add an API key on that user. An OPNsense API key inherits the
  user's privileges, so the dedicated, least-privilege user is the control;
  do not reuse a full-administrator key.
- A reachable management endpoint. The API normally listens on a port other
  than 443, for example `https://172.16.16.1:2443/api/haproxy`, and usually
  presents a self-signed certificate. The URL must be the **full API base
  URL, including `/api/haproxy`**; the client appends `/settings/...` and
  `/service/...` to it.

### Cluster connectivity

The controller pod needs outbound HTTPS to the firewall's management port.
Two further paths depend on the target mode you choose:

| Target mode | Firewall must reach | Address and port used |
| --- | --- | --- |
| `nodeport` (default) | Every cluster Node's IP on the NodePort range | Node IP and the Service's `nodePort` |
| `endpoint` | The cluster's pod CIDRs on the Service's `targetPort` | Pod IP and `targetPort` |

`nodeport` is the safe default: it needs only the routing most clusters
already have between the firewall and the Nodes. `endpoint` gives pod-level
distribution, but produces unreachable servers until the firewall routes to the
pod CIDRs, and that failure is a network fault rather than a senselb error.
`endpoint` also supports **single-port Services only**; a multi-port Service
with `endpoint` is rejected with an `Error` condition. Use `nodeport` for
multi-port Services.

The controller also needs Kubernetes access: Services, Nodes, EndpointSlices
and Events cluster-wide, and ConfigMaps, Secrets and Leases in its own
namespace. The chart's RBAC covers this; leave `rbac.create=true` unless you
manage equivalent grants elsewhere. The plain-manifest copies are in
`config/rbac`, which hard-codes the `senselb-system` namespace.

### Chart

There is **no published Helm repository yet**. The chart lives in this
repository at `charts/senselb`, so vendor that directory into your manifests
repository. A future release may add a `helm repo` flow; until then the copy
in git is the source of truth.

## 3. Installing

### 3.1 Commit the chart and your site values

A layout that works with ArgoCD:

```text
manifests/
  apps/senselb/application.yaml   # the ArgoCD Application
  charts/senselb/                 # this chart, vendored
    values-prod.yaml              # your non-secret site values
```

Use a release name that contains `senselb` (the examples below use `senselb`)
so the objects are named `senselb-controller` and `senselb-config` rather than
carrying a doubled prefix.

`values-prod.yaml` carries only non-secret configuration. It overrides the
chart defaults for the listeners, the provider URL and the image tag:

```yaml
# The chart's appVersion is a development placeholder, so set a real tag. The
# published tags carry no leading "v": git tag v0.1.0 is published as 0.1.0,
# plus "latest" on a stable release, because goreleaser uses {{ .Version }}.
image:
  tag: "0.1.0"

config:
  # The frontends Services attach to. See 3.2 for adopt versus create.
  listeners:
    - name: external
      adopt: true
      existingFrontend: ingress-HTTPS
      mode: ssl
    - name: external-http
      adopt: true
      existingFrontend: HTTP
      mode: http
    - name: internal
      bind:
        - 172.16.16.1:443
      mode: http

  defaults:
    enabled: true
    target-mode: nodeport
    algorithm: roundrobin

provider:
  # Full API base URL, including /api/haproxy.
  url: https://172.16.16.1:2443/api/haproxy
  # The Secret your secret manager creates; the chart never renders a usable
  # credential.
  secretName: senselb-opnsense
  # The management endpoint is commonly self-signed. Prefer caCertSecretName
  # and set this to false once the CA is trusted.
  insecureSkipVerify: true
  caCertSecretName: ""
```

The complete set of values, including what each one means, is documented in
`charts/senselb/values.yaml`. The rendered ConfigMap is equivalent to
`config/samples/senselb-config.yaml`.

A matching ArgoCD Application:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: senselb
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/your-org/manifests.git
    targetRevision: main
    path: charts/senselb
    helm:
      valueFiles:
        - values-prod.yaml
  destination:
    server: https://kubernetes.default.svc
    namespace: senselb-system
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
```

`valueFiles` are resolved relative to `path`, which is why the site values sit
beside the vendored chart. Commit, push and let ArgoCD sync; do not run
`helm install` from a workstation.

### 3.2 Configure the listeners

Listeners are the shared HAProxy frontends Services attach to. Each entry in
`config.listeners` is either:

- **Adopted** (`adopt: true` plus `existingFrontend`): senselb attaches its
  rules to a frontend that already exists, for example a certificate manager's
  `ingress-HTTPS` or `HTTP`. The frontend keeps its own bind addresses, TLS
  material and foreign rules. An adopted listener's `mode` describes that
  frontend; senselb does not change it.
- **Created** (`bind` plus optional `mode`): senselb creates the frontend. On
  the firewall it is named **`senselb-<listener>`**, so a listener called
  `internal` becomes the frontend `senselb-internal`. The listener name stays
  the logical handle used in annotations.

`mode` is `http`, `tcp` or `ssl` for a listener; omitting it means `http`.
`defaultBackend` is optional and names a platform-level catch-all backend
senselb references, never creates.

A Service's `senselb.io/listeners` annotation uses these logical names, for
example `"external,external-http"`. A name that is not configured is reported
as an `Error` condition (`ConfigError`) and the Service contributes nothing.

The ConfigMap is read once at startup. By default the controller reads
`senselb-config` in its release namespace; the chart passes the namespace as
`--config-namespace` and the name as `--config-name`. A Helm upgrade rolls the
pod automatically because the Deployment carries a checksum of the ConfigMap.
If you change the object outside Helm (for example by syncing a hand-written
ConfigMap), restart the controller explicitly:

```sh
kubectl -n senselb-system rollout restart deployment/senselb-controller
```

### 3.3 Provide the provider Secret

Create a Secret named by `provider.secretName` (or
`provider.secret.existingSecret`) in the **controller's namespace**, with:

| Key | Required | Meaning |
| --- | --- | --- |
| `key` | yes | OPNsense API key |
| `secret` | yes | OPNsense API secret |
| `url` | no | Full API base URL; a non-empty value overrides `provider.url` |

`config/samples/opnsense-secret.example.yaml` shows the shape with empty
values. Create the real object through External Secrets, Sealed Secrets or
your OpenBao injection path; **never commit a credential**, and leave
`provider.secret.create=false` (the default). The chart only renders an empty
placeholder when that flag is explicitly set.

`url` precedence is deliberate: if the Secret carries a non-empty `url`, it
wins over the ConfigMap, so one deployment can be pointed at a different
firewall without editing the chart. When both are empty the controller refuses
to start.

For a self-signed management certificate, either enable
`provider.insecureSkipVerify: true` during bring-up, or create a second Secret
named by `provider.caCertSecretName` with the PEM bundle under the key
`ca.crt` and leave verification on. Prefer the CA path once the certificate is
stable.

The Secret is read once at startup. After rotating the key or secret, restart
the controller; unlike the ConfigMap, an externally managed Secret is not part
of the chart's checksum.

## 4. Annotating Services

A Service is managed when it is `type: LoadBalancer` and does not carry
`senselb.io/enabled: "false"`. The quick reference below covers the common
annotations; the full table, defaults and precedence order are in
[`README.md`](../README.md).

| Annotation | Example | Notes |
| --- | --- | --- |
| `senselb.io/enabled` | `"true"` | `"false"` hands the Service back: senselb removes its objects and clears the status. |
| `senselb.io/listeners` | `"external,external-http"` | Logical listener names from the ConfigMap; at least one is required. |
| `senselb.io/host` | `"app.example.com"` | `Host` header prefix match, case-insensitive. |
| `senselb.io/path` | `"/api"` | Path prefix match. |
| `senselb.io/sni` | `"app.example.com"` | SNI match for a TLS frontend. |
| `senselb.io/target-mode` | `"nodeport"` | `nodeport` (default) or `endpoint`; see the routing prerequisites. |
| `senselb.io/algorithm` | `"leastconn"` | `roundrobin` (default), `source`, `leastconn`, `static-rr`, `uri`, `random`. |
| `senselb.io/healthcheck` | `"true"` | HTTP health check per server. |
| `senselb.io/healthcheck-path` | `"/healthz"` | Path for the HTTP health check. |
| `senselb.io/proxy-protocol` | `"true"` | Recorded on the backend health check. |
| `senselb.io/maxconn` | `"100"` | Per-server connection limit. |
| `senselb.io/weight` | `"10"` | Server weight; 0 means no traffic. |
| `senselb.io/sticky` | `"true"` | Sticky sessions. |
| `senselb.io/tls` | `"true"` | Enables TLS on a **created** listener's frontend; requires `tls-cert`. |
| `senselb.io/tls-cert` | `"my-cert"` | Certificate reference for a created TLS frontend. |
| `senselb.io/backend-custom` | see below | Verbatim backend directives, one per line. |
| `senselb.io/backend-name` | `"senselb-web-prod"` | Must start with `senselb-`; multi-port Services get a `-<port>` suffix. |

Four behaviours are easy to trip over:

1. **Timeouts go through `backend-custom`.** `senselb.io/timeout-connect`,
   `timeout-server` and `timeout-client` are accepted by the parser but
   rejected as unmodelled, with an `AnnotationError` that points here. Use
   valid backend directives instead:

   ```yaml
   senselb.io/backend-custom: |
     timeout connect 5s
     timeout server 50s
   ```

2. **`tls-passthrough` is not implemented in v1.** Setting it produces an
   explicit `AnnotationError` rather than being ignored, so do not use it in a
   manifest yet. For HTTP traffic, enable TLS on a created listener with
   `tls` and `tls-cert`. For an adopted listener such as `ingress-HTTPS`, TLS
   already terminates on that frontend; `tls` there is rejected because the
   certificate belongs to the adopted object.

3. **A ConfigMap boolean default can only raise a flag to true.** It cannot
   switch anything off, so `defaults.enabled: false` has no effect. Disable a
   Service with `senselb.io/enabled: "false"` on the Service.

4. **Endpoint mode is single-port.** With several Service ports and
   `target-mode: endpoint`, the Service is rejected with an `Error` condition;
   use `nodeport` for multi-port Services.

A per-Service annotation always overrides the ConfigMap default, including a
blank value that clears an inherited default. Annotations that require a value,
such as `listeners` and the timeouts, reject a blank value.

### Conflicts

senselb never overwrites an object it does not own. Every object it creates
carries the `senselb-` name prefix and the description
`managed by senselb — do not edit`; foreign objects are read-only. When two
Services claim the same backend name, or disagree about the frontend behind a
shared listener, the affected Services are skipped: senselb writes an `Error`
condition and a Kubernetes Event and leaves their configuration alone. A write
that would touch a foreign object is rejected before any request is sent, so
the whole batch is refused rather than half-applied.

One v1 limitation is worth knowing: two Services that route the same
`host:port` on one listener are **not** detected as a conflict. HAProxy
resolves the overlap first-by-name. Keep host and path claims disjoint.

See `config/samples/loadbalancer-service.yaml` for a multi-port nodeport
example and a commented single-port endpoint example.

## 5. Verifying

Check the Service status and its addresses:

```sh
kubectl -n prod get service web
kubectl -n prod get service web \
  -o jsonpath='{.status.loadBalancer.ingress[*].ip}{"\n"}'
```

The ingress entries come from the listeners the Service uses: the bind host of
a created listener, or the live bind host of an adopted frontend. Several
Services sharing a listener therefore share an address; that is the model, not
a fault.

Check the conditions and events:

```sh
kubectl -n prod describe service web
kubectl -n prod get events --field-selector involvedObject.name=web
```

`Ready=True` with reason `Reconciled` means the apply pipeline programmed the
Service. `Error=True` carries a reason you can act on:

| Reason | Meaning |
| --- | --- |
| `ConfigError` | Controller configuration problem, such as an unknown listener or a failed apply. |
| `AnnotationError` | An annotation senselb cannot honour, such as an unmodelled timeout or `tls` on an adopted listener. |
| `UnsupportedProtocol` | A UDP port was skipped; TCP ports on the same Service still apply. |
| `Disabled` | Management is switched off; no Error is reported. |

In OPNsense, open **Services → HAProxy → Settings** and inspect the frontends,
backends, ACLs and rules. Created listeners appear as frontends named
`senselb-<listener>`; backends are named
`senselb-<namespace>-<service>-<port>` unless `backend-name` overrides the
last part. Everything senselb owns carries the managed description. A Service
that was never applied has no `senselb-` objects.

Controller logs and metrics are also useful:

```sh
kubectl -n senselb-system logs deployment/senselb-controller
kubectl -n senselb-system port-forward service/senselb-metrics 8080:8080
```

## 6. Safety

### Ownership

senselb decides ownership from two markers together: the `senselb-` name
prefix and the exact description `managed by senselb — do not edit`. A
prefixed name with any other description is a foreign object: it is read-only
and is never adopted by accident. The controller also persists a
name-to-UUID inventory in the `senselb-store` ConfigMap so it can find the
objects it created across restarts.

Do not rename or hand-edit a `senselb-` object. Editing it removes it from the
set senselb recognises, and it can be left orphaned the next time the
inventory is rebuilt.

### Apply and rollback

Changes go through a debounced, single-flight queue: one `configtest` and one
`reconfigure` per batch, never per object. Before writing, senselb takes a
snapshot. If `configtest` fails after a write, it rolls back its own change,
including restoring the linked-list fields of foreign frontends to their
snapshot values. A rejected batch is reported on the affected Services; it is
never left half-applied if the rollback succeeds.

### The crash window and orphans

Cleanup is asynchronous. Deleting a Service (or disabling it, or changing its
type away from `LoadBalancer`) removes its store entries, enqueues a rebuild
and releases the finalizer. A successful drain prunes its HAProxy objects
while the queue still remembers the pre-cleanup inventory.

If the controller crashes **between deleting the store entries and that
successful drain**, the in-memory inventory is lost, the store no longer lists
the objects, and the startup drift reconcile cannot attribute them. The same
residual appears if the controller restarts during a persistently failing
drain. senselb deliberately leaves such objects in place rather than deleting
work it cannot attribute; an operator removes the leftover `senselb-*`
objects from OPNsense by hand.

This is also why a lost or corrupted `senselb-store` degrades the controller:
it can no longer recognise its prior work, so it will not delete it. Restore
the ConfigMap from backup where possible.

## 7. Uninstalling

Clean up the managed Services **before** removing the controller, otherwise
their finalizers cannot be released.

1. Remove senselb from the Services: delete the Services, remove their
   `senselb.io/` annotations, set `senselb.io/enabled: "false"`, or change
   their type away from `LoadBalancer`. Each path hands the Service back:
   senselb clears the status and removes the finalizer immediately, then prunes
   its HAProxy objects asynchronously on the next apply. Wait until the
   Services no longer carry the `senselb.io/finalizer` finalizer and the
   `senselb-*` objects are gone from OPNsense.
2. Remove the ArgoCD Application, or delete the chart from the manifests
   repository and let prune run. This removes the Deployment, RBAC, the
   `senselb-config` ConfigMap and the metrics Service. The `senselb-store`
   ConfigMap is created by the controller at runtime, so the chart does not
   own it; the provider Secret is yours. Delete both only after the Services
   are clean.
3. Check for manual leftovers. In OPNsense, filter frontends, backends, ACLs
   and rules by name `senselb-` and description
   `managed by senselb — do not edit`. Remove anything the controller could
   not delete, for example objects left by the crash window described in
   section 6. If a Service is stuck terminating on the finalizer because the
   controller is already gone, remove the finalizer deliberately so deletion
   can finish; never do this while the controller is running.
