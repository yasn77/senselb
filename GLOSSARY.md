# senselb glossary

A shared vocabulary for senselb. Where a term is HAProxy-specific or
Kubernetes-specific, the definition says so, because senselb sits between the
two and a reader needs to know which side a word belongs to.

The definitions below are ordered alphabetically.

**ACL** *(HAProxy)*
: A named boolean condition evaluated against a request or response, for
  example matching a `Host` header or a path prefix. senselb renders one ACL
  per non-empty routing term (host, path, SNI) of a rule and references it from
  that rule. A rule only fires when all of its ACLs match.

**Action / rule** *(HAProxy)*
: The construct that acts on a request once its ACLs match, such as
  `http-request` or `use_backend`. senselb renders one action per Service
  routing rule.

**Adopt**
: A way of provisioning a listener: senselb binds its routing rules to a
  frontend that already exists in HAProxy, identified by name. All foreign
  configuration on that frontend — for example ACME-challenge rules owned by a
  certificate manager — is left intact. Contrast with *create*.

**Backend** *(HAProxy)*
: A named server group plus its load-balancing algorithm and health checks.
  For each TCP port of a Service that attaches to a listener, senselb renders
  and owns a backend whose servers come from the Service's nodeport mode or
  endpoint mode.

**ConfigMap defaults**
: In-cluster configuration that supplies a value when neither the Service
  annotation nor a built-in provides one. A ConfigMap default sits in the
  middle of the precedence order: Service annotations beat ConfigMap defaults,
  and ConfigMap defaults beat built-ins.

**configtest** *(HAProxy)*
: The validation step that checks a candidate configuration is syntactically
  correct without applying it. senselb runs one `configtest` per apply batch
  that has changes, ahead of `reconfigure`; a batch with an empty plan skips
  both.

**Create**
: A way of provisioning a listener: senselb creates the HAProxy frontend
  itself, rather than binding to one that already exists. Contrast with
  *adopt*.

**EndpointSlice** *(Kubernetes)*
: The Kubernetes object that lists the ready pod addresses behind a Service.
  Endpoint mode reads EndpointSlices rather than `Endpoints`. senselb maps a
  slice to its Service by the `kubernetes.io/service-name` label, falling back
  to an owner reference of kind `Service`.

**Endpoint mode**
: A backend target mode, selected by annotation, in which senselb renders one
  backend server per ready pod address from EndpointSlices, addressed by pod IP
  and the Service's `targetPort`. It requires the OPNsense firewall to route to
  the cluster's pod CIDRs, and it supports a single TCP port per Service.
  Contrast with *nodeport mode*.

**Finalizer** *(Kubernetes)*
: A marker on an object that keeps it around until a controller has cleaned
  up. senselb adds the `senselb.io/finalizer` finalizer so that deleting a
  Service removes the HAProxy objects senselb created for it before the Service
  disappears.

**Frontend** *(HAProxy)*
: A bind address (and optional TLS) that accepts client connections and
  decides which backend serves each request. In senselb, a frontend is
  represented by a *listener*.

**GitOps**
: The deployment model senselb is shipped under: the Helm chart is consumed by
  an ArgoCD-managed manifests repository, so the cluster's desired state is
  declared in Git and reconciled from there rather than applied by hand.

**Leader election** *(Kubernetes)*
: The mechanism that ensures only one controller replica holds the active
  role at a time. senselb runs a single active replica, and the apply queue is
  a leader-only runnable.

**Listener**
: A named shared HAProxy frontend that a Service attaches to via the
  `listeners` annotation. Each listener is either adopted from an existing
  frontend or created by senselb; a created frontend is named
  `senselb-<listener>`, while the configured name stays the logical handle the
  annotation uses. Each listener's bind IP becomes an entry in
  `status.loadBalancer.ingress`.

**NodePort mode**
: The default backend target mode, in which senselb renders one backend server
  per ready cluster Node, addressed by node IP and the Service's `nodePort`. It
  only requires the OPNsense firewall to route to node IPs. Contrast with
  *endpoint mode*.

**Ownership**
: The rule that senselb touches only the objects it created. Every object
  senselb creates carries a `senselb-` name prefix and the description
  "managed by senselb — do not edit". Foreign objects are strictly read-only.

**Reconfigure** *(HAProxy)*
: The operation that applies the candidate configuration to a running HAProxy
  instance. senselb runs one `reconfigure` per apply batch that has changes,
  after a successful `configtest`.

**senselb.io annotation prefix**
: The prefix that marks a Kubernetes annotation as belonging to senselb, for
  example `senselb.io/listeners`. The prefix is configurable, but the core
  annotation set is documented against the default `senselb.io/`.

**Single-flight**
: A property of the apply pipeline: overlapping reconcile events are coalesced
  so that a burst of changes results in one apply rather than one apply per
  event. The provider additionally serialises a whole mutation sequence under
  its client lock (`WithLock`), so two applies can never interleave their
  writes.

**Snapshot / rollback**
: Before any write, senselb records the live configuration. If `configtest`
  fails after a write, senselb rolls its own change back, including restoring
  the linked-list fields of foreign frontends to their snapshot values.

**Store**
: The ConfigMap-backed inventory of the provider objects senselb owns, named by
  `storeName` in the controller configuration (default `senselb-store`). Its
  JSON document lives under the `state` key, keyed by
  `<namespace>/<service>/<object>` and mapping each object to its provider
  UUID. It is distinct from the controller configuration ConfigMap, whose YAML
  document lives under the `config.yaml` key.
