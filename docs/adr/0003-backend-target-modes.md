# ADR 0003: Backend target modes

## Status

Accepted.

## Context

Once a Service attaches to a listener, senselb must populate the HAProxy
backend behind it with servers, and each server is an address and a port. There
are two plausible sources of that address-and-port pair, and they differ in
both the addresses they use and what the network must be able to reach.

Addressing each cluster Node on a NodePort is the conventional approach and
works with whatever routing already exists between the firewall and the nodes.
Addressing pods directly gives finer distribution across the cluster but
requires the firewall to reach a network it may not currently know about.

Rather than fix one answer, the mode is selected per Service by annotation,
with the safer default.

## Decision

HAProxy backend servers come from two annotation-selectable modes:

- `nodeport` (default): one server per ready cluster Node, address = node IP,
  port = the Service's `nodePort`.
- `endpoint`: one server per ready pod address from EndpointSlices,
  address = pod IP, port = the Service's `targetPort`.

Endpoint mode requires the OPNsense firewall to route to pod CIDRs; this is a
documented prerequisite. nodeport mode only requires routing to node IPs.

## Consequences

- The default mode works on any cluster whose firewall can reach the nodes,
  which is the common case, so adoption does not begin with a network redesign.
- Endpoint mode is available to operators whose firewall already routes to pod
  CIDRs, and gives pod-level load distribution without a per-node NodePort hop.
- Both modes are expressed in the same canonical backend model, so the renderer
  and diff do not branch on platform.
- Honest negative consequence: endpoint mode does not work until the firewall
  routes to pod CIDRs. Choosing it without that routing configured produces a
  backend of unreachable servers, and the failure is a network one, not
  necessarily visible as a senselb error. It is therefore a documented
  prerequisite rather than a checked one.
- Honest negative consequence: nodeport mode depends on the NodePort allocation
  the cluster assigns, so changes to the Service's ports can move the node port
  and require the backend servers to be re-rendered.
