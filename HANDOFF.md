# Headscale Domain Resource Gateway — Design Handoff

## Purpose

Build a Firezone-style domain resource layer on top of Headscale/Tailscale without modifying Tailscale clients.

The system should allow policies to grant access to DNS names as first-class resources while preserving domain identity even when multiple names resolve to the same backend IP and port.

The design uses:

- Headscale/Tailscale for authenticated overlay transport and device identity.
- A custom policy extension layered around the existing Headscale policy proxy/middleman.
- A synthetic DNS resolver that selectively returns fake IPs for authorized domain resources.
- One or more segmented domain gateway groups that advertise synthetic prefixes into the tailnet.
- Gateway-side authorization and translation/proxying from synthetic IPs to real backend destinations.
- Ordinary DNS passthrough for names that are not authorized as domain resources for the querying user.

The system should avoid per-domain or per-IP route churn in Headscale.

---

# Core Goals

## Functional goals

1. Treat DNS names as policy resources.
2. Preserve domain identity all the way to the gateway.
3. Avoid policy conflation when multiple FQDNs resolve to the same real IP.
4. Support wildcard resources.
5. Support port/protocol restrictions.
6. Support segmented gateways:
   - `a.com -> gateway group 1`
   - `b.com -> gateway group 2`
7. Support multiple physical gateways in an HA group.
8. Allow each gateway group to resolve names using its own local/private DNS environment.
9. Allow unauthorized domain-resource lookups to fall through to ordinary DNS.
10. Require gateway-side authorization even if a client guesses or learns a synthetic IP.
11. Keep Headscale unaware of individual synthetic mappings whenever possible.
12. Work with unmodified Tailscale clients.

## Non-goals for V1

Likely defer:

- ICMP proxying/translation.
- Application-layer HTTP or TLS inspection.
- Per-domain Headscale route advertisements.
- Headscale source modifications.
- Advanced kernel dataplane optimization.
- Cross-gateway overlapping synthetic address spaces.
- DNS-based blocking as a primary security control.

---

# High-Level Architecture

```text
                         SCIM / identity sources
                                |
                                v
                         +---------------+
                         | Identity DB   |
                         +-------+-------+
                                 |
                                 v
+----------------+        +------+-------+
| User policy    |------->| Policy       |
| HuJSON +       |        | compiler /   |
| extensions     |        | middleman    |
+----------------+        +------+-------+
                                 |
                 +---------------+----------------+
                 |                                |
                 v                                v
        +----------------+               +------------------+
        | Headscale      |               | Domain control   |
        | standard       |               | plane            |
        | policy only    |               |                  |
        +----------------+               | - DNS resolver   |
                                         | - allocator      |
                                         | - policy distro  |
                                         +--------+---------+
                                                  |
                         +------------------------+----------------------+
                         |                                               |
                         v                                               v
                +------------------+                            +------------------+
                | Gateway group A  |                            | Gateway group B  |
                | synthetic prefix |                            | synthetic prefix |
                | 10.254.0.0/18    |                            | 10.254.64.0/18   |
                +--------+---------+                            +---------+--------+
                         |                                                |
                +--------+--------+                              +--------+--------+
                |                 |                              |                 |
                v                 v                              v                 v
             GW A1             GW A2                          GW B1              ...
              HA                HA
```

---

# Main Architectural Decision

## Headscale should not learn individual synthetic IP mappings

Do **not** dynamically add `/32` or `/128` routes to Headscale whenever a domain is allocated a synthetic address.

Instead:

- Each logical gateway group owns one fixed synthetic prefix.
- Physical gateway instances in that group advertise the same prefix.
- Headscale approves that prefix once.
- DNS allocates synthetic addresses from the prefix assigned to the resource's gateway group.

Example:

```text
Gateway group home:
  synthetic prefix = 10.254.0.0/18

Gateway group cloud:
  synthetic prefix = 10.254.64.0/18
```

Mappings:

```text
a.com -> gateway:home  -> 10.254.0.17
b.com -> gateway:cloud -> 10.254.64.9
```

Routing naturally selects the correct gateway group based on the synthetic destination IP.

This avoids:

- Headscale policy rewrites per DNS allocation.
- Route propagation races.
- Control-plane churn.
- TTL/routing synchronization problems.
- Per-domain route cleanup complexity.

---

# Trust and Security Model

The system should explicitly separate responsibilities.

```text
Headscale/Tailscale
    = authenticated transport + node identity

Synthetic DNS
    = selective resource discovery / indirection

Domain Gateway
    = authoritative domain resource authorization

Policy compiler
    = source of normalized policy consumed by both Headscale and gateways
```

The DNS server is **not** the enforcement boundary.

A client must be denied if it:

- guesses a synthetic IP,
- learns another user's synthetic IP,
- scans the synthetic prefix,
- bypasses the custom DNS server,
- manually uses `curl --resolve`,
- sends traffic directly to a known synthetic address.

The gateway must re-authorize every new flow.

---

# Policy Extension

The existing Headscale policy proxy/middleman should accept custom fields and strip or compile them before sending policy to Headscale.

Illustrative syntax:

```hujson
{
  domainGateways: {
    "gateway:home": {
      ipv4: "10.254.0.0/18",
    },

    "gateway:cloud": {
      ipv4: "10.254.64.0/18",
    },
  },

  domainResources: {
    "domain:a": {
      domains: [
        "a.com",
      ],
      gateway: "gateway:home",
    },

    "domain:b": {
      domains: [
        "b.com",
      ],
      gateway: "gateway:cloud",
    },

    "domain:dev": {
      domains: [
        "*.dev.example.com",
      ],
      gateway: "gateway:home",
    },
  },

  domainGrants: [
    {
      src: [
        "group:developers",
      ],
      dst: [
        "domain:a",
      ],
      ports: [
        "tcp:443",
      ],
    },
  ],

  grants: [
    // normal Tailscale/Headscale grants
  ],
}
```

Exact syntax can change during implementation. The important semantics are:

- Domain resources are named policy objects.
- A resource contains one or more FQDN or wildcard patterns.
- A resource references one logical gateway group.
- Grants bind source identities/groups/tags to resources.
- Grants may restrict protocol and destination port.
- Gateway group configuration includes at least a synthetic prefix.
- Multiple physical gateway instances may service one gateway group.

---

# Policy Compiler Outputs

The policy middleman/compiler should produce at least three views.

## 1. Headscale policy

Contains only standard Headscale/Tailscale-compatible policy.

It should include whatever broad access is required so eligible nodes can reach the synthetic prefixes.

Headscale policy should remain coarse. For example:

```text
eligible tailnet users -> 10.254.0.0/16
```

or optionally more restrictive by logical segment:

```text
group:home-users  -> 10.254.0.0/18
group:cloud-users -> 10.254.64.0/18
```

These Headscale grants are defense-in-depth only.

They are not the authoritative domain policy.

## 2. DNS policy

The DNS service needs:

- domain patterns,
- resource IDs,
- gateway group assignment,
- user/group/tag authorization,
- enough identity data to map a querying Tailscale IP to policy principals.

## 3. Gateway-specific policy

Each gateway group should receive only the resources and grants relevant to that group.

Example:

```text
gateway:home receives:
  synthetic prefix 10.254.0.0/18
  a.com
  *.dev.example.com
  associated grants

gateway:cloud receives:
  synthetic prefix 10.254.64.0/18
  b.com
  associated grants
```

A home gateway does not need policy state for cloud-only resources.

---

# Identity Model

The system needs to map a source Tailscale IP to an authorization principal.

Conceptually:

```text
100.64.0.20
    -> Headscale node
    -> user
    -> groups
    -> tags / other normalized attributes
```

The existing SCIM/group broker can be reused as a shared source of normalized identity.

Preferred architecture:

```text
                       SCIM
                         |
                         v
                    Identity DB
                    /         \
                   /           \
          Headscale policy    Domain policy
             compiler           engine
```

Avoid separately reimplementing group resolution from unrelated data sources.

Gateways and DNS may cache node-to-principal mappings, but stale identity behavior must be considered.

---

# DNS Behavior

## Core rule

The custom DNS service is a **selective synthetic overlay on top of ordinary DNS**.

For each query:

```text
query + source Tailscale IP
          |
          v
    resource matcher
          |
      +---+---+
      |       |
 authorized  not authorized
      |       |
      v       v
 synthetic   ordinary upstream DNS
 answer      passthrough
```

### Authorized query

If the queried FQDN matches a domain resource and the querying principal has permission:

- Return a synthetic IP allocated from the resource gateway group's synthetic prefix.
- Do not reveal the real backend IP to the client.

Example:

```text
alice queries a.com
alice is authorized
a.com belongs to gateway:home

answer:
  a.com A 10.254.0.17
```

### Unauthorized or non-resource query

If:

- the domain does not match any domain resource, or
- it matches a resource but the user is not authorized,

the DNS server should resolve it using ordinary upstream DNS and return the normal answer.

Do not rely on `REFUSED`, `SERVFAIL`, or `NXDOMAIN` to make the OS resolver try another nameserver.

The fall-through must happen **inside this DNS server**.

Example:

```text
bob queries a.com
bob is not authorized for domain:a

custom DNS forwards upstream
returns the ordinary public/private DNS result
```

This behavior is intentional.

The system does not attempt to hide the existence or real IP of unauthorized names.

Access control is enforced at the gateway and by any ordinary Headscale subnet ACLs.

---

# DNS Result State Model

Internally, DNS evaluation should support at least:

```text
SYNTHESIZE
  User is authorized for a domain resource.
  Return synthetic A/AAAA.

PASSTHROUGH
  Resource does not apply to this user.
  Resolve normally.

BLOCK
  Optional future mode for explicit DNS filtering.
```

V1 only requires `SYNTHESIZE` and `PASSTHROUGH`.

---

# Split DNS Integration

The custom DNS server should be configured as the resolver for the minimum required suffixes.

Example resources:

```text
grafana.corp.example.com
gitlab.corp.example.com
*.dev.example.com
```

Possible generated split-DNS routes:

```text
corp.example.com -> custom domain DNS
dev.example.com  -> custom domain DNS
```

Inside the custom resolver:

```text
gitlab.corp.example.com
  authorized -> synthetic

random.corp.example.com
  no matching domain resource -> upstream DNS

grafana.corp.example.com
  unauthorized -> upstream DNS
```

This allows hijacking a suffix for selective synthetic resolution without changing normal DNS semantics for unrelated names.

---

# A and AAAA Handling

Authorized resources must not leak a real address through one record family.

Bad:

```text
A     -> synthetic IPv4
AAAA  -> real IPv6 via passthrough
```

A Happy Eyeballs client could bypass the synthetic gateway.

For an authorized domain:

Preferred eventual behavior:

```text
A     -> synthetic IPv4
AAAA  -> synthetic IPv6
```

Acceptable V1 behavior if IPv6 is deferred:

```text
A     -> synthetic IPv4
AAAA  -> NOERROR / NODATA
```

Never passthrough AAAA for a name currently being synthesized.

---

# CNAME Handling

An authorized resource must not cause the client to discover the real backend through a CNAME chain.

Example backend DNS:

```text
a.com
  CNAME proxy.internal
proxy.internal
  A 10.1.0.50
```

Client-facing DNS should synthesize the resource directly:

```text
a.com A 10.254.0.17
```

The gateway later performs real DNS resolution and follows the backend CNAME chain locally.

The client should not need to resolve the canonical backend target.

---

# Synthetic Address Allocation

## Allocation scope

Mappings should be scoped to:

```text
(gateway_group, fqdn)
```

not just:

```text
fqdn
```

Example:

```text
(gateway:home, a.com) -> 10.254.0.17
```

Reasons:

- Gateway selection is encoded in the synthetic prefix.
- The same name may exist in multiple independent network contexts.
- Moving a resource between gateways should result in a new synthetic address.
- Gateway-local DNS can resolve the same name differently in different segments.

## Persistence

Mappings should be persistent.

Possible data model:

```text
synthetic_ip
fqdn
resource_id
gateway_group
created_at
last_used
state
```

A simple DB such as SQLite may be sufficient for V1 if running a single control-plane instance.

Postgres may be preferable if HA control-plane state is required immediately.

## Allocation strategy

Prefer a simple allocator over a deterministic hash.

Reason:

- Hash collisions still require state.
- Persistent allocation simplifies debugging.
- Address reuse can be controlled.
- Migrations can use explicit grace periods.

## Address reuse

Do not immediately reuse released addresses.

Retain retired mappings for at least:

```text
DNS TTL + safety/grace period
```

to avoid stale client caches reaching a different resource.

---

# Wildcard Resource Handling

Example:

```text
*.dev.example.com
```

Do not allocate an address for the wildcard itself.

Allocate lazily when a concrete FQDN is queried.

Example:

```text
foo.dev.example.com
  -> matches domain:dev
  -> gateway:home
  -> allocate 10.254.0.42
```

Persist:

```text
foo.dev.example.com -> 10.254.0.42
```

The mapping should retain:

- concrete FQDN,
- matched resource,
- gateway group.

---

# Segmented Gateway Model

Distinguish between:

## Gateway group / segment

Logical egress domain.

Example:

```text
gateway:home
gateway:cloud
gateway:customer-a
```

A gateway group owns:

- one synthetic IPv4 prefix,
- optionally one synthetic IPv6 prefix,
- one DNS/network environment,
- one policy subset,
- zero or more physical gateway instances.

## Gateway instance

Actual Tailscale node/process.

Example:

```text
home-gw-1
home-gw-2
cloud-gw-1
```

Relationship:

```text
a.com -> gateway:home
             |
             +-> home-gw-1
             +-> home-gw-2

b.com -> gateway:cloud
             |
             +-> cloud-gw-1
```

---

# Synthetic Prefix Invariant

One synthetic prefix belongs to exactly one logical gateway group.

Multiple physical gateway instances may advertise the same prefix **only when they are interchangeable members of the same HA group**.

Example:

```text
gateway:home
  prefix: 10.254.0.0/18

home-gw-1 advertises 10.254.0.0/18
home-gw-2 advertises 10.254.0.0/18
```

Do not configure the same prefix on gateways with different backend reachability.

Otherwise Tailscale may treat them as equivalent route candidates, breaking resource routing.

For segmentation, use non-overlapping prefixes:

```text
gateway:home  -> 10.254.0.0/18
gateway:cloud -> 10.254.64.0/18
```

---

# Gateway HA

HA should use multiple physical Tailscale subnet routers advertising the exact same synthetic prefix.

Example:

```text
gateway:home
  synthetic prefix = 10.254.0.0/18

         +------------------+
         |                  |
         v                  v
    home-gw-1           home-gw-2
    advertises          advertises
    10.254.0.0/18       10.254.0.0/18
```

Both gateways need access to:

- the same synthetic allocation registry,
- the same relevant policy state,
- equivalent backend connectivity,
- equivalent DNS view for that gateway group.

They do **not** need to share resolved real-IP cache entries.

Each gateway may resolve backend names locally.

---

# Backend DNS Resolution

The client-facing DNS server should not resolve and expose real backend addresses for authorized resources.

**Gateway backend resolution MUST bypass synthetic Domain DNS behavior.** When a gateway resolves a resource FQDN to establish a backend connection, it must receive the real upstream A, AAAA, or CNAME result, never the synthetic address returned to clients.

Instead:

```text
client DNS
    -> resource identity
    -> synthetic IP

gateway receives connection
    -> synthetic IP -> fqdn
    -> gateway-local DNS resolution
    -> real backend IP
```

Thus:

```text
10.254.0.17 == resource "a.com"
```

not:

```text
10.254.0.17 == backend IP 10.1.0.50
```

Benefits:

- split-horizon DNS works.
- private site-local DNS works.
- overlapping RFC1918 networks are supported.
- backend IP changes do not change the synthetic resource IP.
- clients do not learn backend IPs through synthesized DNS.
- gateway-specific DNS views are possible.
- the same FQDN may resolve differently on different gateway groups.

---

# Example Segmented Resolution

```text
a.internal -> gateway:home
b.internal -> gateway:cloud
```

Central DNS knows:

```text
a.internal -> synthetic 10.254.0.17
b.internal -> synthetic 10.254.64.9
```

Home gateway resolves:

```text
a.internal -> 10.1.0.20
```

Cloud gateway resolves:

```text
b.internal -> 172.20.5.14
```

The central DNS service does not need connectivity to either backend network.

---

# Gateway Flow Processing

Every new connection reaches the gateway with at least:

```text
source Tailscale IP
synthetic destination IP
protocol
destination port
```

Example:

```text
src = 100.64.0.20
dst = 10.254.0.17
proto = TCP
port = 443
```

Processing:

```text
100.64.0.20
    -> node/user/groups/tags

10.254.0.17
    -> gateway:home
    -> a.com
    -> domain:a

authorize:
    principal
    resource
    protocol
    port

if allowed:
    resolve a.com locally
    choose real backend
    establish forwarding state

if denied:
    drop/reject
```

Gateway-side authorization is mandatory.

---

# Same-IP Virtual Host Isolation

This design must safely support:

```text
gitlab.internal  -> 10.1.0.50:443
grafana.internal -> 10.1.0.50:443
admin.internal   -> 10.1.0.50:443
```

Synthetic DNS gives:

```text
gitlab.internal  -> 10.254.0.10
grafana.internal -> 10.254.0.11
admin.internal   -> 10.254.0.12
```

The gateway can therefore enforce three separate resources even though they share the same backend IP and port.

No HTTP Host or TLS SNI inspection is required.

The destination synthetic IP preserves resource identity.

---

# Ordinary Backend Network Access

If a user can directly access the real backend subnet through another Headscale subnet route, domain-resource isolation does not prevent that.

Example:

```text
a.com -> 10.1.0.50
```

If the user also has normal access to:

```text
10.1.0.0/16
```

then they may bypass the domain resource gateway by connecting directly to `10.1.0.50`.

Therefore:

- Headscale ACLs must still govern direct subnet access.
- The domain gateway only protects traffic routed through its synthetic prefix.
- A deployment expecting domain-only isolation must ensure clients do not have broader direct access to backend ranges.

---

# Dataplane Design

## Recommended V1

Start with a userspace L3/L4 gateway daemon.

Responsibilities:

- receive traffic destined for the synthetic prefix,
- identify synthetic destination,
- evaluate policy,
- resolve real backend,
- forward TCP,
- maintain flow state,
- later support UDP.

Avoid making nftables DNAT the primary architecture in V1.

Reason:

The gateway needs dynamic logic for:

- source identity,
- resource lookup,
- wildcard policy,
- protocol/port rules,
- backend DNS,
- multiple A/AAAA results,
- policy updates,
- audit logs,
- gateway-specific state.

A userspace daemon is easier to reason about initially.

## Future optimization

Later:

```text
userspace authorization
    -> install conntrack/NAT/kernel state
    -> kernel handles established flow
```

Possible technologies:

- nftables,
- eBPF,
- TPROXY,
- tun-based forwarding,
- kernel route/NAT programming.

Do not optimize this before correctness.

---

# TCP Support

TCP should be first-class in V1.

A userspace proxy can:

1. accept/receive synthetic-destination flow,
2. authorize it,
3. resolve backend,
4. establish outbound connection,
5. copy bytes bidirectionally.

This covers many important resource types:

- HTTPS,
- HTTP,
- SSH,
- databases,
- admin UIs,
- internal APIs,
- Git servers.

---

# UDP Support

UDP requires explicit flow state.

Likely key:

```text
(
  source_tailscale_ip,
  source_port,
  synthetic_destination_ip,
  destination_port,
  protocol
)
```

State maps to:

```text
resource
real destination
gateway policy decision
last activity
```

Requirements:

- idle timeout,
- reverse translation,
- backend selection persistence for a flow,
- policy reevaluation strategy on updates.

Implement after TCP.

---

# ICMP

Not required for V1.

Synthetic IPs may not respond to ping.

This is acceptable unless future use cases require it.

---

# Resource Migration Between Gateway Groups

If a resource moves:

```text
a.com:
  old gateway = gateway:home
  new gateway = gateway:cloud
```

its synthetic IP should change because gateway selection is encoded in the prefix.

Example:

```text
old: 10.254.0.17
new: 10.254.64.23
```

Migration behavior:

1. Allocate new address in new gateway prefix.
2. DNS begins returning new address.
3. Retain old mapping for TTL + grace period.
4. Old gateway may:
   - allow existing connections to drain,
   - reject new connections after a cutover point.
5. Eventually retire old mapping.
6. Do not immediately reuse old synthetic address.

---

# DNS TTL Strategy

Synthetic records should have a controlled TTL.

Requirements:

- TTL should be short enough for policy/gateway migration.
- TTL should not create excessive DNS load.
- Mapping lifetime and address reuse must account for cached records.
- Gateway removal/migration procedures must include TTL grace.

The exact V1 TTL is an implementation choice.

---

# Backend DNS Caching

Gateway-local DNS results may be cached.

Requirements:

- respect reasonable DNS TTL semantics,
- avoid pinning stale backend addresses indefinitely,
- handle multiple A/AAAA records,
- establish a deterministic backend selection strategy per flow,
- allow different gateway groups to see different DNS answers.

Synthetic mapping lifetime is separate from backend DNS TTL.

A resource's fake IP should remain stable even as the real backend IP changes.

---

# Policy Update Behavior

The control plane must distribute policy changes to DNS and gateway instances.

Desired properties:

- atomic-enough policy snapshots,
- version number / generation ID,
- gateways can report current applied generation,
- old state remains usable during update,
- avoid inconsistent mapping/resource references.

For example:

```text
policy generation 42
  domain resources
  grants
  gateway assignments
  identity references
```

Each DNS/gateway process should know which generation it has loaded.

---

# State Ownership

Potential logical stores:

## Identity state

Contains:

- users,
- groups,
- mappings,
- node metadata where needed.

Can reuse the existing SCIM/group broker database.

## Domain policy state

Contains:

- gateway groups,
- domain resources,
- grants,
- compiled resource matching information.

## Synthetic allocation state

Contains:

- concrete FQDN,
- resource,
- gateway group,
- synthetic IP,
- active/retired state,
- timestamps.

These may live in one database initially.

---

# Audit Logging

Gateways should eventually log authorization decisions.

Useful fields:

```text
timestamp
policy_generation
source_tailnet_ip
source_node
source_user
source_groups/tags as needed
resource_id
fqdn
synthetic_ip
protocol
destination_port
resolved_backend_ip
decision
reason
gateway_group
gateway_instance
```

DNS should optionally log:

```text
source node/user
query
matched resource
SYNTHESIZE vs PASSTHROUGH
synthetic answer
gateway group
```

Be mindful of DNS privacy and log volume.

---

# Failure Behavior

## DNS service unavailable

Clients may lose synthetic domain-resource resolution.

Normal DNS fallback depends on how split DNS is configured and should not be assumed.

This needs explicit operational design.

## Gateway unavailable

Tailscale route HA should select another instance if the gateway group has interchangeable HA members.

## Backend DNS failure

Gateway rejects/fails the connection.

The client-facing synthetic mapping may remain stable.

## Policy service unavailable

DNS/gateways should continue using the last valid policy snapshot rather than failing open.

Fail closed for new resource authorization if required state is unavailable and no valid cached policy exists.

## Identity lookup unavailable

Prefer cached identity state.

Do not fail open.

---

# Address Space Considerations

Do not use Firezone's `100.96.0.0/11` because it overlaps Tailscale's CGNAT address space `100.64.0.0/10`.

Preferred approach:

- make synthetic IPv4 prefix configurable,
- choose an unused RFC1918 block in the deployment,
- avoid collisions with LANs/VPCs expected on clients.

Example used throughout this design:

```text
10.254.0.0/16
```

This is only illustrative.

The design must not hard-code it.

IPv6 synthetic addressing may be added later.

---

# Why This Design Instead of Tailscale App Connectors

Tailscale App Connectors and NetBird domain resources ultimately route the real resolved IP.

That causes policy conflation when multiple names share one destination IP.

This design intentionally mirrors Firezone's stronger model:

```text
domain resource
    -> unique synthetic overlay address
    -> gateway
    -> real backend
```

The synthetic destination keeps the domain/resource identity available at the enforcement point.

---

# Key Invariants

1. A synthesized domain's real backend address is never returned by custom DNS for that authorized query.
2. Unauthorized domain-resource queries fall through to ordinary DNS.
3. DNS authorization is not sufficient for access.
4. Every new gateway flow is authorized independently.
5. A synthetic IP maps to one concrete FQDN/resource within one gateway group.
6. One synthetic prefix belongs to exactly one logical gateway group.
7. Multiple physical gateways may advertise the same prefix only if they are interchangeable HA members.
8. Headscale does not require per-domain synthetic route updates.
9. Gateway routing is selected by the destination synthetic prefix.
10. Gateway backend DNS resolution bypasses synthetic Domain DNS behavior and receives only real upstream A/AAAA/CNAME results.
11. Synthetic IP stability is independent of backend DNS/IP changes.
12. Clients with direct access to backend subnets can bypass domain-resource isolation; normal Headscale ACLs must prevent that where required.
13. Authorized A and AAAA behavior must not expose a bypass path.
14. Retired synthetic addresses are not immediately reused.

---

# Suggested V1 Scope

A reasonable first implementation should include:

1. Policy parser/compiler extension.
2. Gateway group definitions.
3. Domain resource definitions.
4. Domain grants with source + TCP port restrictions.
5. IPv4 synthetic prefixes only.
6. Persistent concrete-FQDN synthetic allocator.
7. Wildcard FQDN matching.
8. Custom DNS server:
   - source-Tailscale-IP aware,
   - synthetic A answers for authorized resources,
   - AAAA NODATA for synthesized resources,
   - upstream passthrough otherwise.
9. One gateway daemon implementation.
10. Multiple logical gateway groups.
11. One or more physical gateway instances per group.
12. TCP forwarding.
13. Gateway-side policy revalidation.
14. Gateway-local backend DNS resolution.
15. Basic policy generation/versioning.
16. Basic audit logs.
17. Static broad synthetic-prefix routes in Headscale.

Defer:

- UDP,
- IPv6,
- ICMP,
- eBPF/nftables fast path,
- sophisticated DNS load balancing,
- control-plane HA unless needed immediately,
- dynamic route updates,
- DNS BLOCK semantics,
- advanced session draining.

---

# Open Implementation Questions

The next agent should break these down and choose concrete mechanisms.

## Gateway packet interception

Options may include:

- TUN device,
- userspace network stack,
- local bind across synthetic addresses,
- nftables REDIRECT/TPROXY into a userspace daemon,
- raw socket / transparent proxy architecture.

Need to determine the cleanest way to receive arbitrary traffic for an advertised synthetic subnet on Linux.

## Source identity synchronization

Need to choose how DNS/gateways obtain:

```text
Tailscale IP -> node -> user/groups/tags
```

Possibilities:

- Headscale API,
- existing proxy/broker DB,
- generated policy snapshot,
- event/watch feed if available.

Prefer avoiding synchronous Headscale API calls on every DNS query or connection.

## DNS split configuration generation

Need to decide whether:

- Headscale DNS config is generated automatically from domain resource suffixes, or
- administrator explicitly configures the suffixes.

Automatic generation is preferable if safe.

## Policy syntax

Need final HuJSON extension schema.

The examples in this document are illustrative rather than frozen API.

## Synthetic prefix sizing

Need define:

- per-gateway minimum pool size,
- allocation exhaustion behavior,
- configurable parent synthetic range,
- reserved addresses,
- future IPv6 support.

## Multiple resource matches

Need deterministic behavior when one FQDN matches multiple resources.

Possible rules:

- reject ambiguous config,
- most-specific pattern wins,
- merge grants only if gateway assignment agrees.

Strong preference: reject configurations where overlapping resource patterns resolve to different gateway groups unless semantics are explicitly defined.

## Multiple gateway-local A/AAAA results

Need connection/backend selection semantics.

Possible:

- round robin,
- random,
- first healthy,
- preserve DNS ordering.

## Existing connection behavior on policy revoke

Need decide whether revocation:

- only blocks new flows, or
- also terminates existing sessions.

V1 may reasonably apply policy to new flows only.

## HA control plane

If DNS/control-plane redundancy is required, determine shared DB requirements and leaderless allocation semantics.

---

# Recommended Breakdown for the Next Agent

Suggested workstreams:

1. **Policy schema**
   - finalize `domainGateways`
   - finalize `domainResources`
   - finalize `domainGrants`
   - validation rules
   - Headscale policy stripping/compilation

2. **Identity integration**
   - node/IP ownership
   - groups
   - tags
   - cache/update strategy

3. **Synthetic allocator**
   - schema
   - pool allocation
   - wildcard concrete-name allocation
   - migration
   - retirement/reuse rules

4. **DNS service**
   - split DNS
   - source IP identification
   - policy match
   - SYNTHESIZE/PASSTHROUGH
   - A/AAAA handling
   - CNAME handling
   - upstream forwarding

5. **Gateway dataplane**
   - synthetic subnet advertisement
   - packet interception
   - TCP proxying
   - source identity lookup
   - policy evaluation
   - local backend DNS
   - audit logs

6. **Gateway segmentation**
   - prefix ownership
   - resource assignment
   - HA group semantics
   - config validation

7. **Policy/state distribution**
   - generations
   - reload semantics
   - stale-state behavior
   - fail-closed rules

8. **Testing**
   - same-IP multi-domain isolation
   - unauthorized synthetic-IP guessing
   - DNS passthrough
   - wildcard resources
   - segmented gateway routing
   - HA failover
   - backend DNS changes
   - resource migration
   - policy revoke
   - direct real-IP bypass expectations

9. **Operational packaging**
   - deployment model
   - systemd/container
   - gateway route advertisement
   - metrics
   - health checks
   - observability

---

# Critical Test Cases

## Same backend IP, different policy

```text
allowed.example.com -> 10.1.0.50:443
denied.example.com  -> 10.1.0.50:443
```

Expected:

```text
allowed.example.com -> synthetic A
denied.example.com  -> ordinary DNS if user unauthorized

user cannot reach denied resource through allowed synthetic IP
```

## Guessed synthetic address

User learns another resource's synthetic IP.

Expected:

```text
connection reaches gateway
gateway resolves synthetic -> resource
gateway denies based on source principal
```

## Segmented gateways

```text
a.com -> gateway:home
b.com -> gateway:cloud
```

Expected:

```text
a.com gets IP from home synthetic prefix
b.com gets IP from cloud synthetic prefix

Tailscale routing selects correct gateway group
```

## HA

Two equivalent gateways advertise same exact prefix.

Expected:

- normal connectivity through either,
- failover if one disappears,
- same mapping/policy interpretation on both.

## Wildcard

```text
*.dev.example.com
```

Expected:

```text
foo.dev.example.com -> concrete synthetic allocation
bar.dev.example.com -> separate concrete synthetic allocation
```

## Unauthorized DNS

Unauthorized user queries a configured domain resource.

Expected:

- ordinary upstream DNS result,
- not NXDOMAIN/REFUSED solely because policy denies synthetic access.

## AAAA bypass

Authorized synthetic domain has real IPv6 backend DNS.

Expected V1:

- A -> synthetic IPv4,
- AAAA -> NODATA,
- never real backend IPv6.

## Backend IP change

```text
a.com:
  old backend 10.1.0.50
  new backend 10.1.0.60
```

Expected:

- synthetic IP remains unchanged,
- gateway DNS cache eventually refreshes,
- new connections use updated backend.

---

# Final Design Summary

The intended system is best thought of as:

> A Firezone-style resource gateway that uses Tailscale/Headscale purely as the authenticated overlay transport.

A domain resource receives a synthetic destination IP. The prefix containing that IP determines the logical gateway segment. Tailscale routes the packet to a gateway instance for that segment. The gateway uses the synthetic IP to recover the original resource identity, maps the source Tailscale IP to a user/device identity, evaluates domain/port/protocol policy, resolves the real backend using the gateway's own DNS environment, and forwards the connection.

Headscale remains largely unchanged and only needs static synthetic subnet advertisements plus coarse transport policy.

The most important architectural properties are:

- domain identity survives to the enforcement point,
- domains sharing a backend IP remain independently authorizable,
- gateway segmentation is encoded by synthetic prefixes,
- DNS falls through normally for unauthorized resources,
- authorization is enforced at the gateway, not trusted to DNS,
- backend addressing and DNS remain local to each gateway segment,
- no per-domain Headscale route churn is required.
