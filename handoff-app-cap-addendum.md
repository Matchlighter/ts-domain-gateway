# Addendum: Use Tailscale App Capabilities for Domain Resource Policy

## Purpose

This addendum revises the policy and identity portions of the original `handoff.md`.

The preferred design is now to express Domain Gateway authorization using standard Tailscale/Headscale grant `app` capabilities rather than inventing new top-level policy syntax such as:

```hujson
domainGateways: { ... }
domainResources: { ... }
domainGrants: [ ... ]
```

This has several advantages:

- Headscale remains responsible for parsing and compiling users, groups, tags, and grants.
- The Domain DNS service and Domain Gateway consume the already-compiled authorization result from local `tailscaled`.
- The project no longer needs its own general-purpose user/group policy compiler.
- Email, OIDC provider identifiers, usernames, groups, and tag semantics remain Headscale's responsibility.
- DNS and gateway instances can independently enforce the same application capability.
- The policy remains valid Tailscale-style grant syntax.

This addendum supersedes the original handoff where it proposed custom top-level domain policy fields or a separate identity-to-group compilation layer.

---

# Core Policy Model

Use a custom application capability namespace under a domain controlled by the project owner.

Example capability name:

```text
matchlighter.net/cap/domain-gateway
```

Illustrative grant:

```hujson
{
  "src": ["group:whatever"],

  "dst": [
    "tag:gateway1",
    "tag:dns",
  ],

  "app": {
    "matchlighter.net/cap/domain-gateway": [
      {
        "gateway": "tag:gateway1",
        "resources": [
          {
            "domain": "example.com",
          },
          {
            "domain": "example.org",
            "ports": ["tcp:443"],
          },
        ],
      },
    ],
  },
}
```

The capability payload is application-defined data.

Headscale/Tailscale handle:

```text
src selectors
  -> users
  -> groups
  -> tags
  -> aliases
  -> grant merging
  -> resulting application capabilities
```

The Domain Gateway project handles only the contents of:

```text
matchlighter.net/cap/domain-gateway
```

---

# Why This Is Preferred

Previous design:

```text
policy file
    |
    v
custom parser/compiler
    |
    +-> resolve users/groups
    +-> resolve tags
    +-> maintain identity aliases
    +-> build DNS policy
    +-> build gateway policy
```

Revised design:

```text
policy file
    |
    v
Headscale grant compiler
    |
    v
tailscaled netmap
    |
    v
LocalAPI WhoIs / capability map
    |
    +-> Domain DNS
    |
    +-> Domain Gateway
```

The project consumes Headscale's compiled authorization result instead of reimplementing Headscale policy semantics.

---

# Capability Delivery

The same application capability should normally be targeted to:

```text
tag:dns
```

and the appropriate logical gateway tag:

```text
tag:gateway1
```

Example:

```hujson
{
  "src": ["group:developers"],

  "dst": [
    "tag:dns",
    "tag:gateway1",
  ],

  "app": {
    "matchlighter.net/cap/domain-gateway": [
      {
        "gateway": "tag:gateway1",
        "resources": [
          {
            "domain": "*.dev.example.com",
            "ports": ["tcp:443"],
          },
        ],
      },
    ],
  },
}
```

This deliberately gives both enforcement participants the same authorization object.

The DNS service needs it to answer:

> Should this source receive a synthetic address for this domain?

The gateway needs it to answer:

> Is this source authorized to connect to this synthetic resource on this protocol/port?

---

# Gateway Must Be Explicit in the Capability

Do not infer the intended gateway only from the grant's `dst`.

The capability payload itself must contain the logical gateway assignment.

Example:

```hujson
{
  "gateway": "tag:gateway1",
  "resources": [
    {
      "domain": "example.com",
    },
  ],
}
```

Reason:

The DNS server receives the application capability but needs to know which synthetic address pool should be used for the resource.

The original grant might target both:

```text
tag:dns
tag:gateway1
```

but the resulting opaque application capability should be self-describing.

---

# Recommended Capability Schema

Preferred shape:

```hujson
{
  "gateway": "tag:gateway1",

  "resources": [
    {
      "domain": "example.com",
    },

    {
      "domain": "example.org",
      "ports": [
        "tcp:443",
      ],
    },

    {
      "domain": "*.dev.example.com",
      "ports": [
        "tcp:443",
        "tcp:8443",
      ],
    },
  ],
}
```

This is preferred over string shorthand such as:

```text
example.org:443
```

because it leaves room for:

- TCP vs UDP,
- multiple ports,
- port ranges,
- wildcard domains,
- future per-resource attributes,
- protocol-specific behavior.

A terse string grammar may still be acceptable if simplicity is strongly preferred, but structured objects are the safer long-term API.

---

# Domain Matching

The Domain DNS and Domain Gateway must interpret the same resource matching rules.

At minimum support:

```text
example.com
*.example.com
```

Possible future support:

```text
**.example.com
```

if desired.

The implementation must define wildcard semantics precisely.

Recommended rule:

```text
*.example.com
```

matches exactly one label below `example.com`.

Example:

```text
foo.example.com       -> match
bar.example.com       -> match
x.y.example.com       -> no match
example.com           -> no match
```

If recursive wildcards are desired later, define them separately.

---

# Grant Merging

Application capability grants are additive.

If multiple grants apply to a source, the Domain Gateway application should treat the capability objects as a union.

Example:

```hujson
{
  "src": ["group:developers"],
  "dst": ["tag:dns", "tag:gateway1"],

  "app": {
    "matchlighter.net/cap/domain-gateway": [
      {
        "gateway": "tag:gateway1",
        "resources": [
          {
            "domain": "git.example.com",
            "ports": ["tcp:443"],
          },
        ],
      },
    ],
  },
},

{
  "src": ["group:admins"],
  "dst": ["tag:dns", "tag:gateway1"],

  "app": {
    "matchlighter.net/cap/domain-gateway": [
      {
        "gateway": "tag:gateway1",
        "resources": [
          {
            "domain": "admin.example.com",
            "ports": ["tcp:443"],
          },
        ],
      },
    ],
  },
}
```

A source in both groups should effectively receive:

```text
gateway: tag:gateway1

resources:
  git.example.com:443
  admin.example.com:443
```

The application must not implement "last rule wins" semantics.

---

# Runtime Identity Resolution

The project should no longer attempt to maintain its own comprehensive mapping of:

```text
Tailscale IP
  -> Headscale user
  -> email alias
  -> OIDC provider identifier
  -> username
  -> groups
  -> tags
```

Instead, use local `tailscaled` as the hot-path source of compiled authorization.

Conceptually:

```text
packet/query source IP
        |
        v
tailscaled LocalAPI WhoIs
        |
        v
WhoIsResponse
        |
        +-> Node
        +-> UserProfile
        +-> CapMap
```

The important object is the capability map.

The application extracts:

```text
matchlighter.net/cap/domain-gateway
```

and evaluates the resulting capability objects.

This means Headscale remains responsible for resolving policy identities.

---

# Why This Solves User Alias Complexity

A single Headscale user may be representable in policy by several strings:

```text
email
username
OIDC provider identifier
```

The project should not normalize those itself at request time.

Headscale resolves these selectors as part of grant compilation.

At runtime, the Domain Gateway only sees the resulting capability.

Therefore:

```text
policy alias complexity
        |
        v
Headscale
        |
        v
compiled app capability
        |
        v
Domain Gateway
```

No separate user-alias database is required for authorization.

---

# Tags

Tagged devices should likewise rely on Headscale/Tailscale grant semantics.

Do not independently reinterpret:

```text
tag ownership
user ownership
tagged-device identity
```

inside the Domain Gateway project unless absolutely necessary.

The capability map already represents the result of Headscale's grant evaluation.

The Domain Gateway should ask:

> What domain-gateway application capabilities does this source have when communicating with this enforcement node?

rather than reconstructing the original policy selectors.

---

# DNS Runtime Authorization

For a DNS request:

```text
src = 100.64.0.20
query = example.com
```

processing becomes:

```text
100.64.0.20
    |
    v
tailscaled LocalAPI WhoIs
    |
    v
CapMap
    |
    v
matchlighter.net/cap/domain-gateway
    |
    v
find matching resource
    |
    +-- authorized
    |      |
    |      v
    |   gateway = tag:gateway1
    |      |
    |      v
    |   allocate/lookup synthetic IP
    |      |
    |      v
    |   return synthetic A/AAAA
    |
    +-- no match
           |
           v
       upstream DNS passthrough
```

The DNS service does not need a separate group/user lookup.

---

# Gateway Runtime Authorization

For a new gateway flow:

```text
src = 100.64.0.20
dst = 10.254.0.17
proto = TCP
port = 443
```

processing becomes:

```text
synthetic IP
    |
    v
resource registry
    |
    v
example.com
gateway = tag:gateway1

source IP
    |
    v
tailscaled LocalAPI WhoIs
    |
    v
CapMap
    |
    v
matchlighter.net/cap/domain-gateway

evaluate:
    gateway matches tag:gateway1
    domain matches example.com
    tcp:443 permitted
```

Only then should the gateway resolve the real destination and establish the backend connection.

---

# Gateway Backend DNS Must Never Be Synthetic

This is a critical invariant.

When the gateway receives:

```text
10.254.0.17
```

and maps it to:

```text
example.com
```

the gateway must resolve `example.com` through a backend-resolution path that bypasses synthetic Domain DNS behavior.

Bad:

```text
Gateway
   |
   | resolve example.com
   v
Domain DNS
   |
   | gateway itself is authorized
   v
10.254.0.17
   |
   +-> resolution loop
```

Required:

```text
Client:
example.com
    |
    v
synthetic Domain DNS
    |
    v
10.254.0.17


Gateway:
10.254.0.17
    |
    v
example.com
    |
    v
REAL backend resolver
    |
    v
10.1.0.50
```

Gateway backend resolution must therefore use one of:

1. a separately configured backend resolver, or
2. an explicit authenticated/internal "resolve real backend" mode in the Domain DNS service.

Do not decide this merely by checking whether the DNS requester happens to be a gateway source IP.

Backend-resolution mode should be explicit and unambiguous.

---

# IP Grants Remain Separate from App Capabilities

Application capabilities answer:

> Which named Domain Resources is the principal authorized to use?

They do not, by themselves, replace the transport-level packet grants needed for Tailscale to carry traffic.

Use separate `ip` grants.

## DNS transport

Example:

```hujson
{
  "src": ["group:whatever"],
  "dst": ["tag:dns"],

  "ip": [
    "udp:53",
    "tcp:53",
  ],
}
```

TCP/53 should be included because legitimate DNS traffic may use or retry over TCP.

---

# Synthetic Prefix Transport

Do not grant transport to:

```text
tag:gateway1
```

when the actual packet destination is a synthetic IP routed through that gateway.

The routed packet destination remains:

```text
10.254.0.17:443
```

Therefore transport grants should target the synthetic prefix.

Example:

```hujson
{
  "src": ["group:whatever"],

  "dst": [
    "10.254.0.0/18",
  ],

  "via": [
    "tag:gateway1",
  ],

  "ip": [
    "tcp:443",
  ],
}
```

Conceptually:

```text
app capability:
  named-resource authorization

ip grant:
  synthetic L3/L4 transport authorization
```

These are separate layers.

---

# `via` and Gateway Segmentation

Synthetic prefix routing and the `via` selector can reinforce one another.

Example logical segment:

```text
tag:gateway1
synthetic prefix 10.254.0.0/18
```

Transport policy:

```hujson
{
  "src": ["group:whatever"],
  "dst": ["10.254.0.0/18"],
  "via": ["tag:gateway1"],
  "ip": ["tcp:443"],
}
```

This constrains access to that synthetic address range through the expected routing gateway tag.

The Domain Gateway must still independently evaluate the application capability.

Do not rely on the `ip` grant alone to distinguish individual domain resources.

---

# Example Complete Policy

Illustrative configuration:

```hujson
{
  "groups": {
    "group:developers": [
      "alice@example.com",
      "bob@example.com",
    ],
  },

  "tagOwners": {
    "tag:dns": [
      "group:admins",
    ],

    "tag:gateway1": [
      "group:admins",
    ],
  },

  "grants": [
    // Domain authorization for Gateway 1.
    {
      "src": ["group:developers"],

      "dst": [
        "tag:dns",
        "tag:gateway1",
      ],

      "app": {
        "matchlighter.net/cap/domain-gateway": [
          {
            "gateway": "tag:gateway1",

            "resources": [
              {
                "domain": "example.com",
                "ports": ["tcp:443"],
              },

              {
                "domain": "*.dev.example.com",
                "ports": [
                  "tcp:443",
                  "tcp:8443",
                ],
              },
            ],
          },
        ],
      },
    },

    // DNS transport.
    {
      "src": ["group:developers"],
      "dst": ["tag:dns"],

      "ip": [
        "udp:53",
        "tcp:53",
      ],
    },

    // Synthetic subnet transport for Gateway 1.
    {
      "src": ["group:developers"],
      "dst": ["10.254.0.0/18"],
      "via": ["tag:gateway1"],

      "ip": [
        "tcp:443",
        "tcp:8443",
      ],
    },
  ],
}
```

---

# Segmented Gateway Example

Suppose:

```text
example.com -> Gateway 1
example.org -> Gateway 2
```

Synthetic ranges:

```text
tag:gateway1 -> 10.254.0.0/18
tag:gateway2 -> 10.254.64.0/18
```

DNS:

```text
example.com
  -> authorized cap says tag:gateway1
  -> allocate from 10.254.0.0/18
  -> 10.254.0.17

example.org
  -> authorized cap says tag:gateway2
  -> allocate from 10.254.64.0/18
  -> 10.254.64.9
```

Tailscale routing then naturally selects the appropriate gateway segment.

---

# Gateway-to-Prefix Mapping

The application capability identifies a gateway by logical tag:

```text
tag:gateway1
```

The project still needs configuration mapping that logical gateway to a synthetic prefix.

Example service configuration:

```yaml
gateways:
  tag:gateway1:
    ipv4: 10.254.0.0/18

  tag:gateway2:
    ipv4: 10.254.64.0/18
```

This mapping does not necessarily need to live in Headscale policy.

It may be local service configuration.

An alternative future capability schema could include a logical gateway name independent of the actual Tailscale tag.

For V1, using the tag directly keeps the model simple.

---

# HA Semantics Remain Unchanged

One logical gateway tag/group may correspond to multiple interchangeable physical gateway instances.

Example:

```text
gateway logical identity:
  tag:gateway1

physical nodes:
  gateway1-a
  gateway1-b

both advertise:
  10.254.0.0/18
```

Both should receive/evaluate the same app capabilities.

Both must have:

- the same synthetic allocation registry,
- the same backend DNS/network view,
- equivalent backend reachability,
- compatible policy generation.

The synthetic prefix still belongs to exactly one logical gateway group.

---

# LocalAPI Capability Lookup

Preferred hot-path design:

```text
DNS/Gateway process
      |
      v
local tailscaled
      |
      v
WhoIs(source IP)
      |
      v
CapMap
```

Do not make remote Headscale API calls per DNS query or per connection.

The local `tailscaled` already has the current control-plane state.

A short local cache may be used for DNS query volume, but gateway connection authorization should prefer fresh or minimally cached capability state.

---

# Potential `WhoIsForIP` Use

For gateway authorization, a future implementation may evaluate whether `WhoIsForIP(source, syntheticDestination)` provides useful destination-scoped capability semantics.

However, the initial design should not depend on it.

The current capability design intentionally sends the same application capability to:

```text
tag:dns
tag:gateway1
```

while packet transport is separately governed by:

```text
dst: synthetic prefix
via: gateway tag
```

This separation is simple and understandable.

---

# Security Invariants

The following remain mandatory:

1. DNS synthesis is not the authorization boundary.
2. The gateway re-authorizes every new flow.
3. A guessed synthetic IP must not grant access.
4. A copied DNS answer from another user must not grant access.
5. App capability authorization and IP transport authorization are separate checks.
6. Backend DNS resolution must bypass synthetic resolution.
7. Unauthorized DNS queries pass through to ordinary DNS.
8. Authorized A/AAAA handling must not reveal an unsynthesized bypass.
9. Direct real-subnet access must remain separately controlled by Headscale ACL/grant policy.
10. Grant capability union must be additive.
11. The project should not reinterpret Headscale user/group/tag semantics unless required.
12. Gateway identity must be explicit in the app capability payload.

---

# Revised Component Responsibilities

## Headscale

Responsible for:

- parsing standard grant syntax,
- resolving users/groups/tags,
- compiling `src`/`dst` semantics,
- app capability delivery,
- IP packet transport policy,
- node identity/control-plane state.

## `tailscaled`

Responsible for:

- local netmap,
- local WhoIs/identity/capability lookup,
- Tailscale transport,
- subnet routing.

## Domain DNS

Responsible for:

- receiving client DNS queries,
- identifying source through local `tailscaled`,
- reading domain-gateway app capabilities,
- matching requested FQDN,
- choosing the logical gateway,
- allocating/looking up synthetic IP,
- returning synthetic records for authorized resources,
- upstream passthrough otherwise.

## Domain Gateway

Responsible for:

- receiving synthetic-prefix traffic,
- mapping synthetic IP to FQDN/resource,
- identifying source through local `tailscaled`,
- reading domain-gateway app capabilities,
- authorizing gateway/domain/protocol/port,
- resolving the real backend through a non-synthetic resolver path,
- forwarding the connection,
- audit logging.

## Shared Resource Registry

Still responsible for:

```text
gateway
fqdn
resource
synthetic IP
allocation state
retirement state
```

The app-capability approach removes most identity-policy state from this registry.

---

# Changes From Original Handoff

The following original design ideas should be considered superseded.

## Superseded: custom top-level policy syntax

Do not require:

```hujson
domainGateways
domainResources
domainGrants
```

unless a later requirement cannot be represented cleanly through app capabilities.

Use standard `grants[].app` instead.

## Superseded: custom group/user compiler

Do not build a separate runtime policy compiler whose primary purpose is resolving:

```text
email
OIDC provider ID
username
groups
tags
```

into internal user identities.

Headscale already performs this work.

## Superseded: separate DNS/gateway policy distribution

Do not create a parallel authorization distribution system unless needed for non-policy state.

Use:

```text
Headscale
 -> tailscaled
 -> app capability map
```

as the authorization distribution mechanism.

Synthetic allocation state and gateway-prefix configuration still need their own distribution/storage mechanism.

---

# Open Questions Introduced by This Design

The next implementation agent should verify and decide:

1. Exact Headscale versions required for custom grant app capabilities.
2. Exact LocalAPI capability representation returned by the Headscale/Tailscale version in use.
3. Whether normal `WhoIs` is sufficient for all gateway cases or whether `WhoIsForIP` improves correctness.
4. App capability cache invalidation behavior after policy changes.
5. Whether Headscale preserves arbitrary JSON capability objects exactly as required.
6. Validation rules for malformed domain-gateway capability payloads.
7. Whether the project should reject capability resources naming a gateway tag different from the receiving gateway.
8. How logical gateway tag -> synthetic prefix configuration is distributed.
9. Whether capability-level `ports` should support ranges and UDP in V1.
10. Exact wildcard semantics.
11. How DNS handles conflicting matching capabilities that assign the same FQDN to different gateways.

Strong recommendation for item 11:

> Treat a FQDN that is simultaneously authorized for multiple different gateway groups as an ambiguous policy error rather than choosing one implicitly.

---

# Revised Mental Model

The system is no longer:

> A custom domain-policy engine layered alongside Headscale.

It is:

> A Tailscale application that consumes Headscale-compiled app capabilities and uses synthetic addressing to enforce domain-level resource identity.

Authorization flow:

```text
human policy
    |
    v
Headscale grants
    |
    v
compiled custom app capabilities
    |
    v
tailscaled
    |
    +------------------------+
    |                        |
    v                        v
Domain DNS              Domain Gateway
    |                        |
    v                        v
synthetic discovery      real enforcement
```

This is the preferred policy architecture going forward.
