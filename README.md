# Headscale Domain Proxies

`domain-gateway` provides identity-aware DNS and TCP egress for domain
resources authorized by Headscale/Tailscale application capabilities. The DNS
role returns stable synthetic IPv4 addresses only to authorized tailnet
sources. The egress role reauthorizes every TCP flow and resolves its backend
only through that gateway's segment resolver.

The complete, commented Headscale policy is [sample.jsonc](sample.jsonc). It
is the source of truth for capability grants and per-node gateway settings;
adapt its tags, groups, domains, prefixes, and resolver addresses before use.

## Roles and transports

Role and runtime are deliberately separate:

```text
domain-gateway dns    -mode tsnet|tailscaled [flags]
domain-gateway egress -mode tsnet|tailscaled [flags]
```

`dns` is the sole allocation authority. It persists synthetic-address to
domain mappings and answers PTR records. `egress` is stateless: it queries
those PTR records and never reads the allocation database.

Synthetic allocations have a 60-minute lease by default. Successful synthetic
forward and PTR lookups renew it; database renewals are debounced to one write
per mapping every five minutes. Set `allocation_lease` in `config.json` (or
`-allocation-lease`) to a positive Go duration such as `90m`. Synthetic A and
PTR answers use a 10-minute DNS TTL.

`-mode tsnet` runs an embedded userspace Tailscale node. It requires
`tsnet.dir` and ordinarily a tagged pre-auth key on first enrollment.
`-mode tailscaled` uses only the configured local tailscaled LocalAPI and host
network stack. It never starts tsnet. Conversely, tsnet mode never falls back
to tailscaled. Invalid mode values fail at startup. The old `-mode dns` and
`-mode gateway` role selector has been removed; use the explicit subcommands.

For tailscaled egress on Linux, advertise the synthetic prefix with
tailscaled, then redirect only TCP traffic for that prefix to the listener:

```text
iptables -t nat -A PREROUTING -d 10.254.0.0/18 -p tcp -j REDIRECT --to-ports 15001
```

Set `gateway_listen` to `0.0.0.0:15001`. The process uses
`SO_ORIGINAL_DST`, so authorization sees the client-visible synthetic address
and port, never its local redirect address. In tsnet egress mode the subnet
router advertises its local egress-assignment prefixes and receives the original destination
in its userspace fallback handler instead.

## Daemon configuration

Put long-lived settings in `config.json`; every field can be overridden on the
command line using the matching hyphenated flag. `database` is always a
database URL: use `sqlite://file/path` for a relative SQLite file,
`sqlite:///absolute/path` for an absolute SQLite file, or `postgres://...` for
PostgreSQL. `tsnet.dir` is `-tsnet-dir`. The former top-level `tsnet_*` keys
are rejected; move their values into the `tsnet` object.

```jsonc
{
  // Optional explicit bind address for DNS. Empty binds UDP 53 on the chosen
  // Tailscale address, which is the usual and safest setting.
  "dns_listen": "",

  // Local listener for tailscaled egress transparent interception.
  "gateway_listen": "0.0.0.0:15001",

  // Unix LocalAPI socket used only with -mode tailscaled.
  "tailscaled_socket": "/var/run/tailscale/tailscaled.sock",

  // DNS allocation storage. SQLite and PostgreSQL use the same schema;
  // it is created automatically. SQLite is one authority only; DNS HA needs
  // a PostgreSQL URL shared by every DNS replica.
  "database": "postgres://domain_gateway:secret@db.example:5432/domain_gateway?sslmode=require",

  // Optional egress fallback resolver. A gateway-visible NodeAttr upstreamDNS
  // wins. "system" uses the host's non-Tailscale resolver.
  "upstream_resolver": "system",

  // Required only by the egress role. This local assignment drives flow
  // enforcement and tsnet route advertisement. In tailscaled mode, advertise
  // the same ranges with tailscaled and redirect their TCP traffic above.
  "egress": {
    "tag": "tag:gateway1",
    "ranges": ["10.254.0.0/18"],

    // Optional IP address of the internal DNS authority for synthetic-address
    // PTR recovery. Port 53 is used; backend DNS follows capability, NodeAttr,
    // and upstream_resolver precedence below.
    "dns_resolver": "192.0.2.53",

    // Backend resolver transport in tsnet mode: auto uses tailnet only when
    // an active peer subnet route contains the appcap resolver IP; otherwise
    // it uses the host network. Set tailnet or host to force that path.
    "upstream_dns_interface": "auto"
  },

  "tsnet": {
    // Persistent tsnet state and identity. dir is required with -mode tsnet.
    "dir": "/var/lib/domain-gateway/tsnet",
    "hostname": "domain-dns",

    // Optional coordination server. Leave empty for Tailscale's default
    // (or TS_CONTROL_URL); set it for a Headscale deployment.
    "control_url": "https://headscale.example.com",

    // First-enrollment key. Prefer TS_AUTHKEY in the service environment
    // rather than committing a key here; it is unnecessary after state exists.
    "auth_key": "",

    // Tags are requested only when no auth key is supplied. A tagged auth key
    // owns tag assignment, so client-side tags are suppressed then.
    "tags": ["tag:dns"]
  },

}
```

Typical DNS authority, embedded transport:

```text
domain-gateway dns -config /etc/domain-gateway/config.json -mode tsnet
```

Typical host-daemon egress, with an explicit listener override:

```text
domain-gateway egress -config /etc/domain-gateway/config.json -mode tailscaled -gateway-listen 0.0.0.0:15001
```

`tsnet.control_url` may be overridden with `-tsnet-control-url`. It selects
the Tailscale coordination server for tsnet mode (for example, a Headscale
URL); it is ignored in tailscaled mode.

## Local Docker E2E

Run the complete live suite against a disposable Docker Headscale built from
[Headscale PR #3121](https://github.com/juanfont/headscale/pull/3121):

```text
./e2e/run-compose.sh
```

The script requires Docker with the Compose plugin. It builds the project and
the pinned Headscale image, then starts a DNS authority, egress gateway,
deterministic upstream DNS/HTTP/HTTPS server, and isolated tagged clients. It
waits for the tailnet to form, exercises the end-to-end checks, and removes
all containers, networks, and volumes on exit. It makes no changes to the
repository or a real tailnet.

The suite uses the in-stack `protected.example.test` host rather than an
Internet site. It verifies synthetic and ordinary DNS results, a denied client
receiving the real address after an authorized client has allocated a
synthetic address, PTR, TCP/HTTP, TLS/HTTPS, gateway-origin DNS passthrough,
and automatic discovery of the gateway synthetic range. UDP remains an
explicit expected-red probe because the gateway currently proxies TCP only.

The database is DNS-only storage. The allocation table has unique
gateway/domain and synthetic-IP keys. PostgreSQL is a shared allocation
registry: multiple DNS replicas can use it concurrently, converge on one
mapping, and answer PTR records allocated by another replica. SQLite is
limited to a single DNS authority and is not an HA deployment.

## Headscale policy and routing

Optionally configure upstream resolution in the DNS NodeAttr application
payload shown in [sample.jsonc](sample.jsonc). A `range` on a
`matchlighter.net/cap/domain-gateway` grant is required. It is the synthetic
pool DNS allocates from and must exactly match the local egress assignment that
serves it. DNS discovers tagged gateway clusters' active synthetic ranges from
stable Tailnet Status `PrimaryRoutes` only to identify gateway-originated
queries.
`gateways` in that NodeAttr is optional: when present it is an explicit
administrator override, wins over discovery, and logs a warning on mismatch.
The NodeAttr can target only `tag:dns`; egress instead requires the local
`egress` assignment above and never reads this NodeAttr.

The DNS node returns a synthetic address only for a matching authorized domain;
all other records are forwarded through its NodeAttr `upstreamDNS`, or the
system resolver when it is unset. Egress uses `egress.dns_resolver` (or the
configured Tailnet DNS resolvers) only to recover the synthetic destination by
PTR. The backend lookup precedence is resource `upstreamDNS`, grant
`upstreamDNS`, a gateway-visible NodeAttr `upstreamDNS`, then
`upstream_resolver`, and finally `system`. `system` selects the first
non-Tailscale resolver in `/etc/resolv.conf`; `100.100.100.100` is ignored to
avoid a DNS loop. The policy compiler/control plane must preserve the
object-valued `app` payload in NodeCapMap.

An individual `matchlighter.net/cap/domain-gateway` grant may set
`upstreamDNS` to a concrete `host:port` resolver endpoint. Its resources may
set `upstreamDNS` too; a resource value wins over the grant value, and either
wins over the gateway's configured resolver. These values are validated while
the capability is parsed and are used only for the matching authorized flow.
`system`, a bare hostname, port zero, and malformed endpoints are rejected
with the whole capability entry, so policy data cannot turn into an arbitrary
outbound connection.

In tsnet egress mode, the gateway accepts advertised tailnet subnet routes.
For each backend DNS lookup other than `system`, `egress.upstream_dns_interface`
defaults to `auto`: it uses the tsnet path only when an active peer
`PrimaryRoutes` prefix contains that resolver IP or the resolver is in a
Tailnet address reported by the control plane; otherwise it uses the host
network. This accommodates Headscale custom IP prefixes. Set it to `tailnet`
or `host` to force the DNS path, including PTR recovery.

Tailnet transport grants must independently let clients reach both the DNS
node on UDP 53 and the synthetic prefix through the appropriate gateway tag.
Configure clients to send protected resource suffixes to the DNS node.
Unauthorized resource queries and ordinary names are forwarded upstream;
authorized AAAA queries receive NODATA so IPv6 cannot bypass the gateway.

Every interchangeable HA egress member must use the same local egress
assignment and have equivalent backend reachability. Never route a segment
prefix to a gateway that reaches a different backend. Advertise the same
synthetic prefix from each egress member so Tailscale can
select an available subnet router. Advertise every DNS replica as a tailnet
resolver; tsnet egress tries each advertised resolver for its PTR lookup. DNS
replicas must share PostgreSQL. If a new protected mapping has no active
discovered route, DNS returns `SERVFAIL` rather than forwarding the name
upstream. Existing leased mappings remain answerable until their lease expires.

Build and run the focused proof suite with:

```text
go test ./...
```
