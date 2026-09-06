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
`tsnet_dir` and ordinarily a tagged pre-auth key on first enrollment.
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
router advertises the NodeAttr prefixes and receives the original destination
in its userspace fallback handler instead.

## Daemon configuration

Put long-lived settings in `config.json`; every field can be overridden on the
command line using the matching hyphenated flag. `database` is always a
database URL: use `sqlite://file/path` for a relative SQLite file,
`sqlite:///absolute/path` for an absolute SQLite file, or `postgres://...` for
PostgreSQL. `tsnet_dir` is `-tsnet-dir`.

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

  // Persistent tsnet state and identity. Required with -mode tsnet.
  "tsnet_dir": "/var/lib/domain-gateway/tsnet",
  "tsnet_hostname": "domain-dns",

  // First-enrollment key. Prefer TS_AUTHKEY in the service environment rather
  // than committing a key here; it is unnecessary after tsnet state exists.
  "tsnet_auth_key": "",

  // Tags requested only when no auth key is supplied. A tagged auth key owns
  // tag assignment, so client-side tags are intentionally suppressed then.
  "tsnet_tags": ["tag:dns"],

  // Optional static data for the special *.tags DNS namespace, not gateway
  // authorization. Each address is a Tailscale node and tags are its labels.
  "tagged_nodes": [{"address": "100.64.0.4", "tags": ["tag:ops"]}]
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

The database is DNS-only storage. The allocation table has unique
gateway/domain and synthetic-IP keys. PostgreSQL is a shared allocation
registry: multiple DNS replicas can use it concurrently, converge on one
mapping, and answer PTR records allocated by another replica. SQLite is
limited to a single DNS authority and is not an HA deployment.

## Headscale policy and routing

Configure upstream resolution and every gateway segment in the NodeAttr
application payload shown in [sample.jsonc](sample.jsonc), not in daemon
configuration. Each daemon reads its own typed setting from its self CapMap:
the tsnet LocalClient in tsnet mode, or local tailscaled LocalAPI in tailscaled
mode. There is deliberately no local gateway map.

The DNS node uses its configured resolver for ordinary forwarded names. An
egress node uses its own setting to resolve the real backend. `system` selects
the first non-Tailscale resolver in `/etc/resolv.conf`; `100.100.100.100` is
ignored to avoid a DNS loop. The policy compiler/control plane must preserve
the object-valued `app` payload in NodeCapMap.

Tailnet transport grants must independently let clients reach both the DNS
node on UDP 53 and the synthetic prefix through the appropriate gateway tag.
Configure clients to send protected resource suffixes to the DNS node.
Unauthorized resource queries and ordinary names are forwarded upstream;
authorized AAAA queries receive NODATA so IPv6 cannot bypass the gateway.

Every interchangeable HA egress member must receive the same validated
NodeAttr prefix configuration and must have equivalent backend reachability.
Never route a segment prefix to a gateway that reaches a different backend.
Advertise the same synthetic prefix from each egress member so Tailscale can
select an available subnet router. Advertise every DNS replica as a tailnet
resolver; tsnet egress tries each advertised resolver for its PTR lookup. DNS
replicas must share PostgreSQL and identical gateway NodeAttrs.

Build and run the focused proof suite with:

```text
go test ./...
```
