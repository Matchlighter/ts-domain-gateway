# Headscale Domain Proxies

An identity-aware DNS overlay and TCP gateway for domain resources carried by
Headscale/Tailscale application capabilities. DNS returns stable synthetic IPv4
addresses only to authorized tailnet sources. The gateway reauthorizes every
new flow and resolves the real backend only through its segment resolver.

Create `config.json`:

```json
{
  "state_db": "/var/lib/domain-gateway/state.db",
  "tailscaled_socket": "/var/run/tailscale/tailscaled.sock",
  "gateway_listen": "0.0.0.0:15001",
  "tsnet_dir": "/var/lib/domain-gateway/tsnet",
  "tsnet_hostname": "domain-dns",
  "tsnet_tags": ["tag:dns"]
}
```

`tsnet_auth_key` is also accepted for first enrollment; persisted tsnet state
means it should not be needed on later starts. Build with `go build
./cmd/domain-gateway`, then run `./domain-gateway -mode dns -config
config.json` on the DNS node. It joins the tailnet as `tag:dns` and listens on
its own Tailscale IPv4 address at UDP 53, so use that node as the tailnet DNS
server. DNS is the sole allocation authority; gateway members use its PTR
records rather than sharing allocation state.

Run `./domain-gateway -mode gateway -config config.json` on each
interchangeable gateway member. `--space=kernel` uses the local tailscaled
socket and Linux transparent interception. `--space=user` starts a tagged
tsnet subnet router, advertises its NodeAttr-derived synthetic prefixes, and
receives the original synthetic destination directly in its fallback handler.
The default `--space=auto` selects kernel only when the configured local
tailscaled LocalAPI is usable; otherwise it selects userspace. A user-mode
gateway needs its own `tsnet_dir`, hostname, and gateway tag in `tsnet_tags`.
Never route a segment prefix to a gateway with different backend reachability.

Headscale transport grants must separately allow clients to reach the fixed
synthetic prefix via the matching tag. App capabilities are the authoritative
domain authorization. Configure clients to send resource suffixes to this DNS
server. Unauthorized and non-resource names relay upstream; authorized AAAA
queries receive NODATA, preventing a real IPv6 bypass.

Configure upstream resolution and every gateway segment in Headscale NodeAttrs,
not daemon config:

```jsonc
{
  "nodeAttrs": [
    { "target": ["tag:dns"], "app": { "matchlighter.net/cap/domain-gateway-config": [{ "upstreamDNS": "system", "gateways": [{ "tag": "tag:gateway1", "prefix": "10.254.0.0/18" }] }] } },
    { "target": ["tag:gateway1"], "app": { "matchlighter.net/cap/domain-gateway-config": [{ "upstreamDNS": "10.0.0.53:53", "gateways": [{ "tag": "tag:gateway1", "prefix": "10.254.0.0/18" }] }] } }
  ]
}
```

Each daemon reads its own setting from its self `CapMap` (the tsnet LocalClient
for embedded nodes, or the host LocalAPI in kernel mode). There is deliberately
no local `gateways` map: the NodeAttr object is the only source of tag/prefix
mapping. The DNS node uses its resolver for ordinary forwarded lookups, while a
gateway uses its own setting for real backend DNS. `system` selects the first non-Tailscale
nameserver in `/etc/resolv.conf`; `100.100.100.100` is ignored to avoid loops.
This is the object-valued Tailscale NodeAttr form. It requires a policy
compiler/control plane that preserves the `app` payload in NodeCapMap; use
Headscale PR #3121 until that capability ships in a release.

Run the proof suite with `go test ./...`.

`tagged_nodes` can optionally publish tag-expression DNS: `a.b.tags.` requires
both tags, `a-or-b.tags.` accepts either tag, and `a.no-b.tags.` excludes a
tag. Each entry is `{ "address": "100.64.0.4", "tags": ["tag:a"] }`.

Each HA gateway member receives the same validated NodeAttr gateway-prefix
configuration; only interchangeable members may advertise a shared synthetic
prefix.

On Linux gateways, advertise the configured synthetic prefix with tailscaled,
then redirect only TCP packets addressed to it to the local listener (use an
unprivileged port such as `15001`):

```text
iptables -t nat -A PREROUTING -d 10.254.0.0/18 -p tcp -j REDIRECT --to-ports 15001
```

Set `gateway_listen` to `0.0.0.0:15001`. The gateway uses Linux
`SO_ORIGINAL_DST` to recover the synthetic destination and original port; it
does not authorize a connection based on the redirected listener address.

DNS persists allocations locally and serves each allocated synthetic IPv4
address as a PTR record with TTL 60. Tailscale advertises this DNS server to
gateways, so they recover the FQDN with ordinary PTR resolution and never read
`state_db`; that file belongs only to DNS. The gateway derives its tag from the
synthetic prefix and rechecks local tailscaled capability data.
