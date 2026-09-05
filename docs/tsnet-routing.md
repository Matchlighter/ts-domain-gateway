# tsnet routing feasibility

## Conclusion

`tsnet` can receive a TCP flow whose destination is an approved advertised
subnet address rather than one of the embedded node's own Tailscale addresses.
That makes a fully userspace, passive synthetic-IP gateway feasible. The
earlier conclusion that a kernel REDIRECT/TPROXY path was required was
incorrect.

## What the implementation supports

`tsnet.Server` uses a fake/userspace TUN by default. In that mode it enables
both `ProcessLocalIPs` and `ProcessSubnets` on its netstack
([source](https://github.com/tailscale/tailscale/blob/5201273aec737d6372ab7423c31c04ca3ca2a0c2/tsnet/tsnet.go#L907-L925)).
`ProcessSubnets` is explicitly defined as handling inbound traffic for
non-local destinations, i.e. operating as a subnet router
([source](https://github.com/tailscale/tailscale/blob/5201273aec737d6372ab7423c31c04ca3ca2a0c2/wgengine/netstack/netstack.go#L199-L208)).

A convenience listener such as `Listen("tcp", ":443")` only matches the
node's own IPv4/IPv6 addresses. For a routed synthetic destination, either:

1. listen on that exact address, for example `Listen("tcp", "100.0.1.1:443")`; or
2. register `Server.RegisterFallbackTCPHandler`.

This distinction and both mechanisms are part of tsnet's source documentation
([listener matching](https://github.com/tailscale/tailscale/blob/5201273aec737d6372ab7423c31c04ca3ca2a0c2/tsnet/tsnet.go#L1304-L1311),
[fallback API](https://github.com/tailscale/tailscale/blob/5201273aec737d6372ab7423c31c04ca3ca2a0c2/tsnet/tsnet.go#L1434-L1450)).
The fallback callback receives the true `src` and `dst` `netip.AddrPort`
values before accepting the connection
([implementation](https://github.com/tailscale/tailscale/blob/5201273aec737d6372ab7423c31c04ca3ca2a0c2/tsnet/tsnet.go#L1280-L1302)).
It therefore replaces `SO_ORIGINAL_DST`: the gateway has the synthetic
destination and port directly, with no DNAT or host firewall rules.

The underlying netstack dynamically adds an inbound non-local destination as
a subnet address before handing the flow to its TCP forwarder
([source](https://github.com/tailscale/tailscale/blob/5201273aec737d6372ab7423c31c04ca3ca2a0c2/wgengine/netstack/netstack.go#L515-L613)).
The response path can consequently retain the synthetic source address without
kernel NAT.

## Recommended gateway shape

```text
client -- TCP synthetic-ip:port --> tsnet gateway
                                      |
                                      +-- fallback(src, dst)
                                            1. PTR(dst.IP) via tailnet DNS
                                            2. authorize src/domain/protocol/port
                                            3. resolve the real backend via NodeAttr resolver
                                            4. tsnet or system dial to real backend
                                            5. relay bytes
```

The gateway advertises the synthetic prefix through its LocalAPI preferences,
then the control plane must approve the route. The preference model records
advertised routes in `Prefs.AdvertiseRoutes` and exposes route advertisement to
the control plane through host information
([preference update](https://github.com/tailscale/tailscale/blob/5201273aec737d6372ab7423c31c04ca3ca2a0c2/ipn/ipnlocal/local.go#L8521-L8557),
[host information](https://github.com/tailscale/tailscale/blob/5201273aec737d6372ab7423c31c04ca3ca2a0c2/ipn/ipnlocal/local.go#L6648-L6652)).
For an embedded node, obtain `Server.LocalClient()` and call `EditPrefs` with
`ipn.MaskedPrefs{AdvertiseRoutesSet: true, ...}`; tsnet itself exposes that
in-process LocalAPI client
([source](https://github.com/tailscale/tailscale/blob/5201273aec737d6372ab7423c31c04ca3ca2a0c2/tsnet/tsnet.go#L436-L444)).

## Boundary and tradeoff

This answers the passive-client requirement: a client still connects only to
the synthetic address and requested port. No gateway address, proxy port,
`SO_ORIGINAL_DST`, `iptables`, or `nftables` is client-visible or required.

This is a gVisor userspace netstack, not kernel forwarding. It is the cleanest
architecture for the gateway's per-flow authorization and dynamic synthetic
mapping, but throughput and CPU use must be benchmarked with representative
connection concurrency and payload sizes before presenting it as equivalent to
a kernel dataplane. UDP has a separate `GetUDPHandlerForFlow` path, so this
conclusion proves the proposed TCP gateway only.
