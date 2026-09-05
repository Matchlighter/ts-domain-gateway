# LocalAPI application-capability contract

This service requires Headscale release **v0.26.0 or later** (the release that
added policy `grants[].app` support) and a current supported `tailscaled`
release able to receive that netmap. In production, pin Headscale and
tailscaled to a tested release pair and run the contract fixture below during
upgrades; this project does not silently reinterpret a changed LocalAPI shape.

For each DNS request or new gateway flow, it calls the local Unix-socket API:

```text
GET /localapi/v0/whois?addr=<source-tailnet-IP>
```

DNS uses that request. Gateway flows add `dst_ip=<synthetic-IP>`, so current
tailscaled releases return destination-scoped peer capabilities when available.
The expected JSON object contains `CapMap`, whose value for
`matchlighter.net/cap/domain-gateway` is an array of arbitrary JSON values.
The service preserves the outer payload until the application schema parser
validates it. A payload must be exactly:

```json
{"gateway":"tag:home","resources":[{"domain":"example.com","ports":["tcp:443"]}]}
```

`CapMap` entries from all applicable grants are an additive union. A missing,
unavailable, non-object, malformed, or unknown-gateway payload grants no
access. LocalAPI is called for every decision: policy changes therefore take
effect on the next DNS request/connection. An outage fails closed for new
synthesis and flows; this V1 deliberately has no authorization cache that can
extend a revoked grant.

The Go runtime does not cache authorization capabilities: every DNS decision
and every new gateway flow obtains the source's current compiled CapMap from
its local tailscaled. Allocation state is cached separately and authoritatively
by DNS through PTR records; gateways never treat an allocation record as an
authorization grant.

The unit suite exercises raw JSON payload decoding, additive capability
entries, malformed/unknown rejection, source-specific gateway reauthorization,
and the exact/wildcard matcher. Before deploying, verify the target versions
against a real `tailscaled` by comparing its WhoIs response to this contract.
