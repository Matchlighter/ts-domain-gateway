# Headscale Domain Proxies

`domain-gateway` (`dgw`) provides identity-aware DNS and TCP egress for domain
resources authorized by Headscale/Tailscale application capabilities.

It's is conceptually similar to Tailscale's "App Connectors" but operates with one major difference: App Connectors are largely IP-based - if two services share an IP, Tailscale can't distinguish them. `dgw` defers the IP-resolution so that aliased domains (eg served by your reverse proxy) can be treated and routed differently. `dgw` also lets you enforce policy on the domain - not just the IP.

## Configuration
They guys at Tailscale are _smart_ - they made a policy engine that is extensible, fairly easy to use, and (importantly) fast to query. They made this level of simple/direct integration straightforward.

### Policy
```jsonc
{
    "grants": [
        {
            // Sources/Users permitted to request the protected domains
            "src": [
                "group:whatever"
            ],
            // Both DNS and egress need to see/receive the application grant
            "dst": [
                "tag:dgw-egress-1",
                "tag:dgw-dns"
            ],
            "app": {
                "matchlighter.net/domain-gateway": [
                    {
                        // Specify a range of Synthetic-IPs to which lookups should be mapped.
                        // Must exactly match the subnet advertised by the egress instance's `egress.ranges`.
                        "range": ["10.254.0.0/18"],

                        // Optional resolver for every resource in this grant. It must be
                        // a concrete host[:port] endpoint (port defaults to 53), or "system".
                        "upstreamDNS": "9.9.9.9:53",

                        // Any and all requests to matched _domains_ (regardless of port) will be mapped to a Synthetic-IP in `range`.
                        // Think of it a equivalent to { src: ["group:whatever"], dst: [lookup(<domain>)], ip: [...] }
                        "resources": [
                            "example.net:443,80", // Shorthand
                            {
                                // Exact FQDN (or a one-label wildcard such as *.example.com).
                                "domain": "example.com",
                            },
                            {
                                "domain": "example.org",
                                // A resource resolver wins over the grant resolver above.
                                "upstreamDNS": "192.0.2.54:53",
                                // Omit ip for all ports; otherwise use tcp:N - UDP is not yet supported
                                "ip": [
                                    "tcp:443",
                                ]
                            }
                        ]
                    }
                ]
            }
        },
        {
            // Make sure your users (and the Egress) can perform DNS queries against
            "src": [
                "group:whatever",
                "tag:dgw-egress"
            ],
            "dst": [ "tag:dgw-dns" ],
            "ip": [ "udp:53" ]
        },
        {
            // Make sure your users can communicate with the configured Synthetic IPs
            "src": [
                "group:whatever"
            ],
            "dst": [ "10.254.0.0/18" ],
            // You can do a granular policy here as well, but the Egress will also enforce based on the domain-gateway policies
            "ip": [ "*" ],
            "via": "tag:dgw-egress-1"
        }
    ],
    "nodeAttrs": [{
            "target": [
                "tag:dgw-dns",
                "tag:dgw-egress",
            ],
            "app": {
                "matchlighter.net/domain-gateway": [{
                    // Set the default/fallback upsteam DNS server
                    // "system" (the default) chooses a non-Tailscale /etc/resolv.conf resolver.
                    // You _can_ change the `target` above to selectively apply this setting
                    "upstreamDNS": "system",
                }]
            }
        },
    ]
}

```

### Daemon

```jsonc
{
  // Optional explicit bind address for DNS. Empty binds UDP 53 on the chosen
  // Tailscale address, which is the usual and safest setting.
  // "dns_listen": "",

  // Local listener for tailscaled egress transparent interception.
  // "gateway_listen": "0.0.0.0:15001",

  // Unix LocalAPI socket used only with -mode tailscaled.
  // "tailscaled_socket": "/var/run/tailscale/tailscaled.sock",

  // DNS allocation storage. SQLite and PostgreSQL use the same schema;
  // it is created automatically. SQLite is one authority only; DNS HA needs
  // a PostgreSQL URL shared by every DNS replica.
  // "database": "postgres://domain_gateway:secret@db.example:5432/domain_gateway?sslmode=require",
  "database": "sqlite://./dgw.db",

  // Optional egress fallback resolver (host[:port]; port defaults to 53). A gateway-visible NodeAttr upstreamDNS
  // wins. "system" uses the host's non-Tailscale resolver.
  "upstream_resolver": "system", // Defaults "system" on DNS, or to Tailscale's configured DNS on Egress

  // Backend resolver transport in tsnet mode: auto uses tailnet only when
  // an active peer subnet route contains the resolver IP; otherwise
  // it uses the host network. Set tailnet or host to force that path.
  "upstream_resolver_interface": "auto",

  // Required only by the egress role. This local assignment drives flow
  // enforcement and tsnet route advertisement. In tailscaled mode, advertise
  // the same ranges with tailscaled and redirect their TCP traffic above.
  "egress": {
    "ranges": ["10.254.0.0/18"],

    // Optional IP address (optionally with port) of the internal DNS authority
    // for synthetic-address PTR recovery. An omitted port defaults to 53; backend DNS follows capability, NodeAttr,
    // and upstream_resolver precedence below.
    "ptr_resolver": "192.0.2.53",

    // Backend resolver transport in tsnet mode: auto uses tailnet only when
    // an active peer subnet route contains the resolver IP; otherwise
    // it uses the host network. Set tailnet or host to force that path.
    "ptr_resolver_interface": "auto"
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
    "tags": ["tag:..."]
  },
}
```

## Running

Domain-Gateway is composed of two services: DNS and Gateway/Egress.

### DNS
DNS (obviously) handles DNS queries and handles mapping of domains to "Synthetic IPs" and vice-versa. DNS is stateful, requiring a SQLite or Postgres DB. It should be capable of HA if a Postgres DB is provided.

```shell
domain-gateway dns -config ./dns.json
```

### Egress
Egress receives traffic destined for a Synthetic IP, consults DNS to map it back to a domain, resolves the real IP, and forwards the connection. It is stateless (aside from the actual connections running through it) and should be HA-capable as well.

```shell
domain-gateway egress -config ./gw.json
```

### Tailscale Modes
Both services were designed to be uses with an embedded Tailscale implementation - not a separate `tailscaled` install. However, they are keyed to detect an existing Tailscaled scoket and use that instead of using the embedded `tsnet`. You can also explicitly state which mode to use.

`-mode tsnet` runs an embedded userspace Tailscale node. It requires `tsnet.dir` and ordinarily a tagged pre-auth key on first enrollment.
`-mode tailscaled` uses only the configured local tailscaled LocalAPI and host network stack. It never starts tsnet. Conversely, tsnet mode never falls back to tailscaled. Invalid mode values fail at startup. More details below.

For tailscaled _egress_ on Linux, advertise the synthetic prefix with
tailscaled, then redirect only TCP traffic for that prefix to the listener:

```text
iptables -t nat -A PREROUTING -d 10.254.0.0/18 -p tcp -j REDIRECT --to-ports 15001
```

Set `gateway_listen` to `0.0.0.0:15001`. The process uses
`SO_ORIGINAL_DST`, so authorization sees the client-visible synthetic address
and port, never its local redirect address. In tsnet egress mode the subnet
router advertises its local egress-assignment prefixes and receives the original destination
in its userspace fallback handler instead.

## Development

### Local Docker E2E

Run the complete live suite against a disposable Docker Headscale built from
[Headscale PR #3121](https://github.com/juanfont/headscale/pull/3121):

```text
python3 e2e2/test.py
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
