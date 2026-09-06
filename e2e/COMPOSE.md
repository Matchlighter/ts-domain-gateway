# Compose E2E

Run `./e2e/run-compose.sh`. It builds a disposable Headscale from the
capability-supporting PR, starts the DNS authority, egress gateway, deterministic
DNS/HTTP/HTTPS upstream, and three Tailscale clients, then removes containers
and volumes on exit. It uses Tailscale userspace networking through SOCKS5, so
Docker with Compose is the only host requirement.

The suite uses `protected.example.test`, served only by the in-stack upstream;
it never queries an Internet site. It checks synthesized and ordinary DNS,
authorization-specific passthrough after a mapping already exists, PTR, TCP,
HTTPS, a gateway-tagged DNS source, and automatic route discovery. UDP is an
explicit expected-red probe because the gateway currently only proxies TCP.
