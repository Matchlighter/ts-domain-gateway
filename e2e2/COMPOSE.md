# Compose E2E v2

Run `python3 e2e2/test.py`. The coordinator starts one disposable Headscale,
DNS, gateway, and deterministic upstream stack, installs the policy through
Headscale's database policy API, then runs fresh tagged client containers in a
fixed order. It removes containers, networks, and volumes on exit.

The authorized client verifies synthetic and ordinary DNS, PTR, HTTP, HTTPS,
and the expected-red UDP path. Fresh denied and gateway-tagged clients then
verify that the protected name resolves to its ordinary upstream address even
after the synthetic allocation exists.
