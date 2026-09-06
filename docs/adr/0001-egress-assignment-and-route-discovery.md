# Egress assignment and active route discovery

Each egress instance has an explicit local egress assignment of gateway tag and synthetic ranges, which is its startup authority and drives tsnet route advertisement and flow enforcement. DNS normally discovers active `PrimaryRoutes` for the tagged gateway cluster from stable Tailnet status; an optional NodeAttr gateway declaration is an administrative override and emits a warning when it disagrees with discovery. This separates egress bootstrap from DNS topology observation, preserves HA through a shared gateway tag, and avoids unsupported LocalAPI debug surfaces.

## Consequences

New protected mappings return `SERVFAIL` when DNS has no usable discovered route; existing mappings remain valid through their lease. Tailscaled deployments still require tailscaled route advertisement and host redirection for the assigned synthetic ranges.
