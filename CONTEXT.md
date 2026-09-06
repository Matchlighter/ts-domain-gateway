# Headscale Domain Proxies

Identity-aware synthetic DNS allocation and TCP egress through Tailnet subnet routing.

## Language

**Egress assignment**:
The local declaration that binds one running egress instance to a gateway tag and its synthetic ranges. It is the startup authority for that instance.
_Avoid_: gateway configuration, route configuration

**Gateway cluster**:
All egress instances carrying one gateway tag and able to serve the same synthetic ranges and backend reachability. Any member may receive an authorized flow.
_Avoid_: gateway node, primary gateway

**Active route discovery**:
DNS's view of a gateway cluster's currently control-plane-selected synthetic routes, derived from Tailnet status. It is operational state, not the startup authority.
_Avoid_: route configuration, route ownership
