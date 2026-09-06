package domain

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

type TaggedNode struct {
	Address       string
	Tags          map[string]struct{}
	PrimaryRoutes []netip.Prefix
}

// TaggedNodeSource supplies the current tailnet node inventory. It is kept
// separate from Identity because resolving the special DNS namespace does not
// authorize a client or a gateway.
type TaggedNodeSource interface {
	TaggedNodes(context.Context) ([]TaggedNode, error)
}

// DiscoverGatewayRoutes derives the active synthetic prefixes for every
// tagged gateway cluster from stable Tailnet Status PrimaryRoutes. Duplicate
// routes within one tag are expected in HA; overlap across tags is ambiguous
// and therefore rejected.
func DiscoverGatewayRoutes(nodes []TaggedNode) (map[string][]netip.Prefix, error) {
	routes := map[string][]netip.Prefix{}
	for _, node := range nodes {
		for tag := range node.Tags {
			if !strings.HasPrefix(tag, "tag:") {
				continue
			}
			for _, prefix := range node.PrimaryRoutes {
				if !prefix.IsValid() || !prefix.Addr().Is4() || prefix != prefix.Masked() {
					return nil, fmt.Errorf("invalid active route %q for %s", prefix, tag)
				}
				duplicate := false
				for _, prior := range routes[tag] {
					if prefix == prior {
						duplicate = true
					}
				}
				if !duplicate {
					routes[tag] = append(routes[tag], prefix)
				}
			}
		}
	}
	seen := map[string]string{}
	for tag, prefixes := range routes {
		sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].String() < prefixes[j].String() })
		for _, prefix := range prefixes {
			for key, owner := range seen {
				prior, _ := netip.ParsePrefix(key)
				if owner != tag && prefix.Overlaps(prior) {
					return nil, fmt.Errorf("active route %s overlaps %s for %s", prefix, prior, owner)
				}
			}
			seen[prefix.String()] = tag
		}
	}
	return routes, nil
}

// ResolveTags resolves a tag expression against a fresh tailnet inventory.
// An unavailable inventory is still a handled .tags request: it must not be
// forwarded to an unrelated upstream resolver.
func ResolveTags(ctx context.Context, name string, source TaggedNodeSource) ([]string, bool) {
	nodes, err := source.TaggedNodes(ctx)
	if err != nil {
		_, tagged := TagExpression(name, nil)
		return nil, tagged
	}
	return TagExpression(name, nodes)
}

// TagExpression resolves a.b.tags. (AND), a-or-b.tags. (OR), and a.no-b.tags. (exclusion).
func TagExpression(name string, nodes []TaggedNode) ([]string, bool) {
	parts := strings.Split(strings.TrimSuffix(strings.ToLower(name), "."), ".")
	if len(parts) < 2 || parts[len(parts)-1] != "tags" {
		return nil, false
	}
	var required []string
	var either [][]string
	var excluded []string
	for _, part := range parts[:len(parts)-1] {
		opts := strings.Split(part, "-or-")
		if len(opts) == 0 {
			return nil, false
		}
		pos := make([]string, 0, len(opts))
		for _, tag := range opts {
			if tag == "" {
				return nil, false
			}
			if strings.HasPrefix(tag, "no-") {
				if len(tag) == 3 {
					return nil, false
				}
				excluded = append(excluded, "tag:"+tag[3:])
			} else {
				pos = append(pos, "tag:"+tag)
			}
		}
		if len(pos) == 1 {
			required = append(required, pos[0])
		} else if len(pos) > 1 {
			either = append(either, pos)
		}
	}
	out := make([]string, 0)
	for _, node := range nodes {
		yes := true
		for _, tag := range required {
			if _, ok := node.Tags[tag]; !ok {
				yes = false
			}
		}
		for _, choices := range either {
			any := false
			for _, tag := range choices {
				_, any = node.Tags[tag]
				if any {
					break
				}
			}
			yes = yes && any
		}
		for _, tag := range excluded {
			if _, ok := node.Tags[tag]; ok {
				yes = false
			}
		}
		if yes {
			out = append(out, node.Address)
		}
	}
	return out, true
}
