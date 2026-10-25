package analysis

import (
	"fmt"
	"strings"
)

// checkDependencyOrder records nodes that cannot be placed in a layer. This is
// a modeled graph-order warning, not an observed apply failure.
func (a *analyzer) checkDependencyOrder() {
	unordered := a.g.DependencyLayers()
	if len(unordered) == 0 {
		return
	}
	shown := unordered
	if len(shown) > 6 {
		shown = shown[:6]
	}
	names := make([]string, 0, len(shown))
	for _, id := range shown {
		n := a.g.Nodes[id]
		names = append(names, n.State+" · "+n.Address)
	}
	more := ""
	if len(unordered) > len(shown) {
		more = fmt.Sprintf(", and %d more", len(unordered)-len(shown))
	}
	a.add(Finding{
		Rule: "CW505", Severity: SevMedium, Category: CatState,
		Title: "Dependency graph has no complete order",
		Detail: fmt.Sprintf("%d resources cannot be ordered because recorded state dependencies and configuration references form a cycle, or depend on one: %s%s. A state-recorded edge can be stale after a refactor, so refresh the snapshot and plan from the same revision.",
			len(unordered), strings.Join(names, ", "), more),
		Remediation: "Confirm the dependency direction in the current configuration and replan. Do not use the unresolved layer group as an execution order.",
		Nodes:       unordered,
	})
}

// DependencyLayers assigns each node its longest recorded dependency chain.
// Only dependency edges constrain the order; remote-state, identity and
// federation edges stay visible but do not move nodes. Any node left with an
// unresolved predecessor (a cycle, or something depending on one) gets layer
// -1 and is returned in sorted node order.
func (g *Graph) DependencyLayers() []string {
	users := make(map[string][]string, len(g.Nodes))
	pending := make(map[string]int, len(g.Nodes))
	for id := range g.Nodes {
		pending[id] = 0
	}
	seen := make(map[[2]string]bool)
	for _, e := range g.Edges {
		if e.Kind != EdgeDependency || g.Nodes[e.From] == nil || g.Nodes[e.To] == nil {
			continue
		}
		key := [2]string{e.From, e.To}
		if seen[key] {
			continue
		}
		seen[key] = true
		users[e.To] = append(users[e.To], e.From)
		pending[e.From]++
	}

	ordered := g.SortedNodes()
	layer := make(map[string]int, len(ordered))
	queue := make([]string, 0, len(ordered))
	for _, n := range ordered {
		if pending[n.ID] == 0 {
			queue = append(queue, n.ID)
		}
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, dependent := range users[id] {
			if layer[id]+1 > layer[dependent] {
				layer[dependent] = layer[id] + 1
			}
			pending[dependent]--
			if pending[dependent] == 0 {
				queue = append(queue, dependent)
			}
		}
	}

	var unordered []string
	for _, n := range ordered {
		if pending[n.ID] > 0 {
			n.Layer = -1
			n.Unordered = true
			unordered = append(unordered, n.ID)
			continue
		}
		n.Layer = layer[n.ID]
	}
	return unordered
}
