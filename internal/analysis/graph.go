package analysis

import (
	"sort"

	"github.com/vedantparmar12/cloudweave/internal/state"
)

const (
	EdgeDependency  = "dependency"   // recorded by Terraform or configuration
	EdgeRemoteState = "remote-state" // terraform_remote_state output consumption
	EdgeIDMatch     = "id-match"     // attribute value equals another state's resource ID
	EdgeFederation  = "federation"   // STS / workload identity federation trust
)

const (
	ConfHigh   = "high"
	ConfMedium = "medium"
	ConfLow    = "low"
)

const (
	RoleSeed       = "changed"
	RoleDownstream = "impacted"
	RoleUpstream   = "dependency"
)

// Node is a resource (or output) in one state. It carries metadata only,
// never attribute values.
type Node struct {
	ID        string      `json:"id"`
	State     string      `json:"state"`
	Address   string      `json:"address"`
	Module    string      `json:"module,omitempty"`
	Mode      string      `json:"mode"`
	Type      string      `json:"type"`
	Provider  string      `json:"provider,omitempty"`
	Cloud     state.Cloud `json:"cloud"`
	Instances int         `json:"instances"`
	Action    string      `json:"action,omitempty"`
	Drift     string      `json:"drift,omitempty"`
	Tainted   bool        `json:"tainted,omitempty"`
	Deposed   bool        `json:"deposed,omitempty"`
	Planned   bool        `json:"planned,omitempty"` // exists only in the plan
	Role      string      `json:"role,omitempty"`
	Distance  int         `json:"distance,omitempty"`
	Impact    int         `json:"impact,omitempty"`
	CrossImp  int         `json:"cross_impact,omitempty"`
	// Why the plan touches this resource: attribute names and reasons only.
	ChangedAttrs   []string `json:"changed_attrs,omitempty"`
	UnknownAttrs   []string `json:"unknown_attrs,omitempty"`
	ReplacePaths   []string `json:"replace_paths,omitempty"`
	SensitiveAttrs int      `json:"sensitive_attrs,omitempty"`
	Reasons        []string `json:"reasons,omitempty"`
	Importing      bool     `json:"importing,omitempty"`
}

// Edge means From depends on To.
type Edge struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Kind       string `json:"kind"`
	Confidence string `json:"confidence,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
}

type Graph struct {
	Nodes map[string]*Node
	Edges []Edge

	edgeIdx    map[[3]string]int
	deps       map[string][]int // node -> edges where node is From
	dependents map[string][]int // node -> edges where node is To
	byStripped map[string][]string
}

func NewGraph() *Graph {
	return &Graph{
		Nodes:      map[string]*Node{},
		edgeIdx:    map[[3]string]int{},
		deps:       map[string][]int{},
		dependents: map[string][]int{},
		byStripped: map[string][]string{},
	}
}

func NodeID(stateName, addr string) string { return stateName + "::" + addr }

func (g *Graph) AddNode(n *Node) *Node {
	if existing, ok := g.Nodes[n.ID]; ok {
		return existing
	}
	g.Nodes[n.ID] = n
	key := n.State + "::" + state.StripAllKeys(n.Address)
	g.byStripped[key] = append(g.byStripped[key], n.ID)
	return n
}

// AddEdge adds or upgrades an edge. Self edges are ignored.
func (g *Graph) AddEdge(e Edge) {
	if e.From == e.To || g.Nodes[e.From] == nil || g.Nodes[e.To] == nil {
		return
	}
	key := [3]string{e.From, e.To, e.Kind}
	if i, ok := g.edgeIdx[key]; ok {
		if confRank(e.Confidence) > confRank(g.Edges[i].Confidence) {
			g.Edges[i].Confidence = e.Confidence
			g.Edges[i].Evidence = e.Evidence
		}
		return
	}
	g.Edges = append(g.Edges, e)
	i := len(g.Edges) - 1
	g.edgeIdx[key] = i
	g.deps[e.From] = append(g.deps[e.From], i)
	g.dependents[e.To] = append(g.dependents[e.To], i)
}

// Lookup resolves a configuration address (without instance keys) in a state.
func (g *Graph) Lookup(stateName, addr string) []string {
	return g.byStripped[stateName+"::"+state.StripAllKeys(addr)]
}

// Resolve prefers an exact address match and falls back to Lookup.
func (g *Graph) Resolve(stateName, addr string) []string {
	if id := NodeID(stateName, addr); g.Nodes[id] != nil {
		return []string{id}
	}
	return g.Lookup(stateName, addr)
}

func (g *Graph) Dependencies(id string) []Edge {
	out := make([]Edge, 0, len(g.deps[id]))
	for _, i := range g.deps[id] {
		out = append(out, g.Edges[i])
	}
	return out
}

func (g *Graph) Dependents(id string) []Edge {
	out := make([]Edge, 0, len(g.dependents[id]))
	for _, i := range g.dependents[id] {
		out = append(out, g.Edges[i])
	}
	return out
}

// Downstream returns every node that transitively depends on any seed, with
// its distance from the nearest seed. Seeds themselves are excluded.
func (g *Graph) Downstream(seeds []string) map[string]int {
	return g.bfs(seeds, func(id string) []string {
		var next []string
		for _, i := range g.dependents[id] {
			next = append(next, g.Edges[i].From)
		}
		return next
	})
}

// Upstream returns transitive dependencies of the seeds up to maxDepth.
func (g *Graph) Upstream(seeds []string, maxDepth int) map[string]int {
	dist := g.bfs(seeds, func(id string) []string {
		var next []string
		for _, i := range g.deps[id] {
			next = append(next, g.Edges[i].To)
		}
		return next
	})
	for id, d := range dist {
		if d > maxDepth {
			delete(dist, id)
		}
	}
	return dist
}

func (g *Graph) bfs(seeds []string, next func(string) []string) map[string]int {
	dist := map[string]int{}
	isSeed := map[string]bool{}
	queue := make([]string, 0, len(seeds))
	for _, s := range seeds {
		if g.Nodes[s] == nil || isSeed[s] {
			continue
		}
		isSeed[s] = true
		queue = append(queue, s)
	}
	depth := map[string]int{}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, n := range next(cur) {
			if isSeed[n] {
				continue
			}
			if _, seen := dist[n]; seen {
				continue
			}
			dist[n] = depth[cur] + 1
			depth[n] = depth[cur] + 1
			queue = append(queue, n)
		}
	}
	return dist
}

// SortedNodes returns nodes ordered by state then address.
func (g *Graph) SortedNodes() []*Node {
	out := make([]*Node, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].State != out[j].State {
			return out[i].State < out[j].State
		}
		return out[i].Address < out[j].Address
	})
	return out
}

func confRank(c string) int {
	switch c {
	case ConfHigh, "":
		return 3
	case ConfMedium:
		return 2
	case ConfLow:
		return 1
	}
	return 0
}

// buildStateGraph adds nodes and Terraform-recorded dependency edges for a state.
func buildStateGraph(g *Graph, st *state.State) {
	for _, r := range st.Resources {
		n := &Node{
			ID:        NodeID(st.Name, r.Address),
			State:     st.Name,
			Address:   r.Address,
			Module:    r.Module,
			Mode:      r.Mode,
			Type:      r.Type,
			Provider:  r.ProviderShort(),
			Cloud:     r.Cloud,
			Instances: len(r.Instances),
			Tainted:   r.Tainted,
		}
		for _, inst := range r.Instances {
			if inst.Deposed != "" {
				n.Deposed = true
			}
		}
		g.AddNode(n)
	}
	for _, r := range st.Resources {
		from := NodeID(st.Name, r.Address)
		for _, dep := range r.Dependencies {
			for _, to := range g.Resolve(st.Name, dep) {
				g.AddEdge(Edge{From: from, To: to, Kind: EdgeDependency})
			}
		}
	}
}
