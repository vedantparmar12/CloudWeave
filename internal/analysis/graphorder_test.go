package analysis

import "testing"

func TestDependencyLayersUseLongestChain(t *testing.T) {
	g := NewGraph()
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		g.AddNode(&Node{ID: id, State: "s", Address: "test." + id})
	}
	for _, edge := range [][2]string{{"a", "b"}, {"a", "c"}, {"c", "b"}, {"d", "a"}} {
		g.AddEdge(Edge{From: edge[0], To: edge[1], Kind: EdgeDependency})
	}
	if unordered := g.DependencyLayers(); len(unordered) != 0 {
		t.Fatalf("unexpected unresolved nodes: %v", unordered)
	}
	want := map[string]int{"a": 2, "b": 0, "c": 1, "d": 3, "e": 0}
	for id, layer := range want {
		if n := g.Nodes[id]; n.Layer != layer || n.Unordered {
			t.Errorf("%s layer=%d unordered=%v, want %d false", id, n.Layer, n.Unordered, layer)
		}
	}
}

func TestDependencyLayersIgnoreAdvisoryEdges(t *testing.T) {
	g := NewGraph()
	for _, id := range []string{"consumer", "producer"} {
		g.AddNode(&Node{ID: id, State: "s", Address: "test." + id})
	}
	g.AddEdge(Edge{From: "consumer", To: "producer", Kind: EdgeFederation})
	g.AddEdge(Edge{From: "consumer", To: "producer", Kind: EdgeRemoteState})
	if unordered := g.DependencyLayers(); len(unordered) != 0 {
		t.Fatalf("unexpected unresolved nodes: %v", unordered)
	}
	for _, n := range g.Nodes {
		if n.Layer != 0 {
			t.Errorf("%s layer=%d, advisory edges must not constrain order", n.ID, n.Layer)
		}
	}
}

func TestDependencyLayersExposeCycleAndDependents(t *testing.T) {
	g := NewGraph()
	for _, id := range []string{"x", "y", "z", "w"} {
		g.AddNode(&Node{ID: id, State: "s", Address: "test." + id})
	}
	g.AddEdge(Edge{From: "x", To: "y", Kind: EdgeDependency})
	g.AddEdge(Edge{From: "y", To: "x", Kind: EdgeDependency})
	g.AddEdge(Edge{From: "z", To: "x", Kind: EdgeDependency})

	if unordered := g.DependencyLayers(); len(unordered) != 3 {
		t.Fatalf("unresolved = %v, want x, y and dependent z", unordered)
	}
	for _, id := range []string{"x", "y", "z"} {
		if n := g.Nodes[id]; n.Layer != -1 || !n.Unordered {
			t.Errorf("%s layer=%d unordered=%v, want -1 true", id, n.Layer, n.Unordered)
		}
	}
	if n := g.Nodes["w"]; n.Layer != 0 || n.Unordered {
		t.Errorf("independent node = %+v, want layer 0", n)
	}

	a := &analyzer{g: g}
	a.checkDependencyOrder()
	if len(a.findings) != 1 {
		t.Fatalf("findings = %+v, want one CW505", a.findings)
	}
	f := a.findings[0]
	if f.Rule != "CW505" || f.Severity != SevMedium || len(f.Nodes) != 3 {
		t.Fatalf("finding = %+v", f)
	}
}
