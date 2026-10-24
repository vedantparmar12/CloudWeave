package analysis

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vedantparmar12/cloudweave/internal/state"
)

func simulationFixture(actions map[string][]string, edges ...[2]string) *analyzer {
	a := &analyzer{g: NewGraph(), plan: &state.Plan{}, primary: &state.State{Name: "s"}, opts: Options{ApplyWindow: time.Hour}}
	for name, seq := range actions {
		action := state.ActionNoop
		if len(seq) > 0 {
			action = seq[0]
		}
		if len(seq) == 2 {
			action = state.ActionReplace
		}
		address := "null_resource." + name
		a.g.AddNode(&Node{ID: NodeID("s", address), State: "s", Address: address, Action: action, Instances: 1, Planned: action == state.ActionCreate})
		a.plan.Changes = append(a.plan.Changes, state.Change{Address: address, Action: action, Actions: seq})
	}
	for _, edge := range edges {
		a.g.AddEdge(Edge{From: NodeID("s", "null_resource."+edge[0]), To: NodeID("s", "null_resource."+edge[1]), Kind: EdgeDependency})
	}
	return a
}

func TestSimulationReplacementPhases(t *testing.T) {
	for _, seq := range [][]string{{"delete", "create"}, {"create", "delete"}} {
		t.Run(strings.Join(seq, "-"), func(t *testing.T) {
			a := simulationFixture(map[string][]string{"a": seq, "b": {"update"}}, [2]string{"b", "a"})
			before, _ := json.Marshal(a.g.SortedNodes())
			result := a.simulate()
			var steps []SimStep
			for _, step := range result.Steps {
				if step.Node == NodeID("s", "null_resource.a") {
					steps = append(steps, step)
				}
			}
			if len(steps) != 2 || steps[0].Action != seq[0] || steps[1].Action != seq[1] || steps[0].Step >= steps[1].Step {
				t.Fatalf("wrong phases: %+v", steps)
			}
			if seq[0] == "delete" && steps[0].After != "absent" {
				t.Fatalf("delete-first state: %+v", steps[0])
			}
			if seq[0] == "create" && (steps[0].After != "old and replacement exist" || steps[1].After != "new object exists") {
				t.Fatalf("replacement was deleted: %+v", steps)
			}
			after, _ := json.Marshal(a.g.SortedNodes())
			if string(before) != string(after) {
				t.Fatal("simulation mutated original graph")
			}
			repeated := a.simulate()
			if !reflect.DeepEqual(result, repeated) {
				t.Fatal("replay is nondeterministic")
			}
		})
	}
}

func TestSimulationDeletesReverseDependencies(t *testing.T) {
	a := simulationFixture(map[string][]string{"a": {"delete"}, "b": {"delete"}}, [2]string{"b", "a"})
	s := a.simulate()
	if len(s.Steps) != 2 || s.Steps[0].Node != NodeID("s", "null_resource.b") || s.Steps[0].Step >= s.Steps[1].Step {
		t.Fatalf("wrong delete order: %+v", s)
	}
	if s.Steps[1].After != "absent" {
		t.Fatal("object not removed in copy")
	}
}

func TestSimulationUnchangedBridgeAndCycle(t *testing.T) {
	a := simulationFixture(map[string][]string{"a": {"create"}, "b": {"no-op"}, "c": {"create"}}, [2]string{"c", "b"}, [2]string{"b", "a"})
	result := a.simulate()
	if len(result.Steps) != 2 || result.Steps[0].Node != NodeID("s", "null_resource.a") || result.Steps[0].Step >= result.Steps[1].Step {
		t.Fatalf("lost unchanged bridge: %+v", result)
	}
	a = simulationFixture(map[string][]string{"a": {"create"}, "b": {"create"}}, [2]string{"b", "a"}, [2]string{"a", "b"})
	result = a.simulate()
	if result.Blocked != 2 {
		t.Fatalf("cycle must block, not invent order: %+v", result)
	}
	for _, step := range result.Steps {
		if step.After != "" {
			t.Fatal("cycle replayed")
		}
	}
}

func TestSimulationAbsentDependencyAndForget(t *testing.T) {
	a := simulationFixture(map[string][]string{"a": {"no-op"}, "b": {"create"}, "c": {"create"}}, [2]string{"b", "a"}, [2]string{"c", "b"})
	a.g.Nodes[NodeID("s", "null_resource.a")].Drift = state.ActionDelete
	result := a.simulate()
	if result.Fails != 1 || result.Blocked != 1 || result.Steps[0].After != "absent" {
		t.Fatalf("failed operation must not create object: %+v", result)
	}
	a = simulationFixture(map[string][]string{"a": {"forget"}, "b": {"create"}}, [2]string{"b", "a"})
	result = a.simulate()
	if result.Fails != 0 || result.Steps[0].After != "unmanaged (object retained)" {
		t.Fatalf("forget destroyed object: %+v", result)
	}
}

func TestSimulationMixedInstancesAndCredentialUncertainty(t *testing.T) {
	a := simulationFixture(map[string][]string{"a": {"delete", "create"}, "b": {"create"}}, [2]string{"b", "a"})
	a.plan.Changes = append(a.plan.Changes, state.Change{Address: "null_resource.a", Action: state.ActionNoop, Actions: []string{"no-op"}})
	result := a.simulate()
	if result.Blocked != 2 {
		t.Fatalf("mixed instance actions must remain unresolved: %+v", result)
	}
	a = simulationFixture(map[string][]string{"a": {"create"}})
	a.noteCredential(time.Minute)
	result = a.simulate()
	if result.Warns != 1 || !strings.Contains(strings.Join(result.Steps[0].Notes, " "), "exact affected steps") {
		t.Fatal("single-step expiry risk lost or timing invented")
	}
	a.plan = nil
	if a.simulate() != nil {
		t.Fatal("state-only input must not invent a plan")
	}
}
