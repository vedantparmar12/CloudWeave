# CloudWeave architecture

## Goals and non-goals

CloudWeave is an **offline, read-only preflight** that runs between `terraform plan` and `terraform apply`.

Goals:

- Make very large states understandable without rendering 100k nodes.
- Explain *why* an apply may fail even though the plan succeeded.
- Trace impact across separately-managed states, including Azure ↔ GCP identity federation.

Non-goals:

- Writing, locking, migrating or "fixing" state.
- Calling cloud APIs. A future live mode will be opt-in, read-only and separate.
- Replacing policy engines (OPA/Sentinel) or cost tools.

The original idea of a "shadow state" that CloudWeave keeps in sync was dropped. Exported snapshots (`terraform state pull`, `terraform show -json`) give the same isolation, and no code path in CloudWeave touches the backend.

## Pipeline

```
 state files ──► state.LoadState ─┐
                                  ├─► analysis.Analyze ──► report.Build ──► HTML / JSON / terminal
 plan JSON  ──► state.LoadPlan  ──┘
```

1. **Load** (`internal/state`)
   - Raw v4 states and `show -json` states are normalized into one model: resources aggregated across instances, with dependencies, sensitive paths and outputs.
   - Plans are parsed with `hashicorp/terraform-json`, plus `applyable`/`errored`, which that library does not expose.
   - From the plan we take resource changes, drift, the refreshed prior state, configuration references (module-aware) and explicit `terraform_remote_state` output references.
2. **Analyze** (`internal/analysis`)
   1. Name inputs uniquely and pick the *primary* state. Auto-detection hashes instance IDs in each state and in the plan's prior state and picks the best overlap. If nothing matches, the plan's own prior state is used and CW008 is raised.
   2. Build one graph for all states. Node ID = `state::address`. An edge `A → B` means "A depends on B".
   3. Overlay the plan:
      - Actions and drift go onto nodes.
      - Planned creates become new nodes.
      - Configuration references add edges for new resources.
      - Remote-state references connect resources to the data source they read.
   4. **Cross-state linking**:
      - `terraform_remote_state` outputs are matched to producer outputs by canonical JSON value; stale copies raise CW502.
      - The data source is then wired to the producer resource that owns the output value.
      - ID matching uses an owner index of hashed top-level identity attributes.
   5. **Federation analysis**:
      - Index tenants, apps, principals, pools, providers, service accounts, IAM grants and federated identity credentials.
      - Validate the trust chain both ways (Azure → GCP WIF, and GCP → Entra FIC).
      - Add federation edges.
   6. **Change cone**:
      - Seeds are mutations and drift.
      - Downstream is a BFS over dependents, across states.
      - Upstream is the direct dependencies of the seeds.
      - Per-seed impact counts include cross-state counts.
   7. Run plan, drift, blast-radius, state-hygiene and (optionally) credential checks.
   8. **Apply order**: collapse cross-state edges (excluding low-confidence and federation edges, since trust can be wired in either order) into a state graph and order it topologically. Cycles raise CW504.
   9. Sort findings and derive the verdict.
3. **Report** (`internal/report`)
   - A JSON schema (`cloudweave.report/v1`) carries metadata only.
   - The HTML file embeds that JSON in a non-executable script tag and renders it with vanilla JS/SVG.
   - The Markdown writer renders the same report as a PR comment; input text is escaped so names cannot break tables or inject HTML.

### Explaining each change without values

For update and replace actions, `state.LoadPlan` compares `before` and `after` in memory, attribute by attribute, and keeps only the **names** of top-level attributes that differ. It also records attributes with unknown values from `after_unknown`, `replace_paths` (formatted as `network[0].subnet`) and `action_reason`. Values are discarded right away. This is how the report can say "forces replacement: location · known after apply: client_id" while still never containing a value.

Attributes that Terraform marks sensitive (`before_sensitive` / `after_sensitive`) are not named at all. The report only says how many sensitive attributes are touched, so a changed `administrator_login_password` shows up as "1 sensitive attribute (hidden)". If the whole object is sensitive, no attribute names are listed.

## Visualizing huge states

A full-graph render of an 80k-line state is useless. The report never draws everything:

- **State map**: one box per state, with aggregated cross-state edges.
- **Plan changes**: only changed and drifted resources, in a state → module tree (module paths split with the bracket-aware parser), each with its reason.
- **Change cone**: only the plan's seeds and their impact, layered by distance, with depth and state filters.
- **Explore**: radius-limited neighborhood of one resource, with dependencies left and dependents right.
- **Inventory**: lazily expanded tree (state → module → type → resource).

Each column is capped (`--max-nodes`) with "+N more". A synthetic 612k-line (15 MB) state analyzes in about 3 seconds and yields a ~130 KB report.

Graph views pan and zoom with a single SVG transform rather than re-layout, so moving around stays cheap. Hovering a node fades everything except its direct neighbours. SVG export clones the current graph, removes the view transform and inlines the few styles it needs, so the file renders on its own.

### Design borrowed from existing tools

Two shipped visualizers were reverse engineered with REA to choose these interactions:

- [Rover](https://github.com/im2nguyen/rover) v0.3.3, a Go binary with an embedded Vue + Cytoscape UI, contributed the neighbourhood fade on focus and SVG export.
- Terraform Visual 0.2.1, a Next.js app using AntV G6, contributed the collapsible module tree of plan changes.

Neither tool links multiple states.

## Edge cases handled

| Case | Handling |
|---|---|
| Addresses with dots/brackets in keys (`module.a["x.y"]`), modules named `data`, nested module instances | Bracket- and quote-aware address parser; module instance keys are kept and resource instance keys are stripped. |
| `sensitive_attributes` as cty step objects, scalar paths or boolean trees | All three are parsed; sensitive paths never feed identity matching. |
| A plan file passed as `--state` (or the reverse); state format < 4 | Rejected with a clear message. |
| Two snapshots of the same state | Same lineage → no cross-links, CW011. |
| Short or generic values (`"rg"`, `"default"`, regions) | Excluded from ID matching; only strong identifiers count (resource paths, UUIDs, emails, long numeric IDs). Values with more than 3 foreign owners are treated as ambiguous and skipped. |
| Data sources that read a resource managed elsewhere | Not treated as owners, so they never cause duplicate-ownership false positives. |
| Drift-deleted resources | Excluded from plan/state mismatch detection; raised as CW102 instead. |
| Resource moved between states without `removed {}` | `delete_because_no_resource_config` → CW206 (the old state would destroy it). |
| Identity replacement breaking federation in another state | Federation edges (grant subject → managed identity, FIC subject → service account unique_id) put the other state in the cone → CW201 + CW312. |
| Tokens expiring during a long apply | `--apply-window` vs JWT `exp` → CW402. |
| New IAM grants used in the same apply | CW313 (eventual consistency). |
| Saved plan applied later | CW003 plus CW004 (prior state differs from current state). |
| Output path collides with an input | Refused, including `*.tfstate*` names and hard links (`os.SameFile`). |
| HTML injection through resource names | JSON is HTML-escaped and the DOM is built with `textContent` only, under a CSP that forbids external loads. |

## Known gaps / roadmap

1. **Opt-in live preflight**: read-only Azure/GCP API calls to confirm existence and enabled state of pools, providers, identities and FICs, and to dry-run STS token exchange with the current credentials.
2. More federation shapes: AWS IAM OIDC providers, GitHub/GitLab OIDC subjects and Kubernetes service-account issuers.
3. Provider-aware ID semantics, e.g. which attribute of each resource type is the reference identity, to raise ID-match confidence.
4. `moved` / `import` blocks in the change cone.
5. Report diffing between two runs ("what changed since yesterday's plan").
6. A Terraform Cloud / OpenTofu run-task wrapper.
