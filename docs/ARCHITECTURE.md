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

CloudWeave does not keep a shadow backend in sync. It analyzes exported snapshots (`terraform state pull`, `terraform show -json`) or reads a snapshot from Terraform's PostgreSQL backend with a read-only SELECT. Pseudo-apply updates only an in-memory presence model; it never updates state or calls Terraform.

## Pipeline

```
 state files ──► state.LoadState   ─┐
 pg backend  ──► state.LoadPGState ─┼─► analysis.Analyze ─► report.Build ─► HTML / JSON / Markdown / terminal
 plan JSON   ──► state.LoadPlan    ─┘
```

1. **Load** (`internal/state`)
   - Raw v4 states and `show -json` states are normalized into one model: resources aggregated across instances, with dependencies, sensitive paths and outputs.
   - Optional `--pg-state name=ENV_VAR` reads raw JSON text from Terraform's PostgreSQL backend using pgx. The DSN comes only from the named environment variable; labels, schema and workspace are validated, and errors never wrap driver messages or include connection strings. Database inputs have no file path.
   - PostgreSQL uses `BEGIN READ ONLY`, `SELECT data FROM <quoted-schema>.states WHERE name=$1`, then rollback, with no writes, DDL, commit or advisory locks. Schema is identifier-quoted; workspace is bound via the extended protocol even if the DSN requests simple protocol. Connection-time `target_session_attrs` checks are rejected because they can issue extra SQL. Ordinary PostgreSQL read locks still apply.
   - Connect/read work has a 15-second deadline; rollback and close each have independent 5-second cleanup deadlines. Schema and workspace flags apply to every PostgreSQL input. Reads are independent snapshots, not an atomic multi-database snapshot. Wire-protocol tests use a loopback fake, not a live database.
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
   9. **Pseudo-apply**: copy resource presence into an in-memory model; build a deterministic operation DAG from recorded plan actions and same-state dependency edges. Preserve replacement phase order, reverse destroy dependencies and retain objects for forget operations. Unchanged resources can connect operations. Cycles, mixed instance actions and deposed objects stay unresolved. Model failures do not transition objects; dependent operations become blocked. Cross-state consumers, federation, IAM propagation and credential expiry are conditional warnings, not observed failures. Other states get follow-up planning reminders only.
   10. Attach static fix templates using placeholders, not values or executable interpolated metadata. Add CW601 for model failures/unresolved operations, sort findings and derive the verdict.
3. **Report** (`internal/report`)
   - A JSON schema (`cloudweave.report/v1`) carries metadata only.
   - The HTML file embeds that JSON in a non-executable script tag and renders it with vanilla JS/SVG.
   - The Markdown writer renders the same report as a PR comment; input text is escaped so names cannot break tables or inject HTML.

### Explaining each change without values

For update and replace actions, `state.LoadPlan` compares `before` and `after` in memory, attribute by attribute, and keeps only the **names** of top-level attributes that differ. It also records attributes with unknown values from `after_unknown`, `replace_paths` (formatted as `network[0].subnet`) and `action_reason`. Values are discarded right away. This is how the report can say "forces replacement: location · known after apply: client_id" while still never containing a value.

Attributes that Terraform marks sensitive (`before_sensitive` / `after_sensitive`) are not named at all. The report only says how many sensitive attributes are touched, so a changed `administrator_login_password` shows up as "1 sensitive attribute (hidden)". If the whole object is sensitive, no attribute names are listed.

## Visualizing huge states

One graph page replaces the previous tabs. With a plan it starts with changed/impacted resources and direct dependencies; without a plan it shows a bounded graph grouped by state. Search covers the full metadata inventory and focuses a neighborhood on the same canvas. The total rendered node count is bounded by `--max-nodes`, with hidden counts shown.

A side panel holds all findings (including global findings), resource explanations, display-only fix templates, and the pseudo-apply timeline. State filters and graph reset keep navigation on one page. The header's state order is advisory, not an execution schedule.

Pan and zoom use a single SVG transform. Hovering traces neighbors; SVG export inlines styles so it renders independently. The implementation remains original vanilla JS/SVG, with no embedded third-party visualizer.

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
