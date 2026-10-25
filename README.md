# CloudWeave

**A read-only preflight for Terraform: see what an apply will really touch before it touches anything.**

CloudWeave reads Terraform state and plan JSON offline and answers the questions `terraform plan` doesn't:

- **What is this 80k-line state?** One self-contained graph page with search, a suggested state order, and a resource side panel explaining changes, findings and fix steps. Local snapshots work without Terraform or cloud credentials; an optional read-only PostgreSQL input reads Terraform's `pg` backend directly.
- **Why did plan succeed but apply fail?** It flags drift that overlaps or feeds planned changes, resources deleted out of band, stale saved plans, plan/state mismatch, version skew, eventually-consistent IAM grants, provisioners that only run at apply time and credentials that expire mid-apply.
- **What breaks in my *other* states?** It stitches several states together through `terraform_remote_state` outputs, shared resource IDs and Azure ↔ GCP identity federation. A replacement in one state then shows up as an impact in the others, and CloudWeave tells you which state to apply first.
- **Will the cross-cloud trust chain still work?** It runs static checks of GCP Workload Identity Federation and Entra ID federated credentials: issuer, audience, subject, attribute mapping/condition, disabled pools and replaced identities.

```
$ cloudweave analyze -s azure=azure.tfstate -s gcp=gcp.tfstate -p plan.json -o report.html
CloudWeave preflight: BLOCK
  state azure                         9 resources     10 instances    3 outputs [primary]
  state gcp                           6 resources      6 instances    5 outputs
  plan: 2 create, 1 update, 2 replace, 1 delete; 2 drifted; 0 deferred

12 findings (2 critical, 6 high, 3 medium, 1 low)
  CRITICAL CW201  replace azurerm_user_assigned_identity.workload is used by other states
  CRITICAL CW312  Plan deletes or replaces identity federation resources
  HIGH     CW101  Drift overlaps planned changes
  HIGH     CW102  Resources were deleted outside Terraform
  HIGH     CW206  Resources will be destroyed because their configuration was removed
  HIGH     CW305  Azure v1 issuer is missing its trailing slash
  HIGH     CW305  Google issuer in federated credential is not exact
  ...
```

## Safety model

CloudWeave is built to run against production state before an apply:

| Guarantee | How |
|---|---|
| Never modifies state | Local files are only read. Optional PostgreSQL input uses a read-only transaction and a parameterized SELECT, then rolls back. No state pushes or SQL writes. Report paths cannot overwrite input files or `*.tfstate*` names. |
| Never takes Terraform locks | No Terraform locking or PostgreSQL advisory locks. A SELECT takes PostgreSQL's ordinary read locks, not Terraform's state lock. Use a SELECT-only database role for defense in depth. |
| No cloud calls, no telemetry | File analysis and reports work offline. Only an explicitly requested PostgreSQL input makes a database connection. |
| No secrets in reports | Reports contain addresses, types, actions, counts, edges and changed attribute *names*, never attribute values. Attributes Terraform marks sensitive are not even named, only counted. Sensitive paths are skipped during matching. Identifiers in finding text are masked (`c0ff…89ab`) unless you pass `--reveal-ids`. Credential checks decode JWT claims locally and never print tokens. |
| Private output | Reports are written with mode `0600`. The HTML report has a strict CSP, loads nothing external, and embeds data as escaped JSON rendered only via `textContent`. |

A clean report lowers risk; it cannot guarantee that `terraform apply` succeeds.

## Install

```sh
go install github.com/vedantparmar12/cloudweave/cmd/cloudweave@latest
```

Or build from source with `go build ./cmd/cloudweave`. Requires Go 1.24+.

## Usage

```sh
# 1. Snapshot every state involved (read-only; does not lock).
terraform -chdir=azure state pull > azure.tfstate
terraform -chdir=gcp   state pull > gcp.tfstate

# 2. Create the plan you intend to apply and export it as JSON.
terraform -chdir=azure plan -out tfplan
terraform -chdir=azure show -json tfplan > plan.json

# 3. Analyze.
cloudweave analyze \
  --state azure=azure.tfstate --state gcp=gcp.tfstate \
  --plan plan.json \
  --out report.html --json report.json
```

`--state` accepts raw `.tfstate` (format v4) or `terraform show -json` output, and can be repeated. Without a plan, CloudWeave still visualizes the states and runs the cross-state and federation checks.

| Flag | Default | Meaning |
|---|---|---|
| `-s, --state [name=]path` | | State file, repeatable. The name labels it in the report. |
| `--pg-state name=ENV_VAR` | | Read a Terraform `pg` backend; the environment variable holds the connection string. Repeatable; can mix with files. |
| `--pg-schema name` | `terraform_remote_state` | Backend schema shared by all `--pg-state` inputs. |
| `--pg-workspace name` | `default` | Terraform workspace shared by all `--pg-state` inputs. |
| `-p, --plan path` | | Plan JSON from `terraform show -json`. |
| `--primary-state name` | auto | State the plan applies to. Auto-detected by matching resource IDs with the plan's prior state. |
| `--config path` | | Terraform configuration directory (native `.tf` syntax, root module plus local modules) for lifecycle and remote-state hints. Literals only; expressions are never evaluated. |
| `-o, --out path` | | Self-contained HTML report. |
| `--json path\|-` | | Machine-readable report (`cloudweave.report/v1`). |
| `--markdown path\|-` | | Markdown summary for pull-request comments: verdict, apply order, findings table and largest blast radius. |
| `--fail-on sev` | `none` | Exit `2` if any finding is at or above `info\|low\|medium\|high\|critical`. |
| `--plan-max-age` | `1h` | Saved plans older than this are flagged. |
| `--apply-window` | `30m` | Expected apply duration; credentials expiring within it are flagged. |
| `--blast-radius` | `25` | Flag single changes impacting more resources than this. |
| `--max-nodes` | `400` | Node cap per view in the HTML report. |
| `--check-credentials` | off | Inspect local federation credentials (see below). |
| `--reveal-ids` | off | Show full identifiers in finding text. |
| `-q, --quiet` | off | No terminal summary. |

Exit codes: `0` success, `1` usage or input error, `2` findings at or above `--fail-on`.

### PostgreSQL backend

Have your approved secret manager or CI secret injection populate `TF_PG_DSN` with the PostgreSQL connection string. Do not paste credentials into command arguments or shell history. Use a dedicated role limited to connecting, schema usage and SELECT on the backend's `states` table; prefer `sslmode=verify-full` with a trusted root certificate for remote connections.

```sh
# Graph and findings from the existing Terraform pg backend; no plan required.
cloudweave analyze --pg-state prod=TF_PG_DSN --out report.html

# Add a saved plan and another state for impact analysis and pseudo-apply.
cloudweave analyze \
  --pg-state prod=TF_PG_DSN --pg-schema terraform_remote_state --pg-workspace default \
  --state shared=shared.tfstate --primary-state prod \
  --plan plan.json --out report.html
```

`prod` is only the report label, not the Terraform workspace. `--pg-schema` and `--pg-workspace` apply to **all** PostgreSQL inputs in one invocation. The reader expects Terraform's `states` table with `name` and raw JSON text `data`; it does not create tables, decode base64 or migrate the backend. Different databases are read independently, not as one atomic snapshot.

The reader begins a read-only transaction, selects the workspace using a bound parameter, then rolls back. It never takes Terraform advisory locks; PostgreSQL still takes normal read locks. Connect/read work has a 15-second deadline, with bounded cleanup afterward. `target_session_attrs` configurations that require extra connection-time SQL are rejected. Connection and parse errors omit driver details and credentials. Automated tests use a local fake PostgreSQL protocol server; a live PostgreSQL integration has not been verified.

### Configuration directory (optional)

Pass the primary state's configuration directory with `--config` to enrich the analysis with facts that are absent from plan JSON:

- `lifecycle` flags (`prevent_destroy`, `create_before_destroy`) and count/for_each presence appear as node metadata and in the "why" text.
- **CW603** flags replacements whose recorded order destroys the current object first even though the configuration declares `create_before_destroy`.
- **CW206** tells you whether destroyed-because-removed resources are really absent from the configuration or still declared (count/for_each may just have evaluated to zero).
- **CW501** names the remote-state backend and workspace, and points PostgreSQL backends at `--pg-state`.

Only native-syntax `.tf` files are read, and only literals are extracted — expressions are never evaluated, so this needs no variables, providers or cloud access. Local module sources (`./`, `../`, optionally `//subdir`) are followed recursively, with module-prefixed addresses matching every module instance; registry, remote and dynamic module sources cannot be read offline, and CW206 caveats its absence claim rather than asserting it. Inside a `terraform_remote_state` config block only the `workspace` key may be read — in every module; credential-bearing keys such as `conn_string`, `access_key`, `secret_key`, `password` or `token` are never read, stored or logged, even when their values are literals.

### CI example

```yaml
- run: terraform show -json tfplan > plan.json
- run: terraform state pull > current.tfstate
- run: cloudweave analyze -s current.tfstate -s other.tfstate -p plan.json -o cloudweave.html --markdown cloudweave.md --fail-on critical
- uses: actions/upload-artifact@v4
  if: always()
  with: { name: cloudweave, path: cloudweave.html }
- if: always() && github.event_name == 'pull_request'
  run: gh pr comment ${{ github.event.pull_request.number }} --body-file cloudweave.md
  env: { GH_TOKEN: "${{ github.token }}" }
```

The Markdown summary contains the same data as the reports: addresses, actions, attribute *names* and counts, never values.

### Credential checks (`--check-credentials`)

These checks are optional and fully local. CloudWeave reads:

- `GOOGLE_APPLICATION_CREDENTIALS` / `GOOGLE_CREDENTIALS` (external_account configs)
- `GOOGLE_OAUTH_ACCESS_TOKEN`
- `ARM_OIDC_TOKEN`, `ARM_OIDC_TOKEN_FILE_PATH`, `AZURE_FEDERATED_TOKEN_FILE`
- `ARM_TENANT_ID` / `AZURE_TENANT_ID`
- client-secret variables (checked for presence only)

Subject tokens are decoded without signature verification, only to compare `exp`, `iss`, `aud` and `sub` against the federation config found in your states.

## The report

There are no tabs: just the graph and a side panel.

- JSON files (raw state or `terraform show -json`), PostgreSQL snapshots, and mixed inputs share the same graph. Source labels identify their origin without connection details. **Inputs & help** explains each workflow; the HTML itself never connects to a database.
- With a plan, the graph starts with changed resources, their dependencies and impact. Switch to **All resources** to explore the full inventory within the node limit. Without a plan, this view is the default.
- Search any resource (press `/`) and open its neighborhood on the same canvas. Reset restores the starting graph; the state filter narrows it.
- Select a resource for its change explanation, findings, suggested fix templates and modeled operations. The inspector can be hidden for more canvas space; on mobile, it stacks below the graph.
- Choose **System**, **Dark**, or **Light**. Only the theme preference is saved in browser storage; analysis data is not.
- Scroll to zoom, drag to pan, hover to trace neighbors, and export a standalone SVG in the current theme. With the canvas focused, arrow keys pan, `+`/`-` zoom and `0` fits.

**Pseudo apply** replays the supplied plan on an in-memory resource model. It preserves recorded create-before-destroy or destroy-before-create phases, reverses dependency order for deletes, and exposes unresolved cycles. It flags absent dependencies, possibly broken consumers, federation changes, IAM propagation and credential lifetime risks. Other states receive follow-up planning reminders, not fabricated applies.

The step list shows before/after presence, warnings and limitations. It is not Terraform's execution engine: provider behavior, real timing, credential refresh and live infrastructure are unknown. Mixed instance actions and deposed objects remain unresolved. `ok` means no modeled issue, not a guarantee; `fail` means a model failure, not an observed cloud failure. CW601 brings model failures and unresolved steps into the review verdict and `--fail-on` checks.

Fix templates use placeholders rather than secrets or interpolated input. Review and adapt them before use; CloudWeave never runs commands, changes authentication or applies fixes. Suggestions involving state ownership or trust changes require coordination. A fixed IAM wait or `create_before_destroy` alone cannot guarantee a safe cross-state migration.

The inspector's suggested state order ignores low-confidence and federation links. It is a planning aid, not an apply execution schedule.

## Rules

| Rule | Severity | Finding |
|---|---|---|
| CW001 | critical | Plan errored |
| CW002 | high | Plan is incomplete (`-target`, deferred changes) |
| CW003 | medium/high | Saved plan is older than `--plan-max-age` (high after 24h) |
| CW004 | high | Plan's prior state disagrees with the provided state (the state moved after planning) |
| CW005 | high/low | State written by a newer Terraform than the plan / apply upgrades the state version |
| CW006 | high | `.terraform.tfstate.lock.info` present next to a state |
| CW007 | info | Plan has nothing to apply |
| CW008 | medium | Plan matches none of the provided states |
| CW011 | medium | Two inputs are snapshots of the same state (same lineage) |
| CW101 | high | Drift overlaps planned changes |
| CW102 | high | Resources deleted outside Terraform (they will be recreated with new IDs) |
| CW103 | medium | Drifted resources feed planned changes |
| CW104 | low | Other drift |
| CW201 | critical | Destructive change to a resource that other states depend on |
| CW202 | medium | Resources will be deleted or replaced |
| CW203 | medium | Blast radius exceeds `--blast-radius` |
| CW204 | medium | Changed outputs are consumed by another state |
| CW205 | medium | Tainted or deposed objects |
| CW206 | high | Destroy because configuration was removed (often a resource moved to another state without a `removed` block) |
| CW301 | high | Workload identity pool or provider disabled/deleted |
| CW302 | high | WIF provider has no `google.subject` mapping |
| CW303 | high | `attribute_condition` uses unmapped attributes |
| CW304 | medium | WIF issuer tenant not found in Azure states |
| CW305 | high | Issuer not exact (`sts.windows.net/<tenant>/` needs the trailing slash; `https://accounts.google.com` must not have one) |
| CW306 | low/medium | Default audience / `allowed_audiences` match no Azure app or identity |
| CW307 | medium | IAM grant points at an unknown pool (wrong project number) |
| CW308 | high | IAM grant uses an attribute no provider maps |
| CW309 | medium | `principal://…/subject/<id>` matches no Azure identity (identity recreated?) |
| CW310 | medium | Federated credential subject is not a GCP service account `unique_id` (an email never matches) |
| CW311 | low | Federated credential uses a non-default audience |
| CW312 | critical/high | Plan replaces/deletes (critical) or updates (high) federation resources |
| CW313 | low | New IAM grants are eventually consistent (403 during the same apply) |
| CW314 | low | Pool has no IAM grants |
| CW401 | critical | Federation token expired |
| CW402 | high/medium | Token expires during the apply window / static access token |
| CW403 | critical/high | Credential config targets a disabled or unknown WIF provider |
| CW404 | high | Subject token file missing |
| CW405 | medium | Impersonated service account not in GCP states |
| CW406 | high | Subject token issuer, audience or subject rejected by the trust config |
| CW407 | low | Long-lived secret or key in use |
| CW408 | medium | Azure credentials target a different tenant |
| CW501 | info | `terraform_remote_state` source not provided |
| CW502 | medium | Consumer holds a stale copy of producer outputs |
| CW503 | high | Same cloud resource managed by two states |
| CW504 | medium | States depend on each other in a cycle, so no safe apply order exists |
| CW601 | high | Pseudo-apply model has missing dependencies or unresolved operations |
| CW602 | medium | Changed resources run provisioners, which `terraform plan` never executes |
| CW603 | medium | Recorded replacement order destroys first although the configuration declares `create_before_destroy` |

## Limits

- **Drift is only as fresh as the plan.** `-refresh=false` or `-refresh-only` plans hide drift; plan right before running CloudWeave.
- **Static analysis.** Live checks (does the pool exist *now*, can the token actually be exchanged) are on the roadmap as an opt-in mode. Apply-time failures such as quotas, policy denials or API validation remain invisible to any plan-based tool.
- **Cross-state links are inferred.** Remote-state links are exact. ID matching only uses strong identifiers, skips ambiguous values and sensitive attributes, and marks every edge with a confidence level.
- Only state format v4 (Terraform ≥ 0.12 and OpenTofu) is supported.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design, edge cases and roadmap.

## Development

```sh
go test ./...
go run ./cmd/cloudweave analyze \
  -s azure=testdata/multicloud/azure.tfstate -s gcp=testdata/multicloud/gcp.tfstate \
  -p testdata/multicloud/azure-plan.json -o report.html
```

`testdata/multicloud` models an AKS workload that federates into GCP, plus a GCP service account that federates into Entra ID. The plan replaces the managed identity, reverts portal drift and recreates a deleted storage account.

## License

Apache-2.0
