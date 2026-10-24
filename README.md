# CloudWeave

**A read-only preflight for Terraform: see what an apply will really touch before it touches anything.**

CloudWeave reads Terraform state and plan JSON offline and answers the questions `terraform plan` doesn't:

- **What is this 80k-line state?** It gives you a single self-contained HTML report with a state map, the plan's change cone, a searchable neighborhood explorer and an inventory tree. It works without Terraform, a backend or a cloud login.
- **Why did plan succeed but apply fail?** It flags drift that overlaps or feeds planned changes, resources deleted out of band, stale saved plans, plan/state mismatch, version skew, eventually-consistent IAM grants and credentials that expire mid-apply.
- **What breaks in my *other* states?** It stitches several states together through `terraform_remote_state` outputs, shared resource IDs and Azure ↔ GCP identity federation. A replacement in one state then shows up as an impact in the others.
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
| Never modifies state | It only reads files you pass. It has no `state push`, no backend client and no lock handling. It refuses to write a report onto any input file or anything named `*.tfstate*`. |
| Never holds the lock | It never talks to a backend. You export snapshots yourself with `terraform state pull` (read-only, lock-free). |
| No cloud calls, no telemetry | It needs no network access at all. |
| No secrets in reports | Reports contain addresses, types, actions, counts and edges, never attribute values. Sensitive paths are skipped during matching. Identifiers in finding text are masked (`c0ff…89ab`) unless you pass `--reveal-ids`. Credential checks decode JWT claims locally and never print tokens. |
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
| `-p, --plan path` | | Plan JSON from `terraform show -json`. |
| `--primary-state name` | auto | State the plan applies to. Auto-detected by matching resource IDs with the plan's prior state. |
| `-o, --out path` | | Self-contained HTML report. |
| `--json path\|-` | | Machine-readable report (`cloudweave.report/v1`). |
| `--fail-on sev` | `none` | Exit `2` if any finding is at or above `info\|low\|medium\|high\|critical`. |
| `--plan-max-age` | `1h` | Saved plans older than this are flagged. |
| `--apply-window` | `30m` | Expected apply duration; credentials expiring within it are flagged. |
| `--blast-radius` | `25` | Flag single changes impacting more resources than this. |
| `--max-nodes` | `400` | Node cap per view in the HTML report. |
| `--check-credentials` | off | Inspect local federation credentials (see below). |
| `--reveal-ids` | off | Show full identifiers in finding text. |
| `-q, --quiet` | off | No terminal summary. |

Exit codes: `0` success, `1` usage or input error, `2` findings at or above `--fail-on`.

### CI example

```yaml
- run: terraform show -json tfplan > plan.json
- run: terraform state pull > current.tfstate
- run: cloudweave analyze -s current.tfstate -s other.tfstate -p plan.json -o cloudweave.html --fail-on critical
- uses: actions/upload-artifact@v4
  if: always()
  with: { name: cloudweave, path: cloudweave.html }
```

### Credential checks (`--check-credentials`)

These checks are optional and fully local. CloudWeave reads:

- `GOOGLE_APPLICATION_CREDENTIALS` / `GOOGLE_CREDENTIALS` (external_account configs)
- `GOOGLE_OAUTH_ACCESS_TOKEN`
- `ARM_OIDC_TOKEN`, `ARM_OIDC_TOKEN_FILE_PATH`, `AZURE_FEDERATED_TOKEN_FILE`
- `ARM_TENANT_ID` / `AZURE_TENANT_ID`
- client-secret variables (checked for presence only)

Subject tokens are decoded without signature verification, only to compare `exp`, `iss`, `aud` and `sub` against the federation config found in your states.

## The report

| Tab | What it shows |
|---|---|
| Overview | Verdict, key numbers, top findings, a map of states with aggregated cross-state links, and a table of every cross-state edge with its evidence and confidence. |
| Findings | All findings, filterable by severity and category, with remediation and links to the affected resources. |
| Change cone | Changed and drifted resources, everything transitively impacted (across states), and optionally their direct dependencies, laid out by distance. |
| Explore | Search any address, type or module, then walk its neighborhood: dependencies on the left, dependents on the right. |
| Inventory | State → module → type tree, lazily expanded, so huge states stay fast. |

Colors encode cloud (stripe), planned action (border) and drift (dotted). Edge style encodes the kind of link: dependency, remote-state, id-match or federation.

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
