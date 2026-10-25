package analysis

// Snippets are static templates, not executable fixes derived from untrusted metadata.
type FixStep struct {
	Text string `json:"text"`
	Code string `json:"code,omitempty"`
}

const (
	fixReview      = "Read-only preflight: CloudWeave displays suggestions; it never executes commands or changes infrastructure, state, or authentication. Review all manual writes and authentication changes. Templates are not ready to run."
	fixBash        = "Bash template (review and replace <placeholders> before use): "
	fixHCL         = "HCL template (review and adapt to your configuration before use): "
	replan         = "terraform -chdir='<configuration-directory>' plan"
	fixRefreshPlan = "terraform -chdir='<configuration-directory>' plan -refresh-only"
	fixRemoved     = `removed {
  from = <relinquished-resource-address>
  lifecycle {
    destroy = false
  }
}`
	fixImport = `import {
  to = <destination-resource-address>
  id = "<verified-existing-object-id>"
}`
	fixAzureV1Issuer = `oidc {
  issuer_uri = "https://sts.windows.net/<tenant-id>/"
}`
	fixGoogleIssuer = `issuer = "` + googleIssuer + `"`
)

func (a *analyzer) addFixes() {
	for i := range a.findings {
		a.findings[i].Fix = a.fixFor(&a.findings[i])
	}
}

func (a *analyzer) fixFor(f *Finding) []FixStep {
	return append([]FixStep{{Text: fixReview}}, fixTemplates(f)...)
}

// Exact built-in titles select variants without interpolating untrusted finding text.
func fixTemplates(f *Finding) []FixStep {
	if f == nil {
		return fixReviewFallback()
	}
	switch f.Rule {
	case "CW001":
		return []FixStep{{fixBash + "Resolve Terraform's planning errors, then make a new full plan and rerun CloudWeave. Do not use the errored plan.", replan}}
	case "CW002":
		return []FixStep{{fixBash + "Plan the whole configuration without targeting. Review deferred changes; after any separately approved run, make another full plan to confirm convergence.", replan}}
	case "CW003", "CW004":
		return []FixStep{{fixBash + "Confirm the backend and workspace, obtain the current snapshot through your approved secure workflow, and replace the stale plan with a full plan immediately before a reviewed run.", replan}}
	case "CW005":
		return []FixStep{{fixHCL + "Choose a supported Terraform version compatible with the state and providers; use it consistently locally and in CI for planning and execution.", "terraform {\n  required_version = \"= <approved-version>\"\n}"}}
	case "CW006":
		return []FixStep{{Text: "Contact the state owner and check CI and backend run status. Do not remove a lock while a run is active. Only after confirming abandonment, use the backend's reviewed lock-recovery procedure; a lock file alone is not proof of abandonment."}}
	case "CW007":
		return []FixStep{{Text: "No change is needed if a no-change plan was expected. Otherwise verify the selected workspace, configuration, and inputs before making a new full plan."}}
	case "CW008", "CW011":
		return []FixStep{{Text: "Verify the backend, workspace, and snapshot lineage with the state owner. Supply only the latest authoritative snapshot for each state and explicitly select the primary state when needed. Protect exported snapshots and plans as sensitive files, then rerun CloudWeave."}}
	case "CW101", "CW103", "CW104":
		return []FixStep{
			{fixBash + "Review drift without persisting refreshed state. This is a refresh-only PLAN, not approval to write state.", fixRefreshPlan},
			{fixBash + "Decide with the owner whether to codify intentional drift or revert it through reviewed configuration. Make a full plan and rerun CloudWeave; a refresh-only plan does not reconcile infrastructure.", replan},
		}
	case "CW102":
		return []FixStep{
			{fixBash + "Confirm the object is really missing in the intended account and workspace, rather than hidden by permissions. Investigate the deletion cause before accepting recreation.", fixRefreshPlan},
			{fixBash + "If still required, review recreation and every consumer of the old identity. If intentionally retired, review removing its configuration and dependencies. Do not import or forget an object solely because it is reported missing; make a new full plan.", replan},
		}
	case "CW201", "CW312":
		return fixStagedMigration()
	case "CW202":
		return []FixStep{{fixBash + "Review each deletion or replacement and its consumers with the owner. Restore accidentally removed configuration or redesign the change before proceeding; a lifecycle guard in missing configuration cannot protect the object.", replan}}
	case "CW203":
		return []FixStep{{Text: "Review transitive dependents and recovery options with their owners. Split configuration changes into independently reviewed stages with full plans, or schedule an approved maintenance window; targeting is not a substitute for reviewing the whole configuration."}}
	case "CW204", "CW502":
		return []FixStep{{fixBash + "Coordinate producer and consumer owners. Once the producer's approved changes and outputs are stable, make a full plan in each consumer configuration and review the new values and identity references before any consumer writes.", replan}}
	case "CW205":
		if f.Title == "Deposed objects left from a failed replacement" {
			return []FixStep{{fixBash + "Investigate the failed replacement and verify no consumers still use the deposed objects. Retain needed old objects until migration is verified; review any cleanup and state writes with the owner.", replan}}
		}
		return []FixStep{{fixBash + "Investigate the failed operation and verify object health. Do not clear a taint merely to suppress replacement; any manual state change requires owner review and a protected backup. Review a new full plan afterward.", replan}}
	case "CW206":
		return []FixStep{
			{Text: "Restore accidentally removed configuration first. If this is an intentional move, choose ONE of the alternatives below, not both. Review all affected instances and coordinate ownership before any state writes; prevent_destroy in removed configuration is not a fix."},
			{fixHCL + "Alternative A: for a move within the same state, keep the destination configuration and record the address change. Review that the plan moves rather than deletes the object.", "moved {\n  from = <old-resource-address>\n  to   = <new-resource-address>\n}"},
			{fixHCL + "Alternative B: for a cross-state transfer on Terraform >= 1.7, pause competing runs and take protected backups. Use this only in the relinquishing state. Review the full removal scope, including all resource instances, and confirm there is no infrastructure destruction.", fixRemoved},
			{fixHCL + "Continue Alternative B only: coordinate a handoff to exactly one destination owner. Define the matching destination resource and verify its existing cloud identity before import. Review both plans; do not let either state recreate or destroy the object during the handoff.", fixImport},
		}
	case "CW301":
		return []FixStep{{Text: "Confirm whether the pool or provider is disabled or deleted and whether recovery is supported. Use an independent working credential for an owner-approved recovery or parallel replacement; preserve a recovery path and verify token exchange and required access before moving consumers."}}
	case "CW302":
		return []FixStep{{fixHCL + "After authentication-change review, map a verified stable claim to the subject and ensure grants match the mapped result. Preserve other required mappings and validate with the workload; do not assume every issuer uses the same claim.", "attribute_mapping = {\n  \"google.subject\" = \"<stable-subject-expression>\"\n}"}}
	case "CW303", "CW308":
		return []FixStep{{Text: "Review the condition or grant against the provider's mappings and verified workload claims. Add the intended mapping or correct the match without broadening trust; test an authorized and an unauthorized identity before an approved authentication change."}}
	case "CW304", "CW408":
		return []FixStep{{Text: "Verify the tenant and account used by the actual Terraform/CI credential source, not merely an interactive CLI session. Compare with the intended workload and trust configuration; review any authentication change and test it independently before proceeding."}}
	case "CW305":
		switch f.Title {
		case "Azure v1 issuer is missing its trailing slash":
			return []FixStep{{fixHCL + "For verified Entra v1 tokens, use the exact issuer including its trailing slash. Review the trust change using an independent credential; do not substitute a v1 endpoint for a v2 token issuer.", fixAzureV1Issuer}}
		case "Google issuer in federated credential is not exact":
			return []FixStep{{fixHCL + "For verified Google-issued identity tokens, use the exact Google issuer with no trailing slash. Review and test the trust change using an independent credential.", fixGoogleIssuer}}
		default:
			return []FixStep{{Text: "Verify the token's exact issuer and federation direction before editing trust. Google uses its exact issuer without a trailing slash; Entra v1 includes the tenant and trailing slash. Do not infer an issuer from an unrecognized finding or copy unverified token claims into trust."}}
		}
	case "CW306":
		return []FixStep{{fixHCL + "Verify the audience the intended workload actually requests, then review an exact match without broadening trust. Preserve any other deliberately allowed audiences.", "oidc {\n  allowed_audiences = [\"<verified-token-audience>\"]\n}"}}
	case "CW307":
		return []FixStep{{Text: "Verify the grant's project number and pool against the authoritative pool configuration. Include missing owner states in analysis before deciding it is a typo; review any grant correction for least privilege."}}
	case "CW309":
		return []FixStep{{Text: "Verify how the provider maps the workload's subject and compare it with the intended identity's current claims. Do not assume a client ID and object ID are interchangeable. Coordinate grant and consumer changes if the identity was recreated, retaining working authentication until verified."}}
	case "CW310":
		return []FixStep{{fixHCL + "For a service account in the same configuration, reference its numeric unique ID rather than its email. Across states, use a reviewed output instead. Coordinate identity replacement and verify the new subject before retirement.", "subject = google_service_account.<resource-name>.unique_id"}}
	case "CW311":
		return []FixStep{{Text: "Check whether a custom audience is intentional. Otherwise coordinate the workload and federated credential to use " + azureExchangeAud + "; use the audience argument supported by your provider schema and test exchange before switching authentication."}}
	case "CW313":
		return []FixStep{
			{Text: "Separate new grants from operations that require them into reviewed stages, using an independent credential with existing permissions. A dependency orders operations but does not guarantee IAM propagation."},
			{Text: "Verify actual propagation using the intended workload's token exchange and required authorized API access without logging tokens. Follow provider-specific retry guidance; a fixed sleep cannot guarantee readiness. Stop if access is not verified."},
			{fixBash + "After access is verified, make a full, non-targeted plan for dependent configurations and rerun CloudWeave before any approved writes.", replan},
		}
	case "CW314":
		return []FixStep{{Text: "Check authoritative grant-owner states before concluding access is missing. If needed, review a least-privilege grant for the intended workload and verify both token exchange and required API access; successful exchange alone does not establish authorization."}}
	case "CW401", "CW402":
		return []FixStep{
			{Text: "Acquire fresh credentials through the approved CI identity step right before the run. Prefer a refreshable CI credential source and verify that the Terraform provider can renew or reread it throughout the entire run; an interactive login may not affect CI credentials."},
			{fixBash + "Budget for the full run and review credential renewal before replanning. Raising --apply-window does not extend token lifetime; shortening that estimate only hides the warning if the real run is longer. Do not proceed with a source that will expire mid-run.", replan},
		}
	case "CW403":
		return []FixStep{{Text: "Verify the configured federation destination against its authoritative owner state and confirm it is enabled. Missing input is not proof of a wrong destination. Review any credential configuration regeneration or provider recovery using independent working authentication, then test the intended workload."}}
	case "CW404":
		return []FixStep{{Text: "Ensure the approved CI identity step supplies its credential files before Terraform runs. Verify paths and read permissions inside the actual runner without printing file contents. Do not blindly unset authentication settings or fall back to an unintended identity."}}
	case "CW405":
		return []FixStep{{Text: "Verify the intended impersonated account exists using its owner state and confirm the workload has the required least-privilege impersonation grant. Test exchange and API access; missing input alone does not justify creating an account or adding permissions."}}
	case "CW406":
		return []FixStep{{Text: "Privately verify the workload's issuer, audience, and subject against the intended trust configuration. Do not log tokens or trust arbitrary claims. Correct the requesting workload or review a narrowly scoped trust change using independent authentication, then test exchange and required access."}}
	case "CW407":
		return []FixStep{{Text: "Plan a reviewed migration to refreshable workload federation for the relevant cloud and CI platform. Establish and test the new credential path with independent recovery access before switching consumers; retire the old credential only after successful authentication and authorization are verified."}}
	case "CW501":
		return []FixStep{{Text: "Ask the producer owner for a current, securely handled state snapshot and include it with the other analysis inputs. Confirm backend and workspace selection; do not substitute an unrelated state or publish state contents."}}
	case "CW503":
		return []FixStep{
			{Text: "Choose ONE authoritative owner for each duplicated object. Pause competing runs, verify cloud identities, and take protected backups. Keep the chosen owner's resource configuration and state entry intact; never remove every owner."},
			{fixHCL + "Terraform >= 1.7: use this only in the relinquishing state, never in the retained owner's state. Coordinate removal of the relinquishing configuration and review the full scope, including resource instances; confirm no infrastructure destruction or recreation is planned.", fixRemoved},
			{fixBash + "After an approved ownership handoff, replan both states and confirm exactly one owner remains. If the chosen owner already tracks the object, do not import it again.", replan},
		}
	case "CW602":
		return []FixStep{{Text: "Provisioners execute only during apply; terraform plan never runs them. Review each command's runtime needs (tools, network, credentials) with its owner, prefer provider features or native resources over local-exec/remote-exec, and never place secrets in provisioner commands or environment echoes."}}
	case "CW603":
		return []FixStep{
			{Text: "The recorded replacement order destroys the current object first although the configuration declares create_before_destroy. Investigate deposed objects and provider behavior with the owner, and confirm consumers can tolerate any gap before an approved run."},
			{fixBash + "After resolving the ordering question, make a new full plan and rerun CloudWeave to confirm the recorded replacement order.", replan},
		}
	case "CW504":
		return []FixStep{{Text: "Review the cycle with all state owners. Give shared resources and outputs a single owner or remove a cyclic output dependency through an independently reviewed design. Replan all consumers after breaking the cycle; there is no safe universal ordering for the existing cycle."}}
	case "CW505":
		return []FixStep{
			{Text: "Confirm the dependency direction in the current configuration. A cycle prevents a complete Terraform order; if it mixes recorded state edges with a newer configuration, refresh the state snapshot and plan from the same revision."},
			{fixBash + "After a fresh full plan succeeds without a dependency cycle, rerun CloudWeave. Do not treat the unresolved layer group as an execution schedule.", replan},
		}
	case "CW601":
		return []FixStep{{fixBash + "Review the simulation's blocked paths, missing dependencies and per-instance replacement actions against the full plan. Resolve uncertain ordering with the owner; the offline model is not proof of a cloud failure.", replan}}
	default:
		return fixReviewFallback()
	}
}

func fixStagedMigration() []FixStep {
	return []FixStep{
		{Text: "Pause destructive or trust-changing work until all consumer owners review the migration. Establish and verify an independent credential that does not rely on the identity or trust being changed, with an approved recovery path, before any authentication change."},
		{Text: "Use staged parallel identities or resources: retain the old object and trust in configuration while introducing the replacement at a separate address. create_before_destroy alone does not preserve the old identity across separately managed state runs. If parallel operation is impossible, arrange a reviewed maintenance and recovery plan instead."},
		{Text: "Switch consumers in coordinated stages. Verify their token exchange and required authorized API access, using the independent credential to administer and recover the migration. Retire the old identity or trust only after all consumers are verified; do not target federation changes first using credentials that depend on them."},
		{fixBash + "Make a full plan for each affected configuration at each stage and rerun CloudWeave before reviewed execution.", replan},
	}
}

func fixReviewFallback() []FixStep {
	return []FixStep{{Text: "Review this finding against the current configuration and authoritative state with its owner. No automatic change is justified; resolve missing context before planning again."}}
}
