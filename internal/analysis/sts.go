package analysis

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/vedantparmar12/cloudweave/internal/state"
)

const (
	googleIssuer      = "https://accounts.google.com"
	azureExchangeAud  = "api://AzureADTokenExchange"
	wifPrincipalHost  = "iam.googleapis.com/"
	roleWorkloadIDUsr = "roles/iam.workloadIdentityUser"
)

// federationTypes are resources whose change can break cross-cloud token
// exchange for everything that authenticates through them.
var federationTypes = map[string]bool{
	"google_iam_workload_identity_pool":                 true,
	"google_iam_workload_identity_pool_provider":        true,
	"google_service_account":                            true,
	"google_service_account_iam_member":                 true,
	"google_service_account_iam_binding":                true,
	"google_service_account_iam_policy":                 true,
	"azuread_application":                               true,
	"azuread_application_registration":                  true,
	"azuread_service_principal":                         true,
	"azuread_application_federated_identity_credential": true,
	"azurerm_federated_identity_credential":             true,
	"azurerm_user_assigned_identity":                    true,
}

type fedIndex struct {
	tenants    map[string]bool
	apps       map[string]string // client/application id or identifier URI -> node
	principals map[string]string // principal/object id -> node
	pools      map[string]*pool  // pool resource name -> pool
	saUnique   map[string]string // service account unique_id -> node
	saEmail    map[string]string // service account email -> node
	providers  []*wifProvider
	grants     []grant
	fics       []fic
	haveAzure  bool
	haveGCP    bool
}

type pool struct {
	node      string
	name      string
	disabled  bool
	deleted   bool
	providers []*wifProvider
	granted   bool
}

type wifProvider struct {
	node      string
	name      string
	poolName  string
	disabled  bool
	deleted   bool
	issuer    string
	audiences []string
	mapping   map[string]string
	condition string
	hasOIDC   bool
}

type grant struct {
	node   string
	role   string
	member string
}

type fic struct {
	node      string
	issuer    string
	subject   string
	audiences []string
}

func (a *analyzer) analyzeFederation() {
	fx := a.buildFedIndex()
	if len(fx.providers) == 0 && len(fx.fics) == 0 && len(fx.grants) == 0 {
		return
	}
	a.checkProviders(fx)
	a.checkGrants(fx)
	a.checkFICs(fx)
}

func (a *analyzer) buildFedIndex() *fedIndex {
	fx := &fedIndex{
		tenants:    map[string]bool{},
		apps:       map[string]string{},
		principals: map[string]string{},
		pools:      map[string]*pool{},
		saUnique:   map[string]string{},
		saEmail:    map[string]string{},
	}
	for _, st := range a.states {
		for _, r := range st.Resources {
			id := NodeID(st.Name, r.Address)
			switch r.Cloud {
			case state.CloudAzure:
				fx.haveAzure = true
			case state.CloudGCP:
				fx.haveGCP = true
			}
			for _, inst := range r.Instances {
				at := inst.Attributes
				if r.Cloud == state.CloudAzure {
					if t := str(at, "tenant_id"); t != "" {
						fx.tenants[strings.ToLower(t)] = true
					}
					for _, ident := range list(at, "identity") {
						if m, ok := ident.(map[string]any); ok {
							if p := str(m, "principal_id"); p != "" {
								fx.principals[strings.ToLower(p)] = id
							}
							if t := str(m, "tenant_id"); t != "" {
								fx.tenants[strings.ToLower(t)] = true
							}
						}
					}
				}
				if r.Mode == "data" && r.Type != "azurerm_client_config" && r.Type != "azuread_client_config" {
					continue
				}
				switch r.Type {
				case "azuread_application", "azuread_application_registration":
					for _, k := range []string{"client_id", "application_id"} {
						if v := str(at, k); v != "" {
							fx.apps[strings.ToLower(v)] = id
						}
					}
					for _, u := range strs(at, "identifier_uris") {
						fx.apps[strings.ToLower(u)] = id
					}
				case "azuread_service_principal":
					for _, k := range []string{"client_id", "application_id"} {
						if v := str(at, k); v != "" {
							fx.apps[strings.ToLower(v)] = id
						}
					}
					if v := str(at, "object_id"); v != "" {
						fx.principals[strings.ToLower(v)] = id
					}
				case "azurerm_user_assigned_identity":
					if v := str(at, "client_id"); v != "" {
						fx.apps[strings.ToLower(v)] = id
					}
					if v := str(at, "principal_id"); v != "" {
						fx.principals[strings.ToLower(v)] = id
					}
				case "azuread_application_federated_identity_credential", "azurerm_federated_identity_credential":
					auds := strs(at, "audiences")
					if len(auds) == 0 {
						auds = strs(at, "audience")
					}
					fx.fics = append(fx.fics, fic{node: id, issuer: str(at, "issuer"), subject: str(at, "subject"), audiences: auds})
				case "google_iam_workload_identity_pool":
					name := str(at, "name")
					if name == "" {
						continue
					}
					fx.pools[name] = &pool{
						node:     id,
						name:     name,
						disabled: boolean(at, "disabled"),
						deleted:  strings.EqualFold(str(at, "state"), "DELETED"),
					}
				case "google_iam_workload_identity_pool_provider":
					p := &wifProvider{
						node:      id,
						name:      str(at, "name"),
						disabled:  boolean(at, "disabled"),
						deleted:   strings.EqualFold(str(at, "state"), "DELETED"),
						mapping:   strMap(at, "attribute_mapping"),
						condition: str(at, "attribute_condition"),
					}
					if i := strings.Index(p.name, "/providers/"); i > 0 {
						p.poolName = p.name[:i]
					}
					if oidc := list(at, "oidc"); len(oidc) > 0 {
						if m, ok := oidc[0].(map[string]any); ok {
							p.hasOIDC = true
							p.issuer = str(m, "issuer_uri")
							p.audiences = strs(m, "allowed_audiences")
						}
					}
					fx.providers = append(fx.providers, p)
				case "google_service_account":
					if v := str(at, "unique_id"); v != "" {
						fx.saUnique[v] = id
					}
					if v := str(at, "email"); v != "" {
						fx.saEmail[strings.ToLower(v)] = id
					}
				}
				if strings.HasPrefix(r.Type, "google_") && (strings.HasSuffix(r.Type, "_iam_member") || strings.HasSuffix(r.Type, "_iam_binding")) {
					members := strs(at, "members")
					if m := str(at, "member"); m != "" {
						members = append(members, m)
					}
					for _, m := range members {
						if strings.HasPrefix(m, "principal://") || strings.HasPrefix(m, "principalSet://") {
							fx.grants = append(fx.grants, grant{node: id, role: str(at, "role"), member: m})
						}
					}
				}
			}
		}
	}
	for _, p := range fx.providers {
		if pl := fx.pools[p.poolName]; pl != nil {
			pl.providers = append(pl.providers, p)
		}
	}
	return fx
}

var conditionAttr = regexp.MustCompile(`\battribute\.([A-Za-z0-9_]+)`)

func (a *analyzer) checkProviders(fx *fedIndex) {
	for _, pl := range fx.pools {
		if pl.disabled || pl.deleted {
			a.add(Finding{
				Rule: "CW301", Severity: SevHigh, Category: CatSTS,
				Title:       "Workload identity pool is disabled or deleted",
				Detail:      "Token exchange through every provider in this pool fails until it is re-enabled or undeleted (deleted pools are purged after 30 days).",
				Remediation: "Re-enable or undelete the pool before applying anything that authenticates through it.",
				Nodes:       []string{pl.node},
			})
		}
	}
	for _, p := range fx.providers {
		if pl := fx.pools[p.poolName]; pl != nil && pl.node != p.node {
			a.g.AddEdge(Edge{From: p.node, To: pl.node, Kind: EdgeFederation, Confidence: ConfHigh, Evidence: "provider belongs to pool"})
		}
		if p.disabled || p.deleted {
			a.add(Finding{
				Rule: "CW301", Severity: SevHigh, Category: CatSTS,
				Title:       "Workload identity provider is disabled or deleted",
				Detail:      "STS rejects tokens for disabled or deleted providers, so any Terraform provider authenticating through it fails at apply time.",
				Remediation: "Re-enable the provider or switch credentials before applying.",
				Nodes:       []string{p.node},
			})
		}
		if len(p.mapping) > 0 {
			if _, ok := p.mapping["google.subject"]; !ok {
				a.add(Finding{
					Rule: "CW302", Severity: SevHigh, Category: CatSTS,
					Title:       "Workload identity provider has no google.subject mapping",
					Detail:      "Google STS requires attribute_mapping to set google.subject; token exchange fails without it.",
					Remediation: `Add "google.subject" = "assertion.sub" (or another stable claim) to attribute_mapping.`,
					Nodes:       []string{p.node},
				})
			}
		}
		if p.condition != "" {
			var missing []string
			for _, m := range conditionAttr.FindAllStringSubmatch(p.condition, -1) {
				if _, ok := p.mapping["attribute."+m[1]]; !ok {
					missing = appendUniqueStr(missing, "attribute."+m[1])
				}
			}
			if len(missing) > 0 {
				a.add(Finding{
					Rule: "CW303", Severity: SevHigh, Category: CatSTS,
					Title:       "attribute_condition uses unmapped attributes",
					Detail:      fmt.Sprintf("The condition references %s, which attribute_mapping does not define, so the condition never matches and every token exchange is rejected.", strings.Join(missing, ", ")),
					Remediation: "Map the attribute in attribute_mapping or rewrite the condition using assertion.* claims.",
					Nodes:       []string{p.node},
				})
			}
		}
		if p.hasOIDC {
			a.checkAzureIssuer(fx, p)
		}
	}
}

func (a *analyzer) checkAzureIssuer(fx *fedIndex, p *wifProvider) {
	issuer := strings.TrimSpace(p.issuer)
	lower := strings.ToLower(issuer)
	var tenant string
	switch {
	case strings.HasPrefix(lower, "https://sts.windows.net/"):
		tenant = strings.Trim(strings.TrimPrefix(lower, "https://sts.windows.net/"), "/")
		if !strings.HasSuffix(issuer, "/") {
			a.add(Finding{
				Rule: "CW305", Severity: SevHigh, Category: CatSTS,
				Title:       "Azure v1 issuer is missing its trailing slash",
				Detail:      "Entra ID v1 tokens carry iss=\"https://sts.windows.net/<tenant>/\" with a trailing slash. Google STS compares the issuer exactly, so the exchange fails with invalid_grant.",
				Remediation: "Set issuer_uri to https://sts.windows.net/<tenant-id>/ (with the trailing slash).",
				Nodes:       []string{p.node},
			})
		}
	case strings.HasPrefix(lower, "https://login.microsoftonline.com/"):
		rest := strings.TrimPrefix(lower, "https://login.microsoftonline.com/")
		tenant = strings.SplitN(rest, "/", 2)[0]
	default:
		return
	}

	if len(fx.tenants) > 0 && tenant != "" && !fx.tenants[tenant] {
		a.add(Finding{
			Rule: "CW304", Severity: SevMedium, Category: CatSTS,
			Title:       "WIF issuer tenant not found in Azure states",
			Detail:      fmt.Sprintf("The provider trusts tenant %s, but no resource in the provided Azure states belongs to it. Tokens minted by your Azure identities will be rejected if they come from a different tenant.", a.mask(tenant)),
			Remediation: "Confirm the tenant ID in issuer_uri matches the tenant of the identity that requests tokens.",
			Nodes:       []string{p.node},
		})
	}

	if len(p.audiences) == 0 {
		a.add(Finding{
			Rule: "CW306", Severity: SevLow, Category: CatSTS,
			Title:       "WIF provider uses the default audience",
			Detail:      "Without allowed_audiences, the Azure token's aud must equal the provider's full resource URI. Entra only issues such tokens if an app registration exposes that URI.",
			Remediation: "Set allowed_audiences to the Entra app's client ID or identifier URI that your workload requests tokens for.",
			Nodes:       []string{p.node},
		})
		return
	}
	matched := false
	for _, aud := range p.audiences {
		if node, ok := fx.apps[strings.ToLower(aud)]; ok {
			matched = true
			a.g.AddEdge(Edge{From: p.node, To: node, Kind: EdgeFederation, Confidence: ConfHigh, Evidence: "allowed_audiences contains this identity"})
		}
	}
	if !matched && len(fx.apps) > 0 {
		a.add(Finding{
			Rule: "CW306", Severity: SevMedium, Category: CatSTS,
			Title:       "WIF allowed_audiences match no Azure identity",
			Detail:      fmt.Sprintf("None of the %d allowed audiences equals a client ID or identifier URI of an Azure app or managed identity in the provided states.", len(p.audiences)),
			Remediation: "Check that the Azure workload requests its token for one of allowed_audiences.",
			Nodes:       []string{p.node},
		})
	}
}

// parseMember splits principal(Set)://iam.googleapis.com/<pool>/<rest>.
func parseMember(m string) (poolName, kind, value string, ok bool) {
	i := strings.Index(m, wifPrincipalHost)
	if i < 0 {
		return "", "", "", false
	}
	rest := m[i+len(wifPrincipalHost):]
	j := strings.Index(rest, "/workloadIdentityPools/")
	if j < 0 {
		return "", "", "", false
	}
	after := rest[j+len("/workloadIdentityPools/"):]
	parts := strings.SplitN(after, "/", 3)
	poolName = rest[:j] + "/workloadIdentityPools/" + parts[0]
	switch {
	case len(parts) == 1:
		return poolName, "", "", true
	case len(parts) == 2:
		return poolName, parts[1], "", true
	default:
		return poolName, parts[1], parts[2], true
	}
}

func (a *analyzer) checkGrants(fx *fedIndex) {
	for _, gr := range fx.grants {
		poolName, kind, value, ok := parseMember(gr.member)
		if !ok {
			continue
		}
		pl := fx.pools[poolName]
		if pl == nil {
			if len(fx.pools) > 0 {
				a.add(Finding{
					Rule: "CW307", Severity: SevMedium, Category: CatSTS,
					Title:       "IAM grant references an unknown workload identity pool",
					Detail:      fmt.Sprintf("The grant's principal points to pool %s, which is not in the provided states. Pool IDs embed the project number; a typo or wrong project silently grants nothing.", a.mask(poolName)),
					Remediation: "Compare the project number and pool ID in the member string with the pool's name attribute.",
					Nodes:       []string{gr.node},
				})
			}
			continue
		}
		pl.granted = true
		a.g.AddEdge(Edge{From: gr.node, To: pl.node, Kind: EdgeFederation, Confidence: ConfHigh, Evidence: "grants pool principals " + gr.role})

		if strings.HasPrefix(kind, "attribute.") {
			mapped := false
			for _, p := range pl.providers {
				if _, ok := p.mapping[kind]; ok {
					mapped = true
				}
			}
			if !mapped && len(pl.providers) > 0 {
				a.add(Finding{
					Rule: "CW308", Severity: SevHigh, Category: CatSTS,
					Title:       "IAM grant uses an attribute no provider maps",
					Detail:      fmt.Sprintf("The grant matches on %s, but no provider in the pool maps it, so no federated identity can ever satisfy this binding.", kind),
					Remediation: "Add the attribute to the provider's attribute_mapping or change the principalSet.",
					Nodes:       []string{gr.node},
				})
			}
		}
		if kind == "subject" && value != "" {
			a.checkSubject(fx, pl, gr, value)
		}
	}
	for _, pl := range fx.pools {
		if !pl.granted && len(fx.grants) > 0 {
			a.add(Finding{
				Rule: "CW314", Severity: SevLow, Category: CatSTS,
				Title:       "Workload identity pool has no IAM grants in provided states",
				Detail:      "Token exchange will succeed but the federated identity has no permissions, so the first API call fails with 403.",
				Remediation: "Grant " + roleWorkloadIDUsr + " on a service account, or grant direct resource access to a principalSet in this pool.",
				Nodes:       []string{pl.node},
			})
		}
	}
}

func (a *analyzer) checkSubject(fx *fedIndex, pl *pool, gr grant, subject string) {
	candidates := map[string]string{}
	for _, p := range pl.providers {
		lower := strings.ToLower(p.issuer)
		if !strings.Contains(lower, "sts.windows.net") && !strings.Contains(lower, "login.microsoftonline.com") {
			continue
		}
		switch strings.TrimSpace(p.mapping["google.subject"]) {
		case "assertion.sub", "assertion.oid":
			for k, v := range fx.principals {
				candidates[k] = v
			}
		case "assertion.appid", "assertion.azp":
			for k, v := range fx.apps {
				candidates[k] = v
			}
		}
	}
	if len(candidates) == 0 {
		return
	}
	if node, ok := candidates[strings.ToLower(subject)]; ok {
		a.g.AddEdge(Edge{From: gr.node, To: node, Kind: EdgeFederation, Confidence: ConfHigh, Evidence: "principal subject is this Azure identity"})
		return
	}
	a.add(Finding{
		Rule: "CW309", Severity: SevMedium, Category: CatSTS,
		Title:       "Federated subject matches no Azure identity",
		Detail:      fmt.Sprintf("The grant trusts subject %s, but no managed identity or service principal in the Azure states has that ID. If the identity was recreated its object ID changed and the grant no longer matches.", a.mask(subject)),
		Remediation: "Update the principal:// subject to the current principal (object) ID of the Azure identity.",
		Nodes:       []string{gr.node},
	})
}

func (a *analyzer) checkFICs(fx *fedIndex) {
	for _, f := range fx.fics {
		issuer := strings.TrimSpace(f.issuer)
		if !strings.HasPrefix(issuer, googleIssuer) {
			continue
		}
		if issuer != googleIssuer {
			a.add(Finding{
				Rule: "CW305", Severity: SevHigh, Category: CatSTS,
				Title:       "Google issuer in federated credential is not exact",
				Detail:      "Google ID tokens carry iss=\"https://accounts.google.com\" with no trailing slash or path; Entra compares it exactly and rejects the assertion (AADSTS70021).",
				Remediation: "Set issuer to exactly https://accounts.google.com.",
				Nodes:       []string{f.node},
			})
		}
		if len(f.audiences) > 0 && !containsFold(f.audiences, azureExchangeAud) {
			a.add(Finding{
				Rule: "CW311", Severity: SevLow, Category: CatSTS,
				Title:       "Federated credential uses a non-default audience",
				Detail:      "The GCP workload must request its ID token with exactly this audience; most SDKs default to " + azureExchangeAud + ".",
				Remediation: "Use " + azureExchangeAud + " unless your workload deliberately sets a custom audience.",
				Nodes:       []string{f.node},
			})
		}
		if node, ok := fx.saUnique[f.subject]; ok {
			a.g.AddEdge(Edge{From: f.node, To: node, Kind: EdgeFederation, Confidence: ConfHigh, Evidence: "subject is this service account's unique_id"})
			continue
		}
		if len(fx.saUnique) > 0 {
			detail := fmt.Sprintf("Subject %s is not the unique_id of any google_service_account in the provided states. Recreating a service account changes its unique_id even when the email stays the same.", a.mask(f.subject))
			if _, isEmail := fx.saEmail[strings.ToLower(f.subject)]; isEmail {
				detail = "The subject is a service account email; Google ID tokens use the numeric unique_id as sub, so this credential never matches."
			}
			a.add(Finding{
				Rule: "CW310", Severity: SevMedium, Category: CatSTS,
				Title:       "Federated credential subject matches no GCP service account",
				Detail:      detail,
				Remediation: "Set subject to the service account's unique_id (google_service_account.<name>.unique_id).",
				Nodes:       []string{f.node},
			})
		}
	}
}

// checkFederationChanges flags planned changes to the trust chain itself.
func (a *analyzer) checkFederationChanges() {
	var destructive, updates, grants []string
	for _, n := range a.g.SortedNodes() {
		if !isMutation(n.Action) {
			continue
		}
		if federationTypes[n.Type] {
			switch {
			case isDestructive(n.Action):
				destructive = append(destructive, n.ID)
			case n.Action == state.ActionUpdate:
				updates = append(updates, n.ID)
			}
		}
		if n.Action == state.ActionCreate && isIAMGrant(n.Type) {
			grants = append(grants, n.ID)
		}
	}
	if len(destructive) > 0 {
		a.add(Finding{
			Rule: "CW312", Severity: SevCritical, Category: CatSTS,
			Title: "Plan deletes or replaces identity federation resources",
			Detail: "Replacing a service account, managed identity, pool or provider changes its unique/principal ID or trust configuration. " +
				"Anything authenticating through it (including Terraform providers in this or other states) fails mid-apply, and other states that reference the old ID break until re-applied.",
			Remediation: "Verify independent working credentials that do not rely on the changing identity or trust before staging parallel identities with reviewed full, non-targeted plans. Retain the old identity and trust in configuration until all consumers have migrated and verified token exchange and required API authorization; never use targeted federation changes as a shortcut.",
			Nodes:       destructive,
		})
	}
	if len(updates) > 0 {
		a.add(Finding{
			Rule: "CW312", Severity: SevHigh, Category: CatSTS,
			Title:       "Plan updates identity federation resources",
			Detail:      "Changes to issuer, audiences, attribute mapping or conditions take effect immediately and can lock out the credentials this apply is using.",
			Remediation: "Apply these changes on their own and verify a token exchange before the rest of the plan.",
			Nodes:       updates,
		})
	}
	if len(grants) > 0 {
		a.add(Finding{
			Rule: "CW313", Severity: SevLow, Category: CatSTS,
			Title:       "Plan creates IAM grants that are eventually consistent",
			Detail:      "New GCP IAM bindings and Azure role assignments can take minutes to propagate. Resources in the same apply that rely on them may fail with 403 even though the plan succeeded.",
			Remediation: "Separate new grants from dependent operations into reviewed stages using independent working credentials with existing permissions. Verify the workload's actual token exchange and required API authorization before a full, non-targeted dependent plan; neither depends_on nor a fixed sleep guarantees propagation.",
			Nodes:       grants,
		})
	}
}

func isIAMGrant(typ string) bool {
	return typ == "azurerm_role_assignment" ||
		(strings.HasPrefix(typ, "google_") && (strings.HasSuffix(typ, "_iam_member") || strings.HasSuffix(typ, "_iam_binding")))
}

func str(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return v
	default:
		return ""
	}
}

func boolean(m map[string]any, key string) bool {
	b, _ := m[key].(bool)
	return b
}

func list(m map[string]any, key string) []any {
	l, _ := m[key].([]any)
	return l
}

func strs(m map[string]any, key string) []string {
	var out []string
	switch v := m[key].(type) {
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	case string:
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func strMap(m map[string]any, key string) map[string]string {
	src, _ := m[key].(map[string]any)
	out := make(map[string]string, len(src))
	for k, v := range src {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

func containsFold(list []string, v string) bool {
	for _, e := range list {
		if strings.EqualFold(e, v) {
			return true
		}
	}
	return false
}

func appendUniqueStr(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	list = append(list, v)
	sort.Strings(list)
	return list
}
