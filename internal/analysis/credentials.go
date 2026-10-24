package analysis

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type jwtClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud any    `json:"aud"`
	Exp int64  `json:"exp"`
}

func (c jwtClaims) audiences() []string {
	switch v := c.Aud.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// decodeJWT reads claims without verifying the signature; it is only used
// to check expiry and issuer/audience/subject wiring locally.
func decodeJWT(token string) (jwtClaims, bool) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return jwtClaims{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return jwtClaims{}, false
	}
	var c jwtClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return jwtClaims{}, false
	}
	return c, true
}

type externalAccount struct {
	Type                           string `json:"type"`
	Audience                       string `json:"audience"`
	SubjectTokenType               string `json:"subject_token_type"`
	ServiceAccountImpersonationURL string `json:"service_account_impersonation_url"`
	CredentialSource               struct {
		File          string `json:"file"`
		URL           string `json:"url"`
		EnvironmentID string `json:"environment_id"`
		Format        struct {
			Type                  string `json:"type"`
			SubjectTokenFieldName string `json:"subject_token_field_name"`
		} `json:"format"`
	} `json:"credential_source"`
}

func (a *analyzer) checkCredentials() {
	fx := a.buildFedIndex()
	a.checkGoogleCredentials(fx)
	a.checkAzureCredentials(fx)
}

func (a *analyzer) checkGoogleCredentials(fx *fedIndex) {
	if a.opts.Getenv("GOOGLE_OAUTH_ACCESS_TOKEN") != "" {
		a.add(Finding{
			Rule: "CW402", Severity: SevMedium, Category: CatCreds,
			Title:       "GCP uses a static access token",
			Detail:      "GOOGLE_OAUTH_ACCESS_TOKEN cannot be refreshed and lives at most one hour; long applies fail part-way with 401.",
			Remediation: "Use Application Default Credentials or an external_account (WIF) configuration instead.",
		})
	}
	var raw []byte
	source := ""
	if v := a.opts.Getenv("GOOGLE_CREDENTIALS"); strings.HasPrefix(strings.TrimSpace(v), "{") {
		raw, source = []byte(v), "GOOGLE_CREDENTIALS"
	} else {
		for _, env := range []string{"GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CREDENTIALS", "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"} {
			path := a.opts.Getenv(env)
			if path == "" {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				a.add(Finding{
					Rule: "CW404", Severity: SevHigh, Category: CatCreds,
					Title:       env + " points to an unreadable file",
					Detail:      "The Google provider will fail to authenticate at plan or apply time.",
					Remediation: "Fix the path or unset the variable.",
				})
				return
			}
			raw, source = data, env
			break
		}
	}
	if raw == nil {
		return
	}
	var cred externalAccount
	if err := json.Unmarshal(raw, &cred); err != nil {
		return
	}
	switch cred.Type {
	case "service_account":
		a.add(Finding{
			Rule: "CW407", Severity: SevLow, Category: CatCreds,
			Title:       "GCP uses a long-lived service account key",
			Detail:      source + " holds a service account key file. It works, but it bypasses the federation chain this tool checks and is a standing secret.",
			Remediation: "Prefer workload identity federation (external_account) credentials.",
		})
		return
	case "external_account":
	default:
		return
	}

	var matched *wifProvider
	provName := strings.TrimPrefix(cred.Audience, "//iam.googleapis.com/")
	for _, p := range fx.providers {
		if p.name == provName {
			matched = p
		}
	}
	if matched == nil && len(fx.providers) > 0 {
		a.add(Finding{
			Rule: "CW403", Severity: SevHigh, Category: CatCreds,
			Title:       "Credential config targets a WIF provider not in your states",
			Detail:      fmt.Sprintf("%s's audience points to provider %s, which is not in the provided GCP states (wrong project number, pool or provider ID).", source, a.mask(provName)),
			Remediation: "Regenerate the config with gcloud iam workload-identity-pools create-cred-config for the right provider.",
		})
	}
	if matched != nil && (matched.disabled || matched.deleted) {
		a.add(Finding{
			Rule: "CW403", Severity: SevCritical, Category: CatCreds,
			Title:       "Credential config uses a disabled WIF provider",
			Detail:      "Every token exchange the Google provider makes during apply will be rejected.",
			Remediation: "Re-enable the provider or switch credentials.",
			Nodes:       []string{matched.node},
		})
	}
	if url := cred.ServiceAccountImpersonationURL; url != "" && len(fx.saEmail) > 0 {
		email := url
		if i := strings.Index(email, "serviceAccounts/"); i >= 0 {
			email = email[i+len("serviceAccounts/"):]
		}
		email = strings.ToLower(strings.TrimSuffix(email, ":generateAccessToken"))
		if _, ok := fx.saEmail[email]; !ok {
			a.add(Finding{
				Rule: "CW405", Severity: SevMedium, Category: CatCreds,
				Title:       "Impersonated service account not found in GCP states",
				Detail:      fmt.Sprintf("The credential impersonates %s, which no provided state manages.", a.mask(email)),
				Remediation: "Verify the account exists and the pool principal has roles/iam.workloadIdentityUser on it.",
			})
		}
	}

	file := cred.CredentialSource.File
	if file == "" {
		return
	}
	data, err := os.ReadFile(file)
	if err != nil {
		a.add(Finding{
			Rule: "CW404", Severity: SevHigh, Category: CatCreds,
			Title:       "Subject token file for GCP federation is missing",
			Detail:      "credential_source.file does not exist or is unreadable, so the STS exchange cannot start.",
			Remediation: "Make sure the token file is written (e.g. by the CI OIDC step or Azure identity) before running Terraform.",
		})
		return
	}
	token := string(data)
	if strings.EqualFold(cred.CredentialSource.Format.Type, "json") {
		var m map[string]any
		if json.Unmarshal(data, &m) == nil {
			token, _ = m[cred.CredentialSource.Format.SubjectTokenFieldName].(string)
		}
	}
	claims, ok := decodeJWT(token)
	if !ok {
		return
	}
	a.checkExpiry("GCP subject token", claims)
	if matched != nil && matched.issuer != "" && claims.Iss != matched.issuer {
		a.add(Finding{
			Rule: "CW406", Severity: SevHigh, Category: CatCreds,
			Title:       "Subject token issuer does not match the WIF provider",
			Detail:      fmt.Sprintf("Token iss is %s but the provider trusts %s. STS compares these exactly (including trailing slash).", a.mask(claims.Iss), a.mask(matched.issuer)),
			Remediation: "Align the provider's issuer_uri with the token issuer (Entra v1 vs v2 endpoints differ).",
			Nodes:       []string{matched.node},
		})
	}
	if matched != nil && len(matched.audiences) > 0 {
		ok := false
		for _, aud := range claims.audiences() {
			if containsFold(matched.audiences, aud) {
				ok = true
			}
		}
		if !ok {
			a.add(Finding{
				Rule: "CW406", Severity: SevHigh, Category: CatCreds,
				Title:       "Subject token audience is not allowed by the WIF provider",
				Detail:      "None of the token's aud values is in allowed_audiences, so STS returns invalid_grant.",
				Remediation: "Request the Azure token for a resource listed in allowed_audiences.",
				Nodes:       []string{matched.node},
			})
		}
	}
}

func (a *analyzer) checkAzureCredentials(fx *fedIndex) {
	if a.opts.Getenv("ARM_CLIENT_SECRET") != "" || a.opts.Getenv("AZURE_CLIENT_SECRET") != "" {
		a.add(Finding{
			Rule: "CW407", Severity: SevLow, Category: CatCreds,
			Title:       "Azure uses a client secret",
			Detail:      "A long-lived client secret is set. Secrets expire on a fixed date and are a standing credential.",
			Remediation: "Prefer OIDC / federated credentials (ARM_USE_OIDC=true).",
		})
	}
	tenant := a.opts.Getenv("ARM_TENANT_ID")
	if tenant == "" {
		tenant = a.opts.Getenv("AZURE_TENANT_ID")
	}
	if tenant != "" && len(fx.tenants) > 0 && !fx.tenants[strings.ToLower(tenant)] {
		a.add(Finding{
			Rule: "CW408", Severity: SevMedium, Category: CatCreds,
			Title:       "Azure credentials target a different tenant",
			Detail:      fmt.Sprintf("ARM_TENANT_ID/AZURE_TENANT_ID is %s, which no resource in the Azure states belongs to.", a.mask(tenant)),
			Remediation: "Check that you are authenticated to the right tenant before applying.",
		})
	}

	token, label := a.opts.Getenv("ARM_OIDC_TOKEN"), "ARM_OIDC_TOKEN"
	if token == "" {
		for _, env := range []string{"ARM_OIDC_TOKEN_FILE_PATH", "AZURE_FEDERATED_TOKEN_FILE"} {
			path := a.opts.Getenv(env)
			if path == "" {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				a.add(Finding{
					Rule: "CW404", Severity: SevHigh, Category: CatCreds,
					Title:       env + " points to an unreadable file",
					Detail:      "The azurerm/azuread providers cannot perform the federated token exchange.",
					Remediation: "Make sure the federated token file exists before running Terraform.",
				})
				return
			}
			token, label = string(data), env
			break
		}
	}
	if token == "" {
		return
	}
	claims, ok := decodeJWT(token)
	if !ok {
		return
	}
	a.checkExpiry("Azure federated token ("+label+")", claims)
	if claims.Iss != googleIssuer {
		return
	}
	var googleFICs []fic
	for _, f := range fx.fics {
		if strings.HasPrefix(f.issuer, googleIssuer) {
			googleFICs = append(googleFICs, f)
		}
	}
	if len(googleFICs) == 0 {
		return
	}
	for _, f := range googleFICs {
		if f.subject == claims.Sub {
			return
		}
	}
	a.add(Finding{
		Rule: "CW406", Severity: SevHigh, Category: CatCreds,
		Title:       "Google identity token matches no federated credential",
		Detail:      "The token's sub (the GCP service account unique_id) is not the subject of any Google-issued federated credential in the Azure states, so Entra rejects the exchange (AADSTS70021).",
		Remediation: "Point the federated credential subject at this service account's unique_id.",
	})
}

func (a *analyzer) checkExpiry(label string, c jwtClaims) {
	if c.Exp == 0 {
		return
	}
	exp := time.Unix(c.Exp, 0).UTC()
	left := exp.Sub(a.opts.Now)
	a.noteCredential(left)
	switch {
	case left <= 0:
		a.add(Finding{
			Rule: "CW401", Severity: SevCritical, Category: CatCreds,
			Title:       label + " has expired",
			Detail:      fmt.Sprintf("It expired %s ago. The provider's token exchange will fail.", roundDuration(-left)),
			Remediation: "Refresh the token (re-run the OIDC step or az login) right before apply.",
		})
	case left < a.opts.ApplyWindow:
		a.add(Finding{
			Rule: "CW402", Severity: SevHigh, Category: CatCreds,
			Title:       label + " expires during the apply window",
			Detail:      fmt.Sprintf("It expires in %s, shorter than the expected apply duration of %s. Long applies fail half-way when the provider needs a fresh access token, leaving a partial apply.", roundDuration(left), roundDuration(a.opts.ApplyWindow)),
			Remediation: "Use a token source that refreshes (file rewritten by the platform, or an executable source), or refresh immediately before apply.",
		})
	}
}
