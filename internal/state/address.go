package state

import (
	"strings"
)

// AddressInfo is the parsed form of a Terraform resource address.
type AddressInfo struct {
	Module  string // module path, including module instance keys
	Mode    string // "managed" or "data"
	Type    string
	Name    string
	Address string // normalized: no resource instance key
}

// NormalizeAddress removes a trailing resource instance key while preserving
// module instance keys. Example:
//
//	module.vpc[0].aws_subnet.a["x"] -> module.vpc[0].aws_subnet.a
//
// It returns false for addresses that do not identify a resource or data
// source (for example module outputs).
func NormalizeAddress(addr string) (string, bool) {
	info, err := ParseAddress(addr)
	if err != nil {
		return "", false
	}
	return info.Address, true
}

// ParseAddress parses a Terraform resource address. Address keys may contain
// dots, so splitting on "." alone is not sufficient.
func ParseAddress(addr string) (AddressInfo, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return AddressInfo{}, errInvalidAddress
	}

	parts := splitAddress(addr)
	if len(parts) < 2 {
		return AddressInfo{}, errInvalidAddress
	}

	mode := "managed"
	resourceStart := len(parts) - 2
	// "module.data.x.y" is a managed resource in a module named "data".
	if d := len(parts) - 3; d >= 0 && parts[d] == "data" && (d == 0 || parts[d-1] != "module") {
		mode = "data"
		resourceStart = d
	}

	typeIdx := resourceStart
	if mode == "data" {
		typeIdx++
	}
	if strings.ContainsRune(parts[typeIdx], '[') {
		return AddressInfo{}, errInvalidAddress
	}
	typ := parts[typeIdx]
	name := stripInstanceKey(parts[typeIdx+1])
	if !validIdent(typ) || !validIdent(name) {
		return AddressInfo{}, errInvalidAddress
	}

	moduleParts := parts[:resourceStart]
	if len(moduleParts)%2 != 0 {
		return AddressInfo{}, errInvalidAddress
	}
	for i := 0; i < len(moduleParts); i += 2 {
		if moduleParts[i] != "module" || !identChars(stripInstanceKey(moduleParts[i+1])) {
			return AddressInfo{}, errInvalidAddress
		}
	}
	module := strings.Join(moduleParts, ".")

	var b strings.Builder
	if module != "" {
		b.WriteString(module)
		b.WriteByte('.')
	}
	if mode == "data" {
		b.WriteString("data.")
	}
	b.WriteString(typ)
	b.WriteByte('.')
	b.WriteString(name)

	return AddressInfo{
		Module:  module,
		Mode:    mode,
		Type:    typ,
		Name:    name,
		Address: b.String(),
	}, nil
}

// splitAddress splits on dots outside brackets and quoted keys.
func splitAddress(addr string) []string {
	var parts []string
	start := 0
	inBracket := false
	var quote byte
	escaped := false

	for i := 0; i < len(addr); i++ {
		c := addr[i]
		if escaped {
			escaped = false
			continue
		}
		if quote != 0 {
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
		case '[':
			inBracket = true
		case ']':
			inBracket = false
		case '.':
			if !inBracket {
				parts = append(parts, addr[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, addr[start:])
	return parts
}

func stripInstanceKey(s string) string {
	if i := strings.IndexByte(s, '['); i >= 0 {
		return s[:i]
	}
	return s
}

func validIdent(s string) bool {
	if s == "module" || s == "data" {
		return false
	}
	return identChars(s)
}

func identChars(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

// ProviderShort returns the provider's short name, e.g. "azurerm".
func ProviderShort(provider string) string {
	p := strings.TrimSpace(provider)
	if p == "" {
		return ""
	}
	// Raw state: provider["registry.terraform.io/hashicorp/azurerm"]
	if i := strings.Index(p, "\""); i >= 0 {
		if j := strings.Index(p[i+1:], "\""); j >= 0 {
			p = p[i+1 : i+1+j]
		}
	}
	p = strings.TrimPrefix(p, "provider.")
	p = strings.TrimPrefix(p, `provider["`)
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	p = strings.Trim(p, `"]`)
	return p
}

// CloudFor maps a provider or resource type to a cloud family.
func CloudFor(resourceType, provider string) Cloud {
	p := strings.ToLower(ProviderShort(provider))
	switch {
	case p == "azurerm", p == "azuread", p == "azapi", p == "azurestack":
		return CloudAzure
	case p == "google", p == "google-beta", p == "googleworkspace":
		return CloudGCP
	case p == "aws", p == "awscc":
		return CloudAWS
	case p == "kubernetes", p == "helm", p == "kubectl", p == "k8s":
		return CloudKubernetes
	}

	t := resourceType
	switch {
	case strings.HasPrefix(t, "azurerm_"), strings.HasPrefix(t, "azuread_"),
		strings.HasPrefix(t, "azapi_"), strings.HasPrefix(t, "azurestack_"):
		return CloudAzure
	case strings.HasPrefix(t, "google_"), strings.HasPrefix(t, "google-beta_"):
		return CloudGCP
	case strings.HasPrefix(t, "aws_"), strings.HasPrefix(t, "awscc_"):
		return CloudAWS
	case strings.HasPrefix(t, "kubernetes_"), strings.HasPrefix(t, "helm_"),
		strings.HasPrefix(t, "kubectl_"), strings.HasPrefix(t, "k8s_"):
		return CloudKubernetes
	default:
		return CloudOther
	}
}
