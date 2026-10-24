package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var errInvalidAddress = errors.New("invalid Terraform resource address")

type Cloud string

const (
	CloudAzure      Cloud = "azure"
	CloudGCP        Cloud = "gcp"
	CloudAWS        Cloud = "aws"
	CloudKubernetes Cloud = "kubernetes"
	CloudOther      Cloud = "other"
)

// Format is the on-disk representation of a state or plan.
type Format string

const (
	FormatRaw      Format = "raw-state"
	FormatShowJSON Format = "show-json-state"
)

// State is a normalized Terraform state.
type State struct {
	Name             string
	Path             string
	Format           Format
	TerraformVersion string
	Serial           *int64
	Lineage          string
	Resources        []*Resource
	Outputs          []*Output
}

// Resource is a resource block aggregated across all of its instances.
type Resource struct {
	Address      string
	Module       string
	Mode         string
	Type         string
	Name         string
	Provider     string
	Cloud        Cloud
	Instances    []Instance
	Dependencies []string
	Tainted      bool
}

// Instance is one concrete resource instance.
type Instance struct {
	Address             string
	IndexKey            string
	Attributes          map[string]any
	Sensitive           SensitiveSet
	Dependencies        []string
	CreateBeforeDestroy bool
	Status              string
	Deposed             string
}

// Output is a root module output.
type Output struct {
	Name      string
	Sensitive bool
	Value     any
}

// SensitiveSet holds JSON-pointer-like paths whose values are sensitive.
type SensitiveSet map[string]struct{}

// IsSensitive reports whether a path or any of its ancestors is sensitive.
func (s SensitiveSet) IsSensitive(pointer string) bool {
	if len(s) == 0 {
		return false
	}
	if _, ok := s[pointer]; ok {
		return true
	}
	for p := range s {
		if p != "" && strings.HasPrefix(pointer, p+"/") {
			return true
		}
	}
	return false
}

// Leaf is a string or numeric value extracted from state or outputs.
type Leaf struct {
	State   string
	Address string // resource address or output:<name>
	Path    string // JSON-pointer-like path
	Key     string
	Value   string
	Hash    string
}

// AddResource appends a resource and merges instance dependencies.
func (s *State) AddResource(r *Resource) {
	for _, inst := range r.Instances {
		r.Dependencies = appendUnique(r.Dependencies, inst.Dependencies...)
	}
	s.Resources = append(s.Resources, r)
}

// ProviderShort returns the short provider name.
func (r *Resource) ProviderShort() string {
	return ProviderShort(r.Provider)
}

// OutputAddrs returns output names represented in the state.
func (s *State) OutputAddrs() map[string]bool {
	out := make(map[string]bool, len(s.Outputs))
	for _, o := range s.Outputs {
		out[o.Name] = true
	}
	return out
}

// ResourceByAddress finds a normalized resource address in this state.
func (s *State) ResourceByAddress(addr string) *Resource {
	for _, r := range s.Resources {
		if r.Address == addr {
			return r
		}
	}
	return nil
}

// AllStringLeaves walks resource instances and returns leaf values whose key is
// identity-like, or whose value looks like a cloud resource identifier. It
// skips sensitive paths.
func (r *Resource) IdentityLeaves(stateName string) []Leaf {
	var leaves []Leaf
	for _, inst := range r.Instances {
		walkValue(inst.Attributes, "", func(path string, v any) {
			if inst.Sensitive.IsSensitive(path) {
				return
			}
			s, ok := scalarString(v)
			if !ok {
				return
			}
			key := lastKey(path)
			if !identityLike(key, s) {
				return
			}
			leaves = append(leaves, Leaf{
				State:   stateName,
				Address: r.Address,
				Path:    path,
				Key:     key,
				Value:   s,
				Hash:    HashValue(s),
			})
		})
	}
	return leaves
}

// OutputLeaves returns all non-sensitive scalar leaves of an output.
func OutputLeaves(stateName string, o *Output) []Leaf {
	if o == nil || o.Sensitive {
		return nil
	}
	var leaves []Leaf
	walkValue(o.Value, "", func(path string, v any) {
		s, ok := scalarString(v)
		if !ok {
			return
		}
		leaves = append(leaves, Leaf{
			State:   stateName,
			Address: "output:" + o.Name,
			Path:    path,
			Key:     lastKey(path),
			Value:   s,
			Hash:    HashValue(s),
		})
	})
	return leaves
}

// AttrString returns a top-level string attribute from the first instance.
func (r *Resource) AttrString(key string) string {
	if r == nil || len(r.Instances) == 0 {
		return ""
	}
	v, ok := r.Instances[0].Attributes[key]
	if !ok {
		return ""
	}
	s, _ := scalarString(v)
	return s
}

// AttrAny returns a top-level attribute from the first instance.
func (r *Resource) AttrAny(key string) any {
	if r == nil || len(r.Instances) == 0 {
		return nil
	}
	return r.Instances[0].Attributes[key]
}

// AttrStrings returns a top-level attribute as a string slice.
func (r *Resource) AttrStrings(key string) []string {
	v := r.AttrAny(key)
	if v == nil {
		return nil
	}
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := scalarString(e); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return x
	default:
		if s, ok := scalarString(x); ok {
			return []string{s}
		}
	}
	return nil
}

// AttrMapStrings returns a top-level map attribute as map[string]string.
func (r *Resource) AttrMapStrings(key string) map[string]string {
	v := r.AttrAny(key)
	if v == nil {
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, e := range m {
		if s, ok := scalarString(e); ok {
			out[k] = s
		}
	}
	return out
}

// CurrentIDs returns a fingerprint of top-level id attributes for each
// resource. It is used to compare plan prior state with a provided state
// without exposing values.
func (s *State) CurrentIDs() map[string]string {
	out := make(map[string]string, len(s.Resources))
	for _, r := range s.Resources {
		if len(r.Instances) == 0 {
			continue
		}
		if id := r.AttrString("id"); id != "" {
			out[r.Address] = HashValue(id)
		}
	}
	return out
}

// InstanceIDs returns id fingerprints keyed by instance address. It is used
// to compare a provided state with the prior state embedded in a plan.
func (s *State) InstanceIDs() map[string]string {
	out := make(map[string]string)
	for _, r := range s.Resources {
		for _, inst := range r.Instances {
			v, ok := inst.Attributes["id"]
			if !ok {
				continue
			}
			id, ok := scalarString(v)
			if !ok || id == "" {
				continue
			}
			out[inst.Address] = HashValue(id)
		}
	}
	return out
}

// RemoteStateOutputs returns the outputs captured by a
// terraform_remote_state data source. Raw state stores dynamic values as
// {"value": ..., "type": ...}; show-json stores the value directly.
func (r *Resource) RemoteStateOutputs() map[string]any {
	if r == nil || r.Type != "terraform_remote_state" {
		return nil
	}
	v := r.AttrAny("outputs")
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	if inner, ok := m["value"].(map[string]any); ok && len(m) <= 2 {
		if _, hasType := m["type"]; hasType || len(m) == 1 {
			return inner
		}
	}
	return m
}

// HashValue hashes a normalized value with SHA-256.
func HashValue(v string) string {
	sum := sha256.Sum256([]byte(NormalizeValue(v)))
	return hex.EncodeToString(sum[:])
}

// NormalizeValue normalizes identifiers for matching without exposing them.
func NormalizeValue(v string) string {
	v = strings.TrimSpace(v)
	lower := strings.ToLower(v)
	if looksLikeUUID(lower) || strings.HasPrefix(lower, "/subscriptions/") ||
		strings.HasPrefix(lower, "https://sts.windows.net/") ||
		strings.HasPrefix(lower, "https://login.microsoftonline.com/") {
		return lower
	}
	return v
}

func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func scalarString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, x != ""
	case json.Number:
		return x.String(), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case int:
		return strconv.Itoa(x), true
	case int64:
		return strconv.FormatInt(x, 10), true
	default:
		return "", false
	}
}

func walkValue(v any, pointer string, fn func(path string, value any)) {
	switch x := v.(type) {
	case string, float64, json.Number, int, int64:
		fn(pointer, x)
	case []any:
		for i, e := range x {
			walkValue(e, pointer+"/"+strconv.Itoa(i), fn)
		}
	case map[string]any:
		for k, e := range x {
			walkValue(e, pointer+"/"+escapePointer(k), fn)
		}
	}
}

func escapePointer(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	return strings.ReplaceAll(s, "/", "~1")
}

func lastKey(pointer string) string {
	if pointer == "" {
		return ""
	}
	parts := strings.Split(pointer, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == "" {
			continue
		}
		if _, err := strconv.Atoi(parts[i]); err == nil {
			continue
		}
		return strings.ToLower(parts[i])
	}
	return ""
}

var identityKeys = map[string]bool{
	"id": true, "client_id": true, "application_id": true, "tenant_id": true,
	"principal_id": true, "object_id": true, "service_account_id": true,
	"unique_id": true, "email": true, "issuer": true, "issuer_uri": true,
	"audience": true, "allowed_audiences": true, "identifier_uris": true,
	"workload_identity_pool": true, "workload_identity_pool_provider": true,
	"member": true, "members": true, "role": true, "self_link": true,
	"resource_id": true, "subscription_id": true, "project": true,
	"project_id": true, "scope": true, "name": false, "display_name": false,
	"resource_group_name": false, "location": false, "region": false,
	"zone": false, "state": false, "status": false, "password": true,
	"secret": true, "private_key": true,
}

func identityLike(key, value string) bool {
	if key == "" {
		return false
	}
	// Never turn secret-like fields into cross-state graph edges.
	if strings.Contains(key, "secret") || strings.Contains(key, "password") ||
		strings.Contains(key, "private_key") || strings.Contains(key, "token") {
		return false
	}
	if identityKeys[key] && len(value) >= 4 {
		return true
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "/subscriptions/") ||
		strings.HasPrefix(lower, "//iam.googleapis.com/") ||
		strings.HasPrefix(lower, "principal://") ||
		strings.HasPrefix(lower, "principalSet://") ||
		strings.HasPrefix(lower, "https://www.googleapis.com/") ||
		strings.HasPrefix(lower, "https://sts.windows.net/") ||
		strings.HasPrefix(lower, "https://login.microsoftonline.com/") {
		return true
	}
	if strings.Contains(key, "email") && strings.Contains(value, "@") {
		return true
	}
	return false
}

func appendUnique(dst []string, values ...string) []string {
	seen := make(map[string]struct{}, len(dst))
	for _, v := range dst {
		seen[v] = struct{}{}
	}
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		dst = append(dst, v)
	}
	return dst
}

// AddOutput appends an output if not already present.
func (s *State) AddOutput(o *Output) {
	s.Outputs = append(s.Outputs, o)
}

// String returns a short debugging label that never includes attributes.
func (s *State) String() string {
	return fmt.Sprintf("%s (%d resources)", s.Name, len(s.Resources))
}
