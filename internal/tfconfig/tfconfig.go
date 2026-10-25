// Package tfconfig reads a Terraform root module's native-syntax .tf files only
// (.tf.json is not supported), following local module sources recursively, to
// report lifecycle flags, count/for_each presence, terraform_remote_state
// backend hints and required_version. Expressions are never evaluated: only
// static literals are recorded, and only whitelisted backend config keys are
// read, so credentials can never reach reports.
package tfconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// remoteStateDataType is the only data source type Load inspects.
const remoteStateDataType = "terraform_remote_state"

// backendConfigWhitelist lists the only keys that may ever be copied out of a
// terraform_remote_state backend config object. Every other key (for example
// conn_string, access_key, secret_key, password or token) may hold
// credentials and must never be read, stored or logged, even when literal.
var backendConfigWhitelist = []string{"workspace", "schema"}

// topLevelSchema describes the top-level blocks Load understands. Every other
// block type (module, variable, output, provider, locals, ...) is silently
// ignored.
var topLevelSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "terraform"},
		{Type: "resource", LabelNames: []string{"type", "name"}},
		{Type: "data", LabelNames: []string{"type", "name"}},
		{Type: "module", LabelNames: []string{"name"}},
	},
}

// resourceSchema selects the resource arguments and blocks Load inspects;
// provider, depends_on, provisioner and every other item stay untouched in the
// remaining body.
var resourceSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "count"},
		{Name: "for_each"},
	},
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "lifecycle"},
	},
}

// lifecycleSchema selects the lifecycle arguments Load inspects.
var lifecycleSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "prevent_destroy"},
		{Name: "create_before_destroy"},
	},
}

// remoteStateSchema selects the terraform_remote_state arguments Load inspects.
var remoteStateSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "backend"},
		{Name: "config"},
	},
}

// moduleSchema selects the module arguments Load inspects; count, for_each,
// providers and every other item stay untouched in the remaining body.
var moduleSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "source"},
	},
}

// terraformSchema selects the terraform block arguments Load inspects; the
// nested backend and required_providers blocks stay untouched and ignored.
var terraformSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "required_version"},
	},
}

// Config is the merged, read-only view of a Terraform root module directory
// and the local modules it includes.
type Config struct {
	Path string
	// RequiredVersion is the literal terraform.required_version constraint.
	RequiredVersion string
	// Resources maps resource addresses to the facts gathered for them:
	// "aws_instance.web" in the root module, "module.vpc.aws_instance.web"
	// inside a local module. Module instance keys are never recorded, so
	// matching is by key-stripped address.
	Resources map[string]Resource
	// RemoteStates maps full data addresses
	// "data.terraform_remote_state.prod" (root) or
	// "module.vpc.data.terraform_remote_state.prod" (local module) to the
	// facts gathered for them.
	RemoteStates map[string]RemoteState
	// UnresolvedModules is true when at least one module block's source could
	// not be followed (registry, remote or dynamic). Facts from such modules
	// are absent, so "not in the configuration" claims are not certain.
	UnresolvedModules bool
}

// Resource describes the lifecycle and instance-count posture of one resource
// block.
type Resource struct {
	PreventDestroy      bool
	CreateBeforeDestroy bool
	// Count and ForEach record argument presence only; they are never
	// evaluated, so a dynamic expression still sets them.
	Count   bool
	ForEach bool
}

// RemoteState describes the backend of one terraform_remote_state data source.
type RemoteState struct {
	// Backend is the literal backend keyword, e.g. "pg", "s3", "azurerm".
	Backend string
	// Workspace is the literal workspace only; empty when it is an
	// expression or absent.
	Workspace string
}

// Load parses every native-syntax .tf file in dir (the root module; .tf.json is
// ignored) and follows local module sources ("./x", "../x", optionally with a
// "//subdir" suffix) recursively, merging the results, with later files
// overwriting duplicate addresses. It returns a non-nil, empty Config when dir
// holds no .tf files. Only parse errors, unreadable local module directories
// and module cycles are fatal; anything Load does not understand is silently
// skipped.
func Load(dir string) (*Config, error) {
	cfg := &Config{
		Path:         dir,
		Resources:    make(map[string]Resource),
		RemoteStates: make(map[string]RemoteState),
	}
	if err := loadDir(dir, "", cfg, nil); err != nil {
		return nil, err
	}
	return cfg, nil
}

// loadDir parses one module directory. prefix is the module path accumulated
// for nested modules ("" for the root module, "module.vpc." one level in) and
// ancestors holds the cleaned absolute paths of enclosing module directories
// for cycle detection; the same module may appear under several prefixes, but
// never inside its own ancestry.
func loadDir(dir, prefix string, cfg *Config, ancestors []string) error {
	clean, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	clean = filepath.Clean(clean)
	for _, a := range ancestors {
		if a == clean {
			return fmt.Errorf("module cycle through %s", dir)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if prefix == "" {
			return fmt.Errorf("read directory: %w", err)
		}
		return fmt.Errorf("read module directory %q: %w", strings.TrimSuffix(prefix, "."), err)
	}

	// os.ReadDir sorts by filename, so files are merged deterministically in
	// alphabetical order and later files overwrite duplicate addresses.
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tf") {
			continue
		}

		filename := entry.Name()
		src, err := os.ReadFile(filepath.Join(dir, filename))
		if err != nil {
			return fmt.Errorf("read %s: %w", filename, err)
		}

		file, diags := hclsyntax.ParseConfig(src, filename, hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			return parseError(filename, diags)
		}

		// Blocks outside topLevelSchema (variable, output, provider, locals,
		// ...) are excluded from the content and only produce "unsupported
		// block" diagnostics, which are dropped here: that is how they are
		// silently ignored. Only parse errors are fatal.
		content, _ := file.Body.Content(topLevelSchema)
		for _, block := range content.Blocks {
			switch block.Type {
			case "terraform":
				loadTerraformBlock(block, cfg)
			case "resource":
				cfg.Resources[prefix+strings.Join(block.Labels, ".")] = loadResource(block)
			case "data":
				if len(block.Labels) == 2 && block.Labels[0] == remoteStateDataType {
					cfg.RemoteStates[prefix+"data."+strings.Join(block.Labels, ".")] = loadRemoteState(block)
				}
			case "module":
				if err := loadModuleBlock(block, dir, prefix, cfg, ancestors, clean); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// loadModuleBlock follows one module block's local source directory. Registry,
// remote and dynamic sources cannot be read offline; they set
// UnresolvedModules so "not in the configuration" claims can be caveated
// instead of wrong, and nothing from them is recorded.
func loadModuleBlock(block *hcl.Block, dir, prefix string, cfg *Config, ancestors []string, parentClean string) error {
	content, _, _ := block.Body.PartialContent(moduleSchema)
	source, ok := staticString(content.Attributes["source"])
	if !ok || (!strings.HasPrefix(source, "./") && !strings.HasPrefix(source, "../")) {
		cfg.UnresolvedModules = true
		return nil
	}
	if i := strings.Index(source, "//"); i >= 0 {
		source = source[:i] + string(filepath.Separator) + strings.ReplaceAll(source[i+2:], "/", string(filepath.Separator))
	}
	childDir := filepath.Clean(filepath.Join(dir, source))

	next := make([]string, len(ancestors), len(ancestors)+1)
	copy(next, ancestors)
	next = append(next, parentClean)
	return loadDir(childDir, prefix+"module."+block.Labels[0]+".", cfg, next)
}

// parseError turns parse diagnostics into an error naming the offending file.
func parseError(filename string, diags hcl.Diagnostics) error {
	summaries := make([]string, 0, len(diags))
	for _, diag := range diags {
		if diag.Severity == hcl.DiagError {
			summaries = append(summaries, diag.Summary)
		}
	}
	return fmt.Errorf("parse %s: %s", filename, strings.Join(summaries, "; "))
}

// loadTerraformBlock records a static required_version constraint. The
// backend block nested inside terraform is out of scope and stays ignored.
func loadTerraformBlock(block *hcl.Block, cfg *Config) {
	content, _, _ := block.Body.PartialContent(terraformSchema)
	if s, ok := staticString(content.Attributes["required_version"]); ok {
		cfg.RequiredVersion = s
	}
}

// loadResource gathers count/for_each presence (never evaluated) and the
// literal lifecycle flags. provisioner blocks are ignored entirely.
func loadResource(block *hcl.Block) Resource {
	var res Resource

	content, _, _ := block.Body.PartialContent(resourceSchema)
	if _, ok := content.Attributes["count"]; ok {
		res.Count = true
	}
	if _, ok := content.Attributes["for_each"]; ok {
		res.ForEach = true
	}

	for _, lc := range content.Blocks {
		if lc.Type != "lifecycle" {
			continue
		}
		// Other lifecycle arguments (ignore_changes, preconditions, ...)
		// only produce diagnostics here, which are dropped: only parse
		// errors are fatal.
		lcContent, _ := lc.Body.Content(lifecycleSchema)
		if v, ok := staticBool(lcContent.Attributes["prevent_destroy"]); ok {
			res.PreventDestroy = v
		}
		if v, ok := staticBool(lcContent.Attributes["create_before_destroy"]); ok {
			res.CreateBeforeDestroy = v
		}
	}

	return res
}

// loadRemoteState extracts the backend keyword and, from a static object
// literal config, the whitelisted keys. A config value expression is evaluated
// only after its key name passes the whitelist, so conn_string, access_key,
// secret_key, password, token and every other key is never read, stored or
// logged, even when its value is a literal. A config that is not an object
// literal is skipped silently.
func loadRemoteState(block *hcl.Block) RemoteState {
	var rs RemoteState

	content, _, _ := block.Body.PartialContent(remoteStateSchema)
	if attr, ok := content.Attributes["backend"]; ok {
		// A bare keyword (backend = pg) first, a quoted literal string
		// (backend = "s3") as fallback; anything dynamic is skipped.
		if kw := hcl.ExprAsKeyword(attr.Expr); kw != "" {
			rs.Backend = kw
		} else if s, ok := staticString(attr); ok {
			rs.Backend = s
		}
	}

	attr, ok := content.Attributes["config"]
	if !ok {
		return rs
	}
	obj, isObject := attr.Expr.(*hclsyntax.ObjectConsExpr)
	if !isObject {
		return rs
	}
	for _, item := range obj.Items {
		kv, diags := item.KeyExpr.Value(nil)
		if len(diags) != 0 || !kv.IsKnown() || kv.IsNull() || kv.Type() != cty.String {
			continue
		}
		if !slices.Contains(backendConfigWhitelist, kv.AsString()) {
			continue
		}
		if kv.AsString() == "workspace" {
			if s, ok := staticExprString(item.ValueExpr); ok {
				rs.Workspace = s
			}
		}
	}
	return rs
}

// staticBool reports the literal boolean value of attr. ok is false when attr
// is absent or is anything other than a static boolean.
func staticBool(attr *hcl.Attribute) (val bool, ok bool) {
	if attr == nil {
		return false, false
	}
	v, diags := attr.Expr.Value(nil)
	if len(diags) != 0 || !v.IsKnown() || v.IsNull() || v.Type() != cty.Bool {
		return false, false
	}
	return v.True(), true
}

// staticString reports the literal string value of attr. ok is false when
// attr is absent or is anything other than a static string.
func staticString(attr *hcl.Attribute) (val string, ok bool) {
	if attr == nil {
		return "", false
	}
	return staticExprString(attr.Expr)
}

// staticExprString reports the literal string value of expr. ok is false when
// expr is anything other than a static string.
func staticExprString(expr hcl.Expression) (val string, ok bool) {
	v, diags := expr.Value(nil)
	if len(diags) != 0 || !v.IsKnown() || v.IsNull() || v.Type() != cty.String {
		return "", false
	}
	return v.AsString(), true
}
