package migration

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/blang/semver/v4"
	rspec "github.com/opencontainers/runtime-spec/specs-go"
)

// sampleConfig is a 1.1.0-era configuration exercising baseline
// fields, including security-relevant ones.
const sampleConfig = `{
  "ociVersion": "1.1.0",
  "process": {
    "terminal": true,
    "user": {"uid": 1000, "gid": 1000},
    "args": ["sh"],
    "cwd": "/"
  },
  "root": {"path": "rootfs", "readonly": true},
  "hostname": "old-host",
  "linux": {
    "maskedPaths": ["/proc/kcore"],
    "seccomp": {
      "defaultAction": "SCMP_ACT_ERRNO"
    }
  }
}`

func mustParse(t *testing.T, v string) semver.Version {
	t.Helper()
	parsed, err := ParseVersion(v)
	if err != nil {
		t.Fatalf("ParseVersion(%q): %v", v, err)
	}
	return parsed
}

// 1. Source version identification and same-version byte preservation.
func TestConvertSameVersionPreservesBytes(t *testing.T) {
	input := []byte(sampleConfig)
	result, err := Convert(input, "1.1.0", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Changed {
		t.Errorf("Changed = true, want false for equal versions")
	}
	if string(result.Output) != string(input) {
		t.Errorf("same-version conversion altered bytes.\n got: %s\nwant: %s", result.Output, input)
	}
	if !result.SourceVersion.EQ(mustParse(t, "1.1.0")) {
		t.Errorf("source version = %s", result.SourceVersion)
	}
}

func TestConvertRejectsMissingVersion(t *testing.T) {
	if _, err := Convert([]byte(`{"process":{}}`), "1.3.0", Options{}); err == nil {
		t.Fatal("expected error for missing ociVersion")
	}
}

func TestConvertRejectsUnknownVersion(t *testing.T) {
	if _, err := Convert([]byte(`{"ociVersion":"9.9.9"}`), "1.3.0", Options{}); err == nil {
		t.Fatal("expected error for unsupported source version")
	}
}

func TestParseVersionDevSuffix(t *testing.T) {
	v, err := ParseVersion("1.3.0-dev")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v.EQ(mustParse(t, "1.3.0")) {
		t.Errorf("dev suffix not stripped: %s", v)
	}
}

// 2. Field map declares introduction versions, including security kinds.
func TestFieldIntroductions(t *testing.T) {
	records := FieldIntroductions()

	cases := []struct {
		path       string
		introduced string
		isSecurity bool
	}{
		{"linux.netDevices", "1.3.0", true},
		{"linux.memoryPolicy", "1.3.0", true},
		{"linux.intelRdt.enableMonitoring", "1.3.0", true},
		{"process.execCPUAffinity", "1.2.1", false},
		{"freebsd", "1.3.0", false},
		{"process.ioPriority", "1.1.0", true},
		{"linux.seccomp.flags", "1.1.0", true},
	}
	for _, c := range cases {
		rec, ok := records[c.path]
		if !ok {
			t.Errorf("field %q missing from introduction map", c.path)
			continue
		}
		if !rec.IntroducedIn.EQ(mustParse(t, c.introduced)) {
			t.Errorf("%s introduced in %s, want %s", c.path, rec.IntroducedIn, c.introduced)
		}
		if (rec.Kind == FieldSecurity) != c.isSecurity {
			t.Errorf("%s security = %v, want %v", c.path, rec.Kind == FieldSecurity, c.isSecurity)
		}
	}
}

// The reflected baseline must contain core paths, proving unknown
// extension detection has a real schema to compare against.
func TestKnownSchemaBaseline(t *testing.T) {
	paths := KnownFieldPaths()
	joined := strings.Join(paths, "\n")
	for _, want := range []string{
		"process",
		"process.cwd",
		"linux.seccomp.defaultAction",
		"linux.maskedPaths",
		"root.path",
		"linux.netDevices",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("known schema missing baseline path %q", want)
		}
	}
}

// 3. Upgrade carries newer fields across and stamps the new version.
func TestUpgradePreservesAllFields(t *testing.T) {
	input := []byte(`{
  "ociVersion": "1.1.0",
  "root": {"path": "rootfs"},
  "process": {"cwd": "/", "args": ["true"]},
  "domainname": "example.com"
}`)
	result, err := Convert(input, "1.3.0", Options{})
	if err != nil {
		t.Fatalf("upgrade failed: %v", err)
	}
	if !result.Changed {
		t.Error("Changed = false for upgrade")
	}
	var doc map[string]any
	if err := json.Unmarshal(result.Output, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if doc["ociVersion"] != "1.3.0" {
		t.Errorf("ociVersion = %v, want 1.3.0", doc["ociVersion"])
	}
	if _, ok := doc["domainname"]; !ok {
		t.Error("1.1.0 domainname field lost on upgrade")
	}
}

// 3b. Unknown extensions are preserved verbatim and reported.
func TestUnknownExtensionsPreserved(t *testing.T) {
	input := []byte(`{
  "ociVersion": "1.2.0",
  "root": {"path": "rootfs"},
  "process": {"cwd": "/"},
  "x-vendor-custom": {"enabled": true, "nested": [1, 2, 3]},
  "annotations": {"com.example.keep": "yes"}
}`)
	result, err := Convert(input, "1.3.0", Options{})
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}

	foundExt := false
	for _, ext := range result.UnknownExtensions {
		if ext == "x-vendor-custom" || strings.HasPrefix(ext, "x-vendor-custom.") {
			foundExt = true
		}
	}
	if !foundExt {
		t.Errorf("x-vendor-custom not reported as extension, got: %v", result.UnknownExtensions)
	}

	var doc map[string]any
	if err := json.Unmarshal(result.Output, &doc); err != nil {
		t.Fatalf("invalid output: %v", err)
	}
	custom, ok := doc["x-vendor-custom"].(map[string]any)
	if !ok {
		t.Fatalf("unknown extension dropped from output: %s", result.Output)
	}
	if custom["enabled"] != true {
		t.Errorf("extension content altered: %v", custom)
	}
	// Annotations are a known map field and must not be flagged.
	for _, ext := range result.UnknownExtensions {
		if strings.HasPrefix(ext, "annotations") {
			t.Errorf("known map field annotations flagged as extension: %s", ext)
		}
	}
}

// 3c. Downgrade reports target-unsupported fields and refuses by default.
func TestDowngradeRefusesUnsupported(t *testing.T) {
	input := []byte(`{
  "ociVersion": "1.3.0",
  "root": {"path": "rootfs"},
  "process": {"cwd": "/"},
  "linux": {
    "netDevices": {"eth0": {"name": "eth0"}},
    "memoryPolicy": {"mode": "MPOL_BIND", "nodes": "0"}
  }
}`)
	_, err := Convert(input, "1.2.0", Options{})
	if err == nil {
		t.Fatal("expected UnsupportedFieldsError, got nil")
	}
	ufErr, ok := err.(*UnsupportedFieldsError)
	if !ok {
		t.Fatalf("expected *UnsupportedFieldsError, got %T: %v", err, err)
	}

	paths := map[string]bool{}
	securityCount := 0
	for _, f := range ufErr.Fields {
		paths[f.Path] = true
		if f.Security() {
			securityCount++
		}
	}
	if !paths["linux.netDevices"] || !paths["linux.memoryPolicy"] {
		t.Errorf("expected both unsupported fields, got %v", paths)
	}
	if securityCount == 0 {
		t.Error("security-relevant fields were not marked")
	}
	if !strings.Contains(err.Error(), "security-relevant") {
		t.Errorf("error message does not highlight security fields: %v", err)
	}
}

// 3d. Explicit drop removes the fields but records them.
func TestDowngradeWithDropUnsupported(t *testing.T) {
	input := []byte(`{
  "ociVersion": "1.3.0",
  "root": {"path": "rootfs"},
  "process": {"cwd": "/"},
  "linux": {
    "netDevices": {"eth0": {"name": "eth0"}}
  },
  "freebsd": {"jail": {"name": "x"}}
}`)
	result, err := Convert(input, "1.2.0", Options{DropUnsupported: true})
	if err != nil {
		t.Fatalf("explicit drop should succeed: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(result.Output, &doc); err != nil {
		t.Fatalf("invalid output: %v", err)
	}
	if _, ok := doc["freebsd"]; ok {
		t.Error("freebsd should have been dropped")
	}
	linux, _ := doc["linux"].(map[string]any)
	if _, ok := linux["netDevices"]; ok {
		t.Error("netDevices should have been dropped")
	}
	if len(result.UnsupportedFields) == 0 {
		t.Error("dropped fields were not recorded in Result.UnsupportedFields")
	}
}

// 3e. idmap/ridmap mount options (1.2.0) are security-relevant on downgrade.
func TestMountOptionDowngrade(t *testing.T) {
	input := []byte(`{
  "ociVersion": "1.2.0",
  "root": {"path": "rootfs"},
  "process": {"cwd": "/"},
  "mounts": [
    {"destination": "/data", "source": "/host/data", "options": ["rbind", "idmap"]}
  ]
}`)
	_, err := Convert(input, "1.1.0", Options{})
	if err == nil {
		t.Fatal("expected refusal to drop idmap option")
	}
	ufErr := err.(*UnsupportedFieldsError)
	found := false
	for _, f := range ufErr.Fields {
		if f.Path == "mounts[].options.idmap" && f.Security() {
			found = true
		}
	}
	if !found {
		t.Errorf("idmap not reported as security-relevant: %v", ufErr.Fields)
	}

	// Explicit drop keeps the remaining mount options.
	result, err := Convert(input, "1.1.0", Options{DropUnsupported: true})
	if err != nil {
		t.Fatalf("drop failed: %v", err)
	}
	var doc map[string]any
	_ = json.Unmarshal(result.Output, &doc)
	mounts := doc["mounts"].([]any)
	options := mounts[0].(map[string]any)["options"].([]any)
	if len(options) != 1 || options[0] != "rbind" {
		t.Errorf("unexpected options after drop: %v", options)
	}
}

// 3f. The Intel RDT field rename is converted in both directions.
func TestIntelRdtRenameConversion(t *testing.T) {
	old := []byte(`{
  "ociVersion": "1.1.0",
  "root": {"path": "rootfs"},
  "process": {"cwd": "/"},
  "linux": {"intelRdt": {"enableCMT": true, "enableMBM": false, "closID": "a"}}
}`)
	up, err := Convert(old, "1.3.0", Options{})
	if err != nil {
		t.Fatalf("upgrade failed: %v", err)
	}
	var upDoc map[string]any
	_ = json.Unmarshal(up.Output, &upDoc)
	rdt := upDoc["linux"].(map[string]any)["intelRdt"].(map[string]any)
	if rdt["enableMonitoring"] != true {
		t.Errorf("legacy flags not folded into enableMonitoring: %v", rdt)
	}
	if _, ok := rdt["enableCMT"]; ok {
		t.Error("legacy enableCMT survived upgrade")
	}
	if rdt["closID"] != "a" {
		t.Error("unrelated intelRdt field lost during conversion")
	}

	// Round trip back to 1.1.0 expands the flag again.
	back, err := Convert(up.Output, "1.1.0", Options{})
	if err != nil {
		t.Fatalf("downgrade failed: %v", err)
	}
	var backDoc map[string]any
	_ = json.Unmarshal(back.Output, &backDoc)
	rdt2 := backDoc["linux"].(map[string]any)["intelRdt"].(map[string]any)
	if rdt2["enableCMT"] != true || rdt2["enableMBM"] != true {
		t.Errorf("enableMonitoring not expanded back to legacy flags: %v", rdt2)
	}
	if _, ok := rdt2["enableMonitoring"]; ok {
		t.Error("enableMonitoring survived downgrade")
	}
}

// 4. Canonical round trip is stable: converting A -> B -> B yields
// identical bytes, and canonicalization itself is idempotent.
func TestRoundTripStability(t *testing.T) {
	input := []byte(`{
  "ociVersion": "1.1.0",
  "root": {"path": "rootfs", "readonly": true},
  "process": {"cwd": "/", "args": ["sh"], "user": {"uid": 0, "gid": 0}},
  "annotations": {"z": "1", "a": "2"}
}`)

	first, err := Convert(input, "1.3.0", Options{})
	if err != nil {
		t.Fatalf("first conversion failed: %v", err)
	}
	second, err := Convert(first.Output, "1.3.0", Options{})
	if err != nil {
		t.Fatalf("second conversion failed: %v", err)
	}
	if second.Changed {
		t.Error("re-converting at target version should be a no-op")
	}
	if string(first.Output) != string(second.Output) {
		t.Errorf("round trip not stable.\nfirst:  %s\nsecond: %s", first.Output, second.Output)
	}

	// Canonicalize must be idempotent on its own output.
	c1, err := Canonicalize(first.Output)
	if err != nil {
		t.Fatalf("canonicalize failed: %v", err)
	}
	c2, err := Canonicalize(c1.Canonical)
	if err != nil {
		t.Fatalf("second canonicalize failed: %v", err)
	}
	if string(c1.Canonical) != string(c2.Canonical) {
		t.Error("canonicalization is not idempotent")
	}

	// Object keys must be sorted (annotations: a before z).
	idxA := strings.Index(string(c1.Canonical), `"a"`)
	idxZ := strings.Index(string(c1.Canonical), `"z"`)
	if idxA < 0 || idxZ < 0 || idxA > idxZ {
		t.Error("canonical output does not sort object keys")
	}
}

// 4b. The canonical object is the one the typed validator consumes.
func TestCanonicalAsSpec(t *testing.T) {
	c, err := Canonicalize([]byte(sampleConfig))
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	spec, err := c.AsSpec()
	if err != nil {
		t.Fatalf("AsSpec: %v", err)
	}
	if spec.Version != "1.1.0" {
		t.Errorf("typed spec version = %q", spec.Version)
	}
	if spec.Root == nil || spec.Root.Path != "rootfs" {
		t.Errorf("typed spec lost root: %+v", spec.Root)
	}

	spec2, result, err := ConvertToSpec([]byte(sampleConfig), rspec.Version)
	if err != nil {
		t.Fatalf("ConvertToSpec: %v", err)
	}
	if spec2.Version != rspec.Version {
		t.Errorf("ConvertToSpec version = %q, want %s", spec2.Version, rspec.Version)
	}
	if !result.Changed {
		t.Error("ConvertToSpec should report a changed document")
	}
}

// 5. Cross-version matrix: every supported version upgrades to current,
// and a current config without new fields downgrades to every older one.
func TestCrossVersionMatrix(t *testing.T) {
	base := `{
  "ociVersion": %q,
  "root": {"path": "rootfs"},
  "process": {"cwd": "/", "args": ["true"], "user": {"uid": 0, "gid": 0}}
}`
	for _, v := range SupportedVersions {
		input := []byte(fmt.Sprintf(base, v))
		result, err := Convert(input, rspec.Version, Options{})
		if err != nil {
			t.Errorf("upgrade %s -> %s failed: %v", v, rspec.Version, err)
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(result.Output, &doc); err != nil {
			t.Errorf("invalid output for %s: %v", v, err)
		}
		if doc["ociVersion"] != rspec.Version {
			t.Errorf("version stamp wrong for source %s: %v", v, doc["ociVersion"])
		}
	}

	// A minimal current document using only baseline fields downgrades
	// cleanly to every supported older version.
	current := []byte(`{
  "ociVersion": "1.3.0",
  "root": {"path": "rootfs"},
  "process": {"cwd": "/", "args": ["true"], "user": {"uid": 0, "gid": 0}}
}`)
	for _, target := range SupportedVersions {
		if target == rspec.Version {
			continue
		}
		result, err := Convert(current, target, Options{})
		if err != nil {
			t.Errorf("clean downgrade to %s failed: %v", target, err)
			continue
		}
		var doc map[string]any
		_ = json.Unmarshal(result.Output, &doc)
		if doc["ociVersion"] != target {
			t.Errorf("downgrade to %s stamped %v", target, doc["ociVersion"])
		}
	}
}

// Map-typed spec fields (annotations, sysctl, rdma, ...) hold
// user-supplied keys that must never be reported as unknown extensions.
func TestMapKeysAreNotExtensions(t *testing.T) {
	input := []byte(`{
  "ociVersion": "1.2.0",
  "root": {"path": "rootfs"},
  "process": {"cwd": "/"},
  "annotations": {"com.example.any-name": "v"},
  "linux": {
    "sysctl": {"net.ipv4.ip_forward": "1"},
    "resources": {"rdma": {"mlx5_0": {"hcaHandles": 3}}}
  }
}`)
	result, err := Convert(input, "1.3.0", Options{})
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}
	for _, ext := range result.UnknownExtensions {
		if strings.HasPrefix(ext, "annotations") ||
			strings.HasPrefix(ext, "linux.sysctl") ||
			strings.HasPrefix(ext, "linux.resources.rdma") {
			t.Errorf("user map key wrongly reported as extension: %s", ext)
		}
	}
}

// Nested unknown extensions deep inside known objects are preserved and
// reported with their full path.
func TestNestedExtensionPreserved(t *testing.T) {
	input := []byte(`{
  "ociVersion": "1.2.0",
  "root": {"path": "rootfs"},
  "process": {"cwd": "/", "x-deep-extension": {"nested": true}},
  "linux": {"x-linux-extension": [1, 2]}
}`)
	result, err := Convert(input, "1.3.0", Options{})
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}
	joined := strings.Join(result.UnknownExtensions, "\n")
	if !strings.Contains(joined, "process.x-deep-extension") {
		t.Errorf("nested extension not reported: %v", result.UnknownExtensions)
	}
	if !strings.Contains(joined, "linux.x-linux-extension") {
		t.Errorf("linux extension not reported: %v", result.UnknownExtensions)
	}
	var doc map[string]any
	_ = json.Unmarshal(result.Output, &doc)
	proc := doc["process"].(map[string]any)
	if _, ok := proc["x-deep-extension"]; !ok {
		t.Error("nested extension was dropped")
	}
}

// A downgrade that drops every field of a sub-object prunes the empty
// container rather than leaving an empty object behind.
func TestEmptyParentPruned(t *testing.T) {
	input := []byte(`{
  "ociVersion": "1.3.0",
  "root": {"path": "rootfs"},
  "process": {"cwd": "/"},
  "freebsd": {"jail": {"parent": "web"}}
}`)
	result, err := Convert(input, "1.2.0", Options{DropUnsupported: true})
	if err != nil {
		t.Fatalf("drop failed: %v", err)
	}
	var doc map[string]any
	_ = json.Unmarshal(result.Output, &doc)
	if _, ok := doc["freebsd"]; ok {
		t.Error("empty freebsd object was not pruned")
	}
}
