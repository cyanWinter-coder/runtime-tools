package bundle

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/runtime-tools/generate"
)

func testPlatform() string {
	if runtime.GOOS == "windows" {
		return "windows"
	}
	return "linux"
}

// newRootfs creates a minimal local root filesystem.
func newRootfs(t *testing.T) string {
	t.Helper()
	rootfs := filepath.Join(t.TempDir(), "rootfs")
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}
	return rootfs
}

// newGenerator returns a generator for the test platform with the
// rootfs recorded.
func newGenerator(t *testing.T, rootfs string) *generate.Generator {
	t.Helper()
	specgen, err := generate.New(testPlatform())
	if err != nil {
		t.Fatal(err)
	}
	specgen.SetRootPath(rootfs)
	return &specgen
}

// dirEntries lists the names of the entries in dir.
func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestBuildSpecDefaults(t *testing.T) {
	spec, err := BuildSpec(testPlatform(), "")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Version != rspec.Version {
		t.Errorf("unexpected version %q", spec.Version)
	}
	if spec.Root == nil || spec.Root.Path != "rootfs" {
		t.Errorf("unexpected root %+v", spec.Root)
	}
}

func TestBuildSpecBadTemplate(t *testing.T) {
	dir := t.TempDir()

	// Invalid JSON.
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildSpec(testPlatform(), bad); err == nil {
		t.Error("expected an error for an invalid JSON template")
	}

	// Valid JSON, but not an object.
	array := filepath.Join(dir, "array.json")
	if err := os.WriteFile(array, []byte("[1,2,3]"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildSpec(testPlatform(), array); err == nil {
		t.Error("expected an error for a non-object template")
	}

	// Missing file.
	if _, err := BuildSpec(testPlatform(), filepath.Join(dir, "missing.json")); err == nil {
		t.Error("expected an error for a missing template")
	}
}

func TestMergeTemplateEmptyValuesDoNotOverride(t *testing.T) {
	base, err := BuildSpec(testPlatform(), "")
	if err != nil {
		t.Fatal(err)
	}

	template := `{
		"hostname": "",
		"domainname": "example.com",
		"process": {
			"args": [],
			"env": null,
			"cwd": "",
			"terminal": true
		},
		"mounts": [],
		"annotations": {}
	}`
	merged, err := MergeTemplate(base, []byte(template))
	if err != nil {
		t.Fatal(err)
	}

	if merged.Hostname != base.Hostname {
		t.Errorf("empty hostname overrode the default: %q", merged.Hostname)
	}
	if merged.Domainname != "example.com" {
		t.Errorf("non-empty domainname not applied: %q", merged.Domainname)
	}
	if merged.Process == nil {
		t.Fatal("process section lost")
	}
	if len(merged.Process.Args) == 0 {
		t.Error("empty args array overrode the default args")
	}
	if len(merged.Process.Env) == 0 {
		t.Error("null env overrode the default env")
	}
	if merged.Process.Cwd != base.Process.Cwd {
		t.Errorf("empty cwd overrode the default: %q", merged.Process.Cwd)
	}
	if !merged.Process.Terminal {
		t.Error("non-empty terminal value not applied")
	}
	if len(merged.Mounts) != len(base.Mounts) {
		t.Error("empty mounts array overrode the default mounts")
	}
}

func TestMergeTemplateNonEmptyArrayReplaces(t *testing.T) {
	base, err := BuildSpec(testPlatform(), "")
	if err != nil {
		t.Fatal(err)
	}

	merged, err := MergeTemplate(base, []byte(`{"process": {"args": ["/bin/custom", "-x"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Process.Args) != 2 || merged.Process.Args[0] != "/bin/custom" {
		t.Errorf("non-empty args array did not replace the default: %v", merged.Process.Args)
	}
	// Sibling defaults in the same object survive the merge.
	if len(merged.Process.Env) == 0 {
		t.Error("default env lost during object merge")
	}
}

func TestGenerateSuccess(t *testing.T) {
	rootfs := newRootfs(t)
	parent := t.TempDir()
	target := filepath.Join(parent, "bundle")

	specgen := newGenerator(t, "rootfs-placeholder")
	path, err := Generate(context.Background(), target, specgen, Options{
		Rootfs:   rootfs,
		Platform: testPlatform(),
	})
	if err != nil {
		t.Fatal(err)
	}

	absTarget, err := filepath.Abs(target)
	if err != nil {
		t.Fatal(err)
	}
	if path != absTarget {
		t.Errorf("returned path %q, want %q", path, absTarget)
	}

	// The bundle contains exactly the validated config.json; the
	// rootfs is referenced, not copied.
	entries := dirEntries(t, target)
	if len(entries) != 1 || entries[0] != ConfigName {
		t.Errorf("unexpected bundle content: %v", entries)
	}

	data, err := os.ReadFile(filepath.Join(target, ConfigName))
	if err != nil {
		t.Fatal(err)
	}
	var spec rspec.Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(spec.Root.Path) {
		t.Errorf("root.path %q is not absolute", spec.Root.Path)
	}
	resolved, err := filepath.EvalSymlinks(rootfs)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Root.Path != resolved {
		t.Errorf("root.path %q, want %q", spec.Root.Path, resolved)
	}

	// No staging directories are left behind.
	for _, name := range dirEntries(t, parent) {
		if name != "bundle" {
			t.Errorf("unexpected leftover in parent directory: %q", name)
		}
	}
}

func TestGenerateCancelled(t *testing.T) {
	rootfs := newRootfs(t)
	parent := t.TempDir()
	target := filepath.Join(parent, "bundle")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Generate(ctx, target, newGenerator(t, rootfs), Options{Platform: testPlatform()})
	if err == nil {
		t.Fatal("expected an error for a cancelled context")
	}

	if _, statErr := os.Lstat(target); !os.IsNotExist(statErr) {
		t.Error("cancelled generation left a bundle behind")
	}
	if entries := dirEntries(t, parent); len(entries) != 0 {
		t.Errorf("cancelled generation left staging content behind: %v", entries)
	}
}

func TestGenerateExistingTarget(t *testing.T) {
	rootfs := newRootfs(t)
	parent := t.TempDir()
	target := filepath.Join(parent, "bundle")

	// A pre-existing bundle that must not be touched.
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(target, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Generate(context.Background(), target, newGenerator(t, rootfs), Options{Platform: testPlatform()})
	if err == nil {
		t.Fatal("expected an error for an existing target")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("unexpected error: %v", err)
	}

	data, readErr := os.ReadFile(sentinel)
	if readErr != nil || string(data) != "keep me" {
		t.Errorf("existing bundle was modified (data=%q, err=%v)", data, readErr)
	}
	if entries := dirEntries(t, target); len(entries) != 1 || entries[0] != "sentinel" {
		t.Errorf("existing bundle content changed: %v", entries)
	}
	if entries := dirEntries(t, parent); len(entries) != 1 || entries[0] != "bundle" {
		t.Errorf("staging content left behind: %v", entries)
	}
}

func TestGenerateInvalidConfig(t *testing.T) {
	rootfs := newRootfs(t)
	parent := t.TempDir()
	target := filepath.Join(parent, "bundle")

	// A template that parses but fails validation (ociVersion is not
	// SemVer).
	template := filepath.Join(parent, "template.json")
	if err := os.WriteFile(template, []byte(`{"ociVersion": "not-semver"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := BuildSpec(testPlatform(), template)
	if err != nil {
		t.Fatal(err)
	}
	specgen := generate.NewFromSpec(spec)
	specgen.SetRootPath(rootfs)

	_, err = Generate(context.Background(), target, &specgen, Options{Platform: testPlatform()})
	if err == nil {
		t.Fatal("expected a validation error")
	}

	if _, statErr := os.Lstat(target); !os.IsNotExist(statErr) {
		t.Error("failed validation left a bundle behind")
	}
	for _, name := range dirEntries(t, parent) {
		if name != "template.json" {
			t.Errorf("failed validation left staging content behind: %q", name)
		}
	}
}

func TestGenerateMissingRootfs(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "bundle")

	specgen := newGenerator(t, "rootfs-placeholder")
	_, err := Generate(context.Background(), target, specgen, Options{
		Rootfs:   filepath.Join(parent, "no-such-rootfs"),
		Platform: testPlatform(),
	})
	if err == nil {
		t.Fatal("expected an error for a missing rootfs")
	}
	if entries := dirEntries(t, parent); len(entries) != 0 {
		t.Errorf("failed generation left staging content behind: %v", entries)
	}
}

func TestGenerateRelativeRootfsResolvedAgainstBundle(t *testing.T) {
	// A rootfs directory in the process working directory must not
	// satisfy a relative root.path; runtimes resolve it against the
	// bundle directory.
	workdir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workdir, "rootfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(workdir, "bundle")

	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workdir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWd)

	specgen, err := generate.New(testPlatform())
	if err != nil {
		t.Fatal(err)
	}
	// Default root.path is the relative "rootfs".
	_, err = Generate(context.Background(), target, &specgen, Options{Platform: testPlatform()})
	if err == nil {
		t.Fatal("expected an error: relative root.path must resolve inside the bundle")
	}
	if _, statErr := os.Lstat(target); !os.IsNotExist(statErr) {
		t.Error("failed validation left a bundle behind")
	}
}
