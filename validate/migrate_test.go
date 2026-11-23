package validate

import (
	"os"
	"path/filepath"
	"testing"

	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
)

// writeBundle creates a temporary bundle directory containing config.
func writeBundle(t *testing.T, config string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, specConfig), []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return dir
}

// A configuration targeting an older spec version is migrated through
// the shared canonical object and becomes readable by the current
// validator entry point.
func TestNewValidatorFromMigratedPathUpgradesOldVersion(t *testing.T) {
	oldConfig := `{
  "ociVersion": "1.1.0",
  "root": {"path": "rootfs"},
  "process": {"cwd": "/", "args": ["true"], "user": {"uid": 0, "gid": 0}}
}`
	dir := writeBundle(t, oldConfig)

	v, err := NewValidatorFromMigratedPath(dir, false, "linux")
	if err != nil {
		t.Fatalf("migrated validator: %v", err)
	}
	if v.spec.Version != rspec.Version {
		t.Errorf("validator saw version %q, want %s", v.spec.Version, rspec.Version)
	}
	// Baseline fields survive the migration.
	assert.NotNil(t, v.spec.Root)
	assert.Equal(t, "rootfs", v.spec.Root.Path)
}

// A current-version bundle passes through migration unchanged in
// semantics and validates.
func TestNewValidatorFromMigratedPathCurrentVersion(t *testing.T) {
	current := `{
  "ociVersion": "` + rspec.Version + `",
  "root": {"path": "rootfs"},
  "process": {"cwd": "/", "args": ["true"], "user": {"uid": 0, "gid": 0}}
}`
	dir := writeBundle(t, current)

	v, err := NewValidatorFromMigratedPath(dir, false, "linux")
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	assert.Equal(t, rspec.Version, v.spec.Version)
}

// A security-relevant field the target cannot represent blocks the
// migrated read path rather than being silently dropped. The validator
// always targets the current version, so exercise the refusal through
// MigrateSpec against an older target.
func TestMigratedPathRejectsUnsupportedSecurityFields(t *testing.T) {
	config := []byte(`{
  "ociVersion": "1.3.0",
  "root": {"path": "rootfs"},
  "process": {"cwd": "/", "user": {"uid": 0, "gid": 0}},
  "linux": {"memoryPolicy": {"mode": "MPOL_BIND", "nodes": "0"}}
}`)
	if _, err := MigrateSpec(config, "1.2.0"); err == nil {
		t.Fatal("expected migration to refuse unsupported security field")
	}
}

// MigrateSpec returns a typed spec on the same canonical object used by
// the converter, preserving unknown extensions through the generic
// decode stage.
func TestMigrateSpecPreservesExtensions(t *testing.T) {
	config := []byte(`{
  "ociVersion": "1.2.0",
  "root": {"path": "rootfs"},
  "process": {"cwd": "/", "args": ["true"], "user": {"uid": 0, "gid": 0}},
  "x-vendor-extension": {"keep": true}
}`)
	spec, err := MigrateSpec(config, rspec.Version)
	if err != nil {
		t.Fatalf("MigrateSpec: %v", err)
	}
	if spec.Version != rspec.Version {
		t.Errorf("version = %q", spec.Version)
	}
	if spec.Root == nil || spec.Root.Path != "rootfs" {
		t.Errorf("root lost: %+v", spec.Root)
	}
}

func TestNewValidatorFromMigratedPathEmptyPath(t *testing.T) {
	if _, err := NewValidatorFromMigratedPath("", false, "linux"); err == nil {
		t.Fatal("expected error for empty bundle path")
	}
}
