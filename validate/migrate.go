package validate

import (
	"fmt"
	"os"
	"path/filepath"
	"unicode/utf8"

	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/runtime-tools/migration"
)

// NewValidatorFromMigratedPath reads a bundle configuration that may
// target any supported specification version, migrates it to the
// version the validator is built against, and returns a Validator over
// the migrated document.
//
// Migration and validation share the migration.CanonicalSpec: the
// generic object is normalized once, converted in place, and only then
// decoded into the typed rspec.Spec the checks run on. There is no
// second parse that could interpret the bytes differently.
//
// If the configuration already targets the current version its bytes
// pass through untouched. If it uses fields the target version cannot
// represent, the migration is refused (nothing is dropped silently) and
// the UnsupportedFieldsError is returned to the caller.
func NewValidatorFromMigratedPath(bundlePath string, hostSpecific bool, platform string) (Validator, error) {
	if bundlePath == "" {
		return Validator{}, fmt.Errorf("bundle path shouldn't be empty")
	}
	if _, err := os.Stat(bundlePath); err != nil {
		return Validator{}, err
	}

	configPath := filepath.Join(bundlePath, specConfig)
	content, err := os.ReadFile(configPath)
	if err != nil {
		return Validator{}, err
	}
	if !utf8.Valid(content) {
		return Validator{}, fmt.Errorf("%q is not encoded in UTF-8", configPath)
	}

	spec, err := MigrateSpec(content, rspec.Version)
	if err != nil {
		return Validator{}, err
	}
	return NewValidator(&spec, bundlePath, hostSpecific, platform)
}

// MigrateSpec converts raw configuration bytes to targetVersion using
// the shared canonical representation and returns the typed spec the
// rest of the toolchain consumes. It never silently drops
// target-unsupported fields.
func MigrateSpec(content []byte, targetVersion string) (rspec.Spec, error) {
	spec, _, err := migration.ConvertToSpec(content, targetVersion)
	return spec, err
}
