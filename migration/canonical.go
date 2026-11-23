package migration

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/blang/semver/v4"
	rspec "github.com/opencontainers/runtime-spec/specs-go"
)

// CanonicalSpec is the single normalized representation shared by
// migration and validation. It is produced once from raw configuration
// bytes and consumed by both the converter and the validator, so the two
// can never disagree about which document they are operating on.
type CanonicalSpec struct {
	// Version is the parsed ociVersion declared by the document.
	Version semver.Version
	// Document is the generic JSON form with sorted object keys, used
	// for field-level migration and capability checks.
	Document map[string]any
	// Canonical is the stable byte encoding of Document. Re-encoding the
	// document yields identical bytes (the round-trip idempotence
	// guarantee).
	Canonical []byte
}

// Canonicalize decodes raw configuration bytes into the shared
// normalized representation. It:
//   - identifies the source version from ociVersion (and fails without
//     one, rather than guessing),
//   - decodes through map[string]any with json.Number so integer
//     precision and unknown extensions are preserved,
//   - re-encodes with sorted keys and fixed indentation.
//
// Both Convert and the validator build on this representation,
// guaranteeing they see the same object.
func Canonicalize(raw []byte) (*CanonicalSpec, error) {
	var probe struct {
		OCIVersion string `json:"ociVersion"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("decoding configuration: %w", err)
	}
	if probe.OCIVersion == "" {
		return nil, fmt.Errorf("configuration has no ociVersion field; cannot identify source version")
	}
	version, err := ParseVersion(probe.OCIVersion)
	if err != nil {
		return nil, err
	}

	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decoding configuration: %w", err)
	}

	canonical, err := canonicalJSON(doc)
	if err != nil {
		return nil, err
	}
	return &CanonicalSpec{
		Version:   version,
		Document:  doc,
		Canonical: canonical,
	}, nil
}

// Marshal renders the canonical document back to stable bytes.
func (c *CanonicalSpec) Marshal() ([]byte, error) {
	return canonicalJSON(c.Document)
}

// AsSpec decodes the canonical document into the typed specs-go.Spec
// used by the rest of the toolchain. Because it runs on the exact same
// generic object as migration, validation rules run against migrated
// data without a second, divergent parse.
func (c *CanonicalSpec) AsSpec() (rspec.Spec, error) {
	raw, err := c.Marshal()
	if err != nil {
		return rspec.Spec{}, err
	}
	var s rspec.Spec
	if err := json.Unmarshal(raw, &s); err != nil {
		return rspec.Spec{}, err
	}
	return s, nil
}

// ConvertToSpec runs Convert and then decodes the migrated canonical
// document into the typed specs-go.Spec. The conversion refuses to drop
// target-unsupported fields; callers that need the detailed field
// report should use Convert directly.
func ConvertToSpec(input []byte, targetVersion string) (rspec.Spec, *Result, error) {
	result, err := Convert(input, targetVersion, Options{})
	if err != nil {
		return rspec.Spec{}, nil, err
	}
	canonical, err := Canonicalize(result.Output)
	if err != nil {
		return rspec.Spec{}, nil, err
	}
	spec, err := canonical.AsSpec()
	if err != nil {
		return rspec.Spec{}, nil, err
	}
	return spec, result, nil
}
