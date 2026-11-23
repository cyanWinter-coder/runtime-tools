package validate

import (
	"encoding/json"
	"errors"
	"testing"

	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"

	"github.com/opencontainers/runtime-tools/specerror"
)

// TestCheckCrossFieldIgnoresUnknownExtensions verifies the extensibility
// requirement: fields and mount options introduced by a newer spec
// revision must not be rejected by the cross-section checks. The typed
// Spec struct drops unknown JSON properties on unmarshal, so this test
// pins both that behavior and the fact that unknown options are ignored.
func TestCheckCrossFieldIgnoresUnknownExtensions(t *testing.T) {
	// Unknown top-level and nested properties must unmarshal without
	// error and leave the known fields intact.
	raw := []byte(`{
		"ociVersion": "` + rspec.Version + `",
		"futureExtension": {"enabled": true},
		"root": {"path": "rootfs", "futureRootField": 42},
		"process": {"args": ["sh"], "cwd": "/", "futureProcessField": "x"},
		"linux": {
			"namespaces": [{"type": "mount"}, {"type": "pid"}],
			"futureLinuxField": [1, 2, 3],
			"mounts": [
				{
					"destination": "/mnt/data",
					"type": "tmpfs",
					"options": ["noexec", "future-option=1"],
					"futureMountField": "ignored"
				}
			]
		}
	}`)

	var spec rspec.Spec
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("unexpected unmarshal error for unknown fields: %v", err)
	}

	v, err := NewValidator(&spec, "/tmp/some-bundle", false, "linux")
	if err != nil {
		t.Fatalf("unexpected NewValidator error: %+v", err)
	}
	assert.NoError(t, v.CheckCrossField(),
		"unknown extensions must not trigger cross-field errors")
}

// TestCheckCrossFieldUnknownMountOptionTolerated ensures an
// unrecognized mount option never turns into a propagation error, even
// alongside recognized options.
func TestCheckCrossFieldUnknownMountOptionTolerated(t *testing.T) {
	spec := crossFieldSpec()
	spec.Mounts = []rspec.Mount{
		{
			Destination: "/mnt/data",
			Type:        "tmpfs",
			// Exactly one recognized propagation mode plus unknown ones.
			Options: []string{"rshared", "idmap", "some-future-opt"},
		},
	}

	v, err := NewValidator(&spec, "/tmp/some-bundle", false, "linux")
	if err != nil {
		t.Fatalf("unexpected NewValidator error: %+v", err)
	}
	assert.NoError(t, v.CheckCrossField())
}

// TestCheckCrossFieldVersionIndependent makes sure the cross checks do
// not hard-code the vendored spec version: an older, still-semver config
// version is validated exactly the same way and violations still carry
// their stable codes.
func TestCheckCrossFieldVersionIndependent(t *testing.T) {
	spec := crossFieldSpec()
	spec.Version = "1.1.0"
	spec.Linux.RootfsPropagation = "shared"
	spec.Linux.Namespaces = []rspec.LinuxNamespace{{Type: rspec.PIDNamespace}}

	v, err := NewValidator(&spec, "/tmp/some-bundle", false, "linux")
	if err != nil {
		t.Fatalf("unexpected NewValidator error: %+v", err)
	}
	err = v.CheckCrossField()
	assert.Equal(t, specerror.RootfsPropagationConflict,
		specerror.FindError(err, specerror.RootfsPropagationConflict),
		"stable error codes must not depend on the declared spec version: %v", err)
}

// TestFieldErrorCodeAndUnwrap verifies the structured error contract:
// stable code, field path in the message, and errors.As traversability.
func TestFieldErrorCodeAndUnwrap(t *testing.T) {
	fe := newFieldError("linux.mounts[0].destination",
		specerror.PathNotNormalized, "path /a//b is not normalized", rspec.Version)

	assert.Equal(t, "linux.mounts[0].destination", fe.Field)
	assert.Equal(t, specerror.PathNotNormalized, fe.Code())
	assert.Contains(t, fe.Error(), "linux.mounts[0].destination")
	assert.Contains(t, fe.Error(), "path /a//b is not normalized")

	var rfcErr *specerror.Error
	assert.True(t, errors.As(fe, &rfcErr))
	assert.Equal(t, specerror.PathNotNormalized, rfcErr.Code)
}
