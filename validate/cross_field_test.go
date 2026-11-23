package validate

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/go-multierror"
	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"

	"github.com/opencontainers/runtime-tools/specerror"
)

func crossFieldSpec() rspec.Spec {
	return rspec.Spec{
		Version: rspec.Version,
		Root: &rspec.Root{
			Path:     "rootfs",
			Readonly: false,
		},
		Process: &rspec.Process{
			Args: []string{"sh"},
			Cwd:  "/",
		},
		Linux: &rspec.Linux{
			Namespaces: []rspec.LinuxNamespace{
				{Type: rspec.MountNamespace},
				{Type: rspec.PIDNamespace},
			},
		},
	}
}

func TestCheckCrossFieldPaths(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*rspec.Spec)
		expected specerror.Code
		field    string
	}{
		{
			name:     "valid normalized config",
			mutate:   func(s *rspec.Spec) {},
			expected: specerror.NonError,
		},
		{
			name: "unnormalized mount destination",
			mutate: func(s *rspec.Spec) {
				s.Mounts = []rspec.Mount{
					{Destination: "/mnt//data", Type: "tmpfs"},
				}
			},
			expected: specerror.PathNotNormalized,
			field:    "mounts[0].destination",
		},
		{
			name: "mount destination with dot segments",
			mutate: func(s *rspec.Spec) {
				s.Mounts = []rspec.Mount{
					{Destination: "/mnt/./data", Type: "tmpfs"},
				}
			},
			expected: specerror.PathNotNormalized,
			field:    "mounts[0].destination",
		},
		{
			name: "mount destination escaping root via dotdot",
			mutate: func(s *rspec.Spec) {
				s.Mounts = []rspec.Mount{
					{Destination: "/mnt/../etc", Type: "tmpfs"},
				}
			},
			expected: specerror.PathNotNormalized,
			field:    "mounts[0].destination",
		},
		{
			name: "unnormalized process cwd",
			mutate: func(s *rspec.Spec) {
				s.Process.Cwd = "/tmp//work"
			},
			expected: specerror.PathNotNormalized,
			field:    "process.cwd",
		},
		{
			name: "unnormalized namespace path",
			mutate: func(s *rspec.Spec) {
				s.Linux.Namespaces = append(s.Linux.Namespaces, rspec.LinuxNamespace{
					Type: rspec.NetworkNamespace,
					Path: "/proc//1/ns/net",
				})
			},
			expected: specerror.PathNotNormalized,
			field:    "linux.namespaces[2].path",
		},
		{
			name: "unnormalized device path",
			mutate: func(s *rspec.Spec) {
				s.Linux.Devices = []rspec.LinuxDevice{
					{Path: "/dev//null", Type: "c", Major: 1, Minor: 3},
				}
			},
			expected: specerror.PathNotNormalized,
			field:    "linux.devices[0].path",
		},
		{
			name: "unnormalized masked path",
			mutate: func(s *rspec.Spec) {
				s.Linux.MaskedPaths = []string{"/proc//kcore"}
			},
			expected: specerror.PathNotNormalized,
			field:    "linux.maskedPaths[0]",
		},
		{
			name: "unnormalized readonly path",
			mutate: func(s *rspec.Spec) {
				s.Linux.ReadonlyPaths = []string{"/proc//sys"}
			},
			expected: specerror.PathNotNormalized,
			field:    "linux.readonlyPaths[0]",
		},
		{
			name: "relative bind mount source escaping the bundle",
			mutate: func(s *rspec.Spec) {
				s.Mounts = []rspec.Mount{
					{Destination: "/mnt/host", Type: "bind", Source: "../../etc/passwd", Options: []string{"rbind"}},
				}
			},
			expected: specerror.PathEscapesRoot,
			field:    "mounts[0].source",
		},
		{
			name: "relative bind mount source with dotdot normalized inside the bundle",
			mutate: func(s *rspec.Spec) {
				s.Mounts = []rspec.Mount{
					{Destination: "/mnt/host", Type: "bind", Source: "data/../config", Options: []string{"rbind"}},
				}
			},
			expected: specerror.PathNotNormalized,
			field:    "mounts[0].source",
		},
		{
			name: "relative root path escaping the bundle",
			mutate: func(s *rspec.Spec) {
				s.Root.Path = "../shared-root"
			},
			expected: specerror.PathEscapesRoot,
			field:    "root.path",
		},
		{
			name: "relative bind mount source contained in the bundle is accepted",
			mutate: func(s *rspec.Spec) {
				s.Mounts = []rspec.Mount{
					{Destination: "/mnt/host", Type: "bind", Source: "host-data", Options: []string{"rbind"}},
				}
			},
			expected: specerror.NonError,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := crossFieldSpec()
			c.mutate(&spec)
			v, err := NewValidator(&spec, "/tmp/some-bundle", false, "linux")
			if err != nil {
				t.Fatalf("unexpected NewValidator error: %+v", err)
			}
			err = v.CheckCrossField()
			assert.Equal(t, c.expected, specerror.FindError(err, c.expected),
				fmt.Sprintf("failed cross-field path check: %v", err))
			if c.expected != specerror.NonError {
				assertFieldError(t, err, c.field, c.expected)
			}
		})
	}
}

// assertFieldError locates a FieldError carrying both the expected field
// path and the stable code inside the multierror.
func assertFieldError(t *testing.T, err error, field string, code specerror.Code) {
	t.Helper()

	merr, ok := err.(*multierror.Error)
	if !ok || merr == nil {
		t.Fatalf("expected a *multierror.Error, got: %v", err)
	}
	for _, sub := range merr.Errors {
		var fe *FieldError
		if errors.As(sub, &fe) && fe.Field == field && fe.Code() == code {
			assert.Contains(t, fe.Error(), field)
			return
		}
	}
	t.Fatalf("expected a FieldError for field %q with code 0x%x, got: %v", field, code, err)
}
