//go:build linux

package validate

import (
	"testing"

	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"

	"github.com/opencontainers/runtime-tools/specerror"
)

func TestCheckLinuxCrossConflicts(t *testing.T) {
	int64Ptr := func(v int64) *int64 { return &v }

	cases := []struct {
		name     string
		mutate   func(*rspec.Spec)
		expected specerror.Code
		field    string
	}{
		{
			name:     "fresh mount namespace with propagation is valid",
			mutate:   func(s *rspec.Spec) { s.Linux.RootfsPropagation = "shared" },
			expected: specerror.NonError,
		},
		{
			name: "rootfs propagation without mount namespace",
			mutate: func(s *rspec.Spec) {
				s.Linux.RootfsPropagation = "shared"
				s.Linux.Namespaces = []rspec.LinuxNamespace{{Type: rspec.PIDNamespace}}
			},
			expected: specerror.RootfsPropagationConflict,
			field:    "linux.rootfsPropagation",
		},
		{
			name: "rootfs propagation joining an existing mount namespace",
			mutate: func(s *rspec.Spec) {
				s.Linux.RootfsPropagation = "rslave"
				s.Linux.Namespaces = []rspec.LinuxNamespace{
					{Type: rspec.MountNamespace, Path: "/proc/1/ns/mnt"},
				}
			},
			expected: specerror.RootfsPropagationConflict,
			field:    "linux.rootfsPropagation",
		},
		{
			name: "unsupported rootfs propagation value",
			mutate: func(s *rspec.Spec) {
				s.Linux.RootfsPropagation = "explosive"
			},
			expected: specerror.RootfsPropagationValue,
			field:    "linux.rootfsPropagation",
		},
		{
			name: "per-mount propagation without mount namespace",
			mutate: func(s *rspec.Spec) {
				s.Linux.Namespaces = []rspec.LinuxNamespace{{Type: rspec.PIDNamespace}}
				s.Mounts = []rspec.Mount{
					{Destination: "/mnt/data", Type: "tmpfs", Options: []string{"rshared"}},
				}
			},
			expected: specerror.RootfsPropagationConflict,
			field:    "mounts[0].options",
		},
		{
			name: "per-mount propagation with fresh mount namespace is valid",
			mutate: func(s *rspec.Spec) {
				s.Mounts = []rspec.Mount{
					{Destination: "/mnt/data", Type: "tmpfs", Options: []string{"rshared", "noexec"}},
				}
			},
			expected: specerror.NonError,
		},
		{
			name: "duplicate propagation options",
			mutate: func(s *rspec.Spec) {
				s.Mounts = []rspec.Mount{
					{Destination: "/mnt/data", Type: "tmpfs", Options: []string{"shared", "slave"}},
				}
			},
			expected: specerror.DuplicateMountPropagation,
			field:    "mounts[0].options",
		},
		{
			name: "device masked by maskedPaths",
			mutate: func(s *rspec.Spec) {
				s.Linux.Devices = []rspec.LinuxDevice{
					{Path: "/dev/zero", Type: "c", Major: 1, Minor: 5},
				}
				s.Linux.MaskedPaths = []string{"/dev/zero"}
			},
			expected: specerror.DeviceAccessConflict,
			field:    "linux.devices[0].path",
		},
		{
			name: "device under a masked directory",
			mutate: func(s *rspec.Spec) {
				s.Linux.Devices = []rspec.LinuxDevice{
					{Path: "/dev/custom/foo", Type: "c", Major: 10, Minor: 200},
				}
				s.Linux.MaskedPaths = []string{"/dev/custom"}
			},
			expected: specerror.DeviceAccessConflict,
			field:    "linux.devices[0].path",
		},
		{
			name: "device under readonlyPaths",
			mutate: func(s *rspec.Spec) {
				s.Linux.Devices = []rspec.LinuxDevice{
					{Path: "/sys/foo", Type: "c", Major: 10, Minor: 200},
				}
				s.Linux.ReadonlyPaths = []string{"/sys"}
			},
			expected: specerror.DeviceAccessConflict,
			field:    "linux.devices[0].path",
		},
		{
			name: "device under a read-only mount",
			mutate: func(s *rspec.Spec) {
				s.Linux.Devices = []rspec.LinuxDevice{
					{Path: "/mnt/data/foo", Type: "c", Major: 10, Minor: 200},
				}
				s.Mounts = []rspec.Mount{
					{Destination: "/mnt/data", Type: "tmpfs", Options: []string{"ro"}},
				}
			},
			expected: specerror.DeviceAccessConflict,
			field:    "linux.devices[0].path",
		},
		{
			name: "device under a writable mount is not a conflict",
			mutate: func(s *rspec.Spec) {
				s.Linux.Devices = []rspec.LinuxDevice{
					{Path: "/mnt/data/foo", Type: "c", Major: 10, Minor: 200},
				}
				s.Mounts = []rspec.Mount{
					{Destination: "/mnt/data", Type: "tmpfs"},
				}
			},
			expected: specerror.NonError,
		},
		{
			name: "device denied by the final matching cgroup rule",
			mutate: func(s *rspec.Spec) {
				s.Linux.Devices = []rspec.LinuxDevice{
					{Path: "/dev/foo", Type: "c", Major: 10, Minor: 200},
				}
				s.Linux.Resources = &rspec.LinuxResources{
					Devices: []rspec.LinuxDeviceCgroup{
						{Allow: true, Type: "c"},
						{Allow: false, Type: "c", Major: int64Ptr(10), Minor: int64Ptr(200), Access: "rwm"},
					},
				}
			},
			expected: specerror.DeviceAccessConflict,
			field:    "linux.devices[0].path",
		},
		{
			name: "wildcard deny rule applies to the device",
			mutate: func(s *rspec.Spec) {
				s.Linux.Devices = []rspec.LinuxDevice{
					{Path: "/dev/foo", Type: "b", Major: 8, Minor: 1},
				}
				s.Linux.Resources = &rspec.LinuxResources{
					Devices: []rspec.LinuxDeviceCgroup{
						{Allow: false, Access: "m"},
					},
				}
			},
			expected: specerror.DeviceAccessConflict,
			field:    "linux.devices[0].path",
		},
		{
			name: "deny rule without m does not block node creation",
			mutate: func(s *rspec.Spec) {
				s.Linux.Devices = []rspec.LinuxDevice{
					{Path: "/dev/foo", Type: "c", Major: 10, Minor: 200},
				}
				s.Linux.Resources = &rspec.LinuxResources{
					Devices: []rspec.LinuxDeviceCgroup{
						{Allow: false, Type: "c", Major: int64Ptr(10), Minor: int64Ptr(200), Access: "rw"},
					},
				}
			},
			expected: specerror.NonError,
		},
		{
			name: "unmatched cgroup rules do not conflict",
			mutate: func(s *rspec.Spec) {
				s.Linux.Devices = []rspec.LinuxDevice{
					{Path: "/dev/foo", Type: "c", Major: 10, Minor: 200},
				}
				s.Linux.Resources = &rspec.LinuxResources{
					Devices: []rspec.LinuxDeviceCgroup{
						{Allow: false, Type: "b"},
					},
				}
			},
			expected: specerror.NonError,
		},
		{
			name: "u device matches a c character device rule",
			mutate: func(s *rspec.Spec) {
				s.Linux.Devices = []rspec.LinuxDevice{
					{Path: "/dev/foo", Type: "u", Major: 10, Minor: 200},
				}
				s.Linux.Resources = &rspec.LinuxResources{
					Devices: []rspec.LinuxDeviceCgroup{
						{Allow: false, Type: "c", Major: int64Ptr(10), Minor: int64Ptr(200), Access: "rwm"},
					},
				}
			},
			expected: specerror.DeviceAccessConflict,
			field:    "linux.devices[0].path",
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
				"failed cross-conflict check: %v", err)
			if c.expected != specerror.NonError {
				assertFieldError(t, err, c.field, c.expected)
			}
		})
	}
}

func TestCheckCrossFieldAggregatesMultipleIssues(t *testing.T) {
	spec := crossFieldSpec()
	spec.Linux.RootfsPropagation = "shared"
	spec.Linux.Namespaces = []rspec.LinuxNamespace{{Type: rspec.PIDNamespace}}
	spec.Mounts = []rspec.Mount{
		{Destination: "/mnt//data", Type: "tmpfs", Options: []string{"shared", "slave"}},
	}
	spec.Linux.Devices = []rspec.LinuxDevice{
		{Path: "/dev/zero", Type: "c", Major: 1, Minor: 5},
	}
	spec.Linux.MaskedPaths = []string{"/dev/zero"}

	v, err := NewValidator(&spec, "/tmp/some-bundle", false, "linux")
	if err != nil {
		t.Fatalf("unexpected NewValidator error: %+v", err)
	}
	err = v.CheckCrossField()
	if err == nil {
		t.Fatal("expected aggregated errors, got nil")
	}

	for _, code := range []specerror.Code{
		specerror.RootfsPropagationConflict,
		specerror.PathNotNormalized,
		specerror.DuplicateMountPropagation,
		specerror.DeviceAccessConflict,
	} {
		assert.Equal(t, code, specerror.FindError(err, code),
			"expected aggregated error with code 0x%x, got: %v", code, err)
	}
}
