//go:build linux

package validate

import (
	"os"
	"path/filepath"
	"testing"

	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"

	"github.com/opencontainers/runtime-tools/specerror"
)

// mustOK fails the test immediately when err is non-nil. It stands in
// for testify's require package, which is not part of the vendored
// dependencies.
func mustOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// mustErr fails the test immediately when err is nil.
func mustErr(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// newRootlessBundle builds a temp bundle with an empty rootfs and a
// couple of regular directories used as legitimate mount targets.
func newRootlessBundle(t *testing.T) (bundle string) {
	t.Helper()

	bundle = t.TempDir()
	mustOK(t, os.MkdirAll(filepath.Join(bundle, "rootfs", "proc", "sys"), 0o755))
	mustOK(t, os.MkdirAll(filepath.Join(bundle, "rootfs", "data"), 0o755))
	return bundle
}

func rootlessSpec(bundle string) rspec.Spec {
	return rspec.Spec{
		Version: rspec.Version,
		Root:    &rspec.Root{Path: filepath.Join(bundle, "rootfs")},
		Process: &rspec.Process{
			Args: []string{"sh"},
			Cwd:  "/",
			User: rspec.User{UID: 1000, GID: 1000},
		},
		Linux: &rspec.Linux{
			Namespaces: []rspec.LinuxNamespace{
				{Type: rspec.UserNamespace},
			},
			UIDMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 65536},
			},
			GIDMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 65536},
			},
		},
		Mounts: []rspec.Mount{
			{Destination: "/proc", Source: "proc", Type: "proc"},
			{Destination: "/data", Source: "/tmp", Type: "bind"},
		},
	}
}

func TestCheckRootlessPaths(t *testing.T) {
	hostDir := t.TempDir()

	cases := []struct {
		name     string
		setup    func(t *testing.T, bundle string)
		mutate   func(spec *rspec.Spec, bundle string)
		expected specerror.Code
	}{
		{
			name:     "plain bundle with regular mount targets",
			setup:    func(t *testing.T, bundle string) {},
			mutate:   func(spec *rspec.Spec, bundle string) {},
			expected: specerror.NonError,
		},
		{
			name:     "missing mount target is accepted and not created",
			setup:    func(t *testing.T, bundle string) {},
			mutate:   func(spec *rspec.Spec, bundle string) { spec.Mounts[1].Destination = "/data/not/there" },
			expected: specerror.NonError,
		},
		{
			name: "mount destination symlink escapes rootfs",
			setup: func(t *testing.T, bundle string) {
				// The bundle setup creates rootfs/data as a directory;
				// replace it with a symlink pointing at a host directory.
				mustOK(t, os.RemoveAll(filepath.Join(bundle, "rootfs", "data")))
				mustOK(t, os.Symlink(hostDir, filepath.Join(bundle, "rootfs", "data")))
			},
			mutate:   func(spec *rspec.Spec, bundle string) {},
			expected: specerror.MountDestOutsideRootfs,
		},
		{
			name: "nested symlink component escapes rootfs",
			setup: func(t *testing.T, bundle string) {
				mustOK(t, os.Symlink("../../.."+hostDir, filepath.Join(bundle, "rootfs", "data", "leak")))
			},
			mutate:   func(spec *rspec.Spec, bundle string) { spec.Mounts[1].Destination = "/data/leak/inner" },
			expected: specerror.MountDestOutsideRootfs,
		},
		{
			name: "absolute symlink pointing back inside rootfs is accepted",
			setup: func(t *testing.T, bundle string) {
				mustOK(t, os.Symlink(filepath.Join(bundle, "rootfs", "proc"),
					filepath.Join(bundle, "rootfs", "data", "proc-link")))
			},
			mutate:   func(spec *rspec.Spec, bundle string) { spec.Mounts[1].Destination = "/data/proc-link/sys" },
			expected: specerror.NonError,
		},
		{
			name: "relative symlink staying inside rootfs is accepted",
			setup: func(t *testing.T, bundle string) {
				mustOK(t, os.Symlink("../proc", filepath.Join(bundle, "rootfs", "data", "rel-link")))
			},
			mutate:   func(spec *rspec.Spec, bundle string) { spec.Mounts[1].Destination = "/data/rel-link" },
			expected: specerror.NonError,
		},
		{
			name: "rootfs symlink escapes bundle directory",
			setup: func(t *testing.T, bundle string) {
				// Replace the rootfs directory with a symlink to a host dir.
				mustOK(t, os.RemoveAll(filepath.Join(bundle, "rootfs")))
				mustOK(t, os.Symlink(hostDir, filepath.Join(bundle, "rootfs")))
			},
			mutate:   func(spec *rspec.Spec, bundle string) {},
			expected: specerror.RootfsPathOutsideBundle,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bundle := newRootlessBundle(t)
			c.setup(t, bundle)

			spec := rootlessSpec(bundle)
			c.mutate(&spec, bundle)

			v, err := NewValidator(&spec, bundle, true, "linux")
			mustOK(t, err)

			err = v.checkRootlessPaths()
			assert.Equal(t, c.expected, specerror.FindError(err, c.expected),
				"unexpected validation result: %v", err)
		})
	}
}

func TestCheckRootlessPathsNoFilesCreated(t *testing.T) {
	bundle := newRootlessBundle(t)
	spec := rootlessSpec(bundle)
	spec.Mounts = append(spec.Mounts, rspec.Mount{
		Destination: "/does/not/exist/at/all",
		Source:      "/tmp",
		Type:        "bind",
	})

	v, err := NewValidator(&spec, bundle, true, "linux")
	mustOK(t, err)
	mustOK(t, v.checkRootlessPaths())

	_, err = os.Lstat(filepath.Join(bundle, "rootfs", "does"))
	assert.True(t, os.IsNotExist(err), "validation must not create the missing mount target: %v", err)
}

func TestCheckRootlessPathsRequiresHostSpecific(t *testing.T) {
	hostDir := t.TempDir()
	bundle := newRootlessBundle(t)
	mustOK(t, os.RemoveAll(filepath.Join(bundle, "rootfs", "data")))
	mustOK(t, os.Symlink(hostDir, filepath.Join(bundle, "rootfs", "data")))

	spec := rootlessSpec(bundle)
	v, err := NewValidator(&spec, bundle, false, "linux")
	mustOK(t, err)

	// Without host-specific mode filesystem layout is not inspected,
	// so the escaping symlink must not be reported.
	assert.NoError(t, v.checkRootlessPaths())
}

func TestCheckRootlessIDMappings(t *testing.T) {
	cases := []struct {
		name        string
		uidMappings []rspec.LinuxIDMapping
		gidMappings []rspec.LinuxIDMapping
		uid         uint32
		gid         uint32
		expected    specerror.Code
	}{
		{
			name: "mappings cover process uid and gid",
			uidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 65536},
			},
			gidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 65536},
			},
			uid:      1000,
			gid:      1000,
			expected: specerror.NonError,
		},
		{
			name: "process uid outside of mapping ranges",
			uidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 100},
			},
			gidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 65536},
			},
			uid:      1000,
			gid:      1000,
			expected: specerror.UserNSIDNotMapped,
		},
		{
			name: "process gid outside of mapping ranges",
			uidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 65536},
			},
			gidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 100},
			},
			uid:      1000,
			gid:      1000,
			expected: specerror.UserNSIDNotMapped,
		},
		{
			name: "uid on the first id of the range is covered",
			uidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 1000, HostID: 100000, Size: 10},
			},
			gidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 65536},
			},
			uid:      1000,
			gid:      1000,
			expected: specerror.NonError,
		},
		{
			name: "uid just past the end of the range is not covered",
			uidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 1000, HostID: 100000, Size: 10},
			},
			gidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 65536},
			},
			uid:      1010,
			gid:      1000,
			expected: specerror.UserNSIDNotMapped,
		},
		{
			name: "overlapping container ranges rejected",
			uidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 100},
				{ContainerID: 50, HostID: 200000, Size: 100},
			},
			gidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 65536},
			},
			uid:      0,
			gid:      0,
			expected: specerror.UserNSMappingOverlap,
		},
		{
			name: "duplicate mapping rejected",
			uidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 100},
				{ContainerID: 0, HostID: 100000, Size: 100},
			},
			gidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 65536},
			},
			uid:      0,
			gid:      0,
			expected: specerror.UserNSMappingOverlap,
		},
		{
			name: "adjacent ranges do not overlap",
			uidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 100},
				{ContainerID: 100, HostID: 200000, Size: 100},
			},
			gidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 65536},
			},
			uid:      0,
			gid:      0,
			expected: specerror.NonError,
		},
		{
			name: "overlapping host ranges rejected",
			uidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 100},
			},
			gidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 100},
				{ContainerID: 100, HostID: 100050, Size: 100},
			},
			uid:      0,
			gid:      0,
			expected: specerror.UserNSMappingOverlap,
		},
		{
			name: "zero size mapping rejected",
			uidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 0},
			},
			gidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 65536},
			},
			uid:      0,
			gid:      0,
			expected: specerror.UserNSMappingInvalid,
		},
		{
			name: "container range overflow rejected",
			uidMappings: []rspec.LinuxIDMapping{
				{ContainerID: ^uint32(0), HostID: 100000, Size: 2},
			},
			gidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 65536},
			},
			uid:      0,
			gid:      0,
			expected: specerror.UserNSMappingInvalid,
		},
		{
			name: "host range overflow rejected",
			uidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: ^uint32(0), Size: 2},
			},
			gidMappings: []rspec.LinuxIDMapping{
				{ContainerID: 0, HostID: 100000, Size: 65536},
			},
			uid:      0,
			gid:      0,
			expected: specerror.UserNSMappingInvalid,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bundle := newRootlessBundle(t)
			spec := rootlessSpec(bundle)
			spec.Linux.UIDMappings = c.uidMappings
			spec.Linux.GIDMappings = c.gidMappings
			spec.Process.User.UID = c.uid
			spec.Process.User.GID = c.gid

			v, err := NewValidator(&spec, bundle, false, "linux")
			mustOK(t, err)

			err = v.checkRootlessIDMappings()
			assert.Equal(t, c.expected, specerror.FindError(err, c.expected),
				"unexpected validation result: %v", err)
		})
	}
}

func TestCheckRootlessIDMappingsErrorCarriesNamespaceEvidence(t *testing.T) {
	bundle := newRootlessBundle(t)
	spec := rootlessSpec(bundle)
	spec.Linux.UIDMappings = []rspec.LinuxIDMapping{
		{ContainerID: 0, HostID: 100000, Size: 100},
	}
	spec.Process.User.UID = 1000

	v, err := NewValidator(&spec, bundle, false, "linux")
	mustOK(t, err)

	err = v.checkRootlessIDMappings()
	mustErr(t, err)
	assert.Contains(t, err.Error(), "user namespace")
	assert.Contains(t, err.Error(), "1000")
}

func TestCheckMaskedReadonlyOrder(t *testing.T) {
	cases := []struct {
		name          string
		maskedPaths   []string
		readonlyPaths []string
		expected      specerror.Code
	}{
		{
			name:          "unrelated paths are fine",
			maskedPaths:   []string{"/proc/kcore"},
			readonlyPaths: []string{"/proc/sys", "/sys"},
			expected:      specerror.NonError,
		},
		{
			name:        "descendant before ancestor within masked paths",
			maskedPaths: []string{"/proc/sys/kernel", "/proc/sys"},
			expected:    specerror.MaskedReadonlyOrderConflict,
		},
		{
			name:        "ancestor before descendant within masked paths is fine",
			maskedPaths: []string{"/proc/sys", "/proc/sys/kernel"},
			expected:    specerror.NonError,
		},
		{
			name:        "duplicate masked paths conflict",
			maskedPaths: []string{"/proc/kcore", "/proc/kcore"},
			expected:    specerror.MaskedReadonlyOrderConflict,
		},
		{
			name:          "readonly ancestor listed after masked descendant",
			maskedPaths:   []string{"/proc/sys/kernel"},
			readonlyPaths: []string{"/proc/sys"},
			expected:      specerror.MaskedReadonlyOrderConflict,
		},
		{
			name:          "same path in both lists conflicts",
			maskedPaths:   []string{"/proc/sys"},
			readonlyPaths: []string{"/proc/sys"},
			expected:      specerror.MaskedReadonlyOrderConflict,
		},
		{
			name:          "masked ancestor before readonly descendant is fine",
			maskedPaths:   []string{"/proc"},
			readonlyPaths: []string{"/proc/sys"},
			expected:      specerror.NonError,
		},
		{
			name:          "trailing slashes compare equal",
			maskedPaths:   []string{"/proc/sys/"},
			readonlyPaths: []string{"/proc/sys"},
			expected:      specerror.MaskedReadonlyOrderConflict,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bundle := newRootlessBundle(t)
			spec := rootlessSpec(bundle)
			spec.Linux.MaskedPaths = c.maskedPaths
			spec.Linux.ReadonlyPaths = c.readonlyPaths

			v, err := NewValidator(&spec, bundle, false, "linux")
			mustOK(t, err)

			err = v.checkMaskedReadonlyOrder()
			assert.Equal(t, c.expected, specerror.FindError(err, c.expected),
				"unexpected validation result: %v", err)
		})
	}
}

func TestCheckRootlessPrivilegedBundleUnchanged(t *testing.T) {
	bundle := newRootlessBundle(t)

	// A regular root bundle: no user namespace, no mappings.
	spec := rspec.Spec{
		Version: rspec.Version,
		Root:    &rspec.Root{Path: filepath.Join(bundle, "rootfs")},
		Process: &rspec.Process{
			Args: []string{"sh"},
			Cwd:  "/",
			User: rspec.User{UID: 0, GID: 0},
		},
		Linux: &rspec.Linux{
			MaskedPaths:   []string{"/proc/kcore"},
			ReadonlyPaths: []string{"/proc/sys"},
		},
		Mounts: []rspec.Mount{
			{Destination: "/proc", Source: "proc", Type: "proc"},
		},
	}

	v, err := NewValidator(&spec, bundle, true, "linux")
	mustOK(t, err)
	assert.NoError(t, v.CheckRootless())
}

func TestCheckRootlessSymlinkLoop(t *testing.T) {
	bundle := newRootlessBundle(t)
	loop := filepath.Join(bundle, "rootfs", "data", "loop")
	// A relative self-reference keeps the resolver inside the rootfs
	// and forces it to re-read the same symlink until the traversal
	// limit is reached.
	mustOK(t, os.Symlink("loop", loop))

	spec := rootlessSpec(bundle)
	spec.Mounts[1].Destination = "/data/loop"

	v, err := NewValidator(&spec, bundle, true, "linux")
	mustOK(t, err)

	err = v.checkRootlessPaths()
	mustErr(t, err)
	assert.Contains(t, err.Error(), "too many symlinks")
}

func TestCheckRootlessPathErrorCarriesEvidence(t *testing.T) {
	hostDir := t.TempDir()
	bundle := newRootlessBundle(t)
	mustOK(t, os.RemoveAll(filepath.Join(bundle, "rootfs", "data")))
	mustOK(t, os.Symlink(hostDir, filepath.Join(bundle, "rootfs", "data")))

	spec := rootlessSpec(bundle)

	v, err := NewValidator(&spec, bundle, true, "linux")
	mustOK(t, err)

	err = v.checkRootlessPaths()
	mustErr(t, err)
	// The error must name the offending mount destination, the host
	// path it resolves to and the declared rootfs boundary.
	msg := err.Error()
	assert.Contains(t, msg, "/data")
	assert.Contains(t, msg, hostDir)
	assert.Contains(t, msg, "rootfs")
	assert.Equal(t, specerror.MountDestOutsideRootfs,
		specerror.FindError(err, specerror.MountDestOutsideRootfs))
}

func TestCheckRootlessReturnsNilWithoutErrors(t *testing.T) {
	bundle := newRootlessBundle(t)
	spec := rootlessSpec(bundle)

	v, err := NewValidator(&spec, bundle, true, "linux")
	mustOK(t, err)

	// A clean bundle must return a plain nil rather than an empty
	// multierror wrapped in a non-nil interface.
	assert.Nil(t, v.CheckRootless())
}
