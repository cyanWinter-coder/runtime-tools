package specerror

import (
	"fmt"

	rfc2119 "github.com/opencontainers/runtime-tools/error"
)

// The error codes in this file describe cross-field violations that the
// single-field checks cannot express: a value legal on its own becomes
// invalid through the combination of several sections (paths, namespaces,
// mount propagation, devices, ...). They live in a dedicated numeric
// range (0x10001+) so the codes stay stable even when older blocks gain
// new entries.
const (
	// PathNotNormalized represents a path that does not match its own
	// Linux lexical normalization (Clean), e.g. containing "//", "." or
	// resolvable ".." components.
	PathNotNormalized Code = 0x10001 + iota
	// PathEscapesRoot represents a path whose normalized form lands
	// outside of the root it is resolved against (the container rootfs
	// or the bundle directory).
	PathEscapesRoot
	// RootfsPropagationConflict represents a rootfs propagation mode or
	// a per-mount propagation option that requires a new mount namespace,
	// while the configuration joins an existing one.
	RootfsPropagationConflict
	// RootfsPropagationValue represents a rootfsPropagation value that is
	// not one of the supported propagation modes.
	RootfsPropagationValue
	// DuplicateMountPropagation represents a mount carrying more than one
	// propagation option, which cannot be mapped to a single mount(2) call.
	DuplicateMountPropagation
	// DeviceAccessConflict represents a device that is declared in
	// linux.devices but made inaccessible by another section: a deny rule
	// in the device cgroup, a masked path, a read-only path or a mount
	// covering the device node.
	DeviceAccessConflict
)

var (
	// configLinuxMountsRef points at the mount section, which defines both
	// the mount point semantics and the propagation options.
	configLinuxMountsRef = func(version string) (reference string, err error) {
		return fmt.Sprintf(referenceTemplate, version, "config-linux.md#mounts"), nil
	}
	rootfsPropagationRef = func(version string) (reference string, err error) {
		return fmt.Sprintf(referenceTemplate, version, "config-linux.md#rootfs-mount-propagation"), nil
	}
	crossDevicesRef = func(version string) (reference string, err error) {
		return fmt.Sprintf(referenceTemplate, version, "config-linux.md#devices"), nil
	}
)

func init() {
	register(PathNotNormalized, rfc2119.Must, configLinuxMountsRef)
	register(PathEscapesRoot, rfc2119.Must, configLinuxMountsRef)
	register(RootfsPropagationConflict, rfc2119.Must, rootfsPropagationRef)
	register(RootfsPropagationValue, rfc2119.Must, rootfsPropagationRef)
	register(DuplicateMountPropagation, rfc2119.Must, configLinuxMountsRef)
	register(DeviceAccessConflict, rfc2119.Must, crossDevicesRef)
}
