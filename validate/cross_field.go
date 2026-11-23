package validate

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-multierror"
	rspec "github.com/opencontainers/runtime-spec/specs-go"
	osFilepath "github.com/opencontainers/runtime-tools/filepath"
	"github.com/opencontainers/runtime-tools/specerror"
	"github.com/sirupsen/logrus"
)

// bindMountOptions marks the mount(8) options that identify a bind mount
// even when mount "type" is left empty.
var bindMountOptions = map[string]bool{
	"bind":  true,
	"rbind": true,
}

// CheckCrossField runs the cross-section checks that no single-field
// check can express:
//
//   - every path is lexically normalized with Linux semantics and its
//     landing point, once resolved against its root (the bundle for
//     relative host paths, the container rootfs for in-container paths),
//     stays inside that root;
//   - namespace, mount propagation and device-access combinations that
//     are individually legal but cannot be executed together are rejected
//     up front (Linux only, see checkLinuxCrossConflicts).
//
// Each returned error is a *FieldError, carrying the JSON-style field
// path and a stable specerror.Code; all detected problems are collected
// and returned together. Unknown fields and unknown mount options are
// never inspected here, so newer spec revisions cannot trigger false
// positives.
func (v *Validator) CheckCrossField() error {
	logrus.Debugf("check cross-field constraints")

	var errs *multierror.Error
	errs = multierror.Append(errs, v.checkCrossFieldPaths()...)
	if v.platform == "linux" {
		errs = multierror.Append(errs, v.checkLinuxCrossConflicts()...)
	}
	return errs.ErrorOrNil()
}

// checkCrossFieldPaths normalizes all paths participating in cross-section
// resolution and verifies where each one lands. Windows is skipped because
// its path semantics are handled by the platform-specific checks.
func (v *Validator) checkCrossFieldPaths() []error {
	var errs *multierror.Error

	if v.platform == "windows" {
		return nil
	}

	// root.path is host-relative and resolved against the bundle.
	if v.spec.Root != nil && v.spec.Root.Path != "" && !osFilepath.IsAbs(v.platform, v.spec.Root.Path) {
		v.appendHostPathError(&errs, "root.path", v.spec.Root.Path)
	}

	for i, mount := range v.spec.Mounts {
		v.appendContainerPathError(&errs, fmt.Sprintf("mounts[%d].destination", i), mount.Destination)

		// Relative sources only have a defined resolution for bind
		// mounts: they are taken relative to the bundle directory.
		if mount.Source != "" && !osFilepath.IsAbs(v.platform, mount.Source) && mountIsBind(mount) {
			v.appendHostPathError(&errs, fmt.Sprintf("mounts[%d].source", i), mount.Source)
		}
	}

	if v.spec.Process != nil {
		v.appendContainerPathError(&errs, "process.cwd", v.spec.Process.Cwd)
	}

	if v.spec.Linux != nil {
		for i, ns := range v.spec.Linux.Namespaces {
			if ns.Path != "" {
				v.appendContainerPathError(&errs, fmt.Sprintf("linux.namespaces[%d].path", i), ns.Path)
			}
		}
		for i, device := range v.spec.Linux.Devices {
			v.appendContainerPathError(&errs, fmt.Sprintf("linux.devices[%d].path", i), device.Path)
		}
		for i, p := range v.spec.Linux.MaskedPaths {
			v.appendContainerPathError(&errs, fmt.Sprintf("linux.maskedPaths[%d]", i), p)
		}
		for i, p := range v.spec.Linux.ReadonlyPaths {
			v.appendContainerPathError(&errs, fmt.Sprintf("linux.readonlyPaths[%d]", i), p)
		}
	}

	if errs == nil {
		return nil
	}
	return errs.Errors
}

// appendContainerPathError normalizes an absolute, container-internal
// path and verifies that its landing point stays inside the container
// root ("/"). Empty input is left to the single-field checks.
func (v *Validator) appendContainerPathError(errs **multierror.Error, field, path string) {
	if path == "" {
		return
	}

	cleaned := osFilepath.Clean(v.platform, path)
	if cleaned != path {
		*errs = multierror.Append(*errs, newFieldError(field, specerror.PathNotNormalized,
			fmt.Sprintf("path %q is not normalized; the normalized form is %q", path, cleaned), v.spec.Version))
	}
	if !pathUnder("/", cleaned) {
		*errs = multierror.Append(*errs, newFieldError(field, specerror.PathEscapesRoot,
			fmt.Sprintf("path %q resolves outside of the container root filesystem", path), v.spec.Version))
	}
}

// appendHostPathError normalizes a host-relative path and verifies it
// lands inside the bundle directory instead of escaping it through "..".
// Host paths use the host's path/filepath semantics (POSIX on Linux);
// the explicit-OS filepath helper is reserved for container-internal
// paths whose separator follows the target platform.
// Both violations are reported independently so a single fix pass can
// address every problem.
func (v *Validator) appendHostPathError(errs **multierror.Error, field, path string) {
	cleaned := filepath.Clean(path)
	if cleaned != path {
		*errs = multierror.Append(*errs, newFieldError(field, specerror.PathNotNormalized,
			fmt.Sprintf("path %q is not normalized; the normalized form is %q", path, cleaned), v.spec.Version))
	}

	absBundle, err := filepath.Abs(v.bundlePath)
	if err != nil {
		*errs = multierror.Append(*errs, fmt.Errorf("%s: unable to resolve bundle path %q: %w", field, v.bundlePath, err))
		return
	}
	resolved := filepath.Clean(filepath.Join(absBundle, cleaned))
	if !pathUnder(absBundle, resolved) {
		*errs = multierror.Append(*errs, newFieldError(field, specerror.PathEscapesRoot,
			fmt.Sprintf("path %q resolves to %q, outside of the bundle directory %q", path, resolved, absBundle), v.spec.Version))
	}
}

// mountIsBind reports whether a mount entry is a bind mount, either via
// its type or via a bind/rbind option.
func mountIsBind(mount rspec.Mount) bool {
	if mount.Type == "bind" {
		return true
	}
	for _, option := range mount.Options {
		if bindMountOptions[option] {
			return true
		}
	}
	return false
}

// mountIsReadonly reports whether a mount is mounted read-only through
// the conventional "ro" option. Unknown options are ignored on purpose.
func mountIsReadonly(mount rspec.Mount) bool {
	for _, option := range mount.Options {
		if option == "ro" {
			return true
		}
	}
	return false
}

// pathUnder reports whether path is root itself or located strictly
// inside root. Both arguments must already be cleaned, absolute paths.
func pathUnder(root, path string) bool {
	if root == "/" || root == path {
		return true
	}
	return strings.HasPrefix(path, root+"/")
}
