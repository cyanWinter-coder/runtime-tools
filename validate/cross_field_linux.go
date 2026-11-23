//go:build linux

package validate

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-multierror"
	rspec "github.com/opencontainers/runtime-spec/specs-go"
	osFilepath "github.com/opencontainers/runtime-tools/filepath"
	"github.com/opencontainers/runtime-tools/specerror"
)

// propagationModes lists every mount propagation mode accepted by
// mount(2), including the recursive variants. An option outside this set
// is unknown and must be ignored for forward compatibility.
var propagationModes = map[string]bool{
	"shared":      true,
	"slave":       true,
	"private":     true,
	"unbindable":  true,
	"rshared":     true,
	"rslave":      true,
	"rprivate":    true,
	"runbindable": true,
}

// rootfsPropagationModes are the values legal for linux.rootfsPropagation.
// They mirror what the generator accepts.
var rootfsPropagationModes = map[string]bool{
	"private":     true,
	"rprivate":    true,
	"slave":       true,
	"rslave":      true,
	"shared":      true,
	"rshared":     true,
	"unbindable":  true,
	"runbindable": true,
}

// nsState summarizes how each namespace type is used: newlyCreated is
// true when at least one entry has no "path", so the runtime must create
// a fresh namespace of that type (an entry with "path" joins an existing
// namespace instead).
type nsState struct {
	newlyCreated bool
}

func (v *Validator) namespaceStates() map[rspec.LinuxNamespaceType]nsState {
	states := make(map[rspec.LinuxNamespaceType]nsState)
	for _, ns := range v.spec.Linux.Namespaces {
		state := states[ns.Type]
		if ns.Path == "" {
			state.newlyCreated = true
		}
		states[ns.Type] = state
	}
	return states
}

// checkLinuxCrossConflicts rejects namespace, mount propagation and
// device-access combinations that cannot be executed together. Each
// violation is reported with its field path and a stable code.
func (v *Validator) checkLinuxCrossConflicts() []error {
	var errs *multierror.Error
	if v.spec.Linux == nil {
		return nil
	}

	nsStates := v.namespaceStates()
	mountNS := nsStates[rspec.MountNamespace]

	// rootfsPropagation changes the propagation of the rootfs mount,
	// which is only legal inside a fresh mount namespace.
	if rp := v.spec.Linux.RootfsPropagation; rp != "" {
		if !rootfsPropagationModes[rp] {
			errs = multierror.Append(errs, newFieldError("linux.rootfsPropagation", specerror.RootfsPropagationValue,
				fmt.Sprintf("value %q is not one of private, rprivate, slave, rslave, shared, rshared, unbindable, runbindable", rp),
				v.spec.Version))
		} else if !mountNS.newlyCreated {
			errs = multierror.Append(errs, newFieldError("linux.rootfsPropagation", specerror.RootfsPropagationConflict,
				fmt.Sprintf("rootfsPropagation %q requires a new mount namespace, but the configuration joins an existing one or does not declare one", rp),
				v.spec.Version))
		}
	}

	cleanMountDests := make(map[string]bool)
	for i, mount := range v.spec.Mounts {
		cleanDest := osFilepath.Clean(v.platform, mount.Destination)
		cleanMountDests[cleanDest] = true

		var seenPropagation []string
		for _, option := range mount.Options {
			if !propagationModes[option] {
				// Unknown options belong to newer kernels/spec
				// revisions and must be tolerated.
				continue
			}
			seenPropagation = append(seenPropagation, option)
		}
		if len(seenPropagation) > 1 {
			errs = multierror.Append(errs, newFieldError(
				fmt.Sprintf("mounts[%d].options", i), specerror.DuplicateMountPropagation,
				fmt.Sprintf("mount declares conflicting propagation options %s; only one propagation mode is allowed",
					strings.Join(seenPropagation, ", ")),
				v.spec.Version))
			continue
		}
		if len(seenPropagation) == 1 && !mountNS.newlyCreated {
			errs = multierror.Append(errs, newFieldError(
				fmt.Sprintf("mounts[%d].options", i), specerror.RootfsPropagationConflict,
				fmt.Sprintf("propagation option %q requires a new mount namespace, but the configuration joins an existing one or does not declare one",
					seenPropagation[0]),
				v.spec.Version))
		}
	}

	errs = multierror.Append(errs, v.checkDeviceAccessConflicts(cleanMountDests))
	if errs == nil {
		return nil
	}
	return errs.Errors
}

// checkDeviceAccessConflicts verifies that every device declared in
// linux.devices remains usable: it must not be masked, placed on a
// read-only path, covered by a mount, or denied by the device cgroup.
func (v *Validator) checkDeviceAccessConflicts(cleanMountDests map[string]bool) *multierror.Error {
	var errs *multierror.Error
	linux := v.spec.Linux
	masked := make(map[string]bool)
	for _, p := range linux.MaskedPaths {
		masked[osFilepath.Clean(v.platform, p)] = true
	}
	readonly := make(map[string]bool)
	for _, p := range linux.ReadonlyPaths {
		readonly[osFilepath.Clean(v.platform, p)] = true
	}

	readonlyMounts := make(map[string]bool)
	for _, mount := range v.spec.Mounts {
		if mountIsReadonly(mount) {
			readonlyMounts[osFilepath.Clean(v.platform, mount.Destination)] = true
		}
	}

	for i, device := range linux.Devices {
		field := fmt.Sprintf("linux.devices[%d].path", i)
		devPath := osFilepath.Clean(v.platform, device.Path)

		for maskedPath := range masked {
			if maskedPath == devPath || pathUnder(maskedPath, devPath) {
				errs = multierror.Append(errs, newFieldError(field, specerror.DeviceAccessConflict,
					fmt.Sprintf("device %q is inaccessible because %q is listed in linux.maskedPaths", device.Path, maskedPath),
					v.spec.Version))
			}
		}

		for roPath := range readonly {
			if roPath == devPath || pathUnder(roPath, devPath) {
				errs = multierror.Append(errs, newFieldError(field, specerror.DeviceAccessConflict,
					fmt.Sprintf("device node %q cannot be created because %q is listed in linux.readonlyPaths", device.Path, roPath),
					v.spec.Version))
			}
		}

		for dest := range cleanMountDests {
			if dest == devPath || pathUnder(dest, devPath) {
				if readonlyMounts[dest] {
					errs = multierror.Append(errs, newFieldError(field, specerror.DeviceAccessConflict,
						fmt.Sprintf("device node %q cannot be created under the read-only mount at %q", device.Path, dest),
						v.spec.Version))
				}
			}
		}

		if rule, conflicted := deviceCgroupConflict(device, linux.Resources); conflicted {
			errs = multierror.Append(errs, newFieldError(field, specerror.DeviceAccessConflict,
				fmt.Sprintf("device %q is denied by linux.resources.devices cgroup rule (type=%q major=%s minor=%s access=%q allow=%t)",
					device.Path, rule.Type, numberLabel(rule.Major), numberLabel(rule.Minor), rule.Access, rule.Allow),
				v.spec.Version))
		}
	}

	return errs
}

// deviceCgroupConflict applies the device-whitelist rules in order and
// reports the final rule that matches the device when it denies access.
// Creating a node requires "m", so a deny on "m" (or on the whole rwm
// set) makes the declared device unusable.
func deviceCgroupConflict(device rspec.LinuxDevice, resources *rspec.LinuxResources) (rspec.LinuxDeviceCgroup, bool) {
	if resources == nil {
		return rspec.LinuxDeviceCgroup{}, false
	}

	matched := false
	lastRule := rspec.LinuxDeviceCgroup{}
	for _, rule := range resources.Devices {
		if !deviceRuleMatches(device, rule) {
			continue
		}
		matched = true
		lastRule = rule
	}
	if !matched || lastRule.Allow {
		return rspec.LinuxDeviceCgroup{}, false
	}
	if lastRule.Access != "" && !strings.ContainsRune(lastRule.Access, 'm') {
		return rspec.LinuxDeviceCgroup{}, false
	}
	return lastRule, true
}

// deviceRuleMatches reports whether a whitelist rule covers the given
// device. Empty type/major/minor fields act as wildcards, matching the
// spec's device-whitelist semantics.
func deviceRuleMatches(device rspec.LinuxDevice, rule rspec.LinuxDeviceCgroup) bool {
	if rule.Type != "" && rule.Type != device.Type {
		// "u" (unbuffered character device) is a synonym of "c".
		if rule.Type != "c" || (device.Type != "c" && device.Type != "u") {
			return false
		}
	}
	if rule.Major != nil && *rule.Major != device.Major {
		return false
	}
	if rule.Minor != nil && *rule.Minor != device.Minor {
		return false
	}
	return true
}

func numberLabel(value *int64) string {
	if value == nil {
		return "*"
	}
	return fmt.Sprintf("%d", *value)
}
