//go:build linux

package validate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	multierror "github.com/hashicorp/go-multierror"
	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/runtime-tools/specerror"
	"github.com/sirupsen/logrus"
)

// maxSymlinkTraversals mirrors the kernel's MAX_NESTED_LINKS (40) limit
// used when resolving paths, so symlink loops are reported instead of
// hanging the validation.
const maxSymlinkTraversals = 40

// errPathOutsideRoot is the unexported sentinel produced by the
// symlink-aware path resolution when a path leaves its declared root.
var errPathOutsideRoot = errors.New("path resolves outside of its declared root")

// CheckRootless enforces the extra invariants a bundle must satisfy
// before it can be accepted in a rootless setup. In particular:
//
//   - the rootfs and every mount destination, after resolving all
//     symlinks, must stay inside the bundle/rootfs they are declared
//     under, so a planted symlink cannot reach host directories;
//   - user namespace mapping entries must be well-formed, must not
//     overlap, and must cover the process uid/gid;
//   - maskedPaths and readonlyPaths must keep a consistent ancestor
//     ordering, so no later entry can override an earlier one.
//
// Filesystem based checks only run in host-specific mode and never
// create any file or directory: missing targets are simply skipped.
// Plain (privileged, no user namespace) bundles keep their previous
// behavior because the mapping checks below are inert without
// UID/GID mappings.
func (v *Validator) CheckRootless() (errs error) {
	logrus.Debugf("check rootless invariants")

	if v.spec == nil {
		return nil
	}

	collected := multierror.Append(nil,
		v.checkRootlessPaths(),
		v.checkRootlessIDMappings(),
		v.checkMaskedReadonlyOrder(),
	)
	return collected.ErrorOrNil()
}

// rootfsHostPath returns the host path of the declared rootfs,
// resolving the bundle path the same way CheckRoot does.
func (v *Validator) rootfsHostPath() string {
	if v.spec.Root == nil {
		return ""
	}
	if filepath.IsAbs(v.spec.Root.Path) {
		return filepath.Clean(v.spec.Root.Path)
	}
	return filepath.Join(v.bundlePath, v.spec.Root.Path)
}

// checkRootlessPaths verifies that the resolved rootfs stays inside
// the bundle directory and that every resolved mount destination
// stays inside the rootfs.
func (v *Validator) checkRootlessPaths() error {
	var errs *multierror.Error
	if !v.HostSpecific || v.spec.Root == nil {
		return nil
	}

	rootfsPath := v.rootfsHostPath()
	if _, err := os.Lstat(rootfsPath); err != nil {
		// CheckRoot already reports a missing rootfs; nothing to resolve.
		return nil
	}

	absBundle, err := filepath.Abs(v.bundlePath)
	if err != nil {
		return multierror.Append(errs, fmt.Errorf("cannot resolve bundle path %q: %w", v.bundlePath, err)).ErrorOrNil()
	}
	realBundle, err := filepath.EvalSymlinks(absBundle)
	if err != nil {
		return multierror.Append(errs, fmt.Errorf("cannot resolve bundle path %q: %w", absBundle, err)).ErrorOrNil()
	}

	realRootfs, err := filepath.EvalSymlinks(rootfsPath)
	if err != nil {
		return multierror.Append(errs, fmt.Errorf("cannot resolve rootfs path %q: %w", rootfsPath, err)).ErrorOrNil()
	}
	if !pathWithin(realRootfs, realBundle) {
		errs = multierror.Append(errs, specerror.NewError(specerror.RootfsPathOutsideBundle,
			fmt.Errorf("rootfs %q resolves to %q, which is outside of the bundle root %q",
				rootfsPath, realRootfs, realBundle), rspec.Version))
	}

	for i, mount := range v.spec.Mounts {
		// Mount destinations are absolute paths inside the container,
		// so clean them and resolve their symlinks component by
		// component against the real rootfs.
		hostDest := filepath.Join(realRootfs, filepath.Clean("/"+mount.Destination))
		resolved, err := resolveWithinRoot(realRootfs, hostDest)
		if errors.Is(err, errPathOutsideRoot) {
			errs = multierror.Append(errs, specerror.NewError(specerror.MountDestOutsideRootfs,
				fmt.Errorf("mounts[%d].destination %q resolves to %q, which is outside of the rootfs %q",
					i, mount.Destination, resolved, realRootfs), rspec.Version))
			continue
		}
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("cannot resolve mounts[%d].destination %q: %w",
				i, mount.Destination, err))
			continue
		}
		if !pathWithin(resolved, realRootfs) {
			errs = multierror.Append(errs, specerror.NewError(specerror.MountDestOutsideRootfs,
				fmt.Errorf("mounts[%d].destination %q resolves to %q, which is outside of the rootfs %q",
					i, mount.Destination, resolved, realRootfs), rspec.Version))
		}
	}

	return errs.ErrorOrNil()
}

// checkRootlessIDMappings validates the user namespace UID/GID
// mappings and, when mappings are present, checks that the process
// uid and gid are covered by them.
func (v *Validator) checkRootlessIDMappings() error {
	var errs *multierror.Error
	if v.spec.Linux == nil {
		return nil
	}

	newUserNS := false
	for _, ns := range v.spec.Linux.Namespaces {
		if ns.Type == rspec.UserNamespace && ns.Path == "" {
			newUserNS = true
			break
		}
	}

	if v.spec.Process != nil {
		if len(v.spec.Linux.UIDMappings) > 0 {
			errs = multierror.Append(errs, checkIDMappingSet("uidMappings", v.spec.Linux.UIDMappings))
			if !idMapped(v.spec.Linux.UIDMappings, v.spec.Process.User.UID) {
				errs = multierror.Append(errs, specerror.NewError(specerror.UserNSIDNotMapped,
					fmt.Errorf("process uid %d is not covered by any uidMappings entry %v (new user namespace: %t)",
						v.spec.Process.User.UID, v.spec.Linux.UIDMappings, newUserNS), rspec.Version))
			}
		}
		if len(v.spec.Linux.GIDMappings) > 0 {
			errs = multierror.Append(errs, checkIDMappingSet("gidMappings", v.spec.Linux.GIDMappings))
			if !idMapped(v.spec.Linux.GIDMappings, v.spec.Process.User.GID) {
				errs = multierror.Append(errs, specerror.NewError(specerror.UserNSIDNotMapped,
					fmt.Errorf("process gid %d is not covered by any gidMappings entry %v (new user namespace: %t)",
						v.spec.Process.User.GID, v.spec.Linux.GIDMappings, newUserNS), rspec.Version))
			}
		}
	}

	return errs.ErrorOrNil()
}

// checkIDMappingSet rejects zero-sized entries, ranges that overflow
// the 32-bit ID space and entries whose container or host ranges
// overlap.
func checkIDMappingSet(name string, mappings []rspec.LinuxIDMapping) error {
	var errs *multierror.Error
	for i, m := range mappings {
		if m.Size == 0 {
			errs = multierror.Append(errs, specerror.NewError(specerror.UserNSMappingInvalid,
				fmt.Errorf("%s[%d] %+v has a zero size", name, i, m), rspec.Version))
			continue
		}
		// uint64 arithmetic so the sum cannot wrap; the user namespace
		// only supports 32-bit container/host IDs.
		if end := uint64(m.ContainerID) + uint64(m.Size); end > uint64(^uint32(0))+1 {
			errs = multierror.Append(errs, specerror.NewError(specerror.UserNSMappingInvalid,
				fmt.Errorf("%s[%d] %+v container ID range overflows the 32-bit ID space", name, i, m),
				rspec.Version))
		}
		if end := uint64(m.HostID) + uint64(m.Size); end > uint64(^uint32(0))+1 {
			errs = multierror.Append(errs, specerror.NewError(specerror.UserNSMappingInvalid,
				fmt.Errorf("%s[%d] %+v host ID range overflows the 32-bit ID space", name, i, m),
				rspec.Version))
		}
	}

	for i := 0; i < len(mappings); i++ {
		for j := i + 1; j < len(mappings); j++ {
			a, b := mappings[i], mappings[j]
			if rangesOverlap(uint64(a.ContainerID), uint64(a.Size), uint64(b.ContainerID), uint64(b.Size)) {
				errs = multierror.Append(errs, specerror.NewError(specerror.UserNSMappingOverlap,
					fmt.Errorf("%s entries %d %+v and %d %+v have overlapping container ID ranges",
						name, i, a, j, b), rspec.Version))
			}
			if rangesOverlap(uint64(a.HostID), uint64(a.Size), uint64(b.HostID), uint64(b.Size)) {
				errs = multierror.Append(errs, specerror.NewError(specerror.UserNSMappingOverlap,
					fmt.Errorf("%s entries %d %+v and %d %+v have overlapping host ID ranges",
						name, i, a, j, b), rspec.Version))
			}
		}
	}

	return errs.ErrorOrNil()
}

// rangesOverlap reports whether the half-open ranges
// [start, start+size) and [otherStart, otherStart+otherSize)
// intersect. Zero-sized ranges never overlap anything.
func rangesOverlap(start, size, otherStart, otherSize uint64) bool {
	if size == 0 || otherSize == 0 {
		return false
	}
	return start < otherStart+otherSize && otherStart < start+size
}

// idMapped reports whether id falls into one of the container ranges
// of mappings.
func idMapped(mappings []rspec.LinuxIDMapping, id uint32) bool {
	for _, m := range mappings {
		if m.Size > 0 && uint64(id) >= uint64(m.ContainerID) &&
			uint64(id) < uint64(m.ContainerID)+uint64(m.Size) {
			return true
		}
	}
	return false
}

// checkMaskedReadonlyOrder ensures maskedPaths and readonlyPaths keep
// a consistent ancestor ordering. The two lists are applied in the
// order documented by the runtime spec (maskedPaths first, then
// readonlyPaths, each in listed order); an entry appearing later in
// that sequence must never be equal to, or an ancestor of, an entry
// applied earlier, as it would then override it.
func (v *Validator) checkMaskedReadonlyOrder() error {
	var errs *multierror.Error
	if v.spec.Linux == nil {
		return nil
	}

	type orderedPath struct {
		kind string // "maskedPath" or "readonlyPath"
		path string
	}
	ordered := make([]orderedPath, 0,
		len(v.spec.Linux.MaskedPaths)+len(v.spec.Linux.ReadonlyPaths))
	for _, p := range v.spec.Linux.MaskedPaths {
		ordered = append(ordered, orderedPath{"maskedPath", p})
	}
	for _, p := range v.spec.Linux.ReadonlyPaths {
		ordered = append(ordered, orderedPath{"readonlyPath", p})
	}

	for i := 0; i < len(ordered); i++ {
		for j := i + 1; j < len(ordered); j++ {
			earlier, later := ordered[i], ordered[j]
			// The later entry must never equal the earlier one or sit
			// above it in the tree, otherwise applying it afterwards
			// would override the earlier entry's effect.
			if pathContains(later.path, earlier.path) {
				errs = multierror.Append(errs, specerror.NewError(specerror.MaskedReadonlyOrderConflict,
					fmt.Errorf("%s %q listed after %s %q is equal to it or one of its ancestors, so it would override it",
						later.kind, later.path, earlier.kind, earlier.path), rspec.Version))
			}
		}
	}

	return errs.ErrorOrNil()
}

// pathWithin reports whether path is root itself or located below it.
// Both arguments must be cleaned absolute paths.
func pathWithin(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

// pathContains reports whether parent is equal to, or a strict
// ancestor of, child. Paths are cleaned before comparison so lexical
// entries such as "/proc" and "/proc/" compare equal.
func pathContains(parent, child string) bool {
	parent = filepath.Clean(parent)
	child = filepath.Clean(child)
	if parent == child {
		return true
	}
	return strings.HasPrefix(child, parent+string(filepath.Separator))
}

// resolveWithinRoot resolves all symlinks of target (an absolute host
// path located under root) while guaranteeing the result stays within
// root. It performs only Lstat/Readlink operations and never creates
// anything. A missing final component resolves to its cleaned lexical
// path; a symlink whose resolved target leaves root makes the
// resolution fail with errPathOutsideRoot, together with the
// offending host path.
func resolveWithinRoot(root, target string) (string, error) {
	root = filepath.Clean(root)

	// target is expected to be root + an in-container absolute path.
	rel, err := filepath.Rel(root, filepath.Clean(target))
	if err != nil {
		return "", err
	}
	components := splitPathComponents(rel)

	cur := root
	symlinks := 0
	for len(components) > 0 {
		comp := components[0]
		components = components[1:]
		next := filepath.Join(cur, comp)

		fi, lerr := os.Lstat(next)
		if lerr != nil {
			if os.IsNotExist(lerr) {
				// Nothing here (or below) to resolve: keep the lexical tail.
				cur = next
				continue
			}
			// The kernel rejects paths containing a symlink loop in one
			// of their parent components with ELOOP; report it with the
			// same wording as the in-process traversal limit.
			if errors.Is(lerr, syscall.ELOOP) {
				return next, fmt.Errorf("too many symlinks while resolving %q within %q", target, root)
			}
			return next, lerr
		}

		if fi.Mode()&os.ModeSymlink == 0 {
			cur = next
			continue
		}

		symlinks++
		if symlinks > maxSymlinkTraversals {
			return next, fmt.Errorf("too many symlinks while resolving %q within %q", target, root)
		}

		dest, lerr := os.Readlink(next)
		if lerr != nil {
			return next, lerr
		}
		// Resolve the link target with normal host semantics: an
		// absolute target replaces the whole path, a relative target
		// is joined onto the symlink's directory. The resulting base
		// must still be inside root, otherwise the link reaches a
		// host directory.
		if filepath.IsAbs(dest) {
			cur = filepath.Clean(dest)
		} else {
			cur = filepath.Clean(filepath.Join(filepath.Dir(next), dest))
		}
		if !pathWithin(cur, root) {
			return cur, errPathOutsideRoot
		}
		components = append(restPathComponents(cur, root), components...)
	}

	resolved := filepath.Clean(cur)
	if !pathWithin(resolved, root) {
		return resolved, errPathOutsideRoot
	}
	return resolved, nil
}

// restPathComponents returns the components of path after the root
// prefix, i.e. the part that still has to be walked after a symlink
// redirected resolution to an existing directory inside root.
func restPathComponents(path, root string) []string {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return nil
	}
	return splitPathComponents(rel)
}

// splitPathComponents breaks an absolute or relative cleaned path
// into its non-separator components.
func splitPathComponents(path string) []string {
	path = filepath.Clean(path)
	if path == "." || path == string(filepath.Separator) {
		return nil
	}
	path = strings.TrimPrefix(path, string(filepath.Separator))
	if path == "" {
		return nil
	}
	return strings.Split(path, string(filepath.Separator))
}
