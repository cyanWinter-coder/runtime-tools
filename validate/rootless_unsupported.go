//go:build !linux

package validate

// CheckRootless is a noop on platforms without the Linux rootless
// invariants (symlink-scoped rootfs, user namespace ID mappings and
// masked/readonly path ordering).
func (v *Validator) CheckRootless() (errs error) {
	return nil
}
