//go:build !linux

package validate

// checkLinuxCrossConflicts is a noop on non-Linux platforms; the
// namespace/propagation/device conflicts it detects only exist on Linux.
func (v *Validator) checkLinuxCrossConflicts() []error {
	return nil
}
