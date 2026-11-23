package seccomp

import (
	"fmt"
	"sort"
)

// capGatedSyscalls lists the syscalls that are only part of the default
// profile when the corresponding capability is present in the spec. Keeping
// them outside the main whitelist still makes them known names, so a rule
// added explicitly for one of them is not rejected as an unknown syscall.
var capGatedSyscalls = map[string][]string{
	"CAP_DAC_READ_SEARCH": {
		"open_by_handle_at",
	},
	"CAP_SYS_ADMIN": {
		"bpf",
		"clone",
		"fanotify_init",
		"lookup_dcookie",
		"mount",
		"name_to_handle_at",
		"perf_event_open",
		"setdomainname",
		"sethostname",
		"setns",
		"umount",
		"umount2",
		"unshare",
	},
	"CAP_SYS_BOOT": {
		"reboot",
	},
	"CAP_SYS_CHROOT": {
		"chroot",
	},
	"CAP_SYS_MODULE": {
		"delete_module",
		"finit_module",
		"init_module",
		"query_module",
	},
	"CAP_SYS_PACCT": {
		"acct",
	},
	"CAP_SYS_PTRACE": {
		"kcmp",
		"process_vm_readv",
		"process_vm_writev",
		"ptrace",
	},
	"CAP_SYS_RAWIO": {
		"ioperm",
		"iopl",
	},
	"CAP_SYS_TIME": {
		"adjtimex",
		"settimeofday",
		"stime",
	},
	"CAP_SYS_TTY_CONFIG": {
		"vhangup",
	},
}

// archSpecificSyscalls lists syscalls that only exist on a subset of
// architectures. They are still accepted as rule names on every platform so
// that a profile targeting several ABIs can be generated from one host.
var archSpecificSyscalls = map[string][]string{
	"arm": {
		"breakpoint",
		"cacheflush",
		"set_tls",
	},
	"386": {
		"modify_ldt",
	},
	"amd64": {
		"arch_prctl",
		"modify_ldt",
	},
	"s390": {
		"s390_pci_mmio_read",
		"s390_pci_mmio_write",
		"s390_runtime_instr",
	},
}

// knownSyscalls contains every syscall name the generator can emit a rule for.
// It is built once from the default whitelist plus the capability and
// architecture specific names, so the check does not depend on map iteration
// order and is cheap at generation time.
var knownSyscalls = func() map[string]struct{} {
	known := make(map[string]struct{})
	for _, name := range defaultAllowedSyscalls {
		known[name] = struct{}{}
	}
	for _, names := range capGatedSyscalls {
		for _, name := range names {
			known[name] = struct{}{}
		}
	}
	for _, names := range archSpecificSyscalls {
		for _, name := range names {
			known[name] = struct{}{}
		}
	}
	return known
}()

// isKnownSyscall reports whether name identifies a syscall the generator
// understands. The raw name is preserved in the caller facing error instead
// of being silently turned into an allow rule.
func isKnownSyscall(name string) bool {
	_, ok := knownSyscalls[name]
	return ok
}

// sortedCapNames returns the capability names in a fixed order so that the
// cap driven rules are appended at the same position for identical specs.
func sortedCapNames() []string {
	caps := make([]string, 0, len(capGatedSyscalls))
	for cap := range capGatedSyscalls {
		caps = append(caps, cap)
	}
	sort.Strings(caps)
	return caps
}

// ensureKnownSyscall fails with the original syscall name when the generator
// cannot resolve it. Unknown names must never be downgraded to the default
// action or silently allowed.
func ensureKnownSyscall(name string) error {
	if !isKnownSyscall(name) {
		return fmt.Errorf("unrecognized syscall: %q", name)
	}
	return nil
}

// argBitWidth is the width in bits of a seccomp argument comparison value.
// Seccomp data fields are 64 bit on every ABI, so values and the second
// masked-equal operand are always parsed at full width.
const argBitWidth = 64
