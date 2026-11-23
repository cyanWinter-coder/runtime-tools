package seccomp

import (
	"runtime"

	rspec "github.com/opencontainers/runtime-spec/specs-go"
)

// DefaultProfile defines the whitelist for the default seccomp profile.
//
// The profile is built deterministically: the syscall order is fixed by
// defaultAllowedSyscalls, the capability driven rules are appended in sorted
// capability order, and the architecture specific rules follow the
// archSpecificSyscalls table. An architecture without an explicit ABI mapping
// returns an error instead of a profile whose architecture list is empty.
func DefaultProfile(rs *rspec.Spec) (*rspec.LinuxSeccomp, error) {
	architectures, err := arches()
	if err != nil {
		return nil, err
	}

	syscalls := []rspec.LinuxSyscall{
		{
			Names:  append([]string(nil), defaultAllowedSyscalls...),
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
		{
			Names:  []string{"personality"},
			Action: rspec.ActAllow,
			Args: []rspec.LinuxSeccompArg{
				{
					Index: 0,
					Value: 0x0,
					Op:    rspec.OpEqualTo,
				},
			},
		},
		{
			Names:  []string{"personality"},
			Action: rspec.ActAllow,
			Args: []rspec.LinuxSeccompArg{
				{
					Index: 0,
					Value: 0x0008,
					Op:    rspec.OpEqualTo,
				},
			},
		},
		{
			Names:  []string{"personality"},
			Action: rspec.ActAllow,
			Args: []rspec.LinuxSeccompArg{
				{
					Index: 0,
					Value: 0xffffffff,
					Op:    rspec.OpEqualTo,
				},
			},
		},
	}
	var sysCloneFlagsIndex uint

	capSysAdmin := false
	caps := make(map[string]bool)

	for _, cap := range rs.Process.Capabilities.Bounding {
		caps[cap] = true
	}
	for _, cap := range rs.Process.Capabilities.Effective {
		caps[cap] = true
	}
	for _, cap := range rs.Process.Capabilities.Inheritable {
		caps[cap] = true
	}
	for _, cap := range rs.Process.Capabilities.Permitted {
		caps[cap] = true
	}
	for _, cap := range rs.Process.Capabilities.Ambient {
		caps[cap] = true
	}

	// Iterate capabilities in a fixed order so identical specs produce
	// identical syscall slices regardless of map randomisation.
	for _, cap := range sortedCapNames() {
		if !caps[cap] {
			continue
		}
		names, ok := capGatedSyscalls[cap]
		if !ok {
			continue
		}
		if cap == "CAP_SYS_ADMIN" {
			capSysAdmin = true
		}
		syscalls = append(syscalls, rspec.LinuxSyscall{
			Names:  append([]string(nil), names...),
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		})
	}

	if !capSysAdmin {
		syscalls = append(syscalls, rspec.LinuxSyscall{
			Names:  []string{"clone"},
			Action: rspec.ActAllow,
			Args: []rspec.LinuxSeccompArg{
				{
					Index:    sysCloneFlagsIndex,
					Value:    CloneNewNS | CloneNewUTS | CloneNewIPC | CloneNewUser | CloneNewPID | CloneNewNet | CloneNewCgroup,
					ValueTwo: 0,
					Op:       rspec.OpMaskedEqual,
				},
			},
		})
	}

	archSyscalls, cloneArgIndex, err := archSpecificRules(runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	syscalls = append(syscalls, archSyscalls...)
	if cloneArgIndex >= 0 {
		syscalls = append(syscalls, rspec.LinuxSyscall{
			Names:  []string{"clone"},
			Action: rspec.ActAllow,
			Args: []rspec.LinuxSeccompArg{
				{
					// Flags parameter of the clone syscall is the 2nd on s390.
					Index:    uint(cloneArgIndex),
					Value:    2080505856,
					ValueTwo: 0,
					Op:       rspec.OpMaskedEqual,
				},
			},
		})
	}

	return &rspec.LinuxSeccomp{
		DefaultAction: rspec.ActErrno,
		Architectures: architectures,
		Syscalls:      syscalls,
	}, nil
}

// archSpecificRules returns the extra syscall rules that only apply on the
// given Go architecture, plus the clone flags argument index when the
// architecture places it outside the default position (-1 otherwise). The
// returned slice is empty for architectures without architecture specific
// rules, which is not an error; an unknown architecture is.
func archSpecificRules(goarch string) ([]rspec.LinuxSyscall, int, error) {
	switch goarch {
	case "arm", "arm64":
		return []rspec.LinuxSyscall{
			{
				Names:  append([]string(nil), archSpecificSyscalls["arm"]...),
				Action: rspec.ActAllow,
				Args:   []rspec.LinuxSeccompArg{},
			},
		}, -1, nil
	case "386", "amd64":
		rules := []rspec.LinuxSyscall{}
		if goarch == "amd64" {
			rules = append(rules, rspec.LinuxSyscall{
				Names:  []string{"arch_prctl"},
				Action: rspec.ActAllow,
				Args:   []rspec.LinuxSeccompArg{},
			})
		}
		rules = append(rules, rspec.LinuxSyscall{
			Names:  []string{"modify_ldt"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		})
		return rules, -1, nil
	case "s390", "s390x":
		return []rspec.LinuxSyscall{
			{
				Names:  append([]string(nil), archSpecificSyscalls["s390"]...),
				Action: rspec.ActAllow,
				Args:   []rspec.LinuxSeccompArg{},
			},
		}, 1, nil
	default:
		if _, err := nativeArches(goarch); err != nil {
			return nil, -1, err
		}
		return nil, -1, nil
	}
}
