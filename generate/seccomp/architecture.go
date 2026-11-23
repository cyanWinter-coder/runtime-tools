package seccomp

import (
	"fmt"
	"runtime"
	"sort"

	rspec "github.com/opencontainers/runtime-spec/specs-go"
)

// archToABIs maps the user facing architecture name (the value accepted by the
// --linux-seccomp-arch flag) to the seccomp ABI token written into the
// generated configuration. The mapping is explicit instead of being derived
// from runtime.GOARCH, so that an unsupported architecture fails before any
// filter is generated rather than silently producing an empty or partial
// architecture list.
var archToABIs = map[string]rspec.Arch{
	"x86":         rspec.ArchX86,
	"amd64":       rspec.ArchX86_64,
	"x32":         rspec.ArchX32,
	"arm":         rspec.ArchARM,
	"arm64":       rspec.ArchAARCH64,
	"mips":        rspec.ArchMIPS,
	"mips64":      rspec.ArchMIPS64,
	"mips64n32":   rspec.ArchMIPS64N32,
	"mipsel":      rspec.ArchMIPSEL,
	"mipsel64":    rspec.ArchMIPSEL64,
	"mipsel64n32": rspec.ArchMIPSEL64N32,
	"parisc":      rspec.ArchPARISC,
	"parisc64":    rspec.ArchPARISC64,
	"ppc":         rspec.ArchPPC,
	"ppc64":       rspec.ArchPPC64,
	"ppc64le":     rspec.ArchPPC64LE,
	"riscv64":     rspec.ArchRISCV64,
	"s390":        rspec.ArchS390,
	"s390x":       rspec.ArchS390X,
	"loong64":     rspec.ArchLOONGARCH64,
}

// nativeABIs maps every supported runtime.GOARCH value to the seccomp ABIs a
// native process on that architecture can use. This is the single source of
// truth for the architecture list of the default profile: a Go architecture
// without an entry here is reported as an error instead of being silently
// dropped from the generated filter.
var nativeABIs = map[string][]rspec.Arch{
	"386":      {rspec.ArchX86},
	"amd64":    {rspec.ArchX86_64, rspec.ArchX86, rspec.ArchX32},
	"arm":      {rspec.ArchARM},
	"arm64":    {rspec.ArchARM, rspec.ArchAARCH64},
	"mips":     {rspec.ArchMIPSEL, rspec.ArchMIPS},
	"mips64":   {rspec.ArchMIPS, rspec.ArchMIPS64, rspec.ArchMIPS64N32},
	"mips64le": {rspec.ArchMIPSEL, rspec.ArchMIPSEL64, rspec.ArchMIPSEL64N32},
	"mipsle":   {rspec.ArchMIPSEL},
	"ppc":      {rspec.ArchPPC},
	"ppc64":    {rspec.ArchPPC, rspec.ArchPPC64},
	"ppc64le":  {rspec.ArchPPC64LE},
	"riscv64":  {rspec.ArchRISCV64},
	"s390":     {rspec.ArchS390},
	"s390x":    {rspec.ArchS390, rspec.ArchS390X},
	"loong64":  {rspec.ArchLOONGARCH64},
}

// parseArch resolves the raw architecture name passed on the command line to
// its seccomp ABI. The original value is quoted in the error so callers can
// tell exactly which unsupported architecture was requested.
func parseArch(arch string) (rspec.Arch, error) {
	abi, ok := archToABIs[arch]
	if !ok {
		return "", fmt.Errorf("unrecognized architecture: %q", arch)
	}
	return abi, nil
}

// nativeArches returns the seccomp ABIs that native processes of the given Go
// architecture can use. It returns an error for architectures without an
// explicit ABI mapping so that profile generation fails fast instead of
// emitting a filter that matches no native ABI.
func nativeArches(goarch string) ([]rspec.Arch, error) {
	abis, ok := nativeABIs[goarch]
	if !ok {
		return nil, fmt.Errorf("seccomp is not supported on architecture: %q", goarch)
	}
	return abis, nil
}

// supportedArchNames returns the accepted architecture names in a stable
// order. It is used both for deterministic iteration and for error messages.
func supportedArchNames() []string {
	names := make([]string, 0, len(archToABIs))
	for name := range archToABIs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// arches returns the native seccomp ABIs of the host architecture. The result
// order is fixed by nativeABIs, independent of map iteration.
func arches() ([]rspec.Arch, error) {
	return nativeArches(runtime.GOARCH)
}
