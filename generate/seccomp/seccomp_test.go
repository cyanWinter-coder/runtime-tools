package seccomp

import (
	"encoding/json"
	"runtime"
	"testing"

	rspec "github.com/opencontainers/runtime-spec/specs-go"
)

func testConfig() *rspec.LinuxSeccomp {
	return &rspec.LinuxSeccomp{
		DefaultAction: rspec.ActErrno,
		Syscalls:      []rspec.LinuxSyscall{},
	}
}

func TestParseArchExplicitMapping(t *testing.T) {
	for name, want := range archToABIs {
		got, err := parseArch(name)
		if err != nil {
			t.Fatalf("parseArch(%q) returned error: %v", name, err)
		}
		if got != want {
			t.Errorf("parseArch(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestParseArchUnsupportedFailsWithRawValue(t *testing.T) {
	for _, arch := range []string{"", "AMD64", "x86_64", "weirdarch"} {
		if _, err := parseArch(arch); err == nil {
			t.Errorf("parseArch(%q) expected error, got nil", arch)
		} else if !contains(err.Error(), arch) {
			t.Errorf("parseArch(%q) error %q does not quote the raw input", arch, err.Error())
		}
	}
}

func TestParseArchitectureFlagDedupAndOrder(t *testing.T) {
	config := testConfig()

	if err := ParseArchitectureFlag("amd64", config); err != nil {
		t.Fatal(err)
	}
	if err := ParseArchitectureFlag("amd64", config); err != nil {
		t.Fatal(err)
	}
	if err := ParseArchitectureFlag("arm64", config); err != nil {
		t.Fatal(err)
	}

	want := []rspec.Arch{rspec.ArchX86_64, rspec.ArchAARCH64}
	if len(config.Architectures) != len(want) {
		t.Fatalf("got architectures %v, want %v", config.Architectures, want)
	}
	for i := range want {
		if config.Architectures[i] != want[i] {
			t.Errorf("index %d: got %q, want %q", i, config.Architectures[i], want[i])
		}
	}

	if err := ParseArchitectureFlag("bogus", config); err == nil {
		t.Fatal("unsupported architecture was accepted instead of failing")
	}
	if len(config.Architectures) != len(want) {
		t.Fatalf("failed parse mutated the architecture list: %v", config.Architectures)
	}
}

func TestNativeArchesExplicitMapping(t *testing.T) {
	cases := map[string][]rspec.Arch{
		"amd64":   {rspec.ArchX86_64, rspec.ArchX86, rspec.ArchX32},
		"arm64":   {rspec.ArchARM, rspec.ArchAARCH64},
		"s390x":   {rspec.ArchS390, rspec.ArchS390X},
		"386":     {rspec.ArchX86},
		"riscv64": {rspec.ArchRISCV64},
	}
	for goarch, want := range cases {
		got, err := nativeArches(goarch)
		if err != nil {
			t.Fatalf("nativeArches(%q) error: %v", goarch, err)
		}
		if len(got) != len(want) {
			t.Fatalf("nativeArches(%q) = %v, want %v", goarch, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("nativeArches(%q)[%d] = %q, want %q", goarch, i, got[i], want[i])
			}
		}
	}

	if _, err := nativeArches("bogus"); err == nil {
		t.Fatal("nativeArches accepted an architecture without an ABI mapping")
	}
}

func TestArchesMatchesHostMapping(t *testing.T) {
	got, err := arches()
	if err != nil {
		t.Fatalf("arches() failed on host %q: %v", runtime.GOARCH, err)
	}
	want, err := nativeArches(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("arches() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("arches()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseActionUnknownFailsWithRawValue(t *testing.T) {
	for _, action := range []string{"", "ALLOW", "log", "deny"} {
		if _, err := parseAction(action); err == nil {
			t.Errorf("parseAction(%q) expected error, got nil", action)
		} else if !contains(err.Error(), action) {
			t.Errorf("parseAction(%q) error %q does not quote the raw input", action, err.Error())
		}
	}
}

func TestParseSyscallFlagUnknownActionDoesNotDowngrade(t *testing.T) {
	config := testConfig()
	before := len(config.Syscalls)

	err := ParseSyscallFlag(SyscallOpts{Action: "frobnicate", Syscall: "read"}, config)
	if err == nil {
		t.Fatal("unknown action was accepted instead of failing")
	}
	if !contains(err.Error(), "frobnicate") {
		t.Errorf("error %q does not contain the raw action", err.Error())
	}
	if len(config.Syscalls) != before {
		t.Fatalf("unknown action mutated the rules: %v", config.Syscalls)
	}
}

func TestParseSyscallFlagUnknownSyscallFailsWithRawValue(t *testing.T) {
	config := testConfig()
	before := len(config.Syscalls)

	err := ParseSyscallFlag(SyscallOpts{Action: "allow", Syscall: "definitely_not_a_syscall"}, config)
	if err == nil {
		t.Fatal("unknown syscall was accepted instead of failing")
	}
	if !contains(err.Error(), "definitely_not_a_syscall") {
		t.Errorf("error %q does not contain the raw syscall name", err.Error())
	}
	if len(config.Syscalls) != before {
		t.Fatalf("unknown syscall mutated the rules: %v", config.Syscalls)
	}
}

func TestParseSyscallFlagDuplicateRuleDedup(t *testing.T) {
	config := testConfig()

	opts := SyscallOpts{Action: "allow", Syscall: "read"}
	if err := ParseSyscallFlag(opts, config); err != nil {
		t.Fatal(err)
	}
	if err := ParseSyscallFlag(opts, config); err != nil {
		t.Fatal(err)
	}

	if len(config.Syscalls) != 1 {
		t.Fatalf("expected a single rule after duplicate input, got %v", config.Syscalls)
	}
}

func TestParseSyscallFlagAliasMergedIntoExistingRule(t *testing.T) {
	config := testConfig()
	config.Syscalls = []rspec.LinuxSyscall{
		{
			Names:  []string{"read", "write"},
			Action: rspec.ActAllow,
			Args:   []rspec.LinuxSeccompArg{},
		},
	}

	// "write" is an alias already covered by the multi name rule.
	if err := ParseSyscallFlag(SyscallOpts{Action: "allow", Syscall: "write"}, config); err != nil {
		t.Fatal(err)
	}
	if len(config.Syscalls) != 1 {
		t.Fatalf("alias should be merged, got extra rule: %v", config.Syscalls)
	}
	if len(config.Syscalls[0].Names) != 2 {
		t.Fatalf("existing rule names changed: %v", config.Syscalls[0].Names)
	}
}

func TestRuleAlreadyCoveredRequiresIdenticalComparisons(t *testing.T) {
	existing := []rspec.LinuxSyscall{
		{
			Names:  []string{"clone"},
			Action: rspec.ActAllow,
			Args: []rspec.LinuxSeccompArg{
				{Index: 0, Value: 0x1, ValueTwo: 0x0, Op: rspec.OpMaskedEqual},
			},
		},
	}

	same := &rspec.LinuxSyscall{
		Names:  []string{"clone"},
		Action: rspec.ActAllow,
		Args: []rspec.LinuxSeccompArg{
			{Index: 0, Value: 0x1, ValueTwo: 0x0, Op: rspec.OpMaskedEqual},
		},
	}
	if !ruleAlreadyCovered(same, existing) {
		t.Error("identical rule should be treated as covered")
	}

	differentIndex := &rspec.LinuxSyscall{
		Names:  []string{"clone"},
		Action: rspec.ActAllow,
		Args: []rspec.LinuxSeccompArg{
			{Index: 1, Value: 0x1, ValueTwo: 0x0, Op: rspec.OpMaskedEqual},
		},
	}
	if ruleAlreadyCovered(differentIndex, existing) {
		t.Error("rule with a different argument index must not be merged")
	}

	differentAction := &rspec.LinuxSyscall{
		Names:  []string{"clone"},
		Action: rspec.ActErrno,
		Args:   []rspec.LinuxSeccompArg{},
	}
	if ruleAlreadyCovered(differentAction, existing) {
		t.Error("rule with a different action must not be merged")
	}
}

func TestParseArgumentsKeepsIndexAnd64BitWidth(t *testing.T) {
	const maxUint64 = "18446744073709551615" // 0xffffffffffffffff
	args, err := parseArguments([]string{"clone", "2", maxUint64, maxUint64, "ME"})
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 1 {
		t.Fatalf("expected one argument comparison, got %v", args)
	}
	arg := args[0]
	if arg.Index != 2 {
		t.Errorf("index = %d, want 2", arg.Index)
	}
	if arg.Value != ^uint64(0) || arg.ValueTwo != ^uint64(0) {
		t.Errorf("64 bit values were truncated: value=%d valueTwo=%d", arg.Value, arg.ValueTwo)
	}
	if arg.Op != rspec.OpMaskedEqual {
		t.Errorf("op = %q, want %q", arg.Op, rspec.OpMaskedEqual)
	}

	if _, err := parseArguments([]string{"clone", "2", maxUint64 + "0", "0", "EQ"}); err == nil {
		t.Error("value exceeding 64 bit width should fail instead of overflowing")
	}
	if _, err := parseArguments([]string{"clone", "notanindex", "0", "0", "EQ"}); err == nil {
		t.Error("non numeric index should fail")
	}
	if _, err := parseArguments([]string{"clone", "0", "0", "0", "XX"}); err == nil {
		t.Error("unknown operator should fail")
	}
}

func TestParseSyscallFlagWithArgumentsRoundTrip(t *testing.T) {
	config := testConfig()
	opts := SyscallOpts{
		Action:   "errno",
		Syscall:  "clone",
		Index:    "1",
		Value:    "2080505856",
		ValueTwo: "0",
		Operator: "ME",
	}
	if err := ParseSyscallFlag(opts, config); err != nil {
		t.Fatal(err)
	}
	if len(config.Syscalls) != 1 {
		t.Fatalf("expected one rule, got %v", config.Syscalls)
	}
	arg := config.Syscalls[0].Args[0]
	if arg.Index != 1 || arg.Value != 2080505856 || arg.Op != rspec.OpMaskedEqual {
		t.Errorf("argument comparison was not preserved: %+v", arg)
	}
}

func specWithCaps(caps ...string) *rspec.Spec {
	return &rspec.Spec{
		Process: &rspec.Process{
			Capabilities: &rspec.LinuxCapabilities{
				Bounding:    append([]string(nil), caps...),
				Effective:   append([]string(nil), caps...),
				Inheritable: []string{},
				Permitted:   []string{},
				Ambient:     []string{},
			},
		},
	}
}

func TestDefaultProfileDeterministic(t *testing.T) {
	rs := specWithCaps("CAP_SYS_BOOT", "CAP_SYS_ADMIN", "CAP_SYS_TIME")

	first, err := DefaultProfile(rs)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 20; i++ {
		again, err := DefaultProfile(rs)
		if err != nil {
			t.Fatal(err)
		}
		againJSON, err := json.Marshal(again)
		if err != nil {
			t.Fatal(err)
		}
		if string(firstJSON) != string(againJSON) {
			t.Fatalf("profile output is not deterministic:\n%s\n%s", firstJSON, againJSON)
		}
	}
}

func TestDefaultProfileCompatibility(t *testing.T) {
	profile, err := DefaultProfile(specWithCaps())
	if err != nil {
		t.Fatal(err)
	}

	if profile.DefaultAction != rspec.ActErrno {
		t.Errorf("default action = %q, want %q", profile.DefaultAction, rspec.ActErrno)
	}
	if len(profile.Architectures) == 0 {
		t.Error("default profile must advertise at least one architecture")
	}
	if len(profile.Syscalls) < 4 {
		t.Fatalf("expected base whitelist plus personality rules, got %d", len(profile.Syscalls))
	}

	mainRule := profile.Syscalls[0]
	if mainRule.Action != rspec.ActAllow {
		t.Errorf("whitelist action = %q, want %q", mainRule.Action, rspec.ActAllow)
	}
	if len(mainRule.Names) != len(defaultAllowedSyscalls) {
		t.Fatalf("whitelist has %d names, want %d", len(mainRule.Names), len(defaultAllowedSyscalls))
	}
	for i, name := range defaultAllowedSyscalls {
		if mainRule.Names[i] != name {
			t.Fatalf("whitelist order changed at %d: got %q, want %q", i, mainRule.Names[i], name)
		}
	}

	for i := 1; i <= 3; i++ {
		if profile.Syscalls[i].Names[0] != "personality" {
			t.Errorf("rule %d should be a personality rule, got %v", i, profile.Syscalls[i].Names)
		}
	}
}

func TestDefaultProfileCapabilityRulesAreSorted(t *testing.T) {
	profile, err := DefaultProfile(specWithCaps("CAP_SYS_TIME", "CAP_SYS_BOOT", "CAP_SYS_ADMIN"))
	if err != nil {
		t.Fatal(err)
	}

	// Rules after the four base rules must appear in sorted capability order:
	// CAP_SYS_ADMIN, CAP_SYS_BOOT, CAP_SYS_TIME.
	wantOrder := []string{"CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_TIME"}
	got := []string{}
	for _, rule := range profile.Syscalls[4:] {
		switch rule.Names[0] {
		case "bpf":
			got = append(got, "CAP_SYS_ADMIN")
		case "reboot":
			got = append(got, "CAP_SYS_BOOT")
		case "adjtimex":
			got = append(got, "CAP_SYS_TIME")
		}
	}
	if len(got) != len(wantOrder) {
		t.Fatalf("capability rules not found as expected: %v in %v", got, profile.Syscalls)
	}
	for i := range wantOrder {
		if got[i] != wantOrder[i] {
			t.Errorf("capability rule order = %v, want %v", got, wantOrder)
		}
	}
}

func TestArchSpecificRules(t *testing.T) {
	if _, _, err := archSpecificRules("bogus"); err == nil {
		t.Fatal("unsupported architecture should fail rule generation")
	}

	rules, cloneIndex, err := archSpecificRules("s390x")
	if err != nil {
		t.Fatal(err)
	}
	if cloneIndex != 1 {
		t.Errorf("s390 clone flags index = %d, want 1", cloneIndex)
	}
	if len(rules) != 1 || len(rules[0].Names) != 3 {
		t.Fatalf("unexpected s390 rules: %v", rules)
	}

	rules, cloneIndex, err = archSpecificRules("amd64")
	if err != nil {
		t.Fatal(err)
	}
	if cloneIndex != -1 {
		t.Errorf("amd64 clone index = %d, want -1", cloneIndex)
	}
	if len(rules) != 2 {
		t.Fatalf("amd64 should have arch_prctl and modify_ldt rules, got %v", rules)
	}

	rules, _, err = archSpecificRules("riscv64")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("riscv64 should need no architecture specific rules, got %v", rules)
	}
}

func TestDefaultProfileRejectsUnsupportedArchitecture(t *testing.T) {
	// On every host used to run the test suite, DefaultProfile must succeed
	// because runtime.GOARCH has an explicit ABI mapping.
	if _, err := DefaultProfile(specWithCaps()); err != nil {
		t.Fatalf("DefaultProfile failed on supported host %q: %v", runtime.GOARCH, err)
	}

	// An architecture missing from the explicit mapping must fail the gate
	// before a profile with an empty ABI list can be emitted.
	if _, err := nativeArches("nonexistent-arch"); err == nil {
		t.Fatal("profile generation should fail before emitting an empty ABI list")
	}
}

func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
