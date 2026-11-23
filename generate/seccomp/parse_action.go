package seccomp

import (
	"fmt"
	"strconv"
	"strings"

	rspec "github.com/opencontainers/runtime-spec/specs-go"
)

// SyscallOpts contain options for parsing syscall rules
type SyscallOpts struct {
	Action   string
	Syscall  string
	Index    string
	Value    string
	ValueTwo string
	Operator string
}

// ParseSyscallFlag takes a SyscallOpts struct and the seccomp configuration
// and sets the new syscall rule accordingly.
//
// Failures are reported instead of being downgraded: an unknown action returns
// its original value in the error, and an unknown syscall name is rejected
// before the configuration is touched. When the same syscall (including an
// alias merged into a multi name rule) is already covered by an identical
// rule, the input is dropped so the generated filter stays free of duplicates.
func ParseSyscallFlag(args SyscallOpts, config *rspec.LinuxSeccomp) error {
	var arguments []string
	if args.Index != "" && args.Value != "" && args.ValueTwo != "" && args.Operator != "" {
		arguments = []string{
			args.Action, args.Syscall, args.Index, args.Value,
			args.ValueTwo, args.Operator,
		}
	} else {
		arguments = []string{args.Action, args.Syscall}
	}

	action, err := parseAction(arguments[0])
	if err != nil {
		return err
	}
	if action == config.DefaultAction && args.argsAreEmpty() {
		// default already set, no need to make changes
		return nil
	}

	numOfArgs := len(arguments)
	if numOfArgs != 6 && numOfArgs != 2 {
		return fmt.Errorf("incorrect number of arguments to ParseSyscall: %d", numOfArgs)
	}

	argStruct, err := parseArguments(arguments[1:])
	if err != nil {
		return err
	}

	newSyscall := newSyscallStruct(arguments[1], action, argStruct)

	// Reject syscalls the generator cannot resolve before mutating the
	// configuration, so an unknown name can never end up allowed.
	for _, name := range newSyscall.Names {
		if err := ensureKnownSyscall(name); err != nil {
			return err
		}
	}

	// Merge aliases into an existing equivalent rule instead of emitting a
	// second rule that could be interpreted differently across ABIs.
	if ruleAlreadyCovered(&newSyscall, config.Syscalls) {
		return nil
	}

	decision, err := decideCourseOfAction(&newSyscall, config.Syscalls)
	if err != nil {
		return err
	}
	delimDecision := strings.Split(decision, ":")

	if delimDecision[0] == seccompAppend {
		config.Syscalls = append(config.Syscalls, newSyscall)
	}

	if delimDecision[0] == seccompOverwrite {
		indexForOverwrite, err := strconv.ParseInt(delimDecision[1], 10, 32)
		if err != nil {
			return err
		}
		config.Syscalls[indexForOverwrite] = newSyscall
	}

	return nil
}

var actions = map[string]rspec.LinuxSeccompAction{
	"allow": rspec.ActAllow,
	"errno": rspec.ActErrno,
	"kill":  rspec.ActKill,
	"trace": rspec.ActTrace,
	"trap":  rspec.ActTrap,
}

// parseAction maps the user facing action name to its SCMP_ACT_<ACTION>
// value. The original action string is quoted in the error so an unknown
// action can be traced back to the exact input instead of being treated as
// allow.
func parseAction(action string) (rspec.LinuxSeccompAction, error) {
	a, ok := actions[action]
	if !ok {
		return "", fmt.Errorf("unrecognized action: %q", action)
	}
	return a, nil
}

// ParseDefaultAction sets the default action of the seccomp configuration
// and then removes any rules that were already specified with this action
func ParseDefaultAction(action string, config *rspec.LinuxSeccomp) error {
	if action == "" {
		return nil
	}

	defaultAction, err := parseAction(action)
	if err != nil {
		return err
	}
	config.DefaultAction = defaultAction
	err = RemoveAllMatchingRules(config, defaultAction)
	if err != nil {
		return err
	}
	return nil
}

// ParseDefaultActionForce simply sets the default action of the seccomp configuration
func ParseDefaultActionForce(action string, config *rspec.LinuxSeccomp) error {
	if action == "" {
		return nil
	}

	defaultAction, err := parseAction(action)
	if err != nil {
		return err
	}
	config.DefaultAction = defaultAction
	return nil
}

func newSyscallStruct(name string, action rspec.LinuxSeccompAction, args []rspec.LinuxSeccompArg) rspec.LinuxSyscall {
	syscallStruct := rspec.LinuxSyscall{
		Names:  []string{name},
		Action: action,
		Args:   args,
	}
	return syscallStruct
}

func (s SyscallOpts) argsAreEmpty() bool {
	return (s.Index == "" &&
		s.Value == "" &&
		s.ValueTwo == "" &&
		s.Operator == "")
}
