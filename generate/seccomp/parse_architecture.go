package seccomp

import (
	rspec "github.com/opencontainers/runtime-spec/specs-go"
)

// ParseArchitectureFlag takes the raw string passed with the --arch flag, parses it
// and updates the Seccomp config accordingly. Architectures are resolved through
// the explicit archToABIs mapping, and an unsupported architecture makes the
// parse fail before any filter is generated.
func ParseArchitectureFlag(architectureArg string, config *rspec.LinuxSeccomp) error {
	correctedArch, err := parseArch(architectureArg)
	if err != nil {
		return err
	}

	for _, alreadySpecified := range config.Architectures {
		if correctedArch == alreadySpecified {
			// Same ABI requested twice, keep the entry unique so the
			// generated filter has a deterministic architecture list.
			return nil
		}
	}
	config.Architectures = append(config.Architectures, correctedArch)
	return nil
}
