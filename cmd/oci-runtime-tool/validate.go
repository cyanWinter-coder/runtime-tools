package main

import (
	"fmt"
	"runtime"

	rfc2119 "github.com/opencontainers/runtime-tools/error"
	"github.com/opencontainers/runtime-tools/specerror"
	"github.com/opencontainers/runtime-tools/validate"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var bundleValidateFlags = []cli.Flag{
	cli.StringFlag{Name: "path", Value: ".", Usage: "path to a bundle"},
	cli.StringFlag{Name: "platform", Value: runtime.GOOS, Usage: "platform of the target bundle (linux, windows, solaris)"},
	cli.BoolFlag{Name: "migrate", Usage: "migrate configurations targeting older spec versions to the current version before validating"},
}

var bundleValidateCommand = cli.Command{
	Name:   "validate",
	Usage:  "validate an OCI bundle",
	Flags:  bundleValidateFlags,
	Before: before,
	Action: func(context *cli.Context) error {
		hostSpecific := context.GlobalBool("host-specific")
		complianceLevelString := context.GlobalString("compliance-level")
		complianceLevel, err := rfc2119.ParseLevel(complianceLevelString)
		if err != nil {
			complianceLevel = rfc2119.Must
			logrus.Warningf("%s, using 'MUST' by default.", err.Error())
		}
		inputPath := context.String("path")
		platform := context.String("platform")

		var v validate.Validator
		if context.Bool("migrate") {
			// Old-version entry point: canonicalize and migrate through
			// the shared migration object before running the same checks.
			v, err = validate.NewValidatorFromMigratedPath(inputPath, hostSpecific, platform)
		} else {
			v, err = validate.NewValidatorFromPath(inputPath, hostSpecific, platform)
		}
		if err != nil {
			return err
		}

		if err := v.CheckAll(); err != nil {
			levelErrors, err := specerror.SplitLevel(err, complianceLevel)
			if err != nil {
				return err
			}
			for _, e := range levelErrors.Warnings {
				logrus.Warn(e)
			}

			return levelErrors.Error.ErrorOrNil()
		}
		fmt.Println("Bundle validation succeeded.")
		return nil
	},
}
