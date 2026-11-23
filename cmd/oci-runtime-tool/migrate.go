package main

import (
	"fmt"
	"io"
	"os"

	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/runtime-tools/migration"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var migrateFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "input, i",
		Usage: "path to the source configuration file (defaults to stdin)",
	},
	cli.StringFlag{
		Name:  "output, o",
		Usage: "path to write the migrated configuration (defaults to stdout)",
	},
	cli.StringFlag{
		Name:  "target-version, t",
		Value: rspec.Version,
		Usage: "target OCI runtime specification version",
	},
	cli.BoolFlag{
		Name:  "drop-unsupported",
		Usage: "remove fields the target version does not define (security-relevant fields are still reported)",
	},
}

var migrateCommand = cli.Command{
	Name:   "migrate",
	Usage:  "migrate an OCI runtime configuration between specification versions",
	Flags:  migrateFlags,
	Before: before,
	Action: func(c *cli.Context) error {
		input, err := readMigrationInput(c.String("input"))
		if err != nil {
			return err
		}

		result, err := migration.Convert(input, c.String("target-version"), migration.Options{
			DropUnsupported: c.Bool("drop-unsupported"),
		})
		if err != nil {
			return err
		}

		// Surface capability losses before writing anything, even when
		// dropping was explicitly authorized.
		for _, f := range result.UnsupportedFields {
			if f.Security() {
				logrus.Warnf("dropped security-relevant field %s", f)
			} else {
				logrus.Warnf("dropped unsupported field %s", f)
			}
		}
		for _, ext := range result.UnknownExtensions {
			logrus.Infof("preserving unknown extension %s", ext)
		}

		if !result.Changed {
			logrus.Infof("source already targets %s; original bytes preserved", result.TargetVersion)
		}

		return writeMigrationOutput(c.String("output"), result.Output)
	},
}

func readMigrationInput(path string) ([]byte, error) {
	if path == "" {
		stat, err := os.Stdin.Stat()
		if err != nil {
			return nil, err
		}
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			return nil, fmt.Errorf("no --input given and stdin is a terminal; pipe a configuration or pass --input")
		}
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func writeMigrationOutput(path string, data []byte) error {
	if path == "" {
		// Write the converter's bytes verbatim: same-version conversions
		// must preserve the original byte sequence exactly, including
		// whatever line ending the input had.
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
