package main

import (
	gocontext "context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/opencontainers/runtime-tools/bundle"
	"github.com/opencontainers/runtime-tools/generate"
	"github.com/urfave/cli"
)

// generateBundleFlags mirrors generateFlags (so both commands accept
// the same overrides), except that --output is meaningless for a
// bundle, and --rootfs is added to reference a local root filesystem.
var generateBundleFlags = func() []cli.Flag {
	flags := []cli.Flag{
		cli.StringFlag{
			Name:  "rootfs",
			Usage: "path to a local root filesystem; only its final absolute path is recorded in config.json, nothing is copied",
		},
	}
	for _, flag := range generateFlags {
		if flag.GetName() == "output" {
			continue
		}
		flags = append(flags, flag)
	}
	return flags
}()

var generateBundleCommand = cli.Command{
	Name:      "generate-bundle",
	Usage:     "generate an OCI runtime bundle atomically",
	ArgsUsage: "<bundle-dir>",
	Description: `Generate an OCI runtime bundle containing config.json.

The configuration is assembled with an explicit priority: built-in
defaults first, then the --template file (empty template values never
override defaults), then explicitly set command-line flags.  When
--rootfs is given, only its final absolute path is recorded in
config.json; the root filesystem itself is never copied.

The bundle is written to a staging directory next to <bundle-dir> and
the configuration is fully validated before the staging directory is
renamed into place, so <bundle-dir> only ever appears complete.  On
failure or interruption the staging content is removed and any
pre-existing bundle is left untouched.  On success the absolute path
of the bundle is printed.`,
	Flags:  generateBundleFlags,
	Before: before,
	Action: func(context *cli.Context) error {
		if context.NArg() != 1 {
			return fmt.Errorf("exactly one bundle directory argument is required")
		}
		bundleDir := context.Args().First()
		platform := context.String("os")

		spec, err := bundle.BuildSpec(platform, context.String("template"))
		if err != nil {
			return err
		}
		specgen := generate.NewFromSpec(spec)
		if err := setupSpecExplicit(&specgen, context); err != nil {
			return err
		}

		ctx, stop := signal.NotifyContext(gocontext.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		path, err := bundle.Generate(ctx, bundleDir, &specgen, bundle.Options{
			Rootfs:       context.String("rootfs"),
			HostSpecific: context.GlobalBool("host-specific"),
			Platform:     platform,
		})
		if err != nil {
			return err
		}
		fmt.Println(path)
		return nil
	},
}
