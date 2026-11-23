// Package bundle implements atomic generation of OCI runtime bundles.
//
// A bundle is materialized by writing config.json into a staging
// directory in the same parent directory as the target, validating the
// resulting configuration, and only then renaming the staging directory
// to the target path.  Until the rename succeeds the target path is
// never visible to a runtime, and on any failure or cancellation the
// staging directory is removed without touching any pre-existing
// bundle.
package bundle

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/hashicorp/go-multierror"
	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/runtime-tools/generate"
	"github.com/opencontainers/runtime-tools/validate"
)

// ConfigName is the name of the configuration file inside a bundle.
const ConfigName = "config.json"

// Options controls how Generate assembles a bundle.
type Options struct {
	// Rootfs is the path to a local root filesystem.  Nothing is
	// copied into the bundle; the final absolute path is recorded in
	// config.json as root.path.  When empty, root.path is left as
	// configured in the generator.
	Rootfs string

	// HostSpecific enables host-specific validation of the generated
	// configuration.
	HostSpecific bool

	// Platform is the target platform (GOOS) used for validation.
	// Defaults to the host platform.
	Platform string
}

// BuildSpec returns the default configuration for platform merged with
// the template at templatePath.
//
// The merge follows an explicit priority: built-in defaults first, then
// the template.  Empty values in the template (null, "", [], {}) never
// override defaults; non-empty objects are merged key by key, non-empty
// arrays and scalars replace the default.  Callers may apply further
// overrides (for example command-line flags) on top of the result,
// which then take the highest priority.  An empty templatePath returns
// the defaults unmodified.
func BuildSpec(platform, templatePath string) (*rspec.Spec, error) {
	specgen, err := generate.New(platform)
	if err != nil {
		return nil, err
	}
	if templatePath == "" {
		return specgen.Config, nil
	}

	data, err := os.ReadFile(templatePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("template configuration at %s not found", templatePath)
		}
		return nil, err
	}

	return MergeTemplate(specgen.Config, data)
}

// Generate atomically creates a bundle at targetDir from the
// configuration in g and returns the absolute path of the bundle.
//
// The configuration is written to a staging directory in the same
// parent directory as targetDir and fully validated before the staging
// directory is renamed to targetDir, so the target only ever appears
// complete.  If targetDir already exists, or validation fails, or ctx
// is cancelled, an error is returned, the staging content is removed,
// and any pre-existing bundle at targetDir is left untouched.
func Generate(ctx context.Context, targetDir string, g *generate.Generator, opts Options) (string, error) {
	platform := opts.Platform
	if platform == "" {
		platform = runtime.GOOS
	}

	if err := ctx.Err(); err != nil {
		return "", err
	}

	absTarget, err := filepath.Abs(targetDir)
	if err != nil {
		return "", err
	}

	// Record the final absolute rootfs path; the rootfs itself is
	// referenced, never copied.
	if opts.Rootfs != "" {
		absRootfs, err := filepath.Abs(opts.Rootfs)
		if err != nil {
			return "", err
		}
		resolved, err := filepath.EvalSymlinks(absRootfs)
		if err != nil {
			return "", fmt.Errorf("rootfs %q: %w", opts.Rootfs, err)
		}
		fi, err := os.Stat(resolved)
		if err != nil {
			return "", fmt.Errorf("rootfs %q: %w", opts.Rootfs, err)
		}
		if !fi.IsDir() {
			return "", fmt.Errorf("rootfs %q is not a directory", opts.Rootfs)
		}
		g.SetRootPath(resolved)
	}

	if _, err := os.Lstat(absTarget); err == nil {
		return "", fmt.Errorf("target bundle directory %q already exists", absTarget)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}

	staging, err := os.MkdirTemp(filepath.Dir(absTarget), "."+filepath.Base(absTarget)+".tmp-")
	if err != nil {
		return "", fmt.Errorf("cannot create staging directory: %w", err)
	}
	// MkdirTemp creates the directory with 0700 permissions; a bundle
	// should get the conventional directory permissions instead.
	if err := os.Chmod(staging, 0o755); err != nil {
		os.RemoveAll(staging)
		return "", err
	}
	committed := false
	defer func() {
		if !committed {
			os.RemoveAll(staging)
		}
	}()

	if err := g.SaveToFile(filepath.Join(staging, ConfigName), generate.ExportOptions{}); err != nil {
		return "", err
	}

	if err := validateConfig(g.Config, staging, opts.HostSpecific || g.HostSpecific, platform); err != nil {
		return "", fmt.Errorf("generated configuration is invalid: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return "", err
	}

	// os.Rename silently replaces an existing empty directory, so
	// re-check the target immediately before committing.
	if _, err := os.Lstat(absTarget); err == nil {
		return "", fmt.Errorf("target bundle directory %q already exists", absTarget)
	}
	if err := os.Rename(staging, absTarget); err != nil {
		return "", fmt.Errorf("cannot commit bundle to %q: %w", absTarget, err)
	}
	committed = true
	return absTarget, nil
}

// validateConfig runs the full local validation suite against the
// generated configuration.  CheckJSONSchema is deliberately skipped
// because it downloads the schema over the network; CheckRoot is
// replaced by checkRoot because the OCI bundle-layout rules assume the
// rootfs lives inside the bundle, while Generate intentionally records
// an external rootfs by absolute path.
func validateConfig(spec *rspec.Spec, bundlePath string, hostSpecific bool, platform string) error {
	validator, err := validate.NewValidator(spec, bundlePath, hostSpecific, platform)
	if err != nil {
		return err
	}

	var errs *multierror.Error
	errs = multierror.Append(errs, checkRoot(spec, bundlePath))
	errs = multierror.Append(errs, validator.CheckPlatform())
	errs = multierror.Append(errs, validator.CheckMandatoryFields())
	errs = multierror.Append(errs, validator.CheckSemVer())
	errs = multierror.Append(errs, validator.CheckMounts())
	errs = multierror.Append(errs, validator.CheckProcess())
	errs = multierror.Append(errs, validator.CheckLinux())
	errs = multierror.Append(errs, validator.CheckAnnotations())
	if platform == "linux" || platform == "solaris" {
		errs = multierror.Append(errs, validator.CheckHooks())
	}
	return errs.ErrorOrNil()
}

// checkRoot verifies that root.path is set and points at an existing
// directory, without requiring it to live inside the bundle.  Relative
// paths are resolved against the bundle directory, as the runtime
// would resolve them.
func checkRoot(spec *rspec.Spec, bundlePath string) error {
	if spec.Root == nil {
		return errors.New("root is REQUIRED but not set")
	}
	if spec.Root.Path == "" {
		return errors.New("root.path is REQUIRED but empty")
	}
	rootPath := spec.Root.Path
	if !filepath.IsAbs(rootPath) {
		rootPath = filepath.Join(bundlePath, rootPath)
	}
	fi, err := os.Stat(rootPath)
	if err != nil {
		return fmt.Errorf("cannot find the root path %q", spec.Root.Path)
	}
	if !fi.IsDir() {
		return fmt.Errorf("root.path %q is not a directory", spec.Root.Path)
	}
	return nil
}
