% OCI(1) OCI-RUNTIME-TOOL User Manuals
% OCI Community
% NOVEMBER 2026
# NAME
oci-runtime-tool-generate-bundle - Generate an OCI runtime bundle atomically

# SYNOPSIS
**oci-runtime-tool generate-bundle** *[OPTIONS]* BUNDLE-DIR

# DESCRIPTION

`oci-runtime-tool generate-bundle` generates an OCI runtime bundle
containing a validated `config.json` in BUNDLE-DIR.

The configuration is assembled with an explicit priority: the built-in
defaults first, then the **--template** file, then explicitly set
command-line flags.  Empty values in the template (null, "", [], {})
never override defaults; non-empty objects are merged key by key, and
non-empty arrays and scalars replace the default value.

When **--rootfs** is given, only its final absolute path is recorded in
`config.json` as `root.path`; the root filesystem itself is never
copied into the bundle.

The bundle is written to a staging directory in the same parent
directory as BUNDLE-DIR, and the configuration is fully validated
before the staging directory is renamed into place, so BUNDLE-DIR only
ever appears complete and can never be observed half-written by a
runtime.  If generation fails or is interrupted, the staging content
is removed and any pre-existing bundle is left untouched.  Generation
fails if BUNDLE-DIR already exists.

On success the absolute path of the bundle is printed to stdout.

All options of **oci-runtime-tool-generate**(1) except **--output** are
accepted and take precedence over the template when explicitly set.

# OPTIONS
**--rootfs**=""
  Path to a local root filesystem.  Only its final absolute path is
  recorded in `config.json`; nothing is copied.

**--template**=""
  Base template to use for creating the configuration.  Empty values
  in the template do not override the built-in defaults.

**--help**
  Print usage statement

# SEE ALSO
**oci-runtime-tool-generate**(1), **oci-runtime-tool-validate**(1)

# HISTORY
November 2026, Added by the OCI community.
