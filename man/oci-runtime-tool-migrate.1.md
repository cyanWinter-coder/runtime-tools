% OCI(1) OCI-RUNTIME-TOOL User Manuals
% OCI Community
% NOVEMBER 2026
# NAME
oci-runtime-tool-migrate - Migrate an OCI runtime configuration between specification versions

# SYNOPSIS
**oci-runtime-tool migrate**  *[OPTIONS]*

# DESCRIPTION

Converts an OCI runtime configuration (`config.json`) from its declared
`ociVersion` to another specification version.

The source version is always read from the document itself. When the
target version equals the source version the input bytes are written
back unchanged, so the operation is byte-stable for an already current
configuration.

Each field added after the 1.0.2 baseline carries the version that
introduced it. On a downgrade, fields the target version does not define
are reported before anything is written. Security-relevant fields (for
example seccomp options, resource limits, namespace or device handoff and
idmapped mount options) are never removed silently: by default the
command fails instead. With **--drop-unsupported** the fields are
removed, but each removal is still logged (use the global
**--log-level=warn** to see them) and available programmatically in the
migration result. Properties unknown to every supported version
(extensions) are always preserved verbatim.

# OPTIONS
**--help**
  Print usage statement

**--input**, **-i**=PATH
  Path to the source configuration file. Defaults to standard input.

**--output**, **-o**=PATH
  Path to write the migrated configuration. Defaults to standard output.

**--target-version**, **-t**=VERSION
  Target OCI runtime specification version. Defaults to the version the
  tool is built against.

**--drop-unsupported**
  Remove fields the target version does not define instead of failing.
  Every removed field is reported; security-relevant removals are warned
  about explicitly.

# SEE ALSO
**oci-runtime-tool**(1), **oci-runtime-tool-validate**(1)

# HISTORY
November 2026, version migration support added.
