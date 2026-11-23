// Package migration converts OCI runtime configuration bundles between
// versions of the Open Container Initiative Runtime Specification.
//
// The converter works on the generic JSON representation of a
// configuration (map[string]any) rather than on the typed
// github.com/opencontainers/runtime-spec/specs-go.Spec struct. This has
// three properties required for lossless version migration:
//
//   - Fields introduced by a newer specification version survive a
//     round trip through a toolchain built against an older one.
//   - Extensions unknown to any released specification version are
//     preserved verbatim instead of being dropped by a typed unmarshal.
//   - When source and target versions are equal the original bytes are
//     returned untouched, keeping byte-level semantics stable.
//
// Every field added after the 1.0.2 baseline carries the specification
// version that introduced it (see fieldIntroductions), so fields
// unsupported by the target version can be reported before anything is
// written. Security-relevant fields are never removed silently: a
// downgrade that would drop one fails unless the caller explicitly opts
// in with [Options.DropUnsupported], and even then every removed field
// is returned in [Result.UnsupportedFields].
package migration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/blang/semver/v4"
)

// SupportedVersions lists the specification versions this converter
// knows about, in ascending order. Configurations declaring one of these
// versions can be read and converted.
var SupportedVersions = []string{
	"1.0.2",
	"1.1.0",
	"1.2.0",
	"1.2.1",
	"1.3.0",
}

// FieldKind classifies a known field for downgrade reporting. Security
// and isolation fields cannot be removed without explicit consent.
type FieldKind int

const (
	// FieldGeneric is a field with no direct security or isolation impact.
	FieldGeneric FieldKind = iota
	// FieldSecurity is a field that constrains or mediates what the
	// container can do (seccomp, resource limits, device or namespace
	// handoff, idmapped mounts, ...). Dropping it weakens the security
	// posture of the configuration.
	FieldSecurity
)

// FieldRecord describes a single field known to the converter.
type FieldRecord struct {
	// Path is the dotted JSON location of the field. Array elements are
	// not indexed; the path names the property of the objects held by the
	// array, for example "linux.seccomp.defaultAction".
	Path string
	// IntroducedIn is the first specification version that defines the
	// field. Fields present in 1.0.2 (the oldest supported version) are
	// not listed at all.
	IntroducedIn semver.Version
	// Kind marks fields whose silent removal would weaken the security
	// posture of the configuration.
	Kind FieldKind
}

// Introduction versions used in fieldIntroductions.
var (
	v110 = semver.Version{Major: 1, Minor: 1, Patch: 0}
	v120 = semver.Version{Major: 1, Minor: 2, Patch: 0}
	v121 = semver.Version{Major: 1, Minor: 2, Patch: 1}
	v130 = semver.Version{Major: 1, Minor: 3, Patch: 0}
)

// fieldIntroductions is the declarative field map: every field added
// after the 1.0.2 baseline, keyed by its JSON path, annotated with the
// version that introduced it and with whether it is security relevant.
//
// The list is derived from the runtime-spec ChangeLog and the JSON tags
// of specs-go. A field that does not appear here is either part of the
// 1.0.2 baseline or an unknown extension (and therefore preserved).
//
// Fields introduced in 1.1.0 and 1.2.x are included because a 1.3.0
// configuration may have to be downgraded past the version that
// introduced them.
var fieldIntroductions = map[string]FieldRecord{
	// --- Fields introduced in 1.1.0 ---

	// The scheduler changes how container code runs on the CPU and is
	// part of the process execution constraints.
	"process.scheduler":          {Path: "process.scheduler", IntroducedIn: v110},
	"process.scheduler.policy":   {Path: "process.scheduler.policy", IntroducedIn: v110},
	"process.scheduler.nice":     {Path: "process.scheduler.nice", IntroducedIn: v110},
	"process.scheduler.priority": {Path: "process.scheduler.priority", IntroducedIn: v110},
	"process.scheduler.flags":    {Path: "process.scheduler.flags", IntroducedIn: v110},
	"process.scheduler.runtime":  {Path: "process.scheduler.runtime", IntroducedIn: v110},
	"process.scheduler.deadline": {Path: "process.scheduler.deadline", IntroducedIn: v110},
	"process.scheduler.period":   {Path: "process.scheduler.period", IntroducedIn: v110},
	// I/O priority mediates cgroup I/O scheduling for container tasks.
	"process.ioPriority":          {Path: "process.ioPriority", IntroducedIn: v110, Kind: FieldSecurity},
	"process.ioPriority.class":    {Path: "process.ioPriority.class", IntroducedIn: v110, Kind: FieldSecurity},
	"process.ioPriority.priority": {Path: "process.ioPriority.priority", IntroducedIn: v110, Kind: FieldSecurity},
	// Umask controls the default permissions of files the process makes.
	"process.user.umask": {Path: "process.user.umask", IntroducedIn: v110, Kind: FieldSecurity},
	"domainname":         {Path: "domainname", IntroducedIn: v110},

	// Linux resource controls constrain the container; losing them on a
	// downgrade removes the enforced limits.
	"linux.resources.cpu.idle":                 {Path: "linux.resources.cpu.idle", IntroducedIn: v110, Kind: FieldSecurity},
	"linux.resources.cpu.burst":                {Path: "linux.resources.cpu.burst", IntroducedIn: v110, Kind: FieldSecurity},
	"linux.resources.memory.checkBeforeUpdate": {Path: "linux.resources.memory.checkBeforeUpdate", IntroducedIn: v110, Kind: FieldSecurity},
	"linux.timeOffsets":                        {Path: "linux.timeOffsets", IntroducedIn: v110},
	// Seccomp notify turns the syscall filter into a userspace mediation
	// channel; it is squarely security relevant.
	"linux.seccomp.flags":             {Path: "linux.seccomp.flags", IntroducedIn: v110, Kind: FieldSecurity},
	"linux.seccomp.listenerPath":      {Path: "linux.seccomp.listenerPath", IntroducedIn: v110, Kind: FieldSecurity},
	"linux.seccomp.listenerMetadata":  {Path: "linux.seccomp.listenerMetadata", IntroducedIn: v110, Kind: FieldSecurity},
	"linux.seccomp.syscalls.errnoRet": {Path: "linux.seccomp.syscalls.errnoRet", IntroducedIn: v110, Kind: FieldSecurity},
	"linux.seccomp.defaultErrnoRet":   {Path: "linux.seccomp.defaultErrnoRet", IntroducedIn: v110, Kind: FieldSecurity},
	// Intel RDT monitoring controls (1.1.0 spelling; renamed in 1.3.0).
	"linux.intelRdt.enableCMT": {Path: "linux.intelRdt.enableCMT", IntroducedIn: v110, Kind: FieldSecurity},
	"linux.intelRdt.enableMBM": {Path: "linux.intelRdt.enableMBM", IntroducedIn: v110, Kind: FieldSecurity},

	// --- Fields introduced in 1.2.x ---

	// The idmap/ridmap mount *options* are plain strings inside
	// mounts[].options, so they are covered by mountOptionIntroductions
	// rather than by a struct field path.

	// 1.2.1: CPU affinity for executed processes.
	"process.execCPUAffinity":         {Path: "process.execCPUAffinity", IntroducedIn: v121},
	"process.execCPUAffinity.initial": {Path: "process.execCPUAffinity.initial", IntroducedIn: v121},
	"process.execCPUAffinity.final":   {Path: "process.execCPUAffinity.final", IntroducedIn: v121},

	// 1.2.1: Windows CPU group affinity.
	"windows.resources.cpu.affinity":       {Path: "windows.resources.cpu.affinity", IntroducedIn: v121},
	"windows.resources.cpu.affinity.mask":  {Path: "windows.resources.cpu.affinity.mask", IntroducedIn: v121},
	"windows.resources.cpu.affinity.group": {Path: "windows.resources.cpu.affinity.group", IntroducedIn: v121},

	// --- Fields introduced in 1.3.0 ---

	// 1.3.0: FreeBSD platform configuration.
	"freebsd": {Path: "freebsd", IntroducedIn: v130},

	// 1.3.0: network devices moved into the container network namespace;
	// the field changes the namespace's attack surface.
	"linux.netDevices":      {Path: "linux.netDevices", IntroducedIn: v130, Kind: FieldSecurity},
	"linux.netDevices.name": {Path: "linux.netDevices.name", IntroducedIn: v130, Kind: FieldSecurity},

	// 1.3.0: NUMA memory policy.
	"linux.memoryPolicy":       {Path: "linux.memoryPolicy", IntroducedIn: v130, Kind: FieldSecurity},
	"linux.memoryPolicy.mode":  {Path: "linux.memoryPolicy.mode", IntroducedIn: v130, Kind: FieldSecurity},
	"linux.memoryPolicy.nodes": {Path: "linux.memoryPolicy.nodes", IntroducedIn: v130, Kind: FieldSecurity},
	"linux.memoryPolicy.flags": {Path: "linux.memoryPolicy.flags", IntroducedIn: v130, Kind: FieldSecurity},

	// 1.3.0: Intel RDT extensions.
	"linux.intelRdt.schemata":         {Path: "linux.intelRdt.schemata", IntroducedIn: v130, Kind: FieldSecurity},
	"linux.intelRdt.enableMonitoring": {Path: "linux.intelRdt.enableMonitoring", IntroducedIn: v130, Kind: FieldSecurity},

	// 1.3.0: VM hardware configuration.
	"vm.hwconfig":                 {Path: "vm.hwconfig", IntroducedIn: v130},
	"vm.hwconfig.deviceTree":      {Path: "vm.hwconfig.deviceTree", IntroducedIn: v130},
	"vm.hwconfig.vcpus":           {Path: "vm.hwconfig.vcpus", IntroducedIn: v130},
	"vm.hwconfig.memory":          {Path: "vm.hwconfig.memory", IntroducedIn: v130},
	"vm.hwconfig.dtdevs":          {Path: "vm.hwconfig.dtdevs", IntroducedIn: v130, Kind: FieldSecurity},
	"vm.hwconfig.iomems":          {Path: "vm.hwconfig.iomems", IntroducedIn: v130, Kind: FieldSecurity},
	"vm.hwconfig.iomems.firstGFN": {Path: "vm.hwconfig.iomems.firstGFN", IntroducedIn: v130, Kind: FieldSecurity},
	"vm.hwconfig.iomems.firstMFN": {Path: "vm.hwconfig.iomems.firstMFN", IntroducedIn: v130, Kind: FieldSecurity},
	"vm.hwconfig.iomems.nrMFNs":   {Path: "vm.hwconfig.iomems.nrMFNs", IntroducedIn: v130, Kind: FieldSecurity},
	"vm.hwconfig.irqs":            {Path: "vm.hwconfig.irqs", IntroducedIn: v130, Kind: FieldSecurity},
}

// MountOptionIDMap and MountOptionRIDMap are the mount-option strings
// introduced by 1.2.0 (they live in mounts[].options, whose entries are
// free-form strings and have no per-entry schema).
const (
	MountOptionIDMap  = "idmap"
	MountOptionRIDMap = "ridmap"
)

var mountOptionIntroductions = map[string]semver.Version{
	MountOptionIDMap:  v120,
	MountOptionRIDMap: v120,
}

// UnsupportedField reports a field present in the source configuration
// that the target specification version does not define.
type UnsupportedField struct {
	// Path locates the field the same way FieldRecord.Path does. For a
	// mount option the synthetic path is mounts[].options.<option>.
	Path string
	// IntroducedIn is the version that first defined the field.
	IntroducedIn semver.Version
	// Kind marks fields whose silent removal weakens security.
	Kind FieldKind
}

// Security reports whether the field is security or isolation relevant.
func (u UnsupportedField) Security() bool { return u.Kind == FieldSecurity }

func (u UnsupportedField) String() string {
	scope := "generic"
	if u.Security() {
		scope = "security-relevant"
	}
	return fmt.Sprintf("%s (introduced in %s, %s)", u.Path, u.IntroducedIn, scope)
}

// Options controls a conversion.
type Options struct {
	// DropUnsupported permits removing fields the target version does
	// not know about. Without it, Convert returns an
	// UnsupportedFieldsError instead of touching the document. Every
	// removed field is still reported via Result.UnsupportedFields, so
	// security-relevant content can never disappear without a record.
	DropUnsupported bool
}

// Result is the outcome of a conversion.
type Result struct {
	// SourceVersion and TargetVersion are the parsed semver values.
	SourceVersion semver.Version
	TargetVersion semver.Version
	// Changed is false when source and target versions are equal; in
	// that case Output is the exact input byte sequence.
	Changed bool
	// Output is the migrated configuration, encoded as canonical JSON
	// (two-space indentation, sorted object keys).
	Output []byte
	// UnsupportedFields lists fields the target version cannot
	// represent. When Options.DropUnsupported is false the conversion
	// fails and Output is nil; when it is true these fields have been
	// removed from Output and are recorded here.
	UnsupportedFields []UnsupportedField
	// UnknownExtensions lists properties that match no field of any
	// supported specification version; they are carried over verbatim.
	UnknownExtensions []string
}

// UnsupportedFieldsError is returned by Convert when the target version
// cannot represent one or more source fields and dropping was not
// authorized. It deliberately blocks the write path: a configuration
// must never lose security-relevant content without the caller knowing.
type UnsupportedFieldsError struct {
	Target semver.Version
	Fields []UnsupportedField
}

func (e *UnsupportedFieldsError) Error() string {
	security := 0
	parts := make([]string, 0, len(e.Fields))
	for _, f := range e.Fields {
		if f.Security() {
			security++
		}
		parts = append(parts, "  - "+f.String())
	}
	sort.Strings(parts)
	return fmt.Sprintf("cannot migrate to spec %s: %d field(s) unsupported by the target version (%d security-relevant); refusing to drop them silently. Re-run with DropUnsupported to remove them explicitly:\n%s",
		e.Target, len(e.Fields), security, strings.Join(parts, "\n"))
}

// ParseVersion parses an ociVersion value. A trailing "-dev" suffix
// (used by development branches) is accepted and stripped.
func ParseVersion(raw string) (semver.Version, error) {
	stripped := strings.TrimSpace(strings.TrimSuffix(raw, "-dev"))
	v, err := semver.Parse(stripped)
	if err != nil {
		return semver.Version{}, fmt.Errorf("invalid ociVersion %q: %w", raw, err)
	}
	return v, nil
}

// IsSupported reports whether the converter handles the given version.
func IsSupported(v semver.Version) bool {
	for _, s := range SupportedVersions {
		if sv, err := semver.Parse(s); err == nil && sv.EQ(v) {
			return true
		}
	}
	return false
}

// FieldIntroductions exposes the declarative field map, keyed by JSON
// path. It is intended for tooling (tests, documentation generators)
// that needs to know which specification version introduced a field.
func FieldIntroductions() map[string]FieldRecord {
	out := make(map[string]FieldRecord, len(fieldIntroductions))
	for k, v := range fieldIntroductions {
		out[k] = v
	}
	return out
}

// Convert migrates the configuration in input from its declared
// ociVersion to targetVersion.
//
// The source version is always read from the document itself; callers
// never pass it in, so a mislabelled input cannot be converted against
// the wrong rules. If source and target are the same version the input
// bytes are returned unchanged (Result.Changed == false).
func Convert(input []byte, targetVersion string, opts Options) (*Result, error) {
	// Build the shared normalized representation first; this also
	// identifies and validates the source version from ociVersion.
	canonical, err := Canonicalize(input)
	if err != nil {
		return nil, err
	}
	source := canonical.Version

	if !IsSupported(source) {
		return nil, fmt.Errorf("source spec version %s is not supported (supported: %s)", source, strings.Join(SupportedVersions, ", "))
	}

	target, err := ParseVersion(targetVersion)
	if err != nil {
		return nil, err
	}
	if !IsSupported(target) {
		return nil, fmt.Errorf("target spec version %s is not supported (supported: %s)", target, strings.Join(SupportedVersions, ", "))
	}

	result := &Result{SourceVersion: source, TargetVersion: target}

	// Same version: preserve the original byte semantics exactly.
	if source.EQ(target) {
		result.Output = append([]byte(nil), input...)
		return result, nil
	}

	doc := canonical.Document

	// Structural conversions between released versions run first, while
	// every field is still present, so the inspection afterwards sees
	// the shape the target version actually defines.
	convertIntelRdt(doc, source, target)

	unsupported, unknown := inspect(doc, target)
	result.UnsupportedFields = unsupported
	result.UnknownExtensions = unknown

	if len(unsupported) > 0 && !opts.DropUnsupported {
		return nil, &UnsupportedFieldsError{Target: target, Fields: unsupported}
	}

	if opts.DropUnsupported {
		dropUnsupported(doc, unsupported)
	}

	// Stamp the target version onto the canonical document.
	doc["ociVersion"] = target.String()

	out, err := canonicalJSON(doc)
	if err != nil {
		return nil, err
	}
	result.Output = out
	result.Changed = true
	return result, nil
}

// inspect walks the generic document and returns:
//   - fields present in the document whose introduction version is newer
//     than the target (unsupported),
//   - properties unknown to the reflected specification baseline
//     (extensions to preserve).
func inspect(doc map[string]any, target semver.Version) ([]UnsupportedField, []string) {
	var unsupported []UnsupportedField
	var unknown []string

	walkDocument("", doc, func(path string, value any) {
		if path == "ociVersion" {
			return
		}
		if rec, tracked := fieldIntroductions[path]; tracked {
			if rec.IntroducedIn.GT(target) {
				unsupported = append(unsupported, UnsupportedField{
					Path:         rec.Path,
					IntroducedIn: rec.IntroducedIn,
					Kind:         rec.Kind,
				})
			}
			return
		}
		if !known.isKnown(path) {
			unknown = append(unknown, path)
		}
	})

	// Mount options carry version information outside the struct field
	// map (they are free-form strings).
	if mounts, ok := doc["mounts"].([]any); ok {
		for _, m := range mounts {
			mount, ok := m.(map[string]any)
			if !ok {
				continue
			}
			options, ok := mount["options"].([]any)
			if !ok {
				continue
			}
			for _, o := range options {
				opt, ok := o.(string)
				if !ok {
					continue
				}
				if introduced, ok := mountOptionIntroductions[opt]; ok && introduced.GT(target) {
					unsupported = append(unsupported, UnsupportedField{
						Path:         "mounts[].options." + opt,
						IntroducedIn: introduced,
						// idmap changes the ownership semantics the
						// container sees; treat it as isolation relevant.
						Kind: FieldSecurity,
					})
				}
			}
		}
	}

	sort.Slice(unsupported, func(i, j int) bool { return unsupported[i].Path < unsupported[j].Path })
	sort.Strings(unknown)
	return unsupported, dedup(unknown)
}

// walkDocument invokes visit for every object property reachable from
// v, using normalized paths where map values are not split into their
// user-supplied keys. path is the dotted location of the containing
// object.
func walkDocument(path string, v any, visit func(path string, value any)) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := t[k]
			childPath := k
			if path != "" {
				childPath = path + "." + k
			}
			visit(childPath, child)

			// A spec-defined map (annotations, sysctl, rdma, ...) is a
			// leaf: its keys are user data, not schema properties.
			if known.isMapField(childPath) {
				continue
			}
			walkDocument(childPath, child, visit)
		}
	case []any:
		for _, elem := range t {
			walkDocument(path, elem, visit)
		}
	}
}

// dropUnsupported removes the reported fields from the document. Only
// paths from the report are touched; unknown extensions and baseline
// fields are left alone.
func dropUnsupported(doc map[string]any, unsupported []UnsupportedField) {
	paths := make([]string, 0, len(unsupported))
	for _, f := range unsupported {
		paths = append(paths, f.Path)
	}
	sort.Slice(paths, func(i, j int) bool {
		// Remove deeper paths first so empty parents can be pruned after.
		return strings.Count(paths[i], ".") > strings.Count(paths[j], ".")
	})

	for _, p := range paths {
		if strings.HasPrefix(p, "mounts[].options.") {
			dropMountOption(doc, strings.TrimPrefix(p, "mounts[].options."))
			continue
		}
		removePath(doc, p)
	}
}

// removePath deletes a dotted field path, pruning empty container
// objects (but never arrays) it leaves behind.
func removePath(doc map[string]any, path string) {
	parts := strings.Split(path, ".")
	var parentMaps []map[string]any
	var parentKeys []string

	cur := doc
	for i, part := range parts {
		next, ok := cur[part]
		if !ok {
			return
		}
		if i == len(parts)-1 {
			delete(cur, part)
			break
		}
		switch child := next.(type) {
		case map[string]any:
			parentMaps = append(parentMaps, cur)
			parentKeys = append(parentKeys, part)
			cur = child
		case []any:
			// Property inside array elements: remove the remainder of the
			// path from each element.
			rest := strings.Join(parts[i+1:], ".")
			for _, elem := range child {
				if m, ok := elem.(map[string]any); ok {
					removePath(m, rest)
				}
			}
			return
		default:
			return
		}
	}

	// Prune now-empty ancestor objects (arrays are deliberately kept).
	for i := len(parentMaps) - 1; i >= 0; i-- {
		child, ok := parentMaps[i][parentKeys[i]].(map[string]any)
		if ok && len(child) == 0 {
			delete(parentMaps[i], parentKeys[i])
		} else {
			break
		}
	}
}

func dropMountOption(doc map[string]any, opt string) {
	mounts, ok := doc["mounts"].([]any)
	if !ok {
		return
	}
	for _, m := range mounts {
		mount, ok := m.(map[string]any)
		if !ok {
			continue
		}
		options, ok := mount["options"].([]any)
		if !ok {
			continue
		}
		kept := options[:0]
		for _, o := range options {
			if s, ok := o.(string); ok && s == opt {
				continue
			}
			kept = append(kept, o)
		}
		if len(kept) == 0 {
			delete(mount, "options")
		} else {
			mount["options"] = kept
		}
	}
}

// convertIntelRdt applies the only structural field rename across the
// supported range: enableCMT/enableMBM (1.1.0) <-> enableMonitoring
// (1.3.0). On upgrade the two legacy flags fold into the new one if
// either is set; on downgrade the new flag expands onto both legacy
// flags.
func convertIntelRdt(doc map[string]any, source, target semver.Version) {
	linux, ok := doc["linux"].(map[string]any)
	if !ok {
		return
	}
	rdt, ok := linux["intelRdt"].(map[string]any)
	if !ok {
		return
	}

	if source.LT(v130) && target.GE(v130) {
		cmt, _ := rdt["enableCMT"].(bool)
		mbm, _ := rdt["enableMBM"].(bool)
		if cmt || mbm {
			rdt["enableMonitoring"] = true
		}
		delete(rdt, "enableCMT")
		delete(rdt, "enableMBM")
	} else if source.GE(v130) && target.LT(v130) {
		if monitoring, ok := rdt["enableMonitoring"].(bool); ok && monitoring {
			rdt["enableCMT"] = true
			rdt["enableMBM"] = true
		}
		delete(rdt, "enableMonitoring")
	}
}

// canonicalJSON renders v with sorted object keys and two-space
// indentation so that repeated conversions converge on stable bytes.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// json.Encoder.Encode appends a trailing newline; keep the output
	// self contained and predictable.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func dedup(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
