package migration

import (
	"reflect"
	"sort"
	"strings"

	rspec "github.com/opencontainers/runtime-spec/specs-go"
)

// knownSchema describes every property defined by the typed
// specification the toolchain is built against (currently 1.3.0). It is
// derived once via reflection from rspec.Spec so that it cannot drift
// silently from the compiled-in types: adding a field to specs-go
// automatically adds its paths here.
type knownSchema struct {
	// fields holds every struct-property path, including container
	// paths (e.g. both "linux" and "linux.seccomp" are present).
	fields map[string]struct{}
	// maps holds paths whose Go type is map[string]T. The segment
	// immediately below such a path is a user-supplied map key rather
	// than a spec-defined property, so it is ignored when matching.
	maps map[string]struct{}
	// openEndpoints holds paths whose value type is interface{} (for
	// example windows.credentialSpec). Their contents are free-form by
	// specification and must never be flagged as unknown extensions.
	openEndpoints map[string]struct{}
}

var known = buildKnownSchema(rspec.Spec{})

func buildKnownSchema(root any) knownSchema {
	ks := knownSchema{
		fields:        map[string]struct{}{},
		maps:          map[string]struct{}{},
		openEndpoints: map[string]struct{}{},
	}
	ks.walkType("", reflect.TypeOf(root))
	return ks
}

func (ks knownSchema) walkType(prefix string, t reflect.Type) {
	// Dereference pointers and slice element types; slices do not add a
	// path segment because array indices are not spec properties.
	for t.Kind() == reflect.Ptr || t.Kind() == reflect.Slice {
		t = t.Elem()
	}

	if t.Kind() == reflect.Interface {
		if prefix != "" {
			ks.openEndpoints[prefix] = struct{}{}
		}
		return
	}
	if t.Kind() == reflect.Map {
		if prefix != "" {
			// A map field is itself a known property; only its keys are
			// user data. Record it as a map so document traversal stops
			// descending, but keep it out of neither set entirely.
			ks.maps[prefix] = struct{}{}
			ks.fields[prefix] = struct{}{}
		}
		// Descend into the map value type (key strings carry no schema).
		ks.walkType(prefix, t.Elem())
		return
	}
	if t.Kind() != reflect.Struct {
		// Scalar leaf: the path still names a spec-defined property.
		if prefix != "" {
			ks.fields[prefix] = struct{}{}
		}
		return
	}

	if prefix != "" {
		ks.fields[prefix] = struct{}{}
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" { // unexported field
			continue
		}
		name := jsonName(f)
		if name == "" {
			continue
		}
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		ks.walkType(path, f.Type)
	}
}

// jsonName returns the JSON property name of a struct field, or "" when
// the field is excluded from JSON encoding.
func jsonName(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if tag == "-" {
		return ""
	}
	if i := strings.IndexByte(tag, ','); i >= 0 {
		tag = tag[:i]
	}
	if tag == "" {
		return f.Name
	}
	return tag
}

// isKnown reports whether a normalized document path names a
// spec-defined property (or an open endpoint whose contents are
// intentionally free-form).
func (ks knownSchema) isKnown(path string) bool {
	if _, ok := ks.fields[path]; ok {
		return true
	}
	for open := range ks.openEndpoints {
		if path == open || strings.HasPrefix(path, open+".") {
			return true
		}
	}
	return false
}

// isMapField reports whether path holds a map[string]T value.
func (ks knownSchema) isMapField(path string) bool {
	_, ok := ks.maps[path]
	return ok
}

// KnownFieldPaths returns the sorted list of every spec-defined
// property path. It exists for tests and tooling to inspect the
// reflected baseline.
func KnownFieldPaths() []string {
	out := make([]string, 0, len(known.fields))
	for p := range known.fields {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
