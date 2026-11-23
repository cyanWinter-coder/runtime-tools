package bundle

import (
	"bytes"
	"encoding/json"
	"fmt"

	rspec "github.com/opencontainers/runtime-spec/specs-go"
)

// MergeTemplate overlays a JSON template onto base and returns the
// merged configuration.
//
// The template wins only where it carries content: empty values in the
// template (null, "", [], {}) are ignored so they cannot accidentally
// wipe out defaults.  Non-empty objects are merged key by key, while
// non-empty arrays and scalars replace the base value wholesale.
func MergeTemplate(base *rspec.Spec, template []byte) (*rspec.Spec, error) {
	baseJSON, err := json.Marshal(base)
	if err != nil {
		return nil, err
	}
	var baseMap map[string]json.RawMessage
	if err := json.Unmarshal(baseJSON, &baseMap); err != nil {
		return nil, err
	}

	var templateMap map[string]json.RawMessage
	if err := json.Unmarshal(template, &templateMap); err != nil {
		return nil, fmt.Errorf("invalid template: %w", err)
	}
	if templateMap == nil {
		return nil, fmt.Errorf("invalid template: expected a JSON object")
	}

	mergedJSON, err := json.Marshal(mergeMaps(baseMap, templateMap))
	if err != nil {
		return nil, err
	}
	var merged rspec.Spec
	if err := json.Unmarshal(mergedJSON, &merged); err != nil {
		return nil, fmt.Errorf("template cannot be applied to the configuration schema: %w", err)
	}
	return &merged, nil
}

// mergeMaps deep-merges overlay onto base.  Empty overlay values are
// dropped; non-empty objects merge recursively; everything else in the
// overlay replaces the base value.
func mergeMaps(base, overlay map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(base)+len(overlay))
	for k, v := range base {
		out[k] = v
	}
	for k, ov := range overlay {
		if isEmptyJSON(ov) {
			continue
		}
		if bv, ok := out[k]; ok {
			var baseObj, overlayObj map[string]json.RawMessage
			if err := json.Unmarshal(bv, &baseObj); err == nil && baseObj != nil {
				if err := json.Unmarshal(ov, &overlayObj); err == nil && overlayObj != nil {
					if merged, err := json.Marshal(mergeMaps(baseObj, overlayObj)); err == nil {
						out[k] = merged
						continue
					}
				}
			}
		}
		out[k] = ov
	}
	return out
}

// isEmptyJSON reports whether v is a JSON empty value: null, "", [],
// or {}.
func isEmptyJSON(v json.RawMessage) bool {
	switch string(bytes.TrimSpace(v)) {
	case "null", `""`, "[]", "{}":
		return true
	}
	return false
}
