// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package model

import (
	"bytes"
	"maps"
	"slices"
	"time"
)

// Time returns the time for the current leader.
func (m *PolicyLeader) Time() (time.Time, error) {
	return time.Parse(time.RFC3339Nano, m.Timestamp)
}

// SetTime sets the timestamp.
func (m *PolicyLeader) SetTime(t time.Time) {
	m.Timestamp = t.Format(time.RFC3339Nano)
}

// Time returns the time for the server.
func (m *Server) Time() (time.Time, error) {
	return time.Parse(time.RFC3339Nano, m.Timestamp)
}

// SetTime sets the timestamp.
func (m *Server) SetTime(t time.Time) {
	m.Timestamp = t.Format(time.RFC3339Nano)
}

// CheckDifferentVersion returns Agent version if it is different from ver, otherwise return empty string
func (a *Agent) CheckDifferentVersion(ver string) string {
	if a == nil {
		return ""
	}

	if a.Agent == nil || ver != a.Agent.Version {
		return ver
	}

	return ""
}

// APIKeyIDs returns all the API keys, the valid, in-use as well as the one
// marked to be retired.
func (a *Agent) APIKeyIDs() []ToRetireAPIKeyIdsItems {
	if a == nil {
		return nil
	}
	keys := make([]ToRetireAPIKeyIdsItems, 0, len(a.Outputs)+1)
	if a.AccessAPIKeyID != "" {
		keys = append(keys, ToRetireAPIKeyIdsItems{
			ID:        a.AccessAPIKeyID,
			Output:    "",
			RetiredAt: "",
		})
	}

	for outputName, output := range a.Outputs {
		if output.APIKeyID != "" {
			name := ""
			if outputName != "default" {
				name = outputName
			}
			keys = append(keys, ToRetireAPIKeyIdsItems{
				ID:        output.APIKeyID,
				Output:    name,
				RetiredAt: "",
			})
		}
		for _, key := range output.ToRetireAPIKeyIds {
			if key.ID != "" {
				keys = append(keys, key)
			}
		}
	}

	return keys

}

func ClonePolicyData(d *PolicyData) *PolicyData {
	if d == nil {
		return nil
	}
	res := &PolicyData{
		Agent:             bytes.Clone(d.Agent),
		Fleet:             bytes.Clone(d.Fleet),
		ID:                d.ID,
		Inputs:            nil, // populated below; stays nil when d.Inputs is nil
		OutputPermissions: bytes.Clone(d.OutputPermissions),
		Outputs:           cloneMap(d.Outputs),
		Revision:          d.Revision,
		SecretReferences:  slices.Clone(d.SecretReferences),
	}
	if len(d.Inputs) > 0 {
		res.Inputs = make([]map[string]any, len(d.Inputs))
		for i, m := range d.Inputs {
			res.Inputs[i] = maps.Clone(m)
		}
	}
	if d.Signed != nil {
		res.Signed = &Signed{
			Data:      d.Signed.Data,
			Signature: d.Signed.Signature,
		}
	}
	return res
}

// deepCloneMapAny recursively deep-clones a map[string]any.
func deepCloneMapAny(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	r := make(map[string]any, len(m))
	for k, v := range m {
		switch vt := v.(type) {
		case map[string]any:
			r[k] = deepCloneMapAny(vt)
		case []any:
			r[k] = deepCloneSliceAny(vt)
		default:
			r[k] = v
		}
	}
	return r
}

func deepCloneSliceAny(s []any) []any {
	if s == nil {
		return nil
	}
	r := make([]any, len(s))
	for i, v := range s {
		switch vt := v.(type) {
		case map[string]any:
			r[i] = deepCloneMapAny(vt)
		case []any:
			r[i] = deepCloneSliceAny(vt)
		default:
			r[i] = v
		}
	}
	return r
}


// cloneMap does a deep copy on a map of objects
// TODO generics?
func cloneMap(m map[string]map[string]interface{}) map[string]map[string]interface{} {
	if m == nil {
		return nil
	}
	r := make(map[string]map[string]interface{})
	for k, v := range m {
		r[k] = deepCloneMapAny(v)
	}
	return r
}

// cloneOTelSection deep-clones a map[string]any where values are map[string]any
// component configs. prepareOTelExporters mutates these inner maps in-place, so a
// shallow clone of the outer map is not enough for concurrent safety.
func cloneOTelSection(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	r := make(map[string]any, len(m))
	for k, v := range m {
		if vmap, ok := v.(map[string]any); ok {
			r[k] = deepCloneMapAny(vmap)
		} else {
			r[k] = v
		}
	}
	return r
}
