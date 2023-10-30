// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package model

import (
	"maps"
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
func (a *Agent) APIKeyIDs() []string {
	if a == nil {
		return nil
	}
	keys := make([]string, 0, len(a.Outputs)+1)
	if a.AccessAPIKeyID != "" {
		keys = append(keys, a.AccessAPIKeyID)
	}

	for _, output := range a.Outputs {
		if output.APIKeyID != "" {
			keys = append(keys, output.APIKeyID)
		}
		for _, key := range output.ToRetireAPIKeyIds {
			if key.ID != "" {
				keys = append(keys, key.ID)
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
		Agent:             d.Agent,
		Fleet:             d.Fleet,
		ID:                d.ID,
		Inputs:            make([]map[string]interface{}, 0, len(d.Inputs)),
		OutputPermissions: d.OutputPermissions,
		Outputs:           cloneMap(d.Outputs),
		Revision:          d.Revision,
		SecretReferences:  make([]SecretReferencesItems, 0, len(d.SecretReferences)),
	}
	for _, m := range d.Inputs {
		res.Inputs = append(res.Inputs, maps.Clone(m))
	}
	for _, s := range d.SecretReferences {
		res.SecretReferences = append(res.SecretReferences, s)
	}
	if d.Signed != nil {
		res.Signed = &Signed{
			Data:      d.Signed.Data,
			Signature: d.Signed.Signature,
		}
	}
	return res
}

// cloneMap does a deep copy on a map of objects
// TODO generics?
func cloneMap(m map[string]map[string]interface{}) map[string]map[string]interface{} {
	if m == nil {
		return nil
	}
	r := make(map[string]map[string]interface{})
	for k, v := range m {
		r[k] = maps.Clone(v)
	}
	return r
}
