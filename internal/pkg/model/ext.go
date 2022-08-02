// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package model

import "time"

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
		keys = append(keys, output.APIKeyID)
		for _, key := range output.ToRetireAPIKeys {
			keys = append(keys, key.ID)
		}
	}

	return keys

}
