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
