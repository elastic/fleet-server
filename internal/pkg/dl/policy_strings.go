// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import "github.com/elastic/fleet-server/v7/internal/pkg/model"

// stringSharer deduplicates string values so that equal strings decoded from
// different policy documents share one allocation. It stores the interface
// value that holds each string, so replacing a duplicate with the shared one
// does not allocate.
type stringSharer map[string]any

// share walks v in place. It returns the value to store in place of v and true
// when v is a string that was already seen. Maps and slices are updated in
// place and report false.
func (s stringSharer) share(v any) (any, bool) {
	switch t := v.(type) {
	case string:
		if shared, ok := s[t]; ok {
			return shared, true
		}
		s[t] = v
	case map[string]any:
		s.shareMap(t)
	case []any:
		for i := range t {
			if shared, ok := s.share(t[i]); ok {
				t[i] = shared
			}
		}
	}
	return nil, false
}

func (s stringSharer) shareMap(m map[string]any) {
	for k, v := range m {
		if shared, ok := s.share(v); ok {
			m[k] = shared
		}
	}
}

// shareStrings makes equal string values across the passed policies share
// memory. Policies for the same deployment repeat large parts of their content
// (for example osquery pack queries), and decoding allocates a new copy of each
// string every time. It only replaces strings, which are immutable, so callers
// may keep editing the decoded maps afterwards. Map keys are not shared. The
// policies must not be shared with other goroutines while it runs.
func shareStrings(policies []model.Policy) {
	s := stringSharer{}
	for i := range policies {
		d := policies[i].Data
		if d == nil {
			continue
		}
		for _, section := range []map[string]any{
			d.Agent, d.Connectors, d.Exporters, d.Extensions, d.Fleet, d.Processors, d.Receivers,
		} {
			s.shareMap(section)
		}
		for _, input := range d.Inputs {
			s.shareMap(input)
		}
		for _, output := range d.Outputs {
			s.shareMap(output)
		}
	}
}
