// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import "github.com/elastic/fleet-server/v7/internal/pkg/model"

// stringSharer remembers the first copy of every string value it has seen so that later
// equal values can be pointed at it instead of keeping their own copy alive.
//
// The table stores the string as an `any` (the type the decoded maps hold) rather than as a
// plain string. When a duplicate is found, the shared `any` is written back into the map as is.
// Storing a plain string would force Go to box it into a new `any` for every replacement,
// which allocates once per duplicate and would add that much garbage to every policy load.
type stringSharer map[string]any

// share walks v in place.
//
// It returns the value that should replace v in its parent, and true, only when v is a string
// that has been seen before. For everything else it returns false: either v is a string seen
// for the first time (it becomes the shared copy and stays where it is), or it is a map or
// slice, which is updated in place so the parent needs no change. Keeping the walk in place
// avoids rebuilding every map and slice, which would allocate a second copy of the structure.
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

// shareMap applies share to every value of m. Assigning to a key that already exists while
// ranging over the map is allowed and does not add entries, so this is safe to do in place.
func (s stringSharer) shareMap(m map[string]any) {
	for k, v := range m {
		if shared, ok := s.share(v); ok {
			m[k] = shared
		}
	}
}

// shareStrings makes equal string values across the passed policies share one allocation.
//
// Why: the policy monitor keeps the decoded form of every policy in memory for as long as it
// is the latest revision, and JSON decoding allocates a fresh copy of every string it reads.
// Policies of one deployment often repeat large parts of their content (for example, the same
// osquery pack queries in many policies), so most of that memory is identical text stored many
// times over.
//
// How it is safe to do:
//   - Only string values are replaced. Strings are immutable, so two places holding the same
//     string cannot affect each other. The decoded maps themselves are not shared, so callers
//     (for example the secret replacement done when a policy is parsed) can keep editing them.
//   - The policies passed in must have just been decoded and must not yet be visible to other
//     goroutines, because the maps are edited in place without locking.
//
// Choices worth knowing about:
//   - The sharing table lives only for one call. That keeps the change free of state that
//     outlives a policy load and of locking, at the cost that strings in a later load are
//     shared with each other but not with copies already held from an earlier load.
//   - Map keys are not shared. A map cannot have its key strings swapped in place, so sharing
//     them means rebuilding every map, which costs a lot more allocation for little extra
//     saving.
func shareStrings(policies []model.Policy) {
	s := stringSharer{}
	for i := range policies {
		d := policies[i].Data
		if d == nil {
			continue
		}
		// These are the sections of a policy that hold free-form decoded JSON.
		// The typed fields (IDs, revision numbers and so on) are small and are left alone.
		for _, section := range []map[string]any{
			d.Agent, d.Connectors, d.Exporters, d.Extensions, d.Fleet, d.Processors, d.Receivers,
		} {
			s.shareMap(section)
		}
		// Inputs carry the bulk of a policy's content (integration settings and, for osquery,
		// the packs of scheduled queries).
		for _, input := range d.Inputs {
			s.shareMap(input)
		}
		for _, output := range d.Outputs {
			s.shareMap(output)
		}
	}
}
