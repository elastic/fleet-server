// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import "github.com/elastic/fleet-server/v7/internal/pkg/model"

// minSharedLen is the length, in bytes, below which a string is not worth sharing.
//
// Sharing is only a win when the memory freed by dropping a duplicate is bigger than what the
// table spends tracking it. The table needs an entry (a string header, an interface value and map
// overhead) for every distinct string it has seen, and that cost is paid for every unique string
// in the load, including the many short identifiers and flags that never repeat enough to matter.
// Long strings are where the duplicated bytes are (for example osquery queries), so only those
// are tracked. This also keeps the table small, and with it the peak memory of a policy load,
// when the policies share little.
var minSharedLen = 64

// maxSharedStrings caps how many distinct strings the table remembers. It bounds the table's own
// memory when a load contains very many distinct long strings (a load can contain thousands of
// policies). Once the cap is reached, strings already in the table are still shared and new
// strings are simply left alone.
var maxSharedStrings = 1 << 16

// stringSharer remembers the first copy of every long string value it has seen so that later
// equal values can be pointed at it instead of keeping their own copy alive.
//
// The table stores the string as an `any` (the type the decoded maps hold) rather than as a
// plain string. When a duplicate is found, the shared `any` is written back into the map as is.
// Storing a plain string would force Go to box it into a new `any` for every replacement,
// which allocates once per duplicate and would add that much garbage to every policy load.
type stringSharer struct {
	seen map[string]any
}

// share walks v in place.
//
// It returns the value that should replace v in its parent, and true, only when v is a string
// that has been seen before. For everything else it returns false: either v is a string that is
// too short to share or is seen for the first time (it becomes the shared copy and stays where it
// is), or it is a map or slice, which is updated in place so the parent needs no change. Keeping
// the walk in place avoids rebuilding every map and slice, which would allocate a second copy of
// the structure.
func (s *stringSharer) share(v any) (any, bool) {
	switch t := v.(type) {
	case string:
		if len(t) < minSharedLen {
			return nil, false
		}
		if shared, ok := s.seen[t]; ok {
			return shared, true
		}
		if len(s.seen) < maxSharedStrings {
			s.seen[t] = v
		}
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
func (s *stringSharer) shareMap(m map[string]any) {
	for k, v := range m {
		if shared, ok := s.share(v); ok {
			m[k] = shared
		}
	}
}

// shareStrings makes equal long string values across the passed policies share one allocation.
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
//   - Short strings are skipped and the table is capped (see minSharedLen and maxSharedStrings),
//     so a load whose policies share little pays for few table entries and its peak memory is
//     not noticeably higher than without this step.
//   - The sharing table lives only for one call. That keeps the change free of state that
//     outlives a policy load and of locking, at the cost that strings in a later load are
//     shared with each other but not with copies already held from an earlier load.
//   - Map keys are not shared. A map cannot have its key strings swapped in place, so sharing
//     them means rebuilding every map, which costs a lot more allocation for little extra
//     saving.
func shareStrings(policies []model.Policy) {
	s := &stringSharer{seen: map[string]any{}}
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
