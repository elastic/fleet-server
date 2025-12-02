// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package smap provides a string-map
// the string map will only fail on encoding errors
// TODO this may be a good candidate for generics when we update to go 1.18+
package smap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type Map map[string]interface{}

// GetMap will return the value for k as a Map or a nil.
func (m Map) GetMap(k string) Map {
	if m == nil {
		return m
	}

	v := m[k]
	if v != nil {
		if m, ok := v.(map[string]interface{}); ok {
			return m
		}
	}
	return nil
}

// GetString will return the value for k as a string or "".
func (m Map) GetString(k string) string {
	if m == nil {
		return ""
	}
	if v := m[k]; v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// Hash generates the SHA256 hash for the map.
func (m Map) Hash() (string, error) {
	if m == nil {
		return "", nil
	}

	// Hashing through the json encoder
	h := sha256.New()
	enc := json.NewEncoder(h)
	err := enc.Encode(m)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// Marshal encodes the Map as a json object.
// TODO Should we consider renaming this to MarshalJSON?
func (m Map) Marshal() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}

// Get returns the value at the specified key path
// For example:
// m.Get("a.b.c") => m["a"]["b"]["c"]
// m.Get("a.2") => m["a"][2]
// m.Get("a.2.c") => m["a"][2]["c"]
func (m Map) Get(keyPath string) any {
	if m == nil {
		return nil
	}

	var curr any = m
	var key string
	var index uint
	var isIndex bool

	parts := strings.Split(keyPath, ".")
	for _, part := range parts {
		key = part

		// Check if part is an index
		index, isIndex = parseIndex(part)

		// Traverse to the next level
		if isIndex {
			sCurr, ok := curr.([]any)
			if !ok {
				return nil
			}
			if index >= uint(len(sCurr)) {
				return nil
			}
			curr = sCurr[index]
		} else {
			mCurr, ok := isSMap(curr)
			if !ok {
				return nil
			}
			curr = mCurr[key]
		}
	}

	return curr
}

// Set sets the value at the specified key path.
// For example:
// m.Set("a.b.c", value) => m["a"]["b"]["c"] = value
// m.Set("a.2", value) => m["a"][2] = value
// m.Set("a.2.c", value) => m["a"][2]["c"] = value
func (m Map) Set(keyPath string, value any) error {
	if m == nil {
		return nil
	}

	var curr any = m
	var parent any
	var key string
	var index uint
	var isIndex bool

	parts := strings.Split(keyPath, ".")
	for i, part := range parts {
		key = part
		parent = curr
		parentPath := strings.Join(parts[:i], ".")

		// Check if part is an index
		index, isIndex = parseIndex(part)

		// If last part, set the value
		if i == len(parts)-1 {
			if isIndex {
				sParent, ok := parent.([]any)
				if !ok {
					return fmt.Errorf("expected slice at %s, got %T", parentPath, parent)
				}
				if index >= uint(len(sParent)) {
					return fmt.Errorf("index out of bounds at %s: %d", parentPath, index)
				}
				sParent[index] = value
			} else {
				mParent, ok := isSMap(parent)
				if !ok {
					return fmt.Errorf("expected map at %s, got %T", parentPath, parent)
				}
				mParent[key] = value
			}
			return nil
		}

		// Traverse to the next level
		if isIndex {
			sCurr, ok := curr.([]any)
			if !ok {
				return fmt.Errorf("expected slice at %s, got %T", parentPath, curr)
			}
			if index >= uint(len(sCurr)) {
				return fmt.Errorf("index out of bounds at %s: %d", parentPath, index)
			}
			curr = sCurr[index]
		} else {
			mCurr, ok := isSMap(curr)
			if !ok {
				return fmt.Errorf("expected map at %s, got %T", parentPath, curr)
			}
			curr = mCurr[key]
		}
	}

	return nil
}

// Parse generates a Map from the passed data.
// data is assumed to be a json object.
// TODO Should we refactor this to UnmarshalJSON?
func Parse(data []byte) (Map, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var m Map

	err := json.Unmarshal(data, &m)

	return m, err
}

func parseIndex(str string) (uint, bool) {
	// Try to read str as an integer
	var index uint
	if _, err := fmt.Sscanf(str, "%d", &index); err != nil {
		return 0, false
	}
	return index, true
}

func isSMap(v any) (map[string]any, bool) {
	if mapVal, ok := v.(map[string]any); ok {
		return mapVal, true
	}

	if mapVal, ok := v.(Map); ok {
		return mapVal, true
	}

	return nil, false
}
