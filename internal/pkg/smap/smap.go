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
)

type Map map[string]interface{}

// GetMap will return the value for k as a Map or a nil
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

// GetString will return the value for k as a string or ""
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

// Hash generates the SHA256 hash for the map
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

// Marshal encodes the Map as a json object
// TODO Should we consider renaming this to MarshalJSON
func (m Map) Marshal() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}

// Parse generates a Map from the passed data.
// data is assumed to be a json object.
// TODO Should we refactor this to UnmarshalJSON
func Parse(data []byte) (Map, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var m Map

	err := json.Unmarshal(data, &m)

	return m, err
}
