// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package uploader

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

func ReadDict(r io.Reader) (JSDict, error) {
	var dict JSDict
	decoder := json.NewDecoder(r)
	decoder.UseNumber() // can directly parse numbers from JSON -> int64 instead of float64 in-between
	return dict, decoder.Decode(&dict)
}

// helper for accessing nested properties without panics
// it allows for a safe way to do things like
// js["foo"].(map[string]interface{})["bar"].(map[string]interface{})["baz"].(string)
type JSDict map[string]interface{}

// for a given path, retrieves the raw value in the json structure
// safely, such that if any key is missing, or if any non-leaf key
// is not an object, returns false instead of panicking
func (j JSDict) Val(keys ...string) (interface{}, bool) {
	if len(keys) == 0 {
		return nil, false
	}
	var m map[string]interface{} = j
	for i, k := range keys {
		value, ok := m[k]
		if !ok {
			return nil, false
		}
		if i == len(keys)-1 {
			return value, true
		}
		m, ok = value.(map[string]interface{})
		if !ok {
			return nil, false
		}
	}
	return nil, false
}

// convenience for safely requesting a nested string value
func (j JSDict) Str(keys ...string) (string, bool) {
	if val, ok := j.Val(keys...); ok {
		s, ok := val.(string)
		return s, ok
	}
	return "", false
}

// convenience for safely requesting a nested int64 value
func (j JSDict) Int64(keys ...string) (int64, bool) {
	if val, ok := j.Val(keys...); ok {
		switch v := val.(type) {
		case float64: // standard json decode/unmarshal
			return int64(v), true
		case json.Number: // json UseNumber() to get int64 directly
			n, err := v.Int64()
			return n, err == nil
		case int:
			return int64(v), true
		case int64:
			return v, true
		default:
			return 0, false
		}
	}
	return 0, false
}

// write values to possibly nested locations
func (j JSDict) Put(value interface{}, keys ...string) error {
	if len(keys) == 0 {
		return errors.New("path not provided")
	}
	// simple case
	if len(keys) == 1 {
		j[keys[0]] = value
		return nil
	}
	var m map[string]interface{} = j
	for i, k := range keys {
		if i == len(keys)-1 {
			m[k] = value
			return nil
		}
		// otherwise, we have more to nest. Make sure this level is an object
		x, ok := m[k].(map[string]interface{})
		if !ok {
			return fmt.Errorf("unable to write to %s, missing property at %s", strings.Join(keys, "."), k)
		}
		m = x
	}

	return nil
}
