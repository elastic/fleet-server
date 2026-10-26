// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package eval

import (
	"encoding/json"
	"fmt"

	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/definitions"
)

// TargetingKey is the OpenFeature targeting key attribute.
const TargetingKey = "targetingKey"

// Context is a flattened evaluation context: dotted attribute names mapped to scalar values
// (string, float64, bool) or lists of scalars.
type Context map[string]any

// FlattenContext flattens an OpenFeature evaluation context. Both flat dotted keys
// ({"kibana.version": "9.3.0"}) and nested objects ({"kibana": {"version": "9.3.0"}}) are accepted.
func FlattenContext(raw map[string]any) (Context, error) {
	out := make(Context, len(raw))
	if err := flattenInto(out, "", raw); err != nil {
		return nil, err
	}
	if tk, ok := out[TargetingKey]; ok {
		if _, isString := tk.(string); !isString {
			return nil, fmt.Errorf("%s must be a string", TargetingKey)
		}
	}
	return out, nil
}

func flattenInto(out Context, prefix string, obj map[string]any) error {
	for k, v := range obj {
		if k == "" {
			return fmt.Errorf("empty attribute name under %q", prefix)
		}
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch t := v.(type) {
		case map[string]any:
			if err := flattenInto(out, key, t); err != nil {
				return err
			}
			continue
		case []any:
			for _, item := range t {
				if !isScalar(item) {
					return fmt.Errorf("attribute %q must be a list of scalar values", key)
				}
			}
		case nil:
			// A null attribute is the same as a missing one.
			continue
		default:
			if !isScalar(t) {
				return fmt.Errorf("attribute %q has an unsupported type %T", key, t)
			}
		}
		if _, dup := out[key]; dup {
			return fmt.Errorf("attribute %q is defined more than once", key)
		}
		out[key] = v
	}
	return nil
}

func isScalar(v any) bool {
	switch v.(type) {
	case string, bool, float64, json.Number:
		return true
	}
	return false
}

// TargetingKey returns the targeting key of the context, if any.
func (c Context) TargetingKey() string {
	tk, _ := c[TargetingKey].(string)
	return tk
}

// strings returns the string forms of the attribute, and whether it is present.
func (c Context) strings(attribute string) ([]string, bool) {
	v, ok := c[attribute]
	if !ok {
		return nil, false
	}
	if list, isList := v.([]any); isList {
		out := make([]string, 0, len(list))
		for _, item := range list {
			out = append(out, definitions.ValueKey(item))
		}
		return out, true
	}
	return []string{definitions.ValueKey(v)}, true
}

// scalarString returns the string form of a scalar attribute. Lists are encoded as JSON.
func (c Context) scalarString(attribute string) (string, bool) {
	v, ok := c[attribute]
	if !ok {
		return "", false
	}
	return definitions.ValueKey(v), true
}
