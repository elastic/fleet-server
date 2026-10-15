// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package eql

import "errors"

// Ports of the comparison operators in elastic-agent internal/pkg/eql/compare.go,
// unchanged since Elastic Agent 7.13. Keep in sync.

type nullValue struct{}

// null is the value of a variable that does not exist.
var null = &nullValue{}

var (
	errIncompatible = errors.New("incompatible operand types")
	// errUndecided marks a comparison this port does not decide: dicts are
	// compared in Go map order by the agent, so error vs. false can vary.
	errUndecided = errors.New("comparison not decided")
)

// compareEQ is the agent's ==. != is its exact negation, with the same errors.
func compareEQ(left, right any) (bool, error) {
	switch v := left.(type) {
	case *nullValue:
		return right == null, nil
	case bool:
		r, ok := right.(bool)
		return ok && r == v, nil
	case int:
		switch r := right.(type) {
		case *nullValue:
			return false, nil
		case int:
			return v == r, nil
		case float64:
			return float64(v) == r, nil
		}
		return false, errIncompatible
	case float64:
		switch r := right.(type) {
		case *nullValue:
			return false, nil
		case int:
			return v == float64(r), nil
		case float64:
			return v == r, nil
		}
		return false, errIncompatible
	case string:
		r, ok := right.(string)
		return ok && r == v, nil
	case []any:
		r, ok := right.([]any)
		if !ok || len(v) != len(r) {
			return false, nil
		}
		for i := range v {
			eq, err := compareEQ(v[i], r[i])
			if err != nil || !eq {
				return false, err
			}
		}
		return true, nil
	case map[string]any:
		return false, errUndecided
	}
	return false, errIncompatible
}

// compareOrder is the agent's <, <=, > and >=: both operands must be numbers.
func compareOrder(op tokenKind, left, right any) (bool, error) {
	if li, ok := left.(int); ok {
		if ri, ok := right.(int); ok {
			return orderInts(op, li, ri), nil
		}
	}
	l, ok := toFloat(left)
	if !ok {
		return false, errIncompatible
	}
	r, ok := toFloat(right)
	if !ok {
		return false, errIncompatible
	}
	switch op {
	case tLT:
		return l < r, nil
	case tLTE:
		return l <= r, nil
	case tGT:
		return l > r, nil
	case tGTE:
		return l >= r, nil
	}
	return false, errIncompatible
}

func orderInts(op tokenKind, l, r int) bool {
	switch op {
	case tLT:
		return l < r
	case tLTE:
		return l <= r
	case tGT:
		return l > r
	}
	return l >= r
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}
