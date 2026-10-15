// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package eql decides whether an Elastic Agent input condition can ever be
// true for a given agent, using a port of Elastic Agent's EQL grammar and
// comparison semantics (elastic-agent internal/pkg/eql).
//
// Only ${agent.id} is known to Fleet Server; every other variable may hold any
// value at runtime. A condition is evaluated over all of those possibilities
// and is reported as never true only when no possibility makes it true.
// Anything the port cannot reproduce exactly is reported as undecided.
package eql

import (
	"errors"
	"strings"
)

const (
	agentIDVar = "agent.id"
	// escapedVar only lexes from Elastic Agent 8.15: 8.9 to 8.14 reject it and
	// older agents silently drop it, so conditions using it are never decided.
	escapedVar = "$${"
)

// outcomes is the set of results an expression may produce.
type outcomes uint8

const (
	oTrue  outcomes = 1 << iota
	oFalse          // the boolean false
	oOther          // a non-boolean value
	oError          // an evaluation error
	oAny   = oTrue | oFalse | oOther | oError
)

// value is either a single known value, or a set of possible outcomes.
type value struct {
	known bool
	v     any
	set   outcomes
}

func known(v any) value { return value{known: true, v: v} }

var (
	anyValue   = value{set: oAny}
	errorValue = value{set: oError}
)

func (a value) outcomes() outcomes {
	if !a.known {
		return a.set
	}
	switch a.v {
	case true:
		return oTrue
	case false:
		return oFalse
	}
	return oOther
}

func (a value) alwaysError() bool { return !a.known && a.set == oError }

// world fixes the value of ${agent.id}: the agent's id, or missing.
type world struct {
	agentID string
	present bool
}

type evaluator struct {
	w           world
	unsupported bool
	// vars, when set, gives every variable a concrete value (tests only).
	vars map[string]any
}

// NeverTrue reports whether condition provably never evaluates to true on
// the agent agentID, while still evaluating to false there for some values of
// the other variables (a condition that always errors is left to the agent).
// It returns false when undecided. Conditions that do not reference
// ${agent.id} are never decided.
func NeverTrue(condition, agentID string) bool {
	if !strings.Contains(condition, agentIDVar) || strings.Contains(condition, escapedVar) {
		return false
	}
	n, err := parseCached(condition)
	if err != nil {
		return false
	}
	// The agent provider can be disabled, leaving ${agent.id} unset.
	canFalse := false
	for _, w := range []world{{agentID: agentID, present: true}, {}} {
		ev := evaluator{w: w}
		o := ev.eval(n).topLevel()
		if ev.unsupported || o&oTrue != 0 {
			return false
		}
		if w.present {
			canFalse = o&oFalse != 0
		}
	}
	return canFalse
}

// MayEvaluate reports whether the agent agentID may evaluate condition
// without an error: it parses for every supported agent version and does not
// always fail.
func MayEvaluate(condition, agentID string) bool {
	if strings.Contains(condition, escapedVar) {
		return false
	}
	n, err := parseCached(condition)
	if err != nil {
		return false
	}
	ev := evaluator{w: world{agentID: agentID, present: true}}
	o := ev.eval(n).topLevel()
	return !ev.unsupported && o != oError
}

// topLevel maps a result to what the agent does with it: a non-boolean result
// fails the type assertion on the parse tree root and becomes an error.
func (a value) topLevel() outcomes {
	o := a.outcomes()
	if o&oOther != 0 {
		o = o&^oOther | oError
	}
	return o
}

func (ev *evaluator) eval(n node) value {
	switch n := n.(type) {
	case litNode:
		return known(n.v)
	case varNode:
		return ev.variable(n)
	case evarNode:
		return errorValue
	case funcNode:
		return anyValue
	case notNode:
		x := ev.eval(n.x)
		if x.known {
			if b, ok := x.v.(bool); ok {
				return known(!b)
			}
			return errorValue
		}
		var o outcomes
		if x.set&oTrue != 0 {
			o |= oFalse
		}
		if x.set&oFalse != 0 {
			o |= oTrue
		}
		if x.set&(oOther|oError) != 0 {
			o |= oError
		}
		return value{set: o}
	case binNode:
		// Both sides are always evaluated: the agent does not short-circuit.
		l, r := ev.eval(n.l), ev.eval(n.r)
		switch n.op {
		case tAnd, tOr:
			return logical(n.op, l, r)
		case tEQ, tNEQ, tLT, tLTE, tGT, tGTE:
			return compare(n.op, l, r)
		}
		// Arithmetic is not evaluated.
		if l.alwaysError() || r.alwaysError() {
			return errorValue
		}
		return anyValue
	}
	ev.unsupported = true
	return anyValue
}

// variable resolves ${a|b|'c'}: the first entry that exists wins, and a
// variable that may not exist makes the result unknown.
func (ev *evaluator) variable(n varNode) value {
	for _, e := range n.entries {
		// '-' and '/' only became valid in variable names in Elastic Agent 8.4.
		if strings.ContainsAny(e.name, "-/") {
			ev.unsupported = true
			return anyValue
		}
	}
	for _, e := range n.entries {
		if e.name == "" {
			return known(e.value)
		}
		if ev.vars != nil {
			if v, ok := ev.vars[e.name]; ok {
				return known(v)
			}
			continue
		}
		if e.name != agentIDVar {
			return anyValue
		}
		if ev.w.present {
			return known(ev.w.agentID)
		}
	}
	return known(null)
}

func logical(op tokenKind, l, r value) value {
	if l.known && r.known {
		lb, lok := l.v.(bool)
		rb, rok := r.v.(bool)
		if !lok || !rok {
			return errorValue
		}
		if op == tAnd {
			return known(lb && rb)
		}
		return known(lb || rb)
	}
	var o outcomes
	lo, ro := l.outcomes(), r.outcomes()
	if (lo|ro)&(oOther|oError) != 0 {
		o |= oError
	}
	for _, lb := range boolsIn(lo) {
		for _, rb := range boolsIn(ro) {
			res := lb || rb
			if op == tAnd {
				res = lb && rb
			}
			if res {
				o |= oTrue
			} else {
				o |= oFalse
			}
		}
	}
	return value{set: o}
}

func boolsIn(o outcomes) []bool {
	var out []bool
	if o&oTrue != 0 {
		out = append(out, true)
	}
	if o&oFalse != 0 {
		out = append(out, false)
	}
	return out
}

func compare(op tokenKind, l, r value) value {
	if l.alwaysError() || r.alwaysError() {
		return errorValue
	}
	if !l.known || !r.known {
		return value{set: oTrue | oFalse | oError}
	}
	var res bool
	var err error
	switch op {
	case tEQ:
		res, err = compareEQ(l.v, r.v)
	case tNEQ:
		res, err = compareEQ(l.v, r.v)
		res = !res
	default:
		res, err = compareOrder(op, l.v, r.v)
	}
	if errors.Is(err, errUndecided) {
		return value{set: oTrue | oFalse | oError}
	}
	if err != nil {
		return errorValue
	}
	return known(res)
}
