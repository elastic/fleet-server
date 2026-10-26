// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package eval evaluates feature flag rules against an evaluation context.
//
// Rules are evaluated in order and the first match wins. A match rule either returns a variation or
// evaluates its nested rules, so nesting combines conditions with AND. A match rule whose nested
// rules all fail to match falls back to its own return, if any, and otherwise does not match.
// Percentage rules split traffic across variations by hashing an attribute of the context.
// Prerequisites are evaluated with the same environment and context. When one is not met the flag
// is not served, so the caller keeps its own fallback instead of this flag's default variation.
// The default variation is served only after every prerequisite is met and no rule matches.
package eval

import (
	"fmt"

	"github.com/hashicorp/go-version"

	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/definitions"
)

// Reason is an OpenFeature resolution reason.
type Reason string

// Resolution reasons.
const (
	ReasonStatic         Reason = "STATIC"
	ReasonDefault        Reason = "DEFAULT"
	ReasonTargetingMatch Reason = "TARGETING_MATCH"
	ReasonSplit          Reason = "SPLIT"
	ReasonError          Reason = "ERROR"
)

// ErrorCode is an OpenFeature error code.
type ErrorCode string

// Error codes.
const (
	ErrorFlagNotFound        ErrorCode = "FLAG_NOT_FOUND"
	ErrorParse               ErrorCode = "PARSE_ERROR"
	ErrorTargetingKeyMissing ErrorCode = "TARGETING_KEY_MISSING"
	ErrorInvalidContext      ErrorCode = "INVALID_CONTEXT"
	ErrorGeneral             ErrorCode = "GENERAL"
)

// MaxPrerequisiteDepth bounds how deep prerequisite chains are followed.
const MaxPrerequisiteDepth = 10

// Result is the outcome of evaluating a flag.
type Result struct {
	Value        any
	Variant      string
	Reason       Reason
	ErrorCode    ErrorCode
	ErrorDetails string
}

// Failed reports whether the evaluation ended with an error.
func (r Result) Failed() bool {
	return r.ErrorCode != ""
}

// Lookup returns the flag with key, or nil when it does not exist.
type Lookup func(key string) *Flag

// Evaluate evaluates flag in env for the given context. lookup resolves prerequisite flags.
func Evaluate(flag *Flag, env string, ctx Context, lookup Lookup) Result {
	e := evaluator{env: env, ctx: ctx, lookup: lookup, visiting: map[string]struct{}{}}
	return e.evaluate(flag, 0)
}

type evaluator struct {
	env      string
	ctx      Context
	lookup   Lookup
	visiting map[string]struct{}
}

func failure(code ErrorCode, format string, args ...any) Result {
	return Result{Reason: ReasonError, ErrorCode: code, ErrorDetails: fmt.Sprintf(format, args...)}
}

func (e *evaluator) evaluate(flag *Flag, depth int) Result {
	if flag == nil {
		return failure(ErrorFlagNotFound, "flag not found")
	}
	envDef, ok := flag.envs[e.env]
	if !ok {
		return failure(ErrorFlagNotFound, "flag %q is not configured for environment %q", flag.Key, e.env)
	}
	if flag.Err != nil {
		return failure(ErrorParse, "flag %q is invalid: %s", flag.Key, flag.Err)
	}
	if depth > MaxPrerequisiteDepth {
		return failure(ErrorGeneral, "prerequisites of flag %q are nested deeper than %d", flag.Key, MaxPrerequisiteDepth)
	}
	if _, cycle := e.visiting[flag.Key]; cycle {
		return failure(ErrorGeneral, "prerequisite cycle detected at flag %q", flag.Key)
	}
	e.visiting[flag.Key] = struct{}{}
	defer delete(e.visiting, flag.Key)

	if len(envDef.prerequisites) == 0 && len(envDef.rules) == 0 {
		return flag.result(envDef.defaultIdx, ReasonStatic)
	}

	for _, p := range envDef.prerequisites {
		res := e.evaluate(e.lookup(p.flag), depth+1)
		// A broken prerequisite is reported as-is. A missing flag or a different variation means
		// this flag's rules do not apply, and neither does its default variation.
		if res.Failed() && res.ErrorCode != ErrorFlagNotFound {
			return res
		}
		if res.Failed() || definitions.ValueKey(res.Value) != p.valueKey {
			return failure(ErrorGeneral, "prerequisite %q of flag %q is not met", p.flag, flag.Key)
		}
	}

	res, matched := e.evaluateRules(flag, envDef.rules)
	if matched {
		return res
	}
	return flag.result(envDef.defaultIdx, ReasonDefault)
}

func (e *evaluator) evaluateRules(flag *Flag, rules []*rule) (Result, bool) {
	for _, r := range rules {
		if res, matched := e.evaluateRule(flag, r); matched {
			return res, true
		}
	}
	return Result{}, false
}

func (e *evaluator) evaluateRule(flag *Flag, r *rule) (Result, bool) {
	if r.percentage {
		return e.evaluatePercentage(flag, r)
	}
	if !e.matches(r) {
		return Result{}, false
	}
	if res, matched := e.evaluateRules(flag, r.children); matched {
		return res, true
	}
	if r.returnIdx >= 0 {
		return flag.result(r.returnIdx, ReasonTargetingMatch), true
	}
	return Result{}, false
}

func (e *evaluator) evaluatePercentage(flag *Flag, r *rule) (Result, bool) {
	key, ok := e.ctx.scalarString(r.perAttribute)
	if !ok || key == "" {
		if r.perAttribute == TargetingKey {
			return failure(ErrorTargetingKeyMissing, "flag %q splits traffic by %s, which is missing from the context", flag.Key, TargetingKey), true
		}
		// Without the attribute there is nothing to hash: the rule does not apply.
		return Result{}, false
	}
	idx := pickWeighted(Bucket(key, flag.Key), r.weights)
	if idx < 0 {
		return Result{}, false
	}
	return flag.result(idx, ReasonSplit), true
}

func (e *evaluator) matches(r *rule) bool {
	switch r.operator {
	case definitions.OperatorIn, definitions.OperatorNotIn:
		values, ok := e.ctx.strings(r.attribute)
		found := false
		if ok {
			for _, v := range values {
				if _, hit := r.values[v]; hit {
					found = true
					break
				}
			}
		}
		if r.operator == definitions.OperatorIn {
			return found
		}
		return !found
	default:
		raw, ok := e.ctx.scalarString(r.attribute)
		if !ok {
			return false
		}
		if _, isList := e.ctx[r.attribute].([]any); isList {
			return false
		}
		actual, err := version.NewVersion(raw)
		if err != nil {
			return false
		}
		for _, boundary := range r.versions {
			if compareSemver(r.operator, actual, boundary) {
				return true
			}
		}
		return false
	}
}

func compareSemver(op string, actual, boundary *version.Version) bool {
	c := actual.Compare(boundary)
	switch op {
	case definitions.OperatorSemverLT:
		return c < 0
	case definitions.OperatorSemverLTE:
		return c <= 0
	case definitions.OperatorSemverGT:
		return c > 0
	case definitions.OperatorSemverGTE:
		return c >= 0
	}
	return false
}

func (f *Flag) result(idx int, reason Reason) Result {
	v := f.variations[idx]
	return Result{Value: v.value, Variant: v.key, Reason: reason}
}
