// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package eval

import (
	"errors"
	"fmt"

	"github.com/hashicorp/go-version"

	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/definitions"
)

// Flag is a validated flag definition, ready to be evaluated.
//
// When the definition is invalid, Err is set and evaluating the flag returns PARSE_ERROR.
// Key, Def and the app and environment membership are always populated, so an invalid flag
// is still reported to the apps it is assigned to.
type Flag struct {
	Key  string
	Def  *definitions.Flag
	Err  error
	apps map[string]struct{}
	envs map[string]*envRules

	variations []variation
}

type variation struct {
	value any
	key   string
}

type envRules struct {
	defaultIdx    int
	prerequisites []prerequisite
	rules         []*rule
}

type prerequisite struct {
	flag     string
	valueKey string
}

type rule struct {
	percentage bool

	// match
	attribute string
	operator  string
	values    map[string]struct{}
	versions  []*version.Version
	returnIdx int // -1 when the rule has nested rules instead
	children  []*rule

	// percentage
	perAttribute string
	weights      []int // aligned with Flag.variations
}

// Compile validates def and prepares it for evaluation.
func Compile(def *definitions.Flag) *Flag {
	f := &Flag{
		Key:  def.Key,
		Def:  def,
		apps: make(map[string]struct{}, len(def.Apps)),
		envs: make(map[string]*envRules, len(def.Environments)),
	}
	for _, app := range def.Apps {
		f.apps[app] = struct{}{}
	}
	for env := range def.Environments {
		f.envs[env] = nil
	}
	if err := f.compile(); err != nil {
		f.Err = err
	}
	return f
}

// AssignedTo reports whether the flag is assigned to app.
func (f *Flag) AssignedTo(app string) bool {
	_, ok := f.apps[app]
	return ok
}

// HasEnvironment reports whether the flag has a configuration for env.
func (f *Flag) HasEnvironment(env string) bool {
	_, ok := f.envs[env]
	return ok
}

func (f *Flag) compile() error {
	if f.Key == "" {
		return errors.New("flag key is empty")
	}
	if len(f.Def.Variations) == 0 {
		return errors.New("flag has no variations")
	}
	seen := make(map[string]struct{}, len(f.Def.Variations))
	for _, v := range f.Def.Variations {
		if v == nil {
			return errors.New("variation must not be null")
		}
		k := definitions.ValueKey(v)
		if _, dup := seen[k]; dup {
			return fmt.Errorf("duplicate variation %q", k)
		}
		seen[k] = struct{}{}
		f.variations = append(f.variations, variation{value: v, key: k})
	}
	for name, def := range f.Def.Environments {
		if def == nil {
			return fmt.Errorf("environment %q: empty configuration", name)
		}
		env, err := f.compileEnv(def)
		if err != nil {
			return fmt.Errorf("environment %q: %w", name, err)
		}
		f.envs[name] = env
	}
	return nil
}

func (f *Flag) variationIndex(v any) int {
	if v == nil {
		return -1
	}
	k := definitions.ValueKey(v)
	for i, variation := range f.variations {
		if variation.key == k {
			return i
		}
	}
	return -1
}

func (f *Flag) compileEnv(def *definitions.EnvironmentRules) (*envRules, error) {
	env := &envRules{defaultIdx: f.variationIndex(def.Default)}
	if env.defaultIdx < 0 {
		return nil, fmt.Errorf("default %q is not a variation", definitions.ValueKey(def.Default))
	}
	for i, p := range def.Prerequisites {
		if p.Flag == "" {
			return nil, fmt.Errorf("prerequisite %d: flag is empty", i)
		}
		if p.Value == nil {
			return nil, fmt.Errorf("prerequisite %d: value is empty", i)
		}
		env.prerequisites = append(env.prerequisites, prerequisite{flag: p.Flag, valueKey: definitions.ValueKey(p.Value)})
	}
	rules, err := f.compileRules(def.Rules, "rules")
	if err != nil {
		return nil, err
	}
	env.rules = rules
	return env, nil
}

func (f *Flag) compileRules(defs []definitions.Rule, path string) ([]*rule, error) {
	rules := make([]*rule, 0, len(defs))
	for i := range defs {
		r, err := f.compileRule(&defs[i])
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", path, i, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func (f *Flag) compileRule(def *definitions.Rule) (*rule, error) {
	switch def.Type {
	case definitions.RuleTypeMatch:
		return f.compileMatch(def)
	case definitions.RuleTypePercentage:
		return f.compilePercentage(def)
	default:
		return nil, fmt.Errorf("unknown rule type %q", def.Type)
	}
}

func (f *Flag) compileMatch(def *definitions.Rule) (*rule, error) {
	r := &rule{attribute: def.Attribute, operator: def.Operator, returnIdx: -1}
	if r.attribute == "" {
		return nil, errors.New("match rule without attribute")
	}
	if r.operator == "" {
		r.operator = definitions.OperatorIn
	}
	if len(def.Values) == 0 {
		return nil, errors.New("match rule without values")
	}
	switch r.operator {
	case definitions.OperatorIn, definitions.OperatorNotIn:
		r.values = make(map[string]struct{}, len(def.Values))
		for _, v := range def.Values {
			r.values[definitions.ValueKey(v)] = struct{}{}
		}
	case definitions.OperatorSemverLT, definitions.OperatorSemverGT, definitions.OperatorSemverLTE, definitions.OperatorSemverGTE:
		for _, v := range def.Values {
			ver, err := version.NewVersion(definitions.ValueKey(v))
			if err != nil {
				return nil, fmt.Errorf("invalid semver value %q: %w", definitions.ValueKey(v), err)
			}
			r.versions = append(r.versions, ver)
		}
	default:
		return nil, fmt.Errorf("unknown operator %q", r.operator)
	}

	if def.Return == nil && len(def.Rules) == 0 {
		return nil, errors.New("match rule needs either return or rules")
	}
	if def.Return != nil {
		r.returnIdx = f.variationIndex(def.Return)
		if r.returnIdx < 0 {
			return nil, fmt.Errorf("return %q is not a variation", definitions.ValueKey(def.Return))
		}
	}
	children, err := f.compileRules(def.Rules, "rules")
	if err != nil {
		return nil, err
	}
	r.children = children
	return r, nil
}

func (f *Flag) compilePercentage(def *definitions.Rule) (*rule, error) {
	r := &rule{percentage: true, perAttribute: def.PerAttribute, returnIdx: -1}
	if r.perAttribute == "" {
		return nil, errors.New("percentage rule without per_attribute")
	}
	if len(def.Rules) > 0 || def.Return != nil {
		return nil, errors.New("percentage rule cannot have return or nested rules")
	}
	r.weights = make([]int, len(f.variations))
	total := 0
	for k, w := range def.Percentages {
		idx := f.variationIndex(k)
		if idx < 0 {
			return nil, fmt.Errorf("percentage key %q is not a variation", k)
		}
		if w < 0 || w > 100 {
			return nil, fmt.Errorf("percentage of %q must be between 0 and 100, got %d", k, w)
		}
		r.weights[idx] = w
		total += w
	}
	if total != 100 {
		return nil, fmt.Errorf("percentages must sum to 100, got %d", total)
	}
	return r, nil
}
