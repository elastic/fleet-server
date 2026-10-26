// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package definitions holds the documents stored in the feature flags definitions index.
//
// Every entity type lives in a single index and is distinguished by the type field. Using one
// index avoids a shard per tiny dataset and lets the sync fetch every change with a single query.
package definitions

import (
	"encoding/json"
	"strconv"
)

// Document types stored in the definitions index.
const (
	TypeEnvironment = "environment"
	TypeApp         = "app"
	TypeCredential  = "credential"
	TypeFlag        = "flag"
)

// Rule types.
const (
	RuleTypeMatch      = "match"
	RuleTypePercentage = "percentage"
)

// Match operators.
const (
	OperatorIn        = "in"
	OperatorNotIn     = "not_in"
	OperatorSemverLT  = "semver_lt"
	OperatorSemverGT  = "semver_gt"
	OperatorSemverLTE = "semver_lte"
	OperatorSemverGTE = "semver_gte"
)

// Document is a document of the definitions index. Exactly one of the typed members is set, matching Type.
type Document struct {
	Type        string       `json:"type"`
	CreatedAt   string       `json:"created_at,omitempty"`
	UpdatedAt   string       `json:"updated_at,omitempty"`
	Environment *Environment `json:"environment,omitempty"`
	App         *App         `json:"app,omitempty"`
	Credential  *Credential  `json:"credential,omitempty"`
	Flag        *Flag        `json:"flag,omitempty"`
}

// Environment is a deployment environment, for example "production".
type Environment struct {
	Key         string `json:"key"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// App is an application that evaluates flags, for example "kibana".
type App struct {
	Key         string `json:"key"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// Credential authenticates an SDK for one app and environment.
// The SDK key is secret and only its SHA-256 hash (hex) is stored; the client ID is public.
type Credential struct {
	App         string `json:"app"`
	Environment string `json:"environment"`
	SDKKeyHash  string `json:"sdk_key_hash"`
	SDKKeyHint  string `json:"sdk_key_hint,omitempty"`
	ClientID    string `json:"client_id,omitempty"`
}

// Flag is a feature flag definition.
type Flag struct {
	Key          string                       `json:"key"`
	Name         string                       `json:"name,omitempty"`
	Description  string                       `json:"description,omitempty"`
	ValueType    string                       `json:"value_type"`
	Variations   []any                        `json:"variations"`
	Apps         []string                     `json:"apps"`
	TeamOwner    string                       `json:"team_owner,omitempty"`
	DeprecateBy  string                       `json:"deprecate_by,omitempty"`
	Tags         []string                     `json:"tags,omitempty"`
	Environments map[string]*EnvironmentRules `json:"environments"`
}

// EnvironmentRules is the evaluation configuration of a flag in one environment.
type EnvironmentRules struct {
	Default       any            `json:"default"`
	Prerequisites []Prerequisite `json:"prerequisites,omitempty"`
	Rules         []Rule         `json:"rules,omitempty"`
}

// Prerequisite requires another flag to evaluate to Value before the rules are evaluated.
type Prerequisite struct {
	Flag  string `json:"flag"`
	Value any    `json:"value"`
}

// Rule is either a match rule or a percentage rule.
type Rule struct {
	Type string `json:"type"`

	// Match rule members. Either Return or Rules is set.
	Attribute string `json:"attribute,omitempty"`
	Operator  string `json:"operator,omitempty"`
	Values    []any  `json:"values,omitempty"`
	Return    any    `json:"return,omitempty"`
	Rules     []Rule `json:"rules,omitempty"`

	// Percentage rule members. Keys of Percentages are the string forms of the variations.
	PerAttribute string         `json:"per_attribute,omitempty"`
	Percentages  map[string]int `json:"percentages,omitempty"`
}

// ValueKey returns the string form of a scalar value, used to match variations, percentages keys
// and match rule values regardless of their JSON type.
func ValueKey(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(t), 'f', -1, 32)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case json.Number:
		return t.String()
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(b)
	}
}
