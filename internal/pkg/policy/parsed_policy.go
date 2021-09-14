// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"encoding/json"
	"errors"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/smap"
)

const (
	FieldOutputs            = "outputs"
	FieldOutputType         = "type"
	FieldOutputServiceToken = "service_token"
	FieldOutputPermissions  = "output_permissions"

	OutputTypeElasticsearch = "elasticsearch"
)

var (
	ErrOutputsNotFound             = errors.New("outputs not found")
	ErrDefaultOutputNotFound       = errors.New("default output not found")
	ErrMultipleDefaultOutputsFound = errors.New("multiple default outputs found")
	ErrInvalidPermissionsFormat    = errors.New("invalid permissions format")
)

type RoleT struct {
	Raw  []byte
	Sha2 string
}

type RoleMapT map[string]RoleT

type ParsedPolicyDefaults struct {
	Name string
	Role *RoleT
}

type ParsedPolicy struct {
	Policy  model.Policy
	Fields  map[string]json.RawMessage
	Roles   RoleMapT
	Default ParsedPolicyDefaults
}

func NewParsedPolicy(p model.Policy) (*ParsedPolicy, error) {
	var err error

	var fields map[string]json.RawMessage
	if err = json.Unmarshal(p.Data, &fields); err != nil {
		return nil, err
	}

	// Interpret the output permissions if available
	var roles map[string]RoleT
	if perms, _ := fields[FieldOutputPermissions]; len(perms) != 0 {
		if roles, err = parsePerms(perms); err != nil {
			return nil, err
		}
	}

	// Find the default role.
	outputs, ok := fields[FieldOutputs]
	if !ok {
		return nil, ErrOutputsNotFound
	}
	defaultName, err := findDefaultOutputName(outputs)
	if err != nil {
		return nil, err
	}
	var roleP *RoleT
	if role, ok := roles[defaultName]; ok {
		roleP = &role
	}

	// We are cool and the gang
	pp := &ParsedPolicy{
		Policy: p,
		Fields: fields,
		Roles:  roles,
		Default: ParsedPolicyDefaults{
			Name: defaultName,
			Role: roleP,
		},
	}

	return pp, nil
}

func parsePerms(permsRaw json.RawMessage) (RoleMapT, error) {
	permMap, err := smap.Parse(permsRaw)
	if err != nil {
		return nil, err
	}

	// iterate across the keys
	m := make(RoleMapT, len(permMap))
	for k := range permMap {

		v := permMap.GetMap(k)

		if v != nil {
			var r RoleT

			// Stable hash on permissions payload
			if r.Sha2, err = v.Hash(); err != nil {
				return nil, err
			}

			// Re-marshal, the payload for each section
			if r.Raw, err = json.Marshal(v); err != nil {
				return nil, err
			}
			m[k] = r
		}
	}

	return m, nil
}

func findDefaultOutputName(outputsRaw json.RawMessage) (string, error) {
	outputsMap, err := smap.Parse(outputsRaw)
	if err != nil {
		return "", err
	}

	// iterate across the keys finding the defaults
	var defaults []string
	for k := range outputsMap {

		v := outputsMap.GetMap(k)

		if v != nil {
			outputType := v.GetString(FieldOutputType)
			serviceToken := v.GetString(FieldOutputServiceToken)
			if outputType == OutputTypeElasticsearch && serviceToken == "" {
				defaults = append(defaults, k)
			}
		}
	}

	if len(defaults) == 0 {
		return "", ErrDefaultOutputNotFound
	}
	if len(defaults) == 1 {
		return defaults[0], nil
	}
	return "", ErrMultipleDefaultOutputsFound
}
