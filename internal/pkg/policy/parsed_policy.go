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
	FieldOutputFleetServer  = "fleet_server"
	FieldOutputServiceToken = "service_token"
	FieldOutputPermissions  = "output_permissions"
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
}

type ParsedPolicy struct {
	Policy  model.Policy
	Fields  map[string]json.RawMessage
	Roles   RoleMapT
	Outputs map[string]PolicyOutput
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

	policyOutputs, err := constructPolicyOutputs(outputs, roles)
	if err != nil {
		return nil, err
	}
	defaultName, err := findDefaultOutputName(outputs)
	if err != nil {
		return nil, err
	}

	// We are cool and the gang
	pp := &ParsedPolicy{
		Policy:  p,
		Fields:  fields,
		Roles:   roles,
		Outputs: policyOutputs,
		Default: ParsedPolicyDefaults{
			Name: defaultName,
		},
	}

	return pp, nil
}

func constructPolicyOutputs(outputsRaw json.RawMessage, roles map[string]RoleT) (map[string]PolicyOutput, error) {
	result := make(map[string]PolicyOutput)

	outputsMap, err := smap.Parse(outputsRaw)
	if err != nil {
		return result, err
	}

	for k := range outputsMap {
		v := outputsMap.GetMap(k)

		p := PolicyOutput{
			Name: k,
			Type: v.GetString(FieldOutputType),
		}

		if role, ok := roles[k]; ok {
			p.Role = &role
		}

		result[k] = p
	}

	return result, nil
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
	var ESdefaults []string
	for k := range outputsMap {

		v := outputsMap.GetMap(k)

		if v != nil {
			outputType := v.GetString(FieldOutputType)
			if outputType == OutputTypeElasticsearch {
				ESdefaults = append(ESdefaults, k)
				continue
			}
			fleetServer := v.GetMap(FieldOutputFleetServer)
			if fleetServer == nil {
				defaults = append(defaults, k)
				continue
			}
			serviceToken := fleetServer.GetString(FieldOutputServiceToken)
			if serviceToken == "" {
				defaults = append(defaults, k)
				continue
			}
		}
	}
	// Prefer ES outputs over other types
	defaults = append(ESdefaults, defaults...)

	// Note: When updating this logic to support multiple outputs, this logic
	// should change to not be order dependent.
	if len(defaults) > 0 {
		return defaults[0], nil
	}

	return "", ErrDefaultOutputNotFound
}
