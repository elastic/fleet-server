// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/smap"
	"go.elastic.co/apm/v2"
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
	Roles   RoleMapT
	Outputs map[string]Output
	Default ParsedPolicyDefaults
	Inputs  []map[string]interface{}
	Links   apm.SpanLink
}

func NewParsedPolicy(ctx context.Context, bulker bulk.Bulk, p model.Policy) (*ParsedPolicy, error) {
	var err error
	// Interpret the output permissions if available
	var roles map[string]RoleT
	if roles, err = parsePerms(p.Data.OutputPermissions); err != nil {
		return nil, err
	}

	policyOutputs, err := constructPolicyOutputs(p.Data.Outputs, roles)
	if err != nil {
		return nil, err
	}
	defaultName, err := findDefaultOutputName(p.Data.Outputs)
	if err != nil {
		return nil, err
	}
	policyInputs, err := getPolicyInputsWithSecrets(ctx, p.Data, bulker)
	if err != nil {
		return nil, err
	}

	// We are cool and the gang
	pp := &ParsedPolicy{
		Policy:  p,
		Roles:   roles,
		Outputs: policyOutputs,
		Default: ParsedPolicyDefaults{
			Name: defaultName,
		},
		Inputs: policyInputs,
	}
	if trace := apm.TransactionFromContext(ctx); trace != nil {
		// Pass current transaction link (should be a monitor transaction) to caller (likely a client request).
		tCtx := trace.TraceContext()
		pp.Links = apm.SpanLink{
			Trace: tCtx.Trace,
			Span:  tCtx.Span,
		}
	}

	return pp, nil
}

func constructPolicyOutputs(outputs map[string]map[string]interface{}, roles map[string]RoleT) (map[string]Output, error) {
	result := make(map[string]Output, len(outputs))

	for k, v := range outputs {
		typeStr, ok := v["type"].(string)
		if !ok {
			return nil, fmt.Errorf("missing or invalid output type: %+v", v)
		}
		p := Output{
			Name: k,
			Type: typeStr,
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
			// permission hash created here
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

// findDefaultName returns the name of the 1st output with the "elasticsearch" type or falls back to behaviour that relies on deprecated fields.
//
// Previous fleet-server and elastic-agent released had a default output which was removed Sept 2021.
func findDefaultOutputName(outputs map[string]map[string]interface{}) (string, error) {
	// iterate across the keys finding the defaults
	var defaults []string
	var ESdefaults []string
	for k, v := range outputs {
		if v != nil {
			typeStr, ok := v["type"].(string)
			if ok && typeStr == OutputTypeElasticsearch {
				ESdefaults = append(ESdefaults, k)
				continue
			}

			fleetServer, ok := v[FieldOutputFleetServer]
			if !ok {
				defaults = append(defaults, k)
				continue
			}
			fsMap, ok := fleetServer.(map[string]interface{})
			if ok {
				str, ok := fsMap[FieldOutputServiceToken].(string)
				if ok && str == "" {
					defaults = append(defaults, k)
					continue
				}
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
