// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"encoding/json"
	"errors"
	"regexp"

	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/smap"
	"github.com/elastic/go-elasticsearch/v8"
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

type SecretReference struct {
	Id string `json:"id"`
}

type ParsedPolicy struct {
	Policy  model.Policy
	Fields  map[string]json.RawMessage
	Roles   RoleMapT
	Outputs map[string]Output
	Default ParsedPolicyDefaults
	Inputs  []map[string]interface{}
}

func NewParsedPolicy(p model.Policy, client *elasticsearch.Client) (*ParsedPolicy, error) {
	var err error

	var fields map[string]json.RawMessage
	if err = json.Unmarshal(p.Data, &fields); err != nil {
		return nil, err
	}

	// Interpret the output permissions if available
	var roles map[string]RoleT
	if perms := fields[FieldOutputPermissions]; len(perms) != 0 {
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
	secretReferences, err := getSecretReferences(fields["secret_references"], client)
	policyInputs, err := getPolicyInputsWithSecrets(fields["inputs"], secretReferences)

	// We are cool and the gang
	pp := &ParsedPolicy{
		Policy:  p,
		Fields:  fields,
		Roles:   roles,
		Outputs: policyOutputs,
		Default: ParsedPolicyDefaults{
			Name: defaultName,
		},
		Inputs: policyInputs,
	}

	return pp, nil
}

// returns secrets as id:value map
func getSecretReferences(secretRefsRaw json.RawMessage, client *elasticsearch.Client) (map[string]string, error) {
	if secretRefsRaw == nil {
		return nil, nil
	}
	var secretReferences []SecretReference
	err := json.Unmarshal([]byte(secretRefsRaw), &secretReferences)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string)
	for _, ref := range secretReferences {
		value, err := dl.ReadSecret(client, ref.Id)
		if err != nil {
			return nil, err
		}
		result[ref.Id] = value
	}
	return result, nil
}

func getPolicyInputsWithSecrets(inputsRaw json.RawMessage, secretReferences map[string]string) ([]map[string]interface{}, error) {
	if secretReferences == nil {
		return nil, nil
	}
	var inputs []map[string]interface{}
	err := json.Unmarshal([]byte(inputsRaw), &inputs)
	if err != nil {
		return nil, err
	}
	var result []map[string]interface{}
	for _, input := range inputs {
		newInput := make(map[string]interface{})
		for k, v := range input {
			if k == "streams" {
				if streams, ok := input[k].([]any); ok {
					newStreams := make([]any, 0)
					for _, stream := range streams {
						if streamMap, ok := stream.(map[string]interface{}); ok {
							newStream := make(map[string]interface{})
							for streamKey, streamVal := range streamMap {
								if streamRef, ok := streamMap[streamKey].(string); ok {
									replacedVal := replaceSecretRef(streamRef, secretReferences)
									newStream[streamKey] = replacedVal
								} else {
									newStream[streamKey] = streamVal
								}
							}
							newStreams = append(newStreams, newStream)
						} else {
							newStreams = append(newStreams, stream)
						}
						newInput[k] = newStreams

					}
				}
			} else if ref, ok := input[k].(string); ok {
				val := replaceSecretRef(ref, secretReferences)
				newInput[k] = val
			}
			if _, ok := newInput[k]; !ok {
				newInput[k] = v
			}
		}
		result = append(result, newInput)
	}
	return result, nil
}

func replaceSecretRef(ref string, secretReferences map[string]string) string {
	regexp := regexp.MustCompile(`\$co\.elastic\.secret{(.*)}`)
	matches := regexp.FindStringSubmatch(ref)
	if len(matches) > 1 {
		secretRef := matches[1]
		if val, ok := secretReferences[secretRef]; ok {
			return val
		}
	}
	return ref
}

func constructPolicyOutputs(outputsRaw json.RawMessage, roles map[string]RoleT) (map[string]Output, error) {
	result := make(map[string]Output)

	outputsMap, err := smap.Parse(outputsRaw)
	if err != nil {
		return result, err
	}

	for k := range outputsMap {
		v := outputsMap.GetMap(k)

		p := Output{
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
