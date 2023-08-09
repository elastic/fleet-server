// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
)

type SecretReference struct {
	ID string `json:"id"`
}

var (
	secretRegex = regexp.MustCompile(`\$co\.elastic\.secret{(.*)}`)
)

// read secret values that belong to the agent policy's secret references, returns secrets as id:value map
func getSecretValues(ctx context.Context, secretRefsRaw json.RawMessage, bulker bulk.Bulk) (map[string]string, error) {
	if secretRefsRaw == nil {
		return nil, nil
	}

	var secretValues []SecretReference
	err := json.Unmarshal([]byte(secretRefsRaw), &secretValues)
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0)
	for _, ref := range secretValues {
		ids = append(ids, ref.ID)
	}

	results, err := bulker.ReadSecrets(ctx, ids)
	if err != nil {
		return nil, err
	}

	return results, nil
}

// read inputs and secret_references from agent policy
// replace values of secret refs in inputs and input streams properties
func getPolicyInputsWithSecrets(ctx context.Context, fields map[string]json.RawMessage, bulker bulk.Bulk) ([]map[string]interface{}, error) {
	if fields["inputs"] == nil {
		return nil, nil
	}

	var inputs []map[string]interface{}
	err := json.Unmarshal([]byte(fields["inputs"]), &inputs)
	if err != nil {
		return nil, err
	}

	if fields["secret_references"] == nil {
		return inputs, nil
	}

	secretValues, err := getSecretValues(ctx, fields["secret_references"], bulker)
	if err != nil {
		return nil, err
	}

	result := make([]map[string]interface{}, 0)
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
									replacedVal := replaceSecretRef(streamRef, secretValues)
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
				val := replaceSecretRef(ref, secretValues)
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

// replace values mathing a secret ref regex, e.g. $co.elastic.secret{<secret ref>} -> <secret value>
func replaceSecretRef(ref string, secretValues map[string]string) string {
	matches := secretRegex.FindStringSubmatch(ref)
	if len(matches) > 1 {
		secretRef := matches[1]
		if val, ok := secretValues[secretRef]; ok {
			return strings.Replace(ref, matches[0], val, 1)
		}
	}
	return ref
}
