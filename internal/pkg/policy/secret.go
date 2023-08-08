// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"context"
	"encoding/json"
	"regexp"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
)

type SecretReference struct {
	ID string `json:"id"`
}

// returns secrets as id:value map
func getSecretReferences(ctx context.Context, secretRefsRaw json.RawMessage, bulker bulk.Bulk) (map[string]string, error) {
	if secretRefsRaw == nil {
		return nil, nil
	}
	var secretReferences []SecretReference
	err := json.Unmarshal([]byte(secretRefsRaw), &secretReferences)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0)
	for _, ref := range secretReferences {
		ids = append(ids, ref.ID)
	}
	results, err := bulker.ReadSecrets(ctx, ids)
	if err != nil {
		return nil, err
	}
	return results, nil
}

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

	secretReferences, err := getSecretReferences(ctx, fields["secret_references"], bulker)
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
