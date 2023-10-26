// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"context"
	"regexp"
	"strings"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

var (
	secretRegex = regexp.MustCompile(`\$co\.elastic\.secret{(.*)}`)
)

// read secret values that belong to the agent policy's secret references, returns secrets as id:value map
func getSecretValues(ctx context.Context, secretRefs []model.SecretReferencesItems, bulker bulk.Bulk) (map[string]string, error) {
	if len(secretRefs) == 0 {
		return nil, nil
	}

	ids := make([]string, 0, len(secretRefs))
	for _, ref := range secretRefs {
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
func getPolicyInputsWithSecrets(ctx context.Context, data *model.PolicyData, bulker bulk.Bulk) ([]map[string]interface{}, error) {
	if len(data.Inputs) == 0 {
		return nil, nil
	}

	if len(data.SecretReferences) == 0 {
		return data.Inputs, nil
	}

	secretValues, err := getSecretValues(ctx, data.SecretReferences, bulker)
	if err != nil {
		return nil, err
	}

	result := make([]map[string]interface{}, 0)
	for _, input := range data.Inputs {
		newInput := make(map[string]interface{})
		for k, v := range input {
			// replace secret refs in input stream fields
			if k == "streams" {
				if streams, ok := v.([]any); ok {
					newInput[k] = processStreams(streams, secretValues)
				}
				// replace secret refs in input fields
			} else if ref, ok := input[k].(string); ok {
				val := replaceSecretRef(ref, secretValues)
				newInput[k] = val
			}
			// if any field was not processed, add back as is
			if _, ok := newInput[k]; !ok {
				newInput[k] = v
			}
		}
		result = append(result, newInput)
	}
	data.SecretReferences = nil
	return result, nil
}

func processStreams(streams []any, secretValues map[string]string) []any {
	newStreams := make([]any, 0)
	for _, stream := range streams {
		if streamMap, ok := stream.(map[string]interface{}); ok {
			newStream := replaceSecretsInStream(streamMap, secretValues)
			newStreams = append(newStreams, newStream)
		} else {
			newStreams = append(newStreams, stream)
		}
	}
	return newStreams
}

// if field values are secret refs, replace with secret value, otherwise noop
func replaceSecretsInStream(streamMap map[string]interface{}, secretValues map[string]string) map[string]interface{} {
	newStream := make(map[string]interface{})
	for streamKey, streamVal := range streamMap {
		if streamRef, ok := streamMap[streamKey].(string); ok {
			replacedVal := replaceSecretRef(streamRef, secretValues)
			newStream[streamKey] = replacedVal
		} else {
			newStream[streamKey] = streamVal
		}
	}
	return newStream
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
