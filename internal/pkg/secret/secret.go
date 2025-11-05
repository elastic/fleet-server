// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package secret

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/smap"
)

const (
	FieldOutputSecrets = "secrets"
)

var (
	secretRegex = regexp.MustCompile(`\$co\.elastic\.secret{([^}]*)}`)
)

// read secret values that belong to the agent policy's secret references, returns secrets as id:value map
func GetSecretValues(ctx context.Context, secretRefs []model.SecretReferencesItems, bulker bulk.Bulk) (map[string]string, error) {
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
func ProcessInputsSecrets(ctx context.Context, data *model.PolicyData, bulker bulk.Bulk) ([]map[string]interface{}, []string, error) {
	if len(data.Inputs) == 0 {
		return nil, nil, nil
	}

	if len(data.SecretReferences) == 0 {
		return data.Inputs, nil, nil
	}

	secretValues, err := GetSecretValues(ctx, data.SecretReferences, bulker)
	if err != nil {
		return nil, nil, err
	}

	inputs, keys, err := processInputsWithInlineSecrets(data, secretValues)
	if err != nil {
		return nil, nil, err
	}

	i, k, err := processInputsWithPathSecrets(data, secretValues)
	if err != nil {
		return nil, nil, err
	}

	inputs = append(inputs, i...)
	keys = append(keys, k...)

	data.SecretReferences = nil
	return inputs, keys, nil
}

// processInputsWithInlineSecrets reads inputs and secret_references from agent policy and replaces
// the values of secret refs in inputs and input streams properties using the old format
// for specifying secrets: <path>: $co.elastic.secret{<secret ref>}
func processInputsWithInlineSecrets(data *model.PolicyData, secretValues map[string]string) ([]map[string]interface{}, []string, error) {
	result := make([]map[string]interface{}, 0)
	keys := make([]string, 0)
	for i, input := range data.Inputs {
		replacedInput, ks := replaceInlineSecretRefsInMap(input, secretValues)
		for _, key := range ks {
			keys = append(keys, "inputs."+strconv.Itoa(i)+"."+key)
		}
		result = append(result, replacedInput)
	}
	return result, keys, nil
}

// processInputsWithPathSecrets reads inputs and secret_references from agent policy and replaces
// the values of secret refs in inputs and input streams properties using the new format
// for specifying secrets: secrets.<path-to-key>.<key>.id:<secret ref>
func processInputsWithPathSecrets(data *model.PolicyData, secretValues map[string]string) ([]map[string]interface{}, []string, error) {
	result := make([]map[string]interface{}, 0)
	keys := make([]string, 0)

	for i, inp := range data.Inputs {
		input := smap.Map(inp)
		replacedInput, ks, err := replacePathSecretRefsInMap(input, secretValues)
		if err != nil {
			return nil, nil, err
		}

		for _, key := range ks {
			keys = append(keys, "inputs."+strconv.Itoa(i)+"."+key)
		}
		result = append(result, replacedInput)
	}

	return result, keys, nil
}

func replacePathSecretRefsInMap(m smap.Map, secretValues map[string]string) (map[string]any, []string, error) {
	result := make(map[string]any, len(m))
	keys := make([]string, 0)

	// Check if there are any secrets at the top level of the map
	// and replace them.
	mSecrets := m.GetMap(FieldOutputSecrets)
	delete(m, FieldOutputSecrets)

	secrets, err := getSecretIDAndPath(mSecrets)
	if err != nil {
		return nil, nil, err
	}

	for _, secret := range secrets {
		var key string
		for _, p := range secret.Path {
			if key == "" {
				key = p
				continue
			}
			key = key + "." + p
		}
		keys = append(keys, key)
		err = setSecretPath(m, secretValues[secret.ID], secret.Path)
		if err != nil {
			return nil, nil, err
		}
	}

	// Next, recurse into nested fields and replace any secrets found there.
	for k, v := range m {
		var r any
		var ks []string

		switch t := v.(type) {
		case map[string]any:
			r, ks, err = replacePathSecretRefsInMap(t, secretValues)
			if err != nil {
				return nil, nil, err
			}
		case []any:
			r, ks, err = replacePathSecretRefsInSlice(t, secretValues)
			if err != nil {
				return nil, nil, err
			}
		default:
			r = v
		}

		keys = append(keys, ks...)
		result[k] = r
	}

	return result, keys, nil
}

func replacePathSecretRefsInSlice(arr []any, secretValues map[string]string) ([]any, []string, error) {
	result := make([]any, len(arr))
	keys := make([]string, 0)

	for i, v := range arr {
		var r any
		var ks []string
		var err error

		switch value := v.(type) {
		case map[string]any:
			r, ks, err = replacePathSecretRefsInMap(value, secretValues)
			if err != nil {
				return nil, nil, err
			}
		case []any:
			r, ks, err = replacePathSecretRefsInSlice(value, secretValues)
			if err != nil {
				return nil, nil, err
			}
		default:
			r = v
		}

		for _, key := range ks {
			keys = append(keys, strconv.Itoa(i)+"."+key)
		}
		result[i] = r
	}

	return result, keys, nil
}

func GetActionDataWithSecrets(ctx context.Context, data json.RawMessage, refs []model.SecretReferencesItems, bulker bulk.Bulk) (json.RawMessage, error) {
	if len(refs) == 0 {
		return data, nil
	}

	secretValues, err := GetSecretValues(ctx, refs, bulker)
	if err != nil {
		return data, err
	}

	parsedData, err := smap.Parse(data)
	if err != nil {
		return data, err
	}

	result, _ := replaceInlineSecretRefsInMap(parsedData, secretValues)

	b, err := json.Marshal(result)
	if err != nil {
		return data, err
	}

	return b, nil
}

// replaceInlineSecretRefsInMap replaces all nested secret values in the passed input and returns the resulting input along with a list of keys where inputs have been replaced.
func replaceInlineSecretRefsInMap(input map[string]any, secrets map[string]string) (map[string]any, []string) {
	keys := make([]string, 0)
	result := make(map[string]any, len(input))
	var r any

	for k, v := range input {
		switch value := v.(type) {
		case string:
			ref, replaced := replaceStringRef(value, secrets)
			if replaced {
				keys = append(keys, k)
			}
			r = ref
		case map[string]any:
			ref, ks := replaceInlineSecretRefsInMap(value, secrets)
			for _, key := range ks {
				keys = append(keys, k+"."+key)
			}
			r = ref
		case []any:
			ref, ks := replaceInlineSecretRefsInSlice(value, secrets)
			for _, key := range ks {
				keys = append(keys, k+"."+key)
			}
			r = ref
		default:
			r = v
		}
		result[k] = r
	}
	return result, keys
}

// replaceInlineSecretRefsInSlice replaces all nested secrets within the passed slice and returns the resulting slice along with a list of keys that indicate where values have been replaced.
func replaceInlineSecretRefsInSlice(arr []any, secrets map[string]string) ([]any, []string) {
	keys := make([]string, 0)
	result := make([]any, len(arr))
	var r any

	for i, v := range arr {
		switch value := v.(type) {
		case string:
			ref, replaced := replaceStringRef(value, secrets)
			if replaced {
				keys = append(keys, strconv.Itoa(i))
			}
			r = ref
		case map[string]any:
			ref, ks := replaceInlineSecretRefsInMap(value, secrets)
			for _, key := range ks {
				keys = append(keys, strconv.Itoa(i)+"."+key)
			}
			r = ref
		case []any:
			ref, ks := replaceInlineSecretRefsInSlice(value, secrets)
			for _, key := range ks {
				keys = append(keys, strconv.Itoa(i)+"."+key)
			}
			r = ref
		default:
			r = v
		}
		result[i] = r
	}
	return result, keys
}

type OutputSecret struct {
	Path []string
	ID   string
}

func getSecretIDAndPath(secret smap.Map) ([]OutputSecret, error) {
	outputSecrets := make([]OutputSecret, 0)

	secretID := secret.GetString("id")
	if secretID != "" {
		outputSecrets = append(outputSecrets, OutputSecret{
			Path: make([]string, 0),
			ID:   secretID,
		})

		return outputSecrets, nil
	}

	for secretKey := range secret {
		newOutputSecrets, err := getSecretIDAndPath(secret.GetMap(secretKey))
		if err != nil {
			return nil, err
		}

		for _, secret := range newOutputSecrets {
			path := append([]string{secretKey}, secret.Path...)
			outputSecrets = append(outputSecrets, OutputSecret{
				Path: path,
				ID:   secret.ID,
			})
		}
	}

	return outputSecrets, nil
}

func setSecretPath(output smap.Map, secretValue string, secretPaths []string) error {
	// Break the recursion
	if len(secretPaths) == 1 {
		output[secretPaths[0]] = secretValue

		return nil
	}
	path, secretPaths := secretPaths[0], secretPaths[1:]

	if output.GetMap(path) == nil {
		output[path] = make(map[string]interface{})
	}

	return setSecretPath(output.GetMap(path), secretValue, secretPaths)
}

// Read secret from output and mutate output with secret value
func ProcessOutputSecret(ctx context.Context, output smap.Map, bulker bulk.Bulk) ([]string, error) {
	return processOutputSecretNew(ctx, output, bulker)
}

// processOutputSecretNew reads secrets from the output and mutates the output with the secret values using
// the new format for specifying secrets: secrets.<path-to-field>.<field>.id:<secret ref>
func processOutputSecretNew(ctx context.Context, output smap.Map, bulker bulk.Bulk) ([]string, error) {
	secrets := output.GetMap(FieldOutputSecrets)

	delete(output, FieldOutputSecrets)
	secretReferences := make([]model.SecretReferencesItems, 0)
	outputSecrets, err := getSecretIDAndPath(secrets)
	keys := make([]string, 0, len(outputSecrets))
	if err != nil {
		return nil, err
	}

	for _, secret := range outputSecrets {
		secretReferences = append(secretReferences, model.SecretReferencesItems{
			ID: secret.ID,
		})
	}
	if len(secretReferences) == 0 {
		return nil, nil
	}
	secretValues, err := GetSecretValues(ctx, secretReferences, bulker)
	if err != nil {
		return nil, err
	}
	for _, secret := range outputSecrets {
		var key string
		for _, p := range secret.Path {
			if key == "" {
				key = p
				continue
			}
			key = key + "." + p
		}
		keys = append(keys, key)
		err = setSecretPath(output, secretValues[secret.ID], secret.Path)
		if err != nil {
			return nil, err
		}
	}
	return keys, nil
}

// replaceStringRef replaces values matching a secret ref regex, e.g. $co.elastic.secret{<secret ref>} -> <secret value>
// and does this for multiple matches
// returns the resulting string value, and if any replacements were made
func replaceStringRef(ref string, secretValues map[string]string) (string, bool) {
	hasReplaced := false
	matches := secretRegex.FindStringSubmatch(ref)
	for len(matches) > 1 {
		secretRef := matches[1]
		if val, ok := secretValues[secretRef]; ok {
			hasReplaced = true
			ref = strings.Replace(ref, matches[0], val, 1)
			matches = secretRegex.FindStringSubmatch(ref)
			continue
		}
		break
	}
	return ref, hasReplaced
}
