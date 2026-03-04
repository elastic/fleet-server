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
	FieldSecrets = "secrets"
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
func ProcessInputsSecrets(data *model.PolicyData, secretValues map[string]string) ([]map[string]interface{}, []string) {
	if len(data.Inputs) == 0 {
		// No inputs, so no secret references in them to replace.
		return nil, nil
	}

	if len(data.SecretReferences) == 0 {
		// No list of secret references to replace. Return inputs as is.
		return data.Inputs, nil
	}

	// Unfortunately, there are two ways (formats) of specifying secret references in
	// policies: inline and path (see https://github.com/elastic/fleet-server/pull/5852).
	// So we try replacing secret references in both formats.

	inputs, keys := processInputsWithInlineSecrets(data, secretValues)

	data.Inputs = inputs
	i, k := processInputsWithPathSecrets(data, secretValues)

	inputs = i
	keys = append(keys, k...)

	return inputs, keys
}

// processInputsWithInlineSecrets reads inputs and secret_references from agent policy and replaces
// the values of secret refs in inputs and input streams properties using the old format
// for specifying secrets: <path>: $co.elastic.secret{<secret ref>}
func processInputsWithInlineSecrets(data *model.PolicyData, secretValues map[string]string) ([]map[string]interface{}, []string) {
	result := make([]map[string]interface{}, 0)
	keys := make([]string, 0)
	for i, input := range data.Inputs {
		replacedInput, ks := replaceInlineSecretRefsInMap(input, secretValues)
		for _, key := range ks {
			keys = append(keys, "inputs."+strconv.Itoa(i)+"."+key)
		}
		result = append(result, replacedInput)
	}
	return result, keys
}

// processInputsWithPathSecrets reads inputs and secret_references from agent policy and replaces
// the values of secret refs in inputs and input streams properties using the new format
// for specifying secrets: secrets.<path-to-key>.<key>.id:<secret ref>
func processInputsWithPathSecrets(data *model.PolicyData, secretValues map[string]string) ([]map[string]interface{}, []string) {
	result := make([]map[string]interface{}, 0)
	keys := make([]string, 0)

	for i, inp := range data.Inputs {
		input := smap.Map(inp)
		replacedInput, ks := replacePathSecretRefsInMap(input, secretValues)
		for _, key := range ks {
			keys = append(keys, "inputs."+strconv.Itoa(i)+"."+key)
		}
		result = append(result, replacedInput)
	}

	return result, keys
}

func replacePathSecretRefsInMap(m smap.Map, secretValues map[string]string) (map[string]any, []string) {
	result := make(map[string]any, len(m))
	keys := make([]string, 0)

	// Check if there are any secrets at the top level of the map
	// and replace them.
	mSecrets := m.GetMap(FieldSecrets)
	delete(m, FieldSecrets)

	secrets := getSecretIDAndPath(mSecrets)

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
		setSecretPath(m, secretValues[secret.ID], secret.Path)
	}

	// Next, recurse into nested fields and replace any secrets found there.
	for k, v := range m {
		var r any
		var ks []string

		switch t := v.(type) {
		case map[string]any:
			r, ks = replacePathSecretRefsInMap(t, secretValues)
			for _, key := range ks {
				keys = append(keys, k+"."+key)
			}
		case []any:
			r, ks = replacePathSecretRefsInSlice(t, secretValues)
			for _, key := range ks {
				keys = append(keys, k+"."+key)
			}
		default:
			r = v
		}
		result[k] = r
	}

	return result, keys
}

func replacePathSecretRefsInSlice(arr []any, secretValues map[string]string) ([]any, []string) {
	result := make([]any, len(arr))
	keys := make([]string, 0)

	for i, v := range arr {
		var r any
		var ks []string

		switch value := v.(type) {
		case map[string]any:
			r, ks = replacePathSecretRefsInMap(value, secretValues)
		case []any:
			r, ks = replacePathSecretRefsInSlice(value, secretValues)
		default:
			r = v
		}

		for _, key := range ks {
			keys = append(keys, strconv.Itoa(i)+"."+key)
		}
		result[i] = r
	}

	return result, keys
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

type Secret struct {
	Path []string
	ID   string
}

func getSecretIDAndPath(secret smap.Map) []Secret {
	secrets := make([]Secret, 0)

	secretID := secret.GetString("id")
	if secretID != "" {
		secrets = append(secrets, Secret{
			Path: make([]string, 0),
			ID:   secretID,
		})

		return secrets
	}

	for secretKey := range secret {
		newSecrets := getSecretIDAndPath(secret.GetMap(secretKey))

		for _, newSecret := range newSecrets {
			path := append([]string{secretKey}, newSecret.Path...)
			secrets = append(secrets, Secret{
				Path: path,
				ID:   newSecret.ID,
			})
		}
	}

	return secrets
}

func setSecretPath(section smap.Map, secretValue string, secretPaths []string) {
	// Break the recursion
	if len(secretPaths) == 1 {
		section[secretPaths[0]] = secretValue
		return
	}
	path, secretPaths := secretPaths[0], secretPaths[1:]

	if section.GetMap(path) == nil {
		section[path] = make(map[string]interface{})
	}

	setSecretPath(section.GetMap(path), secretValue, secretPaths)
}

// Read secret from output and mutate output with secret value
func ProcessOutputSecret(output smap.Map, secretValues map[string]string) []string {

	// Unfortunately, there are two ways (formats) of specifying secret references in
	// policies: inline and path (see https://github.com/elastic/fleet-server/pull/5852).
	// So we try replacing secret references in both formats.

	keys := processMapWithInlineSecrets(output, secretValues)
	k := processMapWithPathSecrets(output, secretValues)

	keys = append(keys, k...)
	return keys
}

// processMapWithPathSecrets reads secrets from the output and mutates the output with the secret values using
// the new format for specifying secrets: secrets.<path-to-field>.<field>.id:<secret ref>
func processMapWithPathSecrets(m smap.Map, secretValues map[string]string) []string {
	secrets := m.GetMap(FieldSecrets)

	delete(m, FieldSecrets)
	secretReferences := make([]model.SecretReferencesItems, 0)
	outputSecrets := getSecretIDAndPath(secrets)
	keys := make([]string, 0, len(outputSecrets))

	for _, secret := range outputSecrets {
		secretReferences = append(secretReferences, model.SecretReferencesItems{
			ID: secret.ID,
		})
	}
	if len(secretReferences) == 0 {
		return nil
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
		setSecretPath(m, secretValues[secret.ID], secret.Path)
	}
	return keys
}

func processMapWithInlineSecrets(m smap.Map, secretValues map[string]string) []string {
	replacedM, keys := replaceInlineSecretRefsInMap(m, secretValues)
	for _, key := range keys {
		m[key] = replacedM[key]
	}
	return keys
}

// ProcessMapSecrets reads and replaces secrets in the agent.download section of the policy
func ProcessMapSecrets(m smap.Map, secretValues map[string]string) []string {
	// Unfortunately, there are two ways (formats) of specifying secret references in
	// policies: inline and path (see https://github.com/elastic/fleet-server/pull/5852).
	// So we try replacing secret references in both formats.

	keys := processMapWithInlineSecrets(m, secretValues)
	k := processMapWithPathSecrets(m, secretValues)

	keys = append(keys, k...)
	return keys
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
