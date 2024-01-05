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
	"github.com/elastic/fleet-server/v7/internal/pkg/smap"
)

var (
	secretRegex = regexp.MustCompile(`\$co\.elastic\.secret{([^}]*)}`)
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
			newInput[k] = replaceAnyRef(v, secretValues)
		}
		result = append(result, newInput)
	}
	data.SecretReferences = nil
	return result, nil
}

// replaceAnyRef is a generic approach to replacing any secret references in the passed item.
// It will go through any slices or maps and replace any secret references.
//
// go's generic parameters are not a good fit for rewriting this method as the typeswitch will not work.
func replaceAnyRef(ref any, secrets map[string]string) any {
	var r any
	switch val := ref.(type) {
	case string:
		r = replaceStringRef(val, secrets)
	case map[string]any:
		obj := make(map[string]any)
		for k, v := range val {
			obj[k] = replaceAnyRef(v, secrets)
		}
		r = obj
	case []any:
		arr := make([]any, len(val))
		for i, v := range val {
			arr[i] = replaceAnyRef(v, secrets)
		}
		r = arr
	default:
		r = val
	}
	return r
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
func ProcessOutputSecret(ctx context.Context, output smap.Map, bulker bulk.Bulk) error {
	secrets := output.GetMap(FieldOutputSecrets)

	delete(output, FieldOutputSecrets)
	secretReferences := make([]model.SecretReferencesItems, 0)
	outputSecrets, err := getSecretIDAndPath(secrets)
	if err != nil {
		return err
	}

	for _, secret := range outputSecrets {
		secretReferences = append(secretReferences, model.SecretReferencesItems{
			ID: secret.ID,
		})
	}
	if len(secretReferences) == 0 {
		return nil
	}
	secretValues, err := getSecretValues(ctx, secretReferences, bulker)
	if err != nil {
		return err
	}
	for _, secret := range outputSecrets {
		err = setSecretPath(output, secretValues[secret.ID], secret.Path)
		if err != nil {
			return err
		}
	}
	return nil
}

// replaceStringRef replaces values matching a secret ref regex, e.g. $co.elastic.secret{<secret ref>} -> <secret value>
// and does this for multiple matches
func replaceStringRef(ref string, secretValues map[string]string) string {
	matches := secretRegex.FindStringSubmatch(ref)
	for len(matches) > 1 {
		secretRef := matches[1]
		if val, ok := secretValues[secretRef]; ok {
			ref = strings.Replace(ref, matches[0], val, 1)
			matches = secretRegex.FindStringSubmatch(ref)
			continue
		}
		break
	}
	return ref
}
