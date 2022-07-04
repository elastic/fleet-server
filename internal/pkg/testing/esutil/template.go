// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package esutil

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/rs/zerolog/log"
)

const (
	templateVersion = 1

	defaultSettings = `
    {
		"index.lifecycle.name": "%s"
	}
	`

	defaultTemplate = `
	{
		"version": %v,
		"index_patterns": [ "%s" ],
		%s
		"priority": 200,
		"template": {
			"mappings" : %s,
			"settings" : %s
		}
	}
	`
)

type Template struct {
	Version  int                    `json:"version"`
	Settings map[string]interface{} `json:"settings"`
}

type AckResponse struct {
	Acknowledged bool `json:"acknowledged"`
}

func EnsureTemplate(ctx context.Context, cli *elasticsearch.Client, name, mapping string, ilm bool) (err error) {
	templateName := GetILMPolicyName(name)

	// Get current template
	res, err := cli.Indices.GetTemplate(
		cli.Indices.GetTemplate.WithContext(ctx),
		cli.Indices.GetTemplate.WithFlatSettings(true),
		cli.Indices.GetTemplate.WithName(templateName),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	settings := "{}"
	if ilm {
		policyName := GetILMPolicyName(name)

		settings = fmt.Sprintf(defaultSettings, policyName)
	}

	if res.StatusCode != http.StatusOK {
		// Template not found, create a new one
		return createTemplate(ctx, cli, name, templateVersion, settings, mapping, ilm)
	}

	// Decode template from response
	var r map[string]Template
	err = json.NewDecoder(res.Body).Decode(&r)
	if err != nil {
		return err
	}

	template, ok := r[name]
	if !ok {
		// Template not found, create a new one
		return createTemplate(ctx, cli, name, templateVersion, settings, mapping, ilm)
	}

	// Check settings
	log.Debug().Interface("settings", template.Settings).Msg("Found existing settings")

	if template.Version >= templateVersion {
		log.Info().
			Int("current templated version", template.Version).
			Int("new template version", templateVersion).
			Msg("Skipping template creation because upstream version")
		return nil
	}

	log.Info().
		Int("current templated version", template.Version).
		Int("new template version", templateVersion).
		Msg("Creating template")

	return createTemplate(ctx, cli, name, templateVersion, settings, mapping, ilm)
}

func createTemplate(ctx context.Context, cli *elasticsearch.Client, name string, templateVersion int, settings, mapping string, ilm bool) error {

	log.Info().Str("name", name).Msg("Create template")

	datastream := ""
	if ilm {
		datastream = `"data_stream": { },`
	}
	body := fmt.Sprintf(defaultTemplate, templateVersion, name, datastream, mapping, settings)

	res, err := cli.Indices.PutIndexTemplate(name,
		strings.NewReader(body),
		cli.Indices.PutIndexTemplate.WithContext(ctx),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	err = checkResponseError(res)
	if err != nil {
		if errors.Is(err, ErrResourceAlreadyExists) {
			log.Info().Str("name", name).Msg("Index template already exists")
			return nil
		}
		return err
	}

	var r AckResponse
	err = json.NewDecoder(res.Body).Decode(&r)
	if err != nil {
		return fmt.Errorf("failed to parse put template response: %v version: %v, err: %w", name, templateVersion, err)
	}
	if !r.Acknowledged {
		return fmt.Errorf("failed to receive acknowledgment for put template request: %v version: %v", name, templateVersion)
	}

	return nil
}
