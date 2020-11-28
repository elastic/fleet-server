package esboot

import (
	"context"
	"encoding/json"
	"errors"
	"fleet/internal/pkg/esutil"
	"fmt"
	"net/http"
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog/log"
)

const (
	templateSuffix  = "template"
	templateVersion = 1

	defaultSettings = `
    {
		"index.lifecycle.name": "%s"
	}
	`

	defaultTemplate = `
	{
		"version": %v,
		"index_patterns": [ "%s*" ],
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

func EnsureTemplate(ctx context.Context, es *elasticsearch.Client, name, mapping string, ilm bool) (err error) {
	templateName := nameWithSuffix(name, templateSuffix)

	// Get current template
	res, err := es.Indices.GetTemplate(
		es.Indices.GetTemplate.WithContext(ctx),
		es.Indices.GetTemplate.WithFlatSettings(true),
		es.Indices.GetTemplate.WithName(templateName),
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
		return createTemplate(ctx, es, name, templateVersion, settings, mapping, ilm)
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
		return createTemplate(ctx, es, name, templateVersion, settings, mapping, ilm)
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

	return createTemplate(ctx, es, name, templateVersion, settings, mapping, ilm)
}

func createTemplate(ctx context.Context, es *elasticsearch.Client, name string, templateVersion int, settings, mapping string, ilm bool) error {

	log.Info().Str("name", name).Msg("Create template")

	datastream := ""
	if ilm {
		datastream = `"data_stream": { },`
	}
	body := fmt.Sprintf(defaultTemplate, templateVersion, name, datastream, mapping, settings)

	res, err := es.Indices.PutIndexTemplate(name,
		strings.NewReader(body),
		es.Indices.PutIndexTemplate.WithContext(ctx),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	err = esutil.CheckResponseError(res)
	if err != nil {
		if errors.Is(err, esutil.ErrResourceAlreadyExists) {
			log.Info().Str("name", name).Msg("Index template already exists")
			return nil
		}
		return err
	}

	var r AckResponse
	err = json.NewDecoder(res.Body).Decode(&r)
	if err != nil {
		return fmt.Errorf("failed to parse put template response: %v version: %v, err: %v", name, templateVersion, err)
	}
	if !r.Acknowledged {
		return fmt.Errorf("failed to receive acknowledgment for put template request: %v version: %v", name, templateVersion)
	}

	return nil
}
