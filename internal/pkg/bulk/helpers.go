// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"encoding/json"
	"io/ioutil"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/go-elasticsearch/v7/esapi"
	"github.com/rs/zerolog/log"
)

type UpdateFields map[string]interface{}

func (u UpdateFields) Marshal() ([]byte, error) {
	doc := struct {
		Doc map[string]interface{} `json:"doc"`
	}{
		u,
	}

	return json.Marshal(doc)
}

// Attempt to interpret the response as an elastic error,
// otherwise return generic elastic error.
func parseError(res *esapi.Response) error {

	var e struct {
		Err *es.ErrorT `json:"error"`
	}

	decoder := json.NewDecoder(res.Body)

	if err := decoder.Decode(&e); err != nil {
		log.Error().Err(err).Msg("Cannot decode Elasticsearch error body")
		bodyBytes, readErr := ioutil.ReadAll(res.Body)
		if readErr != nil {
			log.Debug().Err(readErr).Msg("Error reading error response body from Elasticsearch")
		} else {
			log.Debug().Err(err).Bytes("body", bodyBytes).Msg("Error content")
		}

		return err
	}

	return es.TranslateError(res.StatusCode, e.Err)
}
