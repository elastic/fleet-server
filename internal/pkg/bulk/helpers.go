// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"encoding/json"
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
