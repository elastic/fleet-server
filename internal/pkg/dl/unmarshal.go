// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"encoding/json"
	"fleet/internal/pkg/es"
	"fleet/internal/pkg/model"
)

func Unmarshal(hit es.HitT, v interface{}) error {
	err := json.Unmarshal(hit.Source, v)
	if err != nil {
		return err
	}
	if s, ok := v.(model.ESInitializer); ok {
		s.ESInitialize(hit.Id, hit.SeqNo, hit.Version)
	}
	return nil
}
