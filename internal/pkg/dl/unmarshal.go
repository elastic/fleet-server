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
