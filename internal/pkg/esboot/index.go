package esboot

import (
	"context"
	"encoding/json"
	"errors"
	"fleet/internal/pkg/esutil"
	"fmt"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog/log"
)

func CreateIndex(ctx context.Context, es *elasticsearch.Client, name string) error {
	res, err := es.Indices.Create(name,
		es.Indices.Create.WithContext(ctx),
	)

	if err != nil {
		return err
	}

	defer res.Body.Close()

	err = esutil.CheckResponseError(res)
	if err != nil {
		if errors.Is(err, esutil.ErrResourceAlreadyExists) {
			log.Info().Str("name", name).Msg("Index already exists")
			return nil
		}
		return err
	}

	var r AckResponse
	err = json.NewDecoder(res.Body).Decode(&r)
	if err != nil {
		return fmt.Errorf("failed to parse create index response: %v, err: %v", name, err)
	}
	if !r.Acknowledged {
		return fmt.Errorf("failed to receive acknowledgment for create index request: %v", name)
	}

	return nil
}
