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

func CreateDatastream(ctx context.Context, es *elasticsearch.Client, name string) error {
	res, err := es.Indices.CreateDataStream(name,
		es.Indices.CreateDataStream.WithContext(ctx),
	)

	if err != nil {
		return err
	}

	defer res.Body.Close()

	err = esutil.CheckResponseError(res)
	if err != nil {
		if errors.Is(err, esutil.ErrResourceAlreadyExists) {
			log.Info().Str("name", name).Msg("Datastream already exists")
			return nil
		}
		return err
	}

	var r AckResponse
	err = json.NewDecoder(res.Body).Decode(&r)
	if err != nil {
		return fmt.Errorf("failed to parse create datastream response: %v, err: %v", name, err)
	}
	if !r.Acknowledged {
		return fmt.Errorf("failed to receive acknowledgment for create datastream request: %v", name)
	}

	return nil
}
