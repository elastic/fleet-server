// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"sync"
	"time"

	"fleet/internal/pkg/saved"

	"github.com/rs/zerolog/log"
)

const kBulkCheckinFlushInterval = 10 * time.Second

type BulkCheckin struct {
	mut     sync.Mutex
	pending map[string]saved.Fields
}

func NewBulkCheckin() *BulkCheckin {
	return &BulkCheckin{
		pending: make(map[string]saved.Fields),
	}
}

func (bc *BulkCheckin) CheckIn(id string, fields saved.Fields) error {

	if fields == nil {
		fields = make(saved.Fields)
	}

	timeNow := time.Now().UTC().Format(time.RFC3339)
	fields[FieldLastCheckin] = timeNow

	bc.mut.Lock()
	bc.pending[id] = fields
	bc.mut.Unlock()
	return nil
}

func (bc *BulkCheckin) Run(ctx context.Context, sv saved.CRUD) error {

	tick := time.NewTicker(kBulkCheckinFlushInterval)

	var err error
LOOP:
	for {
		select {
		case <-tick.C:
			if err = bc.flush(ctx, sv); err != nil {
				log.Error().Err(err).Msg("Eat bulk checkin error; Keep on truckin'")
				err = nil
			}

		case <-ctx.Done():
			err = ctx.Err()
			break LOOP
		}
	}

	return err
}

func (bc *BulkCheckin) flush(ctx context.Context, sv saved.CRUD) error {
	start := time.Now()

	bc.mut.Lock()
	pending := bc.pending
	bc.pending = make(map[string]saved.Fields, len(pending))
	bc.mut.Unlock()

	if len(pending) == 0 {
		return nil
	}

	updates := make([]saved.UpdateT, 0, len(pending))
	for id, fields := range pending {
		updates = append(updates, saved.UpdateT{
			Id:     id,
			Type:   AGENT_SAVED_OBJECT_TYPE,
			Fields: fields,
		})
	}

	err := sv.MUpdate(ctx, updates)

	log.Debug().
		Err(err).
		Dur("rtt", time.Since(start)).
		Int("cnt", len(updates)).
		Msg("Flush checkin")

	return err
}
