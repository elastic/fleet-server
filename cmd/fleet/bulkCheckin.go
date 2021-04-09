// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"

	"github.com/rs/zerolog/log"
)

type Fields map[string]interface{}

const kBulkCheckinFlushInterval = 10 * time.Second

type PendingData struct {
	fields Fields
	seqNo  sqn.SeqNo
}

type BulkCheckin struct {
	bulker  bulk.Bulk
	mut     sync.Mutex
	pending map[string]PendingData
}

func NewBulkCheckin(bulker bulk.Bulk) *BulkCheckin {
	return &BulkCheckin{
		bulker:  bulker,
		pending: make(map[string]PendingData),
	}
}

func (bc *BulkCheckin) CheckIn(id string, fields Fields, seqno sqn.SeqNo) error {

	if fields == nil {
		fields = make(Fields)
	}

	timeNow := time.Now().UTC().Format(time.RFC3339)
	fields[FieldLastCheckin] = timeNow

	bc.mut.Lock()
	bc.pending[id] = PendingData{fields, seqno}
	bc.mut.Unlock()
	return nil
}

func (bc *BulkCheckin) Run(ctx context.Context) error {

	tick := time.NewTicker(kBulkCheckinFlushInterval)

	var err error
LOOP:
	for {
		select {
		case <-tick.C:
			if err = bc.flush(ctx); err != nil {
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

func (bc *BulkCheckin) flush(ctx context.Context) error {
	start := time.Now()

	bc.mut.Lock()
	pending := bc.pending
	bc.pending = make(map[string]PendingData, len(pending))
	bc.mut.Unlock()

	if len(pending) == 0 {
		return nil
	}

	updates := make([]bulk.BulkOp, 0, len(pending))

	for id, pendingData := range pending {
		doc := pendingData.fields
		doc[dl.FieldUpdatedAt] = time.Now().UTC().Format(time.RFC3339)
		if pendingData.seqNo.IsSet() {
			doc[dl.FieldActionSeqNo] = pendingData.seqNo
		}

		source, err := json.Marshal(map[string]interface{}{
			"doc": doc,
		})

		if err != nil {
			return err
		}

		updates = append(updates, bulk.BulkOp{
			Id:    id,
			Body:  source,
			Index: dl.FleetAgents,
		})
	}

	err := bc.bulker.MUpdate(ctx, updates, bulk.WithRefresh())
	log.Trace().
		Err(err).
		Dur("rtt", time.Since(start)).
		Int("cnt", len(updates)).
		Msg("Flush updates")

	return err
}
