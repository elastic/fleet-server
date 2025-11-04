// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package checkin handles agent check ins.
package checkin

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"

	"github.com/rs/zerolog"

	estypes "github.com/elastic/go-elasticsearch/v8/typedapi/types"
	"github.com/elastic/go-elasticsearch/v8/typedapi/types/enums/scriptlanguage"
)

const defaultFlushInterval = 10 * time.Second

//go:embed deleteAuditFieldsOnCheckin.painless
var deleteAuditAttributesScript string

type optionsT struct {
	flushInterval time.Duration
}

type Opt func(*optionsT)

func WithFlushInterval(d time.Duration) Opt {
	return func(opt *optionsT) {
		opt.flushInterval = d
	}
}

type extraT struct {
	meta        []byte
	seqNo       sqn.SeqNo
	ver         string
	components  []byte
	deleteAudit bool
}

// Minimize the size of this structure.
// There will be 10's of thousands of items
// in the map at any point.
type pendingT struct {
	ts              string
	status          string
	message         string
	extra           *extraT
	unhealthyReason *[]string
}

// Bulk will batch pending checkins and update elasticsearch at a set interval.
type Bulk struct {
	opts    optionsT
	bulker  bulk.Bulk
	mut     sync.Mutex
	pending map[string]pendingT

	ts   string
	unix int64
}

func NewBulk(bulker bulk.Bulk, opts ...Opt) *Bulk {
	parsedOpts := parseOpts(opts...)

	return &Bulk{
		opts:    parsedOpts,
		bulker:  bulker,
		pending: make(map[string]pendingT),
	}
}

func parseOpts(opts ...Opt) optionsT {

	outOpts := optionsT{
		flushInterval: defaultFlushInterval,
	}

	for _, f := range opts {
		f(&outOpts)
	}

	return outOpts
}

// Generate and cache timestamp on seconds change.
// Avoid thousands of formats of an identical string.
func (bc *Bulk) timestamp() string {

	// WARNING: Expects mutex locked.
	now := time.Now()
	if now.Unix() != bc.unix {
		bc.unix = now.Unix()
		bc.ts = now.UTC().Format(time.RFC3339)
	}

	return bc.ts
}

// CheckIn will add the agent (identified by id) to the pending set.
// The pending agents are sent to elasticsearch as a bulk update at each flush interval.
// NOTE: If Checkin is called after Run has returned it will just add the entry to the pending map and not do any operations, this may occur when the fleet-server is shutting down.
// WARNING: Bulk will take ownership of fields, so do not use after passing in.
func (bc *Bulk) CheckIn(id string, status string, message string, meta []byte, components []byte, seqno sqn.SeqNo, newVer string, unhealthyReason *[]string, deleteAudit bool) error {
	// Separate out the extra data to minimize
	// the memory footprint of the 90% case of just
	// updating the timestamp.
	var extra *extraT
	if meta != nil || seqno.IsSet() || newVer != "" || components != nil || deleteAudit {
		extra = &extraT{
			meta:        meta,
			seqNo:       seqno,
			ver:         newVer,
			components:  components,
			deleteAudit: deleteAudit,
		}
	}

	bc.mut.Lock()

	bc.pending[id] = pendingT{
		ts:              bc.timestamp(),
		status:          status,
		message:         message,
		extra:           extra,
		unhealthyReason: unhealthyReason,
	}

	bc.mut.Unlock()
	return nil
}

// Run starts the flush timer and exit only when the context is cancelled.
func (bc *Bulk) Run(ctx context.Context) error {
	tick := time.NewTicker(bc.opts.flushInterval)
	defer tick.Stop()

	for {
		select {
		case <-tick.C:
			if err := bc.flush(ctx); err != nil {
				zerolog.Ctx(ctx).Error().Err(err).Msg("Eat bulk checkin error; Keep on truckin'")
			}

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// flush sends the minium data needed to update records in elasticsearch.
func (bc *Bulk) flush(ctx context.Context) error {
	start := time.Now()

	bc.mut.Lock()
	pending := bc.pending
	bc.pending = make(map[string]pendingT, len(pending))
	bc.mut.Unlock()

	if len(pending) == 0 {
		return nil
	}

	updates := make([]bulk.MultiOp, 0, len(pending))

	simpleCache := make(map[pendingT][]byte)

	nowTimestamp := start.UTC().Format(time.RFC3339)

	var err error
	var needRefresh bool
	for id, pendingData := range pending {

		// In the simple case, there are no fields and no seqNo.
		// When that is true, we can reuse an already generated
		// JSON body containing just the timestamp updates.
		var body []byte
		if pendingData.extra == nil {
			var ok bool
			body, ok = simpleCache[pendingData]
			if !ok {
				fields := bulk.UpdateFields{
					dl.FieldLastCheckin:        pendingData.ts,
					dl.FieldUpdatedAt:          nowTimestamp,
					dl.FieldLastCheckinStatus:  pendingData.status,
					dl.FieldLastCheckinMessage: pendingData.message,
					dl.FieldUnhealthyReason:    pendingData.unhealthyReason,
				}
				if body, err = fields.Marshal(); err != nil {
					return err
				}
				simpleCache[pendingData] = body
			}
		} else if pendingData.extra.deleteAudit {
			// Use a script instead of a partial doc to update if attributes need to be removed
			params, err := encodeParams(nowTimestamp, pendingData)
			if err != nil {
				return err
			}
			action := &estypes.UpdateAction{
				Script: &estypes.Script{
					Lang:    &scriptlanguage.Painless,
					Source:  &deleteAuditAttributesScript,
					Options: map[string]string{},
					Params:  params,
				},
			}
			body, err = json.Marshal(&action)
			if err != nil {
				return fmt.Errorf("could not marshall script action: %w", err)
			}
			if pendingData.extra.seqNo.IsSet() {
				needRefresh = true
			}
		} else {
			fields := bulk.UpdateFields{
				dl.FieldLastCheckin:        pendingData.ts,      // Set the checkin timestamp
				dl.FieldUpdatedAt:          nowTimestamp,        // Set "updated_at" to the current timestamp
				dl.FieldLastCheckinStatus:  pendingData.status,  // Set the pending status
				dl.FieldLastCheckinMessage: pendingData.message, // Set the status message
				dl.FieldUnhealthyReason:    pendingData.unhealthyReason,
			}

			// If the agent version is not empty it needs to be updated
			// Assuming the agent can by upgraded keeping the same id, but incrementing the version
			if pendingData.extra.ver != "" {
				fields[dl.FieldAgent] = map[string]interface{}{
					dl.FieldAgentVersion: pendingData.extra.ver,
				}
			}

			// Update local metadata if provided
			if pendingData.extra.meta != nil {
				// Surprise: The json encodeer compacts this raw JSON during
				// the encode process, so there my be unexpected memory overhead:
				// https://github.com/golang/go/blob/go1.16.3/src/encoding/json/encode.go#L499
				fields[dl.FieldLocalMetadata] = json.RawMessage(pendingData.extra.meta)
			}

			// Update components if provided
			if pendingData.extra.components != nil {
				fields[dl.FieldComponents] = json.RawMessage(pendingData.extra.components)
			}

			// If seqNo changed, set the field appropriately
			if pendingData.extra.seqNo.IsSet() {
				fields[dl.FieldActionSeqNo] = pendingData.extra.seqNo

				// Only refresh if seqNo changed; dropping metadata not important.
				needRefresh = true
			}

			if body, err = fields.Marshal(); err != nil {
				return err
			}
		}

		updates = append(updates, bulk.MultiOp{
			ID:    id,
			Body:  body,
			Index: dl.FleetAgents,
		})
	}

	var opts []bulk.Opt
	if needRefresh {
		opts = append(opts, bulk.WithRefresh())
	}

	_, err = bc.bulker.MUpdate(ctx, updates, opts...)

	zerolog.Ctx(ctx).Trace().
		Err(err).
		Dur("rtt", time.Since(start)).
		Int("cnt", len(updates)).
		Bool("refresh", needRefresh).
		Msg("Flush updates")

	return err
}

func encodeParams(now string, data pendingT) (map[string]json.RawMessage, error) {
	var (
		tsNow      json.RawMessage
		ts         json.RawMessage
		status     json.RawMessage
		message    json.RawMessage
		reason     json.RawMessage
		ver        json.RawMessage
		meta       json.RawMessage
		components json.RawMessage
		isSet      json.RawMessage
		seqNo      json.RawMessage
		err        error
	)
	tsNow, err = json.Marshal(now)
	Err := errors.Join(err)
	ts, err = json.Marshal(data.ts)
	Err = errors.Join(Err, err)
	status, err = json.Marshal(data.status)
	Err = errors.Join(Err, err)
	message, err = json.Marshal(data.message)
	Err = errors.Join(Err, err)
	reason, err = json.Marshal(data.unhealthyReason)
	Err = errors.Join(Err, err)
	ver, err = json.Marshal(data.extra.ver)
	Err = errors.Join(Err, err)
	isSet, err = json.Marshal(data.extra.seqNo.IsSet())
	Err = errors.Join(Err, err)
	seqNo, err = json.Marshal(data.extra.seqNo)
	Err = errors.Join(Err, err)
	if data.extra.meta != nil {
		meta = data.extra.meta
	}
	if data.extra.components != nil {
		components = data.extra.components
	}
	if Err != nil {
		return nil, Err
	}
	return map[string]json.RawMessage{
		"Now":             tsNow,
		"TS":              ts,
		"Status":          status,
		"Message":         message,
		"UnhealthyReason": reason,
		"Ver":             ver,
		"Meta":            meta,
		"Components":      components,
		"SeqNoSet":        isSet,
		"SeqNo":           seqNo,
	}, nil
}
