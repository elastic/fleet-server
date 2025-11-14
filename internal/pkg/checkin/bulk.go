// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package checkin handles agent check ins.
package checkin

import (
	"context"
	_ "embed"
	"encoding/json"
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

// Option is the type for optional arguments for agent checkins.
type Option func(*checkinT)

func WithStatus(status string) Option {
	return func(state *checkinT) {
		state.status.isSet = true
		state.status.value = status
	}
}

func WithMessage(message string) Option {
	return func(state *checkinT) {
		state.message.isSet = true
		state.message.value = message
	}
}

func WithUnhealthyReason(reason *[]string) Option {
	return func(state *checkinT) {
		state.unhealthyReason.isSet = true
		state.unhealthyReason.value = reason
	}
}

func WithMeta(meta *json.RawMessage) Option {
	return func(state *checkinT) {
		state.meta.isSet = true
		state.meta.value = meta
	}
}

func WithSeqNo(seqno sqn.SeqNo) Option {
	return func(state *checkinT) {
		if !seqno.IsSet() {
			return
		}
		state.seqNo = seqno
	}
}

func WithVer(ver string) Option {
	return func(state *checkinT) {
		state.ver.isSet = true
		state.ver.value = ver
	}
}

func WithComponents(components *json.RawMessage) Option {
	return func(state *checkinT) {
		state.components.isSet = true
		state.components.value = components
	}
}

func WithDeleteAudit(del bool) Option {
	return func(state *checkinT) {
		if !del {
			return
		}
		state.deleteAudit = del
	}
}

func WithAgentPolicyID(id string) Option {
	return func(state *checkinT) {
		state.agentPolicyID.isSet = true
		state.agentPolicyID.value = id
	}
}

func WithPolicyRevisionIDX(idx int64) Option {
	return func(state *checkinT) {
		state.revisionIDX.isSet = true
		state.revisionIDX.value = idx
	}
}

func WithUpgradeDetails(details *json.RawMessage) Option {
	return func(state *checkinT) {
		state.upgradeDetails.isSet = true
		state.upgradeDetails.value = details
	}
}

func WithUpgradeStartedAt(startedAt *string) Option {
	return func(state *checkinT) {
		state.upgradeStartedAt.isSet = true
		state.upgradeStartedAt.value = startedAt
	}
}

func WithUpgradeStatus(status *string) Option {
	return func(state *checkinT) {
		state.upgradeStatus.isSet = true
		state.upgradeStatus.value = status
	}
}

func WithUpgradeAttempts(attempts *[]string) Option {
	return func(state *checkinT) {
		state.upgradeAttempts.isSet = true
		state.upgradeAttempts.value = attempts
	}
}

type setT[T any] struct {
	isSet bool
	value T
}

type checkinT struct {
	ts    string
	seqNo sqn.SeqNo

	ver             setT[string]
	status          setT[string]
	message         setT[string]
	unhealthyReason setT[*[]string]

	agentPolicyID setT[string]
	revisionIDX   setT[int64]

	meta       setT[*json.RawMessage]
	components setT[*json.RawMessage]

	upgradeDetails   setT[*json.RawMessage]
	upgradeStartedAt setT[*string]
	upgradeStatus    setT[*string]
	upgradeAttempts  setT[*[]string]

	deleteAudit bool
}

func (c *checkinT) toBody() ([]byte, error) {
	fields := bulk.UpdateFields{
		dl.FieldUpdatedAt:   c.ts,
		dl.FieldLastCheckin: c.ts,
	}
	if c.unhealthyReason.isSet {
		fields[dl.FieldUnhealthyReason] = c.unhealthyReason.value
	}
	if c.status.isSet {
		fields[dl.FieldLastCheckinStatus] = c.status.value
	}
	if c.message.isSet {
		fields[dl.FieldLastCheckinMessage] = c.message.value
	}
	if c.agentPolicyID.isSet {
		fields[dl.FieldAgentPolicyID] = c.agentPolicyID.value
	}
	if c.revisionIDX.isSet {
		fields[dl.FieldPolicyRevisionIdx] = c.revisionIDX.value
	}
	// If the agent version is not empty it needs to be updated
	// Assuming the agent can be upgraded keeping the same id, but incrementing the version
	if c.ver.isSet && c.ver.value != "" {
		fields[dl.FieldAgent] = map[string]interface{}{
			dl.FieldAgentVersion: c.ver,
		}
	}

	// Update local metadata if provided (and has a value)
	if c.meta.isSet {
		// Surprise: The json encoder compacts this raw JSON during
		// the encode process, so there my be unexpected memory overhead:
		// https://github.com/golang/go/blob/de5d7eccb99088e3ab42c0d907da6852d8f9cebe/src/encoding/json/encode.go#L503-L507
		fields[dl.FieldLocalMetadata] = c.meta.value
	}

	// Update components if provided (and has a value)
	if c.components.isSet {
		fields[dl.FieldComponents] = c.components.value
	}

	if c.upgradeDetails.isSet {
		fields[dl.FieldUpgradeDetails] = c.upgradeDetails.value
	}
	if c.upgradeStartedAt.isSet {
		fields[dl.FieldUpgradeStartedAt] = c.upgradeStartedAt.value
	}
	if c.upgradeStatus.isSet {
		fields[dl.FieldUpgradeStatus] = c.upgradeStatus.value
	}
	if c.upgradeAttempts.isSet {
		fields[dl.FieldUpgradeAttempts] = c.upgradeAttempts.value
	}

	// If seqNo changed, set the field appropriately
	if c.seqNo.IsSet() {
		fields[dl.FieldActionSeqNo] = c.seqNo
	}
	return fields.Marshal()
}

// Bulk handles checkins and keeps connected agents updated_at timestamp up-to-date.
type Bulk struct {
	opts      optionsT
	bulker    bulk.Bulk
	mut       sync.RWMutex
	connected map[string]struct{}
}

func NewBulk(bulker bulk.Bulk, opts ...Opt) *Bulk {
	parsedOpts := parseOpts(opts...)

	return &Bulk{
		opts:      parsedOpts,
		bulker:    bulker,
		connected: make(map[string]struct{}),
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

// Add adds the agent to the connected list.
func (bc *Bulk) Add(id string) {
	bc.mut.Lock()
	defer bc.mut.Unlock()
	bc.connected[id] = struct{}{}
}

// Remove removes the agent from the connected list.
func (bc *Bulk) Remove(id string) {
	bc.mut.Lock()
	defer bc.mut.Unlock()
	delete(bc.connected, id)
}

// CheckIn records that the agent has checked-in.
//
// This does not call `Add`, the caller should also call that to record that the agent is connected so that bulk
// can keep the documents `updated_at` fields updated.
// WARNING: CheckIn will take ownership of fields, so do not use after passing in.
func (bc *Bulk) CheckIn(ctx context.Context, id string, opts ...Option) error {
	now := time.Now().UTC().Format(time.RFC3339)
	checkin := checkinT{
		ts: now,
	}
	for _, opt := range opts {
		opt(&checkin)
	}

	// update the agent document
	body, err := checkin.toBody()
	if err != nil {
		return fmt.Errorf("could not marshall update body: %w", err)
	}
	bulkOpts := []bulk.Opt{bulk.WithRetryOnConflict(3)}
	if checkin.seqNo.IsSet() {
		bulkOpts = append(bulkOpts, bulk.WithRefresh())
	}
	err = bc.bulker.Update(ctx, dl.FleetAgents, id, body, bulkOpts...)
	if err != nil {
		return fmt.Errorf("failed to update document: %w", err)
	}

	// deleteAudit performs a second request (being that this should not happen very often
	// it's safer to only use this script when it is needed).
	if checkin.deleteAudit {
		action := &estypes.UpdateAction{
			Script: &estypes.Script{
				Lang:    &scriptlanguage.Painless,
				Source:  &deleteAuditAttributesScript,
				Options: map[string]string{},
			},
		}
		body, err = json.Marshal(&action)
		if err != nil {
			return fmt.Errorf("could not marshall script action: %w", err)
		}
		err = bc.bulker.Update(ctx, dl.FleetAgents, id, body, bulk.WithRetryOnConflict(3))
		if err != nil {
			return fmt.Errorf("failed to remove audit fields with script update: %w", err)
		}
	}

	return nil
}

// Run starts the flush timer and exit only when the context is cancelled.
func (bc *Bulk) Run(ctx context.Context) error {
	tick := time.NewTicker(bc.opts.flushInterval)
	defer tick.Stop()

	for {
		select {
		case <-tick.C:
			if err := bc.flushConnected(ctx); err != nil {
				zerolog.Ctx(ctx).Error().Err(err).Msg("Eat bulk checkin error; Keep on truckin'")
			}

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// flushConnected does an update that updates all the updated_at fields on all currently
// connected agents.
func (bc *Bulk) flushConnected(ctx context.Context) error {
	nowTimestamp := time.Now().UTC().Format(time.RFC3339)
	fields := bulk.UpdateFields{
		dl.FieldUpdatedAt: nowTimestamp,
	}
	body, err := fields.Marshal()
	if err != nil {
		return fmt.Errorf("marshal updated_at field error: %w", err)
	}
	bc.mut.RLock()
	updates := make([]bulk.MultiOp, 0, len(bc.connected))
	for id := range bc.connected {
		updates = append(updates, bulk.MultiOp{
			ID:    id,
			Body:  body,
			Index: dl.FleetAgents,
		})
	}
	bc.mut.RUnlock()
	_, err = bc.bulker.MUpdate(ctx, updates)
	if err != nil {
		return fmt.Errorf("mupdate error: %w", err)
	}
	return nil
}
