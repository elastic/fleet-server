// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"bytes"
	"context"
	"encoding/json"
	"math"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/rs/zerolog"
	"go.elastic.co/apm/v2"
)

const (
	envelopeSize = 64 // 64B
	safeBuffer   = 0.9
)

// The ApiKey API's are not yet bulk enabled. Stub the calls in the bulker
// and limit parallel access to prevent many requests from overloading
// the connection pool in the elastic search client.

type apiKeyUpdateRequest struct {
	ID        string          `json:"id,omitempty"`
	Roles     json.RawMessage `json:"role_descriptors,omitempty"`
	RolesHash string          `json:"role_hash,omitempty"`
}

type esAPIKeyBulkUpdateRequest struct {
	IDs   []string        `json:"ids,omitempty"`
	Roles json.RawMessage `json:"role_descriptors,omitempty"`
}

func (b *Bulker) APIKeyAuth(ctx context.Context, key APIKey) (*SecurityInfo, error) {
	span, ctx := apm.StartSpan(ctx, "authAPIKey", "auth")
	defer span.End()
	if err := b.apikeyLimit.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer b.apikeyLimit.Release(1)
	for _, pt := range b.opts.policyTokens {
		if pt.TokenKey == key.Key {
			return &SecurityInfo{Enabled: true}, nil
		}
	}
	return key.Authenticate(ctx, b.Client())
}

func (b *Bulker) APIKeyCreate(ctx context.Context, name, ttl string, roles []byte, meta interface{}) (*APIKey, error) {
	span, ctx := apm.StartSpan(ctx, "createAPIKey", "auth")
	defer span.End()
	if err := b.apikeyLimit.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer b.apikeyLimit.Release(1)

	return apikey.Create(ctx, b.Client(), name, ttl, "false", roles, meta)
}

func (b *Bulker) APIKeyRead(ctx context.Context, id string, withOwner bool) (*APIKeyMetadata, error) {
	span, ctx := apm.StartSpan(ctx, "readAPIKey", "auth")
	defer span.End()
	if err := b.apikeyLimit.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer b.apikeyLimit.Release(1)

	return apikey.Read(ctx, b.Client(), id, withOwner)
}

func (b *Bulker) APIKeyInvalidate(ctx context.Context, ids ...string) error {
	span, ctx := apm.StartSpan(ctx, "invalidateAPIKey", "auth")
	defer span.End()
	if err := b.apikeyLimit.Acquire(ctx, 1); err != nil {
		return err
	}
	defer b.apikeyLimit.Release(1)

	return apikey.Invalidate(ctx, b.Client(), ids...)
}

func (b *Bulker) APIKeyUpdate(ctx context.Context, id, outputPolicyHash string, roles []byte) error {
	span, ctx := apm.StartSpan(ctx, "updateAPIKey", "auth") // NOTE: this is tracked as updateAPIKey/auth instead of update_api_key/bulker to be consistent with other auth actions that don't use a queue.
	span.Context.SetLabel("api_key_id", id)
	defer span.End()
	req := &apiKeyUpdateRequest{
		ID:        id,
		Roles:     roles,
		RolesHash: outputPolicyHash,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	_, err = b.waitBulkAction(ctx, ActionUpdateAPIKey, "", id, body)
	return err
}

// flushUpdateAPIKey takes an update API Key queue and groups request based on roles applied
// It needs to group agent IDs per Role Hash in order to produce more efficient request containing a list of IDs for a change(update)
// One thing to have in mind is that in a single queue there may be change and ack request with roles. in this case
// Later occurrence wins overwriting policy change to reduced set of permissions.
// Even if the order was incorrect we end up with just a bit broader permission set, never too strict, so agent does not
// end up with fewer permissions than it needs
func (b *Bulker) flushUpdateAPIKey(ctx context.Context, queue queueT) error {
	idsPerRole := make(map[string][]string)
	roles := make(map[string]json.RawMessage)
	rolePerID := make(map[string]string)
	responses := make(map[int]int)
	idxToID := make(map[int32]string)
	IDToResponse := make(map[string]int)
	maxKeySize := 0
	links := []apm.SpanLink{}

	// merge ids
	for n := queue.head; n != nil; n = n.next {
		content := n.buf.Bytes()
		metaMap := make(map[string]interface{})
		dec := json.NewDecoder(bytes.NewReader(content))
		if err := dec.Decode(&metaMap); err != nil {
			zerolog.Ctx(ctx).Error().
				Err(err).
				Str("mod", kModBulk).
				Msg("Failed to unmarshal api key update meta map")
			return err
		}

		var req *apiKeyUpdateRequest
		if err := dec.Decode(&req); err != nil {
			zerolog.Ctx(ctx).Error().
				Err(err).
				Str("mod", kModBulk).
				Str("request", string(content)).
				Msg("Failed to unmarshal api key update request")
			return err
		}

		if _, tracked := roles[req.RolesHash]; !tracked {
			roles[req.RolesHash] = req.Roles
		}

		// last one wins, it may be policy change and ack are in the same queue
		rolePerID[req.ID] = req.RolesHash
		idxToID[n.idx] = req.ID
		if maxKeySize < len(req.ID) {
			maxKeySize = len(req.ID)
		}
		if n.spanLink != nil {
			links = append(links, *n.spanLink)
		}
	}

	if len(links) == 0 {
		links = nil
	}
	span, ctx := apm.StartSpanOptions(ctx, "Flush: apiKeyUpdate", "apiKeyUpdate", apm.SpanOptions{
		Links: links,
	})
	defer span.End()

	for id, roleHash := range rolePerID {
		delete(rolePerID, id)
		idsPerRole[roleHash] = append(idsPerRole[roleHash], id)

	}

	responseIdx := 0
	for hash, role := range roles {
		idsPerBatch := b.getIDsCountPerBatch(len(role), maxKeySize)
		ids := idsPerRole[hash]
		if idsPerBatch <= 0 {
			zerolog.Ctx(ctx).Error().Str("error.message", "request too large").Msg("No API Key ID could fit request size for bulk update")
			zerolog.Ctx(ctx).Debug().
				RawJSON("role", role).
				Strs("ids", ids).
				Msg("IDs could not fit into a message")

			// idsPerRole for specific role no longer needed
			delete(idsPerRole, hash)
			continue
		}

		batches := int(math.Ceil(float64(len(ids)) / float64(idsPerBatch)))

		// batch ids into batches of meaningful size
		for batch := 0; batch < batches; batch++ {
			// guard against indexing out of range
			to := (batch + 1) * idsPerBatch
			if to > len(ids) {
				to = len(ids)
			}

			// handle ids in batch, we put them into single request
			// and assign response index to the id so we can notify caller
			idsInBatch := ids[batch*idsPerBatch : to]
			bulkReq := &esAPIKeyBulkUpdateRequest{
				IDs:   idsInBatch,
				Roles: role,
			}
			delete(roles, hash)

			payload, err := json.Marshal(bulkReq)
			if err != nil {
				return err
			}

			req := &esapi.SecurityBulkUpdateAPIKeysRequest{
				Body: bytes.NewReader(payload),
			}

			res, err := req.Do(ctx, b.es)
			if err != nil {
				zerolog.Ctx(ctx).Error().Err(err).Msg("Error sending bulk API Key update request to Elasticsearch")
				return err
			}
			if res.Body != nil {
				defer res.Body.Close()
			}
			if res.IsError() {
				zerolog.Ctx(ctx).Error().Str("error.message", res.String()).Msg("Error in bulk API Key update result to Elasticsearch")
				return parseError(res, zerolog.Ctx(ctx))
			}

			zerolog.Ctx(ctx).Debug().Strs("IDs", bulkReq.IDs).RawJSON("role", role).Msg("API Keys updated.")

			responses[responseIdx] = res.StatusCode
			for _, id := range idsInBatch {
				IDToResponse[id] = responseIdx
			}
			responseIdx++
		}

		// idsPerRole for specific role no longer needed
		delete(idsPerRole, hash)
	}

	// WARNING: Once we start pushing items to
	// the queue, the node pointers are invalid.
	// Do NOT return a non-nil value or failQueue
	// up the stack will fail.

	for n := queue.head; n != nil; n = n.next {
		// 'n' is invalid immediately on channel send
		responseIdx := IDToResponse[idxToID[n.idx]]
		res := responses[responseIdx]
		select {
		case n.ch <- respT{
			err: nil,
			idx: n.idx,
			data: &BulkIndexerResponseItem{
				DocumentID: "",
				Status:     res,
			},
		}:
		default:
			panic("Unexpected blocked response channel on flushRead")
		}
	}
	return nil
}

func (b *Bulker) getIDsCountPerBatch(roleSize, maxKeySize int) int {
	spareSpace := b.opts.apikeyMaxReqSize - roleSize - envelopeSize
	if spareSpace > maxKeySize {
		return int(float64(spareSpace) * safeBuffer / float64(maxKeySize))
	}
	return 0
}
