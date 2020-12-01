// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"fleet/internal/pkg/config"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gofrs/uuid"

	"fleet/internal/pkg/apikey"
	"fleet/internal/pkg/saved"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"
)

const (
	kEnrollMod = "enroll"

	kCacheAccessInitTTL = time.Second * 30 // Cache a bit longer to handle expensive inital checkin
	kCacheEnrollmentTTL = time.Second * 30
)

var (
	ErrUnknownEnrollType = errors.New("unknown enroll request type")
	ErrServiceBusy       = errors.New("service busy")
	ErrAgentIdFailure    = errors.New("agent persist failure")
)

type EnrollerT struct {
	throttle *semaphore.Weighted
}

func NewEnrollerT(cfg *config.Server) *EnrollerT {
	// This value has more to do with the throughput of elastic search than anything else
	// if you have a large elastic search cluster, you can be more aggressive.
	maxEnrollPending := cfg.MaxEnrollPending

	return &EnrollerT{
		throttle: semaphore.NewWeighted(maxEnrollPending),
	}

}

func (rt Router) handleEnroll(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	start := time.Now()

	// Work around wonky router rule
	if ps.ByName("id") != "enroll" {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	data, err := rt.et.handleEnroll(r, rt.sv)

	if err != nil {
		code := http.StatusBadRequest
		if err == ErrServiceBusy {
			code = http.StatusServiceUnavailable
		}

		// Don't log connection drops
		if err != context.Canceled {
			log.Error().
				Str("mod", kEnrollMod).
				Int("code", code).
				Err(err).Dur("tdiff", time.Since(start)).
				Msg("Enroll fail")
		}

		http.Error(w, err.Error(), code)
		return
	}

	if _, err = w.Write(data); err != nil {
		log.Error().Err(err).Msg("Fail send enroll response")
	}

	log.Trace().
		Err(err).
		RawJSON("raw", data).
		Str("mod", kEnrollMod).
		Dur("rtt", time.Since(start)).
		Msg("handleEnroll OK")
}

func (et *EnrollerT) acquireSemaphore(ctx context.Context) error {
	start := time.Now()

	// Wait a reasonable amount of time, but if busy for N seconds; ask to come back later.
	acquireCtx, cancelF := context.WithTimeout(ctx, time.Second*10)
	defer cancelF()

	if err := et.throttle.Acquire(acquireCtx, 1); err != nil {
		return ErrServiceBusy
	}

	log.Trace().
		Str("mod", kEnrollMod).
		Dur("tdiff", time.Since(start)).
		Msg("Enroll acquire")

	return nil
}

func (et *EnrollerT) handleEnroll(r *http.Request, sv saved.CRUD) ([]byte, error) {

	if err := et.acquireSemaphore(r.Context()); err != nil {
		return nil, err
	}

	defer et.throttle.Release(1)

	key, err := authApiKey(r, sv.Client())
	if err != nil {
		return nil, err
	}

	erec, err := fetchEnrollmentKeyRecord(r.Context(), key.Id, sv)
	if err != nil {
		return nil, err
	}

	// Parse the request body
	req, err := decodeEnrollRequest(r.Body)
	if err != nil {
		return nil, err
	}

	resp, err := _enroll(r.Context(), sv, *req, *erec)
	if err != nil {
		return nil, err
	}

	return json.Marshal(resp)
}

func _enroll(ctx context.Context, sv saved.CRUD, req EnrollRequest, erec EnrollmentApiKey) (*EnrollResponse, error) {

	if req.SharedId != "" {
		// TODO: Support pre-existing install
		return nil, errors.New("preexisting install not yet supported")
	}

	now := time.Now()
	nowStr := now.UTC().Format(time.RFC3339)

	// Generate an ID here so we can pre-create the api key and avoid a round trip
	u, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	// TODO: Cleanup after ourselves on failure:
	// Revoke generated keys.
	// Remove agent record.

	agentId := u.String()

	accessApiKey, err := generateAccessApiKey(ctx, sv.Client(), agentId)
	if err != nil {
		return nil, err
	}

	defaultOutputApiKey, err := generateOutputApiKey(ctx, sv.Client(), agentId, "default")
	if err != nil {
		return nil, err
	}

	log.Debug().
		Dur("rtt", time.Since(now)).
		Str("agentId", agentId).
		Str("accessApiKey.Id", accessApiKey.Id).
		Str("defaultOutputApiKey.Id", defaultOutputApiKey.Id).
		Msg("Created api key")

	agentData := Agent{
		Active:          true,
		PolicyId:        erec.PolicyId,
		Type:            req.Type,
		EnrolledAt:      nowStr,
		UserMeta:        req.Meta.User,
		LocalMeta:       req.Meta.Local,
		AccessApiKeyId:  accessApiKey.Id,
		DefaultApiKeyId: defaultOutputApiKey.Id,
		DefaultApiKey:   defaultOutputApiKey.Token(),
	}

	id, err := sv.Create(
		ctx,
		AGENT_SAVED_OBJECT_TYPE,
		agentData,
		saved.WithId(agentId),
		saved.WithRefresh(),
	)
	if err != nil {
		return nil, err
	}
	if id != fmt.Sprintf("%s:%s", AGENT_SAVED_OBJECT_TYPE, agentId) {
		return nil, ErrAgentIdFailure
	}

	resp := EnrollResponse{
		Action: "created",
		Item: EnrollResponseItem{
			ID:             agentId,
			Active:         agentData.Active,
			PolicyId:       agentData.PolicyId,
			Type:           agentData.Type,
			EnrolledAt:     agentData.EnrolledAt,
			UserMeta:       agentData.UserMeta,
			LocalMeta:      agentData.LocalMeta,
			AccessApiKeyId: agentData.AccessApiKeyId,
			AccessAPIKey:   accessApiKey.Token(),
			Status:         "online",
		},
	}

	// We are Kool & and the Gang; cache the access key to avoid the roundtrip on impending checkin
	gCache.SetApiKey(*accessApiKey, kCacheAccessInitTTL)

	return &resp, nil
}

func generateAccessApiKey(ctx context.Context, client *elasticsearch.Client, agentId string) (*apikey.ApiKey, error) {
	return apikey.Create(ctx, client, agentId, "", []byte(kFleetAccessRolesJSON))
}

func generateOutputApiKey(ctx context.Context, client *elasticsearch.Client, agentId string, outputName string) (*apikey.ApiKey, error) {
	name := fmt.Sprintf("%s:%s", agentId, outputName)
	return apikey.Create(ctx, client, name, "", []byte(kFleetOutputRolesJSON))
}

func fetchEnrollmentKeyRecord(ctx context.Context, id string, sv saved.CRUD) (*EnrollmentApiKey, error) {

	if key, ok := gCache.GetEnrollmentApiKey(id); ok {
		return &key, nil
	}

	fields := map[string]interface{}{
		"api_key_id": id,
	}

	// Pull API key record from saved objects
	hits, err := sv.FindByField(ctx, ENROLLMENT_API_KEYS_SAVED_OBJECT_TYPE, fields)
	if err != nil {
		return nil, err
	}

	// Expect only one hit
	if len(hits) != 1 {
		return nil, fmt.Errorf("hit count mismatch %v", len(hits))
	}

	hit := hits[0]

	var rec EnrollmentApiKey
	if err := sv.Decode(hit, &rec); err != nil {
		return nil, err
	}

	if !rec.Active {
		return nil, fmt.Errorf("Record is inactive")
	} else {
		cost := int64(len(hit.Data))
		gCache.SetEnrollmentApiKey(id, rec, cost, kCacheEnrollmentTTL)
	}

	return &rec, nil
}

func decodeEnrollRequest(data io.Reader) (*EnrollRequest, error) {

	// TODO: defend overflow, slow roll
	var req EnrollRequest
	decoder := json.NewDecoder(data)
	if err := decoder.Decode(&req); err != nil {
		return nil, err
	}

	// Validate
	switch req.Type {
	case "EPHEMERAL", "PERMANENT", "TEMPORARY":
	default:
		return nil, ErrUnknownEnrollType
	}

	return &req, nil
}
