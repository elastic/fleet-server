// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"fleet/internal/pkg/apikey"
	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/config"
	"fleet/internal/pkg/dl"
	"fleet/internal/pkg/dsl"
	"fleet/internal/pkg/model"
	"fleet/internal/pkg/saved"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/gofrs/uuid"
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
	throttle               *semaphore.Weighted
	bulker                 bulk.Bulk
	queryTmplEnrollmentKey *dsl.Tmpl
}

func NewEnrollerT(cfg *config.Server, bulker bulk.Bulk) (*EnrollerT, error) {
	// This value has more to do with the throughput of elastic search than anything else
	// if you have a large elastic search cluster, you can be more aggressive.
	maxEnrollPending := cfg.MaxEnrollPending

	tmpl, err := dl.PrepareQueryAPIKeyByID()
	if err != nil {
		return nil, err
	}
	return &EnrollerT{
		throttle:               semaphore.NewWeighted(maxEnrollPending),
		bulker:                 bulker,
		queryTmplEnrollmentKey: tmpl,
	}, nil

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

	erec, err := et.fetchEnrollmentKeyRecord(r.Context(), key.Id)
	if err != nil {
		return nil, err
	}

	// Parse the request body
	req, err := decodeEnrollRequest(r.Body)
	if err != nil {
		return nil, err
	}

	resp, err := _enroll(r.Context(), sv, et.bulker, *req, *erec)
	if err != nil {
		return nil, err
	}

	return json.Marshal(resp)
}

func _enroll(ctx context.Context, sv saved.CRUD, bulker bulk.Bulk, req EnrollRequest, erec model.EnrollmentApiKey) (*EnrollResponse, error) {

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

	accessApiKey, err := generateAccessApiKey(ctx, bulker.Client(), agentId)
	if err != nil {
		return nil, err
	}

	defaultOutputApiKey, err := generateOutputApiKey(ctx, bulker.Client(), agentId, "default")
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

	// TODO: remove once kibana switched completely to the .fleet-agents
	// Leaving it here still, so it is a double save to both .kibana saved objects and .fleet-agents
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

	// Save agent in the .fleet-agents index as well
	// The saved object above will be transfered to .fleet-agent index in the future
	err = createFleetAgent(ctx, bulker, agentId, agentData)
	if err != nil {
		return nil, err
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

func createFleetAgent(ctx context.Context, bulker bulk.Bulk, id string, agent Agent) error {
	data, err := json.Marshal(agent)
	if err != nil {
		return err
	}

	_, err = bulker.Create(ctx, dl.FleetAgents, id, data, bulk.WithRefresh())
	if err != nil {
		return err
	}
	return nil
}

func generateAccessApiKey(ctx context.Context, client *elasticsearch.Client, agentId string) (*apikey.ApiKey, error) {
	return apikey.Create(ctx, client, agentId, "", []byte(kFleetAccessRolesJSON))
}

func generateOutputApiKey(ctx context.Context, client *elasticsearch.Client, agentId string, outputName string) (*apikey.ApiKey, error) {
	name := fmt.Sprintf("%s:%s", agentId, outputName)
	return apikey.Create(ctx, client, name, "", []byte(kFleetOutputRolesJSON))
}

func (et *EnrollerT) fetchEnrollmentKeyRecord(ctx context.Context, id string) (*model.EnrollmentApiKey, error) {

	if key, ok := gCache.GetEnrollmentApiKey(id); ok {
		return &key, nil
	}

	// Pull API key record from .fleet-enrollment-api-keys
	rec, err := dl.SearchEnrollmentAPIKey(ctx, et.bulker, et.queryTmplEnrollmentKey, id)
	if err != nil {
		return nil, err
	}

	if !rec.Active {
		return nil, fmt.Errorf("record is inactive")
	}

	cost := int64(len(rec.ApiKey))
	gCache.SetEnrollmentApiKey(id, rec, cost, kCacheEnrollmentTTL)

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
