// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/gofrs/uuid"
	"github.com/hashicorp/go-version"
	"github.com/julienschmidt/httprouter"
	"github.com/miolini/datacounter"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

const (
	kEnrollMod = "enroll"

	kCacheAccessInitTTL = time.Second * 30 // Cache a bit longer to handle expensive initial checkin
	kCacheEnrollmentTTL = time.Second * 30

	EnrollEphemeral = "EPHEMERAL"
	EnrollPermanent = "PERMANENT"
	EnrollTemporary = "TEMPORARY"
)

var (
	ErrUnknownEnrollType     = errors.New("unknown enroll request type")
	ErrInactiveEnrollmentKey = errors.New("inactive enrollment key")
)

type EnrollerT struct {
	verCon version.Constraints
	cfg    *config.Server
	bulker bulk.Bulk
	cache  cache.Cache
	limit  *limit.Limiter
}

func NewEnrollerT(verCon version.Constraints, cfg *config.Server, bulker bulk.Bulk, c cache.Cache) (*EnrollerT, error) {

	log.Info().
		Interface("limits", cfg.Limits.EnrollLimit).
		Msg("Enroller install limits")

	return &EnrollerT{
		verCon: verCon,
		cfg:    cfg,
		limit:  limit.NewLimiter(&cfg.Limits.EnrollLimit),
		bulker: bulker,
		cache:  c,
	}, nil

}

func (rt Router) handleEnroll(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	start := time.Now()

	// Work around wonky router rule
	if ps.ByName("id") != "enroll" {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	enrollResponse, err := rt.et.handleEnroll(w, r)

	var data []byte
	if err == nil {
		data, err = json.Marshal(enrollResponse)
	}

	reqId := r.Header.Get(logger.HeaderRequestID)

	if err != nil {
		cntEnroll.IncError(err)
		resp := NewErrorResp(err)

		log.WithLevel(resp.Level).
			Err(err).
			Str(EcsHttpRequestId, reqId).
			Str("mod", kEnrollMod).
			Int(EcsHttpResponseCode, resp.StatusCode).
			Int64(EcsEventDuration, time.Since(start).Nanoseconds()).
			Msg("fail enroll")

		if err := resp.Write(w); err != nil {
			log.Error().Err(err).Str(EcsHttpRequestId, reqId).Msg("fail writing error response")
		}
		return
	}

	var numWritten int
	if numWritten, err = w.Write(data); err != nil {
		log.Error().Err(err).Str(EcsHttpRequestId, reqId).Msg("fail send enroll response")
	}

	cntEnroll.bodyOut.Add(uint64(numWritten))

	log.Info().
		Err(err).
		Str("mod", kEnrollMod).
		Str("agentId", enrollResponse.Item.ID).
		Str("policyId", enrollResponse.Item.PolicyId).
		Str("apiKeyId", enrollResponse.Item.AccessApiKeyId).
		Str(EcsHttpRequestId, reqId).
		Int(EcsHttpResponseBodyBytes, numWritten).
		Int64(EcsEventDuration, time.Since(start).Nanoseconds()).
		Msg("success enroll")
}

func (et *EnrollerT) handleEnroll(w http.ResponseWriter, r *http.Request) (*EnrollResponse, error) {

	limitF, err := et.limit.Acquire()
	if err != nil {
		return nil, err
	}
	defer limitF()

	key, err := authApiKey(r, et.bulker, et.cache)
	if err != nil {
		return nil, err
	}

	err = validateUserAgent(r, et.verCon)
	if err != nil {
		return nil, err
	}

	// Metrics; serenity now.
	dfunc := cntEnroll.IncStart()
	defer dfunc()

	// Validate that an enrollment record exists for a key with this id.
	erec, err := et.fetchEnrollmentKeyRecord(r.Context(), key.Id)
	if err != nil {
		return nil, err
	}

	body := r.Body

	// Limit the size of the body to prevent malicious agent from exhausting RAM in server
	if et.cfg.Limits.EnrollLimit.MaxBody > 0 {
		body = http.MaxBytesReader(w, body, et.cfg.Limits.EnrollLimit.MaxBody)
	}

	readCounter := datacounter.NewReaderCounter(body)

	// Parse the request body
	req, err := decodeEnrollRequest(readCounter)
	if err != nil {
		return nil, err
	}

	cntEnroll.bodyIn.Add(readCounter.Count())

	return _enroll(r.Context(), et.bulker, et.cache, *req, *erec)
}

func _enroll(ctx context.Context, bulker bulk.Bulk, c cache.Cache, req EnrollRequest, erec model.EnrollmentApiKey) (*EnrollResponse, error) {

	if req.SharedId != "" {
		// TODO: Support pre-existing install
		return nil, errors.New("preexisting install not yet supported")
	}

	now := time.Now()

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

	// Update the local metadata agent id
	localMeta, err := updateLocalMetaAgentId(req.Meta.Local, agentId)
	if err != nil {
		return nil, err
	}

	agentData := model.Agent{
		Active:         true,
		PolicyId:       erec.PolicyId,
		Type:           req.Type,
		EnrolledAt:     now.UTC().Format(time.RFC3339),
		LocalMetadata:  localMeta,
		AccessApiKeyId: accessApiKey.Id,
		ActionSeqNo:    []int64{sqn.UndefinedSeqNo},
	}

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
			UserMeta:       agentData.UserProvidedMetadata,
			LocalMeta:      agentData.LocalMetadata,
			AccessApiKeyId: agentData.AccessApiKeyId,
			AccessAPIKey:   accessApiKey.Token(),
			Status:         "online",
		},
	}

	// We are Kool & and the Gang; cache the access key to avoid the roundtrip on impending checkin
	c.SetApiKey(*accessApiKey, kCacheAccessInitTTL)

	return &resp, nil
}

// updateMetaLocalAgentId updates the agent id in the local metadata if exists
// At the time of writing the local metadata blob looks something like this
// {
//     "elastic": {
//         "agent": {
//             "id": "1b9c327a-c93a-4aef-b67f-effbef54d836",
//             "version": "8.0.0",
//             "snapshot": false,
//             "upgradeable": false
//         }
//     },
//     "host": {
//         "architecture": "x86_64",
//         "hostname": "eh-Hounddiamond",
//         "name": "eh-Hounddiamond",
//         "id": "1b9c327a-c93a-4aef-b67f-effbef54d836"
//     },
//     "os": {
//         "family": "darwin",
//         "kernel": "19.6.0",
//         "platform": "darwin",
//         "version": "10.15.7",
//         "name": "Mac OS X",
//         "full": "Mac OS X(10.15.7)"
//     }
// }
func updateLocalMetaAgentId(data []byte, agentId string) ([]byte, error) {
	if data == nil {
		return data, nil
	}

	var m map[string]interface{}
	err := json.Unmarshal(data, &m)
	if err != nil {
		return nil, err
	}

	if v, ok := m["elastic"]; ok {
		if sm, ok := v.(map[string]interface{}); ok {
			if v, ok = sm["agent"]; ok {
				if sm, ok = v.(map[string]interface{}); ok {
					if _, ok = sm["id"]; ok {
						sm["id"] = agentId
						data, err = json.Marshal(m)
						if err != nil {
							return nil, err
						}
					}
				}
			}
		}
	}

	return data, nil
}

func createFleetAgent(ctx context.Context, bulker bulk.Bulk, id string, agent model.Agent) error {
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
	return apikey.Create(ctx, client, agentId, "", []byte(kFleetAccessRolesJSON),
		apikey.NewMetadata(agentId, apikey.TypeAccess))
}

func generateOutputApiKey(ctx context.Context, client *elasticsearch.Client, agentId, outputName string, roles []byte) (*apikey.ApiKey, error) {
	name := fmt.Sprintf("%s:%s", agentId, outputName)
	return apikey.Create(ctx, client, name, "", roles,
		apikey.NewMetadata(agentId, apikey.TypeOutput))
}

func (et *EnrollerT) fetchEnrollmentKeyRecord(ctx context.Context, id string) (*model.EnrollmentApiKey, error) {

	if key, ok := et.cache.GetEnrollmentApiKey(id); ok {
		return &key, nil
	}

	// Pull API key record from .fleet-enrollment-api-keys
	rec, err := dl.FindEnrollmentAPIKey(ctx, et.bulker, dl.QueryEnrollmentAPIKeyByID, dl.FieldApiKeyID, id)
	if err != nil {
		return nil, errors.Wrap(err, "FindEnrollmentAPIKey")
	}

	if !rec.Active {
		return nil, ErrInactiveEnrollmentKey
	}

	cost := int64(len(rec.ApiKey))
	et.cache.SetEnrollmentApiKey(id, rec, cost, kCacheEnrollmentTTL)

	return &rec, nil
}

func decodeEnrollRequest(data io.Reader) (*EnrollRequest, error) {

	var req EnrollRequest
	decoder := json.NewDecoder(data)
	if err := decoder.Decode(&req); err != nil {
		return nil, errors.Wrap(err, "decode enroll request")
	}

	// Validate
	switch req.Type {
	case EnrollEphemeral, EnrollPermanent, EnrollTemporary:
	default:
		return nil, ErrUnknownEnrollType
	}

	return &req, nil
}
