// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"encoding/json"
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
	"github.com/elastic/fleet-server/v7/internal/pkg/rollback"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"

	"github.com/gofrs/uuid"
	"github.com/hashicorp/go-version"
	"github.com/julienschmidt/httprouter"
	"github.com/miolini/datacounter"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	kEnrollMod = "enroll"

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
		Msg("Setting config enroll_limit")

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

	reqID := r.Header.Get(logger.HeaderRequestID)

	zlog := log.With().
		Str(ECSHTTPRequestID, reqID).
		Str("mod", kEnrollMod).
		Logger()

	// Error in the scope for deferred rolback function check
	var err error

	// Initialize rollback/cleanup for enrollment
	// This deletes all the artifacts that were created during enrollment
	rb := rollback.New(zlog)
	defer func() {
		if err != nil {
			zlog.Error().Err(err).Msg("perform rollback on enrollment failure")
			// Using the router context for the rollback
			err = rb.Rollback(rt.ctx)
			if err != nil {
				zlog.Error().Err(err).Msg("rollback error on enrollment failure")
			}
		}
	}()

	var resp *EnrollResponse
	resp, err = rt.et.handleEnroll(rb, &zlog, w, r)

	if err != nil {
		cntEnroll.IncError(err)
		resp := NewHTTPErrResp(err)

		zlog.WithLevel(resp.Level).
			Err(err).
			Int(ECSHTTPResponseCode, resp.StatusCode).
			Int64(ECSEventDuration, time.Since(start).Nanoseconds()).
			Msg("fail enroll")

		if rerr := resp.Write(w); rerr != nil {
			zlog.Error().Err(rerr).Msg("fail writing error response")
		}
		return
	}

	if err = writeResponse(zlog, w, resp, start); err != nil {
		cntEnroll.IncError(err)
		zlog.Error().
			Err(err).
			Int64(ECSEventDuration, time.Since(start).Nanoseconds()).
			Msg("fail write response")
	}
}

func (et *EnrollerT) handleEnroll(rb *rollback.Rollback, zlog *zerolog.Logger, w http.ResponseWriter, r *http.Request) (*EnrollResponse, error) {

	limitF, err := et.limit.Acquire()
	if err != nil {
		return nil, err
	}
	defer limitF()

	key, err := authAPIKey(r, et.bulker, et.cache)
	if err != nil {
		return nil, err
	}

	// Pointer is passed in to allow UpdateContext by child function
	zlog.UpdateContext(func(ctx zerolog.Context) zerolog.Context {
		return ctx.Str(LogEnrollAPIKeyID, key.Id)
	})

	ver, err := validateUserAgent(*zlog, r, et.verCon)
	if err != nil {
		return nil, err
	}

	// Metrics; serenity now.
	dfunc := cntEnroll.IncStart()
	defer dfunc()

	return et.processRequest(rb, *zlog, w, r, key.Id, ver)
}

func (et *EnrollerT) processRequest(rb *rollback.Rollback, zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, enrollmentAPIKeyID, ver string) (*EnrollResponse, error) {

	// Validate that an enrollment record exists for a key with this id.
	erec, err := et.fetchEnrollmentKeyRecord(r.Context(), enrollmentAPIKeyID)
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

	return et._enroll(r.Context(), rb, zlog, req, erec.PolicyID, ver)
}

func (et *EnrollerT) _enroll(ctx context.Context, rb *rollback.Rollback, zlog zerolog.Logger, req *EnrollRequest, policyID, ver string) (*EnrollResponse, error) {

	if req.SharedID != "" {
		// TODO: Support pre-existing install
		return nil, errors.New("preexisting install not yet supported")
	}

	now := time.Now()

	// Generate an ID here so we can pre-create the api key and avoid a round trip
	u, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	agentID := u.String()

	// Update the local metadata agent id
	localMeta, err := updateLocalMetaAgentID(req.Meta.Local, agentID)
	if err != nil {
		return nil, err
	}

	// Generate the Fleet Agent access api key
	accessAPIKey, err := generateAccessAPIKey(ctx, et.bulker, agentID)
	if err != nil {
		return nil, err
	}

	// Register invalidate API key function for enrollment error rollback
	rb.Register("invalidate API key", func(ctx context.Context) error {
		return invalidateAPIKey(ctx, zlog, et.bulker, accessAPIKey.Id)
	})

	agentData := model.Agent{
		Active:         true,
		PolicyID:       policyID,
		Type:           req.Type,
		EnrolledAt:     now.UTC().Format(time.RFC3339),
		LocalMetadata:  localMeta,
		AccessAPIKeyID: accessAPIKey.Id,
		ActionSeqNo:    []int64{sqn.UndefinedSeqNo},
		Agent: &model.AgentMetadata{
			ID:      agentID,
			Version: ver,
		},
	}

	err = createFleetAgent(ctx, et.bulker, agentID, agentData)
	if err != nil {
		return nil, err
	}

	// Register delete fleet agent for enrollment error rollback
	rb.Register("delete agent", func(ctx context.Context) error {
		return deleteAgent(ctx, zlog, et.bulker, agentID)
	})

	resp := EnrollResponse{
		Action: "created",
		Item: EnrollResponseItem{
			ID:             agentID,
			Active:         agentData.Active,
			PolicyID:       agentData.PolicyID,
			Type:           agentData.Type,
			EnrolledAt:     agentData.EnrolledAt,
			UserMeta:       agentData.UserProvidedMetadata,
			LocalMeta:      agentData.LocalMetadata,
			AccessAPIKeyID: agentData.AccessAPIKeyID,
			AccessAPIKey:   accessAPIKey.Token(),
			Status:         "online",
		},
	}

	// We are Kool & and the Gang; cache the access key to avoid the roundtrip on impending checkin
	et.cache.SetApiKey(*accessAPIKey, true)

	return &resp, nil
}

func deleteAgent(ctx context.Context, zlog zerolog.Logger, bulker bulk.Bulk, agentID string) error {
	zlog = zlog.With().Str(LogAgentID, agentID).Logger()

	if err := bulker.Delete(ctx, dl.FleetAgents, agentID); err != nil {
		zlog.Error().Err(err).Msg("agent record failed to delete")
		return err
	}
	zlog.Info().Msg("agent record deleted")
	return nil
}

func invalidateAPIKey(ctx context.Context, zlog zerolog.Logger, bulker bulk.Bulk, apikeyID string) error {

	// hack-a-rama:  We purposely do not force a "refresh:true" on the Apikey creation
	// because doing so causes the api call to slow down at scale.  It is already very slow.
	// So we have to wait for the key to become visible until we can invalidate it.

	zlog = zlog.With().Str(LogAPIKeyID, apikeyID).Logger()

	start := time.Now()

LOOP:
	for {

		_, err := bulker.ApiKeyRead(ctx, apikeyID)

		switch {
		case err == nil:
			break LOOP
		case !errors.Is(err, apikey.ErrApiKeyNotFound):
			zlog.Error().Err(err).Msg("Fail ApiKeyRead")
			return err
		case time.Since(start) > time.Minute:
			err := errors.New("Apikey index failed to refresh")
			zlog.Error().Err(err).Msg("Abort query attempt on apikey")
			return err
		}

		select {
		case <-ctx.Done():
			zlog.Error().
				Err(ctx.Err()).
				Str("apikeyId", apikeyID).
				Msg("Failed to invalidate apiKey on ctx done during hack sleep")
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}

	if err := bulker.ApiKeyInvalidate(ctx, apikeyID); err != nil {
		zlog.Error().Err(err).Msg("fail invalidate apiKey")
		return err
	}

	zlog.Info().Dur("dur", time.Since(start)).Msg("invalidated apiKey")
	return nil
}

func writeResponse(zlog zerolog.Logger, w http.ResponseWriter, resp *EnrollResponse, start time.Time) error {

	data, err := json.Marshal(resp)
	if err != nil {
		return errors.Wrap(err, "marshal enrollResponse")
	}

	numWritten, err := w.Write(data)
	cntEnroll.bodyOut.Add(uint64(numWritten))

	if err != nil {
		return errors.Wrap(err, "fail send enroll response")
	}

	zlog.Info().
		Str(LogAgentID, resp.Item.ID).
		Str(LogPolicyID, resp.Item.PolicyID).
		Str(LogAccessAPIKeyID, resp.Item.AccessAPIKeyID).
		Int(ECSHTTPResponseBodyBytes, numWritten).
		Int64(ECSEventDuration, time.Since(start).Nanoseconds()).
		Msg("Elastic Agent successfully enrolled")

	return nil
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
func updateLocalMetaAgentID(data []byte, agentID string) ([]byte, error) {
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
						sm["id"] = agentID
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

func generateAccessAPIKey(ctx context.Context, bulk bulk.Bulk, agentID string) (*apikey.ApiKey, error) {
	return bulk.ApiKeyCreate(
		ctx,
		agentID,
		"",
		[]byte(kFleetAccessRolesJSON),
		apikey.NewMetadata(agentID, apikey.TypeAccess),
	)
}

func (et *EnrollerT) fetchEnrollmentKeyRecord(ctx context.Context, id string) (*model.EnrollmentAPIKey, error) {

	if key, ok := et.cache.GetEnrollmentApiKey(id); ok {
		return &key, nil
	}

	// Pull API key record from .fleet-enrollment-api-keys
	rec, err := dl.FindEnrollmentAPIKey(ctx, et.bulker, dl.QueryEnrollmentAPIKeyByID, dl.FieldAPIKeyID, id)
	if err != nil {
		return nil, errors.Wrap(err, "FindEnrollmentAPIKey")
	}

	if !rec.Active {
		return nil, ErrInactiveEnrollmentKey
	}

	cost := int64(len(rec.APIKey))
	et.cache.SetEnrollmentApiKey(id, rec, cost)

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
