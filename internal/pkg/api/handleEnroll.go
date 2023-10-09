// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/elastic/elastic-agent-libs/str"
	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/rollback"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"
	"go.elastic.co/apm/v2"

	"github.com/gofrs/uuid"
	"github.com/hashicorp/go-version"
	"github.com/miolini/datacounter"
	"github.com/rs/zerolog"
)

const (
	kEnrollMod = "enroll"

	EnrollEphemeral = "EPHEMERAL"
	EnrollPermanent = "PERMANENT"
	EnrollTemporary = "TEMPORARY"
)

const kFleetAccessRolesJSON = `
{
	"fleet-apikey-access": {
		"cluster": [],
		"applications": [{
			"application": "fleet",
			"privileges": ["no-privileges"],
			"resources": ["*"]
		}]
	}
}
`

var (
	ErrUnknownEnrollType     = errors.New("unknown enroll request type")
	ErrInactiveEnrollmentKey = errors.New("inactive enrollment key")
	ErrPolicyNotFound        = errors.New("policy not found")
)

type EnrollerT struct {
	verCon version.Constraints
	cfg    *config.Server
	bulker bulk.Bulk
	cache  cache.Cache
}

func NewEnrollerT(verCon version.Constraints, cfg *config.Server, bulker bulk.Bulk, c cache.Cache) (*EnrollerT, error) {
	return &EnrollerT{
		verCon: verCon,
		cfg:    cfg,
		bulker: bulker,
		cache:  c,
	}, nil
}

func (et *EnrollerT) handleEnroll(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, rb *rollback.Rollback, userAgent string) error {
	key, err := authAPIKey(r, et.bulker, et.cache)
	if err != nil {
		return err
	}
	zlog = zlog.With().Str(LogEnrollAPIKeyID, key.ID).Logger()
	ctx := zlog.WithContext(r.Context())
	r = r.WithContext(ctx)

	ver, err := validateUserAgent(r.Context(), zlog, userAgent, et.verCon)
	if err != nil {
		return err
	}

	resp, err := et.processRequest(zlog, w, r, rb, key, ver)
	if err != nil {
		return err
	}

	ts, _ := logger.CtxStartTime(r.Context())
	return writeResponse(r.Context(), zlog, w, resp, ts)
}

func (et *EnrollerT) processRequest(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, rb *rollback.Rollback, enrollmentAPIKey *apikey.APIKey, ver string) (*EnrollResponse, error) {
	// Validate that an enrollment record exists for a key with this id.
	var enrollAPI *model.EnrollmentAPIKey
	enrollAPI, err := et.retrieveStaticTokenEnrollmentToken(r.Context(), zlog, enrollmentAPIKey)
	if err != nil {
		return nil, err
	}

	if enrollAPI == nil {
		zlog.Debug().Msgf("Checking enrollment key from database %s", enrollmentAPIKey.ID)
		key, err := et.fetchEnrollmentKeyRecord(r.Context(), enrollmentAPIKey.ID)
		if err != nil {
			return nil, err
		}
		zlog.Debug().Msgf("Found enrollment key %s", key.APIKeyID)
		enrollAPI = key
	}
	body := r.Body

	// Limit the size of the body to prevent malicious agent from exhausting RAM in server
	if et.cfg.Limits.EnrollLimit.MaxBody > 0 {
		body = http.MaxBytesReader(w, body, et.cfg.Limits.EnrollLimit.MaxBody)
	}

	readCounter := datacounter.NewReaderCounter(body)

	// Parse the request body
	req, err := validateRequest(r.Context(), readCounter)
	if err != nil {
		return nil, err
	}

	cntEnroll.bodyIn.Add(readCounter.Count())

	return et._enroll(r.Context(), rb, zlog, req, enrollAPI.PolicyID, ver)
}

// retrieveStaticTokenEnrollmentToken fetches the enrollment key record from the config static tokens.
// If the static policy token feature was not enabled, nothing is returns (nil, nil)
// otherwise either an error or the enrollment key record is returned.
func (et *EnrollerT) retrieveStaticTokenEnrollmentToken(ctx context.Context, zlog zerolog.Logger, enrollmentAPIKey *apikey.APIKey) (*model.EnrollmentAPIKey, error) {
	span, ctx := apm.StartSpan(ctx, "staticTokenCheck", "auth")
	defer span.End()
	if !et.cfg.StaticPolicyTokens.Enabled {
		return nil, nil
	}

	zlog.Debug().Msgf("Checking static enrollment token %s", enrollmentAPIKey.ID)
	for _, pt := range et.cfg.StaticPolicyTokens.PolicyTokens {
		if pt.TokenKey != enrollmentAPIKey.Key {
			continue
		}

		p, err := et.fetchPolicy(ctx, pt.PolicyID)
		if err != nil {
			return nil, err
		}

		return &model.EnrollmentAPIKey{
			PolicyID: p.PolicyID,
			APIKey:   pt.TokenKey,
			Active:   true,
		}, nil

	}
	// no error, just not found
	return nil, nil
}

func (et *EnrollerT) fetchPolicy(ctx context.Context, policyID string) (model.Policy, error) {
	policies, err := dl.QueryLatestPolicies(ctx, et.bulker)
	if err != nil {
		return model.Policy{}, err
	}

	var policy model.Policy
	for _, p := range policies {
		if p.PolicyID == policyID {
			policy = p
		}
	}
	if policy.PolicyID != policyID {
		return model.Policy{}, ErrPolicyNotFound
	}
	return policy, nil
}

func (et *EnrollerT) _enroll(
	ctx context.Context,
	rb *rollback.Rollback,
	zlog zerolog.Logger,
	req *EnrollRequest,
	policyID,
	ver string,
) (*EnrollResponse, error) {
	var agent model.Agent
	var enrollmentID string

	span, ctx := apm.StartSpan(ctx, "enroll", "process")
	defer span.End()

	if req.EnrollmentId != nil {
		vSpan, vCtx := apm.StartSpan(ctx, "checkEnrollmentID", "validate")
		enrollmentID = *req.EnrollmentId
		var err error
		agent, err = dl.FindAgent(vCtx, et.bulker, dl.QueryAgentByEnrollmentID, dl.FieldEnrollmentID, enrollmentID)
		if err != nil {
			zlog.Debug().Err(err).
				Str("EnrollmentId", enrollmentID).
				Msg("Agent with EnrollmentId not found")
			if !errors.Is(err, dl.ErrNotFound) && !strings.Contains(err.Error(), "no such index") {
				vSpan.End()
				return nil, err
			}
		}
		vSpan.End()
	}
	now := time.Now()

	// Generate an ID here so we can pre-create the api key and avoid a round trip
	u, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	agentID := u.String()
	// only delete existing agent if it never checked in
	if agent.Id != "" && agent.LastCheckin == "" {
		zlog.Debug().
			Str("EnrollmentId", enrollmentID).
			Str("AgentId", agent.Id).
			Str("APIKeyID", agent.AccessAPIKeyID).
			Msg("Invalidate old api key and remove existing agent with the same enrollment_id")
		// invalidate previous api key
		err := invalidateAPIKey(ctx, zlog, et.bulker, agent.AccessAPIKeyID)
		if err != nil {
			zlog.Error().Err(err).
				Str("EnrollmentId", enrollmentID).
				Str("AgentId", agent.Id).
				Str("APIKeyID", agent.AccessAPIKeyID).
				Msg("Error when trying to invalidate API key of old agent with enrollment id")
			return nil, err
		}
		// delete existing agent to recreate with new api key
		err = deleteAgent(ctx, zlog, et.bulker, agent.Id)
		if err != nil {
			zlog.Error().Err(err).
				Str("EnrollmentId", enrollmentID).
				Str("AgentId", agent.Id).
				Msg("Error when trying to delete old agent with enrollment id")
			return nil, err
		}
	}

	// Update the local metadata agent id
	localMeta, err := updateLocalMetaAgentID(req.Metadata.Local, agentID)
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
		return invalidateAPIKey(ctx, zlog, et.bulker, accessAPIKey.ID)
	})

	agentData := model.Agent{
		Active:         true,
		PolicyID:       policyID,
		Type:           string(req.Type),
		EnrolledAt:     now.UTC().Format(time.RFC3339),
		LocalMetadata:  localMeta,
		AccessAPIKeyID: accessAPIKey.ID,
		ActionSeqNo:    []int64{sqn.UndefinedSeqNo},
		Agent: &model.AgentMetadata{
			ID:      agentID,
			Version: ver,
		},
		Tags:         removeDuplicateStr(req.Metadata.Tags),
		EnrollmentID: enrollmentID,
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
			AccessApiKey:         accessAPIKey.Token(),
			AccessApiKeyId:       agentData.AccessAPIKeyID,
			Active:               agentData.Active,
			EnrolledAt:           agentData.EnrolledAt,
			Id:                   agentID,
			LocalMetadata:        agentData.LocalMetadata,
			PolicyId:             agentData.PolicyID,
			Status:               "online",
			Tags:                 agentData.Tags,
			Type:                 agentData.Type,
			UserProvidedMetadata: agentData.UserProvidedMetadata,
		},
	}

	// We are Kool & and the Gang; cache the access key to avoid the roundtrip on impending checkin
	et.cache.SetAPIKey(*accessAPIKey, true)

	return &resp, nil
}

// Helper function to remove duplicate agent tags.
// Note that this implementation will also sort the tags alphabetically.
func removeDuplicateStr(strSlice []string) []string {
	return str.MakeSet(strSlice...).ToSlice()
}

func deleteAgent(ctx context.Context, zlog zerolog.Logger, bulker bulk.Bulk, agentID string) error {
	span, ctx := apm.StartSpan(ctx, "deleteAgent", "delete")
	span.Context.SetLabel("agent_id", agentID)
	defer span.End()
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
	// because doing so causes the api call to slow down at scale. It is already very slow.
	// So we have to wait for the key to become visible until we can invalidate it.
	zlog = zlog.With().Str(LogAPIKeyID, apikeyID).Logger()

	start := time.Now()

LOOP:
	for {

		_, err := bulker.APIKeyRead(ctx, apikeyID, true)

		switch {
		case err == nil:
			break LOOP
		case !errors.Is(err, apikey.ErrAPIKeyNotFound):
			zlog.Error().Err(err).Msg("Fail ApiKeyRead")
			return err
		case time.Since(start) > time.Minute:
			err := errors.New("apikey index failed to refresh")
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

	if err := bulker.APIKeyInvalidate(ctx, apikeyID); err != nil {
		zlog.Error().Err(err).Msg("fail invalidate apiKey")
		return err
	}

	zlog.Info().Dur("dur", time.Since(start)).Msg("invalidated apiKey")
	return nil
}

func writeResponse(ctx context.Context, zlog zerolog.Logger, w http.ResponseWriter, resp *EnrollResponse, start time.Time) error {
	span, _ := apm.StartSpan(ctx, "response", "write")
	defer span.End()

	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal enrollResponse: %w", err)
	}

	numWritten, err := w.Write(data)
	cntEnroll.bodyOut.Add(uint64(numWritten))

	if err != nil {
		return fmt.Errorf("fail send enroll response: %w", err)
	}

	zlog.Info().
		Str(LogAgentID, resp.Item.Id).
		Str(LogPolicyID, resp.Item.PolicyId).
		Str(LogAccessAPIKeyID, resp.Item.AccessApiKeyId).
		Int(ECSHTTPResponseBodyBytes, numWritten).
		Int64(ECSEventDuration, time.Since(start).Nanoseconds()).
		Msg("Elastic Agent successfully enrolled")

	return nil
}

// updateMetaLocalAgentId updates the agent id in the local metadata if exists
// At the time of writing the local metadata blob looks something like this
//
//	{
//	    "elastic": {
//	        "agent": {
//	            "id": "1b9c327a-c93a-4aef-b67f-effbef54d836",
//	            "version": "8.0.0",
//	            "snapshot": false,
//	            "upgradeable": false
//	        }
//	    },
//	    "host": {
//	        "architecture": "x86_64",
//	        "hostname": "eh-Hounddiamond",
//	        "name": "eh-Hounddiamond",
//	        "id": "1b9c327a-c93a-4aef-b67f-effbef54d836"
//	    },
//	    "os": {
//	        "family": "darwin",
//	        "kernel": "19.6.0",
//	        "platform": "darwin",
//	        "version": "10.15.7",
//	        "name": "Mac OS X",
//	        "full": "Mac OS X(10.15.7)"
//	    }
//	}
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
	span, ctx := apm.StartSpan(ctx, "createAgent", "create")
	defer span.End()

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

func generateAccessAPIKey(ctx context.Context, bulk bulk.Bulk, agentID string) (*apikey.APIKey, error) {
	return bulk.APIKeyCreate(
		ctx,
		agentID,
		"",
		[]byte(kFleetAccessRolesJSON),
		apikey.NewMetadata(agentID, "", apikey.TypeAccess),
	)
}

func (et *EnrollerT) fetchEnrollmentKeyRecord(ctx context.Context, id string) (*model.EnrollmentAPIKey, error) {
	span, ctx := apm.StartSpan(ctx, "tokenCheck", "auth")
	defer span.End()
	if key, ok := et.cache.GetEnrollmentAPIKey(id); ok {
		return &key, nil
	}

	// Pull API key record from .fleet-enrollment-api-keys
	rec, err := dl.FindEnrollmentAPIKey(ctx, et.bulker, dl.QueryEnrollmentAPIKeyByID, dl.FieldAPIKeyID, id)
	if err != nil {
		return nil, fmt.Errorf("FindEnrollmentAPIKey: %w", err)
	}

	if !rec.Active {
		return nil, ErrInactiveEnrollmentKey
	}

	cost := int64(len(rec.APIKey))
	et.cache.SetEnrollmentAPIKey(id, rec, cost)

	return &rec, nil
}

func validateRequest(ctx context.Context, data io.Reader) (*EnrollRequest, error) {
	span, _ := apm.StartSpan(ctx, "validateRequest", "validate")
	defer span.End()

	var req EnrollRequest
	decoder := json.NewDecoder(data)
	if err := decoder.Decode(&req); err != nil {
		return nil, fmt.Errorf("decode enroll request: %w", err)
	}

	// Validate
	switch req.Type {
	case EnrollEphemeral, EnrollPermanent, EnrollTemporary:
	default:
		return nil, ErrUnknownEnrollType
	}

	return &req, nil
}
