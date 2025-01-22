// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.elastic.co/apm/v2"
	"golang.org/x/crypto/pbkdf2"

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
	ErrAgentNotReplaceable   = errors.New("existing agent cannot be replaced")
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

	return et._enroll(r.Context(), rb, zlog, req, enrollAPI.PolicyID, enrollAPI.Namespaces, ver)
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
	policyID string,
	namespaces []string,
	ver string,
) (*EnrollResponse, error) {
	var agent model.Agent
	var enrollmentID string

	span, ctx := apm.StartSpan(ctx, "enroll", "process")
	defer span.End()

	now := time.Now()

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
		// deleted, so clear the ID so code below knows it needs to be created
		agent.Id = ""
	}

	var agentID string
	if req.Id != nil && *req.Id != "" {
		agentID = *req.Id

		// check if the agent with this ID already exists
		var err error
		agent, err = et._checkAgent(ctx, zlog, agentID)
		if err != nil {
			return nil, err
		}

		if agent.Id != "" {
			// confirm that this agent has a set replace token
			// one is required or replacement of this already enrolled and active
			// agent is not allowed
			if agent.ReplaceToken == "" {
				zlog.Warn().
					Str("AgentId", agent.Id).
					Msg("Existing agent with same ID already enrolled without a replace token set")
				return nil, ErrAgentNotReplaceable
			}
			if req.ReplaceToken == nil || *req.ReplaceToken == "" {
				zlog.Warn().
					Str("AgentId", agent.Id).
					Msg("Existing agent with same ID already enrolled; no replace token given during enrollment")
				return nil, ErrAgentNotReplaceable
			}
			same, err := compareHashAndToken(zlog.With().Str("AgentID", agent.Id).Logger(), agent.ReplaceToken, *req.ReplaceToken, et.cfg.PDKDF2)
			if err != nil {
				// issue with hash comparison; reason already logged
				return nil, ErrAgentNotReplaceable
			}
			if !same {
				// not the same, cannot replace
				// provides no real reason as that would expose too much information
				zlog.Debug().
					Str("AgentId", agent.Id).
					Msg("Existing agent with same ID already enrolled; replace token didn't match")
				return nil, ErrAgentNotReplaceable
			}

			// confirm that its on the same policy
			// it is not supported to have it the same ID enroll into different policies
			if agent.PolicyID != policyID {
				zlog.Warn().
					Str("AgentId", agent.Id).
					Str("PolicyId", policyID).
					Str("CurrentPolicyId", agent.PolicyID).
					Msg("Existing agent with same ID already enrolled into another policy")
				return nil, ErrAgentNotReplaceable
			}

			// invalidate the previous api key
			// this has to be done because it's not possible to get the previous token
			// so the other is invalidated and a new one is generated
			zlog.Debug().
				Str("AgentId", agent.Id).
				Str("APIKeyID", agent.AccessAPIKeyID).
				Msg("Invalidate old api key with same id")
			err = invalidateAPIKey(ctx, zlog, et.bulker, agent.AccessAPIKeyID)
			if err != nil {
				zlog.Error().Err(err).
					Str("AgentId", agent.Id).
					Str("APIKeyID", agent.AccessAPIKeyID).
					Msg("Error when trying to invalidate API key of old agent with same id")
				return nil, err
			}
		}
	} else {
		// No ID provided so generate an ID.
		u, err := uuid.NewV4()
		if err != nil {
			return nil, err
		}
		agentID = u.String()
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

	// Existing agent, only update a subset of the fields
	if agent.Id != "" {
		agent.Active = true
		agent.Namespaces = namespaces
		agent.LocalMetadata = localMeta
		agent.AccessAPIKeyID = accessAPIKey.ID
		agent.Agent = &model.AgentMetadata{
			ID:      agentID,
			Version: ver,
		}
		agent.Tags = removeDuplicateStr(req.Metadata.Tags)
		agentField, err := json.Marshal(agent.Agent)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal agent to JSON: %w", err)
		}
		// update the agent record
		// clears state of policy revision, as this agent needs to get the latest policy
		// clears state of unenrollment, as this is a new enrollment
		doc := bulk.UpdateFields{
			dl.FieldNamespaces:            namespaces,
			dl.FieldLocalMetadata:         json.RawMessage(localMeta),
			dl.FieldAccessAPIKeyID:        accessAPIKey.ID,
			dl.FieldAgent:                 json.RawMessage(agentField),
			dl.FieldTags:                  agent.Tags,
			dl.FieldPolicyRevisionIdx:     0,
			dl.FieldAuditUnenrolledTime:   nil,
			dl.FieldAuditUnenrolledReason: nil,
			dl.FieldUnenrolledAt:          nil,
			dl.FieldUnenrolledReason:      nil,
			dl.FieldUpdatedAt:             now.UTC().Format(time.RFC3339),
		}
		err = updateFleetAgent(ctx, et.bulker, agentID, doc)
		if err != nil {
			return nil, err
		}
	} else {
		var replaceHash string
		if req.ReplaceToken != nil && *req.ReplaceToken != "" {
			var err error
			replaceHash, err = hashReplaceToken(*req.ReplaceToken, et.cfg.PDKDF2)
			if err != nil {
				zlog.Error().Err(err).Msg("failed generate hash of replace token")
				return nil, err
			}
		}

		agent = model.Agent{
			Active:         true,
			PolicyID:       policyID,
			Namespaces:     namespaces,
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
			ReplaceToken: replaceHash,
		}

		err = createFleetAgent(ctx, et.bulker, agentID, agent)
		if err != nil {
			return nil, err
		}
		// Register delete fleet agent for enrollment error rollback
		rb.Register("delete agent", func(ctx context.Context) error {
			return deleteAgent(ctx, zlog, et.bulker, agentID)
		})
	}

	resp := EnrollResponse{
		Action: "created",
		Item: EnrollResponseItem{
			AccessApiKey:         accessAPIKey.Token(),
			AccessApiKeyId:       agent.AccessAPIKeyID,
			Active:               agent.Active,
			EnrolledAt:           agent.EnrolledAt,
			Id:                   agentID,
			LocalMetadata:        agent.LocalMetadata,
			PolicyId:             agent.PolicyID,
			Status:               "online",
			Tags:                 agent.Tags,
			Type:                 agent.Type,
			UserProvidedMetadata: agent.UserProvidedMetadata,
		},
	}

	// We are Kool & and the Gang; cache the access key to avoid the roundtrip on impending checkin
	et.cache.SetAPIKey(*accessAPIKey, true)

	return &resp, nil
}

func (et *EnrollerT) _checkAgent(ctx context.Context, zlog zerolog.Logger, agentID string) (model.Agent, error) {
	vSpan, vCtx := apm.StartSpan(ctx, "checkAgentID", "validate")
	defer vSpan.End()

	agent, err := dl.FindAgent(vCtx, et.bulker, dl.QueryAgentByID, dl.FieldID, agentID)
	if err != nil {
		zlog.Debug().Err(err).
			Str("ID", agentID).
			Msg("Agent with ID not found")
		if !errors.Is(err, dl.ErrNotFound) && !strings.Contains(err.Error(), "no such index") {
			return model.Agent{}, err
		}
		return model.Agent{}, nil
	} else if !agent.Active {
		// inactive agent has been unenrolled and the API key has already been invalidated
		// delete the current record as the new enrollment will overwrite this one
		zlog.Debug().
			Str("ID", agentID).
			Msg("Inactive agent with ID found")
		err = deleteAgent(ctx, zlog, et.bulker, agent.Id)
		if err != nil {
			zlog.Error().Err(err).
				Str("AgentId", agent.Id).
				Msg("Error when trying to delete old agent with same id")
			return model.Agent{}, err
		}
		// deleted, so return like one is not found
		return model.Agent{}, nil
	}
	zlog.Debug().
		Str("ID", agentID).
		Msg("Active agent with ID found")
	return agent, nil
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
	cntEnroll.bodyOut.Add(uint64(numWritten)) //nolint:gosec // disable G115

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

func updateFleetAgent(ctx context.Context, bulker bulk.Bulk, id string, doc bulk.UpdateFields) error {
	span, ctx := apm.StartSpan(ctx, "updateAgent", "update")
	defer span.End()

	body, err := doc.Marshal()
	if err != nil {
		return err
	}
	return bulker.Update(ctx, dl.FleetAgents, id, body, bulk.WithRefresh(), bulk.WithRetryOnConflict(3))
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
		return nil, &BadRequestErr{msg: "unable to decode enroll request", nextErr: err}
	}

	// Validate
	switch req.Type {
	case EnrollEphemeral, EnrollPermanent, EnrollTemporary:
	default:
		return nil, ErrUnknownEnrollType
	}

	return &req, nil
}

func compareHashAndToken(zlog zerolog.Logger, hash string, token string, cfg config.PBKDF2) (bool, error) {
	// format of stored replace_token
	// $pbkdf2-sha512${iterations}${salt]${encoded}
	// ${salt} and ${encoded} are stored base64 encoded
	tokens := strings.Split(hash, "$")
	if len(tokens) != 5 || tokens[0] != "" {
		// stored hash is invalid
		zlog.Error().Err(ErrAgentCorrupted).Msg("replace_token hash is corrupted")
		return false, ErrAgentCorrupted
	}
	if tokens[1] != "pbkdf2-sha512" {
		// unsupported hash
		zlog.Error().Err(ErrAgentCorrupted).Msg("replace_token hash is not pbkdf2-sha512")
		return false, ErrAgentCorrupted
	}
	iterations, err := strconv.Atoi(tokens[2])
	if err != nil {
		// hash invalid format
		zlog.Error().Err(err).Msg("replace_token hash iterations not an integer")
		return false, ErrAgentCorrupted
	}
	salt, err := base64.RawStdEncoding.DecodeString(tokens[3])
	if err != nil {
		// hash invalid format
		zlog.Error().Err(err).Msg("replace_token hash failed to base64 decode salt")
		return false, ErrAgentCorrupted
	}
	encoded, err := base64.RawStdEncoding.DecodeString(tokens[4])
	if err != nil {
		// hash invalid format
		zlog.Error().Err(err).Msg("replace_token hash failed to base64 decode encoded")
		return false, ErrAgentCorrupted
	}
	key := pbkdf2.Key([]byte(token), salt, iterations, cfg.KeyLength, sha512.New)
	// use `hmac.Equal` vs `bytes.Equal` to not leak timing information for comparison
	return hmac.Equal(key, encoded), nil
}

func hashReplaceToken(token string, cfg config.PBKDF2) (string, error) {
	// generate random salt
	r := make([]byte, cfg.SaltLength)
	_, err := rand.Read(r)
	if err != nil {
		return "", errors.New("failed to generate random salt")
	}
	key := pbkdf2.Key([]byte(token), r, cfg.Iterations, cfg.KeyLength, sha512.New)
	salt := base64.RawStdEncoding.EncodeToString(r)
	encoded := base64.RawStdEncoding.EncodeToString(key)
	// format of stored replace_token
	// $pbkdf2-sha512${iterations}${salt]${encoded}
	// ${salt} and ${encoded} are stored base64 encoded
	return fmt.Sprintf("$pbkdf2-sha512$%d$%s$%s", cfg.Iterations, salt, encoded), nil
}
