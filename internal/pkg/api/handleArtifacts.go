// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.elastic.co/apm/v2"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"github.com/elastic/fleet-server/v7/internal/pkg/throttle"

	"github.com/rs/zerolog"
)

const (
	defaultMaxParallel = 8           // TODO: configurable
	defaultThrottleTTL = time.Minute // TODO: configurable
)

var (
	ErrorThrottle           = errors.New("cannot acquire throttle token")
	ErrorBadSha2            = errors.New("malformed sha256")
	ErrorRecord             = errors.New("artifact record mismatch")
	ErrorMismatchSha2       = errors.New("mismatched sha256")
	ErrUnauthorizedArtifact = errors.New("agent not authorized for artifact")
	ErrAgentPolicyIDMissing = errors.New("agent has no policy ID")
)

type ArtifactT struct {
	bulker     bulk.Bulk
	cache      cache.Cache
	esThrottle *throttle.Throttle
	pm         policy.Monitor
}

func NewArtifactT(cfg *config.Server, bulker bulk.Bulk, cache cache.Cache, pm policy.Monitor) *ArtifactT {
	return &ArtifactT{
		bulker:     bulker,
		cache:      cache,
		esThrottle: throttle.NewThrottle(defaultMaxParallel),
		pm:         pm,
	}
}

func (at ArtifactT) handleArtifacts(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, id, sha2 string) error {
	// Authenticate the APIKey; retrieve agent record.
	// Note: This is going to be a bit slow even if we hit the cache on the api key.
	// In order to validate that the agent still has that api key, we fetch the agent record from elastic.
	agent, err := authAgent(r, nil, at.bulker, at.cache)
	if err != nil {
		return err
	}

	zlog = zlog.With().Str(LogAccessAPIKeyID, agent.AccessAPIKeyID).Logger()
	ctx := zlog.WithContext(r.Context())
	r = r.WithContext(ctx)

	if err := at.validateRequest(r.Context(), sha2); err != nil {
		return err
	}

	rdr, err := at.processRequest(r.Context(), zlog, agent, id, sha2)
	if err != nil {
		return err
	}
	span, ctx := apm.StartSpan(r.Context(), "response", "write")
	defer span.End()
	n, err := io.Copy(w, rdr)
	if err != nil {
		return err
	}
	ts, ok := logger.CtxStartTime(ctx)
	e := zlog.Trace().Int64(ECSHTTPResponseBodyBytes, n)
	if ok {
		e = e.Int64(ECSEventDuration, time.Since(ts).Nanoseconds())
	}
	e.Msg("artifact response sent")
	cntArtifacts.bodyOut.Add(uint64(n)) //nolint:gosec // disable G115
	return nil
}

func (at ArtifactT) validateRequest(ctx context.Context, sha2 string) error {
	span, _ := apm.StartSpan(ctx, "validateRequest", "validate")
	defer span.End()

	// Input validation
	return validateSha2String(sha2)
}

func (at ArtifactT) processRequest(ctx context.Context, zlog zerolog.Logger, agent *model.Agent, id, sha2 string) (io.Reader, error) {
	// Determine whether the agent should have access to this artifact
	if err := at.authorizeArtifact(ctx, agent, id, sha2); err != nil {
		zlog.Warn().Err(err).Msg("Unauthorized GET on artifact")
		return nil, err
	}

	// Grab artifact, whether from cache or elastic.
	artifact, err := at.getArtifact(ctx, zlog, id, sha2)
	if err != nil {
		return nil, err
	}

	// Sanity check; just in case something underneath is misbehaving
	if artifact.Identifier != id || artifact.DecodedSha256 != sha2 {
		err = ErrorRecord
		zlog.Info().
			Err(err).
			Str("artifact_id", artifact.Identifier).
			Str("artifact_sha2", artifact.DecodedSha256).
			Msg("Identifier mismatch on url")
		return nil, err
	}

	zlog.Debug().
		Int("sz", len(artifact.Body)).
		Int64("decodedSz", artifact.DecodedSize).
		Str("compression", artifact.CompressionAlgorithm).
		Str("encryption", artifact.EncryptionAlgorithm).
		Str("created", artifact.Created).
		Msg("Artifact GET")

	// Write the payload
	rdr := bytes.NewReader(artifact.Body)
	return rdr, nil
}

// authorizeArtifact checks that the requested artifact is listed in the agent's
// assigned policy. The policy is read from the in-memory cache maintained by the
// policy monitor, which introduces a staleness window between ES updates and
// cache refresh. This creates two race conditions:
//
//   - False negative (deny when should allow): an artifact was just added to a
//     policy but the cache hasn't refreshed yet. This is self-healing — the agent
//     will retry and succeed once the cache catches up.
//
//   - False positive (allow when should deny): an artifact was just removed from
//     a policy but the stale cache still lists it. The agent can download the
//     artifact until the cache refreshes. This is the security-sensitive direction.
//     A future improvement could verify against ES when the cache says "allow".
func (at ArtifactT) authorizeArtifact(ctx context.Context, agent *model.Agent, id, sha2 string) error {
	span, ctx := apm.StartSpan(ctx, "authorizeArtifacts", "auth")
	defer span.End()

	if agent.AgentPolicyID == "" {
		return ErrAgentPolicyIDMissing
	}

	p, err := at.pm.GetPolicy(ctx, agent.AgentPolicyID)
	if err != nil {
		return fmt.Errorf("authorizeArtifact: %w", err)
	}

	if p.Data != nil && policyHasArtifact(p.Data, id, sha2) {
		return nil
	}

	return ErrUnauthorizedArtifact
}

func policyHasArtifact(pd *model.PolicyData, id, sha2 string) bool {
	for _, input := range pd.Inputs {
		if inputHasArtifact(input, id, sha2) {
			return true
		}
	}
	return false
}

func inputHasArtifact(input map[string]any, id, sha2 string) bool {
	manifestRaw, ok := input[dl.FieldArtifactManifest].(map[string]any)
	if !ok {
		return false
	}
	artifacts, ok := manifestRaw[dl.FieldArtifacts].(map[string]any)
	if !ok {
		return false
	}
	entry, ok := artifacts[id].(map[string]any)
	if !ok {
		return false
	}
	sha, _ := entry[dl.FieldDecodedSha256].(string)
	return sha == sha2
}

// Return artifact from cache by sha2 or fetch directly from Elastic.
// Update cache on successful retrieval from Elastic.
func (at ArtifactT) getArtifact(ctx context.Context, zlog zerolog.Logger, ident, sha2 string) (*model.Artifact, error) {
	span, ctx := apm.StartSpan(ctx, "getArtifact", "process")
	defer span.End()

	// Check the cache; return immediately if found.
	if artifact, ok := at.cache.GetArtifact(ident, sha2); ok {
		return &artifact, nil
	}

	// Fetch the artifact from elastic
	art, err := at.fetchArtifact(ctx, zlog, ident, sha2)
	if err != nil {
		zlog.Info().Err(err).Msg("Fail retrieve artifact")
		return nil, err
	}

	// The 'Body' field type is Raw; extract to string.
	var srcPayload string
	if err = json.Unmarshal(art.Body, &srcPayload); err != nil {
		zlog.Error().Err(err).Msg("Cannot unmarshal artifact payload")
		return nil, err
	}

	// Artifact is stored base64 encoded in ElasticSearch.
	// Base64 decode the payload before putting in cache
	// to avoid having to decode on each cache hit.
	dstPayload, err := base64.StdEncoding.DecodeString(srcPayload)
	if err != nil {
		zlog.Error().Err(err).Msg("Fail base64 decode artifact")
		return nil, err
	}

	// Validate the sha256 hash; this is just good hygiene.
	vSpan, _ := apm.StartSpan(ctx, "validateArtifact", "validate")
	if err = validateSha2Data(dstPayload, art.EncodedSha256); err != nil {
		vSpan.End()
		zlog.Error().Err(err).Msg("Fail sha2 hash validation")
		return nil, err
	}
	vSpan.End()

	// Reassign decoded payload before adding to cache, avoid base64 decode on cache hit.
	art.Body = dstPayload

	// Update the cache.
	at.cache.SetArtifact(*art)

	return art, nil
}

// Attempt to fetch the artifact from Elastic
// TODO: Design a mechanism to mitigate a DDOS attack on bogus hashes.
// Perhaps have a cache of the most recently used hashes available, and items that aren't
// in the cache can do a lookup but throttle as below.  We could update the cache every 10m or so.
func (at ArtifactT) fetchArtifact(ctx context.Context, zlog zerolog.Logger, ident, sha2 string) (*model.Artifact, error) {
	span, ctx := apm.StartSpan(ctx, "fetchArtifact", "search")
	defer span.End()
	// Throttle prevents more than N outstanding requests to elastic globally and per sha2.
	if token := at.esThrottle.Acquire(zlog, sha2, defaultThrottleTTL); token == nil {
		return nil, ErrorThrottle
	} else {
		defer token.Release(zlog)
	}

	start := time.Now()
	artifact, err := dl.FindArtifact(ctx, at.bulker, ident, sha2)

	zlog.Info().
		Err(err).
		Int64(ECSEventDuration, time.Since(start).Nanoseconds()).
		Msg("fetch artifact")

	if err != nil {
		return artifact, fmt.Errorf("fetchArtifact: %w", err)
	}
	return artifact, nil
}

func validateSha2String(sha2 string) error {

	if len(sha2) != 64 {
		return ErrorBadSha2
	}

	if _, err := hex.DecodeString(sha2); err != nil {
		return ErrorBadSha2
	}

	return nil
}

func validateSha2Data(data []byte, sha2 string) error {
	src, err := hex.DecodeString(sha2)
	if err != nil {
		return fmt.Errorf("sha2 hex decode: %w", err)
	}

	sum := sha256.Sum256(data)
	if !bytes.Equal(sum[:], src) {
		return ErrorMismatchSha2
	}

	return nil
}
