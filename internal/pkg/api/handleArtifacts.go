// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

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

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/throttle"
	"go.elastic.co/apm/v2"

	"github.com/rs/zerolog"
)

const (
	defaultMaxParallel = 8           // TODO: configurable
	defaultThrottleTTL = time.Minute // TODO: configurable
)

var (
	ErrorThrottle     = errors.New("cannot acquire throttle token")
	ErrorBadSha2      = errors.New("malformed sha256")
	ErrorRecord       = errors.New("artifact record mismatch")
	ErrorMismatchSha2 = errors.New("mismatched sha256")
)

type ArtifactT struct {
	bulker     bulk.Bulk
	cache      cache.Cache
	esThrottle *throttle.Throttle
}

func NewArtifactT(cfg *config.Server, bulker bulk.Bulk, cache cache.Cache) *ArtifactT {
	return &ArtifactT{
		bulker:     bulker,
		cache:      cache,
		esThrottle: throttle.NewThrottle(defaultMaxParallel),
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
	cntArtifacts.bodyOut.Add(uint64(n))
	return nil
}

func (at ArtifactT) processRequest(ctx context.Context, zlog zerolog.Logger, agent *model.Agent, id, sha2 string) (io.Reader, error) {
	vSpan, _ := apm.StartSpan(ctx, "validateRequest", "validate")
	// Input validation
	if err := validateSha2String(sha2); err != nil {
		vSpan.End()
		return nil, err
	}
	vSpan.End()

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

// TODO: Pull the policy record for this agent and validate that the
// requested artifact is assigned to this policy.  This will prevent
// agents from retrieving artifacts that they do not have access to.
// Note that this is racy, the policy could have changed to allow an
// artifact before this instantiation of FleetServer has its local
// copy updated.  Take the race conditions into consideration.
//
// Initial implementation is dependent on security by obscurity; ie.
// it should be difficult for an attacker to guess a guid.
func (at ArtifactT) authorizeArtifact(ctx context.Context, _ *model.Agent, _, _ string) error { //nolint:unparam // remove if this is implemented
	span, _ := apm.StartSpan(ctx, "authorizeArtifacts", "auth") // TODO return and use span ctx if this is ever not a nop
	defer span.End()
	return nil // TODO
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
	if token := at.esThrottle.Acquire(sha2, defaultThrottleTTL); token == nil {
		return nil, ErrorThrottle
	} else {
		defer token.Release()
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
