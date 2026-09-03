// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/rollback"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

func TestRemoveDuplicateStr(t *testing.T) {
	tests := []struct {
		name      string
		inputTags []string
		agentTags []string
	}{
		{
			name:      "empty array",
			inputTags: []string{},
			agentTags: []string{},
		},
		{
			name:      "one duplicated tag",
			inputTags: []string{"foo", "foo", "foo", "foo"},
			agentTags: []string{"foo"},
		},
		{
			name:      "multiple duplicated tags",
			inputTags: []string{"foo", "bar", "bar", "baz", "foo"},
			agentTags: []string{"bar", "baz", "foo"},
		},
	}
	for _, tr := range tests {
		t.Run(tr.name, func(t *testing.T) {
			uniqueTags := removeDuplicateStr(tr.inputTags)
			if !reflect.DeepEqual(uniqueTags, tr.agentTags) {
				t.Fatalf("failed to remove tag duplicates from %v: expected %v, found %v", tr.inputTags, uniqueTags, tr.agentTags)
			}
		})
	}
}

func TestEnroll(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rb := &rollback.Rollback{}
	zlog := zerolog.Logger{}
	enrollmentID := "1234"
	req := &EnrollRequest{
		Type:         "PERMANENT",
		EnrollmentId: &enrollmentID,
		Metadata: EnrollMetadata{
			UserProvided: []byte("{}"),
			Local:        []byte("{}"),
		},
	}
	verCon := mustBuildConstraints("8.9.0")
	cfg := &config.Server{}
	c, _ := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
	bulker := ftesting.NewMockBulk()
	et, _ := NewEnrollerT(verCon, cfg, bulker, c)

	bulker.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&es.ResultT{
		HitsT: es.HitsT{
			Hits: make([]es.HitT, 0),
		},
	}, nil)
	bulker.On("APIKeyCreate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		&apikey.APIKey{
			ID:  "1234",
			Key: "1234",
		}, nil)
	bulker.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		"", nil)
	resp, _ := et._enroll(ctx, rb, zlog, req, "1234", []string{}, "8.9.0")

	if resp.Action != "created" {
		t.Fatal("enroll failed")
	}
}

func TestEnrollWithAgentID(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rb := &rollback.Rollback{}
	zlog := zerolog.Logger{}
	agentID := "1234"
	req := &EnrollRequest{
		Type: "PERMANENT",
		Id:   &agentID,
		Metadata: EnrollMetadata{
			UserProvided: []byte("{}"),
			Local:        []byte("{}"),
		},
	}
	verCon := mustBuildConstraints("8.9.0")
	cfg := &config.Server{}
	c, _ := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
	bulker := ftesting.NewMockBulk()
	et, _ := NewEnrollerT(verCon, cfg, bulker, c)

	bulker.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&es.ResultT{
		HitsT: es.HitsT{
			Hits: make([]es.HitT, 0),
		},
	}, nil)
	bulker.On("APIKeyCreate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		&apikey.APIKey{
			ID:  "1234",
			Key: "1234",
		}, nil)
	bulker.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		"", nil)
	resp, _ := et._enroll(ctx, rb, zlog, req, "1234", []string{}, "8.9.0")

	if resp.Action != "created" {
		t.Fatal("enroll failed")
	}
	if resp.Item.Id != agentID {
		t.Fatalf("agent ID should have been %s (not %s)", agentID, resp.Item.Id)
	}
}

func TestEnrollWithAgentIDExistingNonActive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rb := &rollback.Rollback{}
	zlog := zerolog.Logger{}
	agentID := "1234"
	req := &EnrollRequest{
		Type: "PERMANENT",
		Id:   &agentID,
		Metadata: EnrollMetadata{
			UserProvided: []byte("{}"),
			Local:        []byte("{}"),
		},
	}
	verCon := mustBuildConstraints("8.9.0")
	cfg := &config.Server{}
	c, _ := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
	bulker := ftesting.NewMockBulk()
	et, _ := NewEnrollerT(verCon, cfg, bulker, c)

	bulker.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&es.ResultT{
		HitsT: es.HitsT{
			Hits: []es.HitT{{
				ID:     "1234",
				Index:  dl.FleetAgents,
				Source: []byte(`{"active":false,"agent":{"id":"1234","version":"8.9.0"},"type":"PERMANENT","policy_id":"1234"}`),
			}},
		},
	}, nil)
	bulker.On("Delete", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	bulker.On("APIKeyCreate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		&apikey.APIKey{
			ID:  "1234",
			Key: "1234",
		}, nil)
	bulker.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		"", nil)
	resp, _ := et._enroll(ctx, rb, zlog, req, "1234", []string{}, "8.9.0")

	if resp.Action != "created" {
		t.Fatal("enroll failed")
	}
	if resp.Item.Id != agentID {
		t.Fatalf("agent ID should have been %s (not %s)", agentID, resp.Item.Id)
	}
}

func TestEnrollWithAgentIDExistingActive_NotReplaceable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rb := &rollback.Rollback{}
	zlog := zerolog.Logger{}
	agentID := "1234"
	req := &EnrollRequest{
		Type: "PERMANENT",
		Id:   &agentID,
		Metadata: EnrollMetadata{
			UserProvided: []byte("{}"),
			Local:        []byte("{}"),
		},
	}
	verCon := mustBuildConstraints("8.9.0")
	cfg := &config.Server{}
	c, _ := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
	bulker := ftesting.NewMockBulk()
	et, _ := NewEnrollerT(verCon, cfg, bulker, c)

	bulker.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&es.ResultT{
		HitsT: es.HitsT{
			Hits: []es.HitT{{
				ID:     "1234",
				Index:  dl.FleetAgents,
				Source: []byte(`{"active":true,"agent":{"id":"1234","version":"8.9.0"},"type":"PERMANENT","policy_id":"1234"}`),
			}},
		},
	}, nil)
	_, err := et._enroll(ctx, rb, zlog, req, "1234", []string{}, "8.9.0")
	if !errors.Is(err, ErrAgentNotReplaceable) {
		t.Fatal("should have got error ErrAgentNotReplaceable")
	}
}

func TestEnrollWithAgentIDExistingActive_InvalidReplaceToken_Missing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rb := &rollback.Rollback{}
	zlog := zerolog.Logger{}
	agentID := "1234"
	var pbkdf2Cfg config.PBKDF2
	pbkdf2Cfg.InitDefaults()
	replaceHash, err := hashReplaceToken("password", pbkdf2Cfg)
	if err != nil {
		t.Fatalf("error generating bcrypt hash: %v", err)
	}
	req := &EnrollRequest{
		Type: "PERMANENT",
		Id:   &agentID,
		Metadata: EnrollMetadata{
			UserProvided: []byte("{}"),
			Local:        []byte("{}"),
		},
	}
	verCon := mustBuildConstraints("8.9.0")
	cfg := &config.Server{}
	cfg.InitDefaults()
	c, _ := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
	bulker := ftesting.NewMockBulk()
	et, _ := NewEnrollerT(verCon, cfg, bulker, c)

	source := fmt.Sprintf(`{"active":true,"agent":{"id":"1234","version":"8.9.0"},"type":"PERMANENT","policy_id":"1234","replace_token":"%s"}`, replaceHash)
	bulker.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&es.ResultT{
		HitsT: es.HitsT{
			Hits: []es.HitT{{
				ID:     "1234",
				Index:  dl.FleetAgents,
				Source: []byte(source),
			}},
		},
	}, nil)
	_, err = et._enroll(ctx, rb, zlog, req, "1234", []string{}, "8.9.0")
	if !errors.Is(err, ErrAgentNotReplaceable) {
		t.Fatal("should have got error ErrAgentNotReplaceable")
	}
}

func TestEnrollWithAgentIDExistingActive_InvalidReplaceToken_Mismatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rb := &rollback.Rollback{}
	zlog := zerolog.Logger{}
	agentID := "1234"
	var pbkdf2Cfg config.PBKDF2
	pbkdf2Cfg.InitDefaults()
	replaceHash, err := hashReplaceToken("password", pbkdf2Cfg)
	if err != nil {
		t.Fatalf("error generating bcrypt hash: %v", err)
	}
	wrongToken := "wrong_token"
	req := &EnrollRequest{
		Type: "PERMANENT",
		Id:   &agentID,
		Metadata: EnrollMetadata{
			UserProvided: []byte("{}"),
			Local:        []byte("{}"),
		},
		ReplaceToken: &wrongToken,
	}
	verCon := mustBuildConstraints("8.9.0")
	cfg := &config.Server{}
	cfg.InitDefaults()
	c, _ := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
	bulker := ftesting.NewMockBulk()
	et, _ := NewEnrollerT(verCon, cfg, bulker, c)

	source := fmt.Sprintf(`{"active":true,"agent":{"id":"1234","version":"8.9.0"},"type":"PERMANENT","policy_id":"1234","replace_token":"%s"}`, replaceHash)
	bulker.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&es.ResultT{
		HitsT: es.HitsT{
			Hits: []es.HitT{{
				ID:     "1234",
				Index:  dl.FleetAgents,
				Source: []byte(source),
			}},
		},
	}, nil)
	_, err = et._enroll(ctx, rb, zlog, req, "1234", []string{}, "8.9.0")
	if !errors.Is(err, ErrAgentNotReplaceable) {
		t.Fatal("should have got error ErrAgentNotReplaceable")
	}
}

func TestEnrollWithAgentIDExistingActive_WrongPolicy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rb := &rollback.Rollback{}
	zlog := zerolog.Logger{}
	agentID := "1234"
	replaceToken := "replace_token"
	var pbkdf2Cfg config.PBKDF2
	pbkdf2Cfg.InitDefaults()
	replaceHash, err := hashReplaceToken(replaceToken, pbkdf2Cfg)
	if err != nil {
		t.Fatalf("error generating bcrypt hash: %v", err)
	}
	req := &EnrollRequest{
		Type: "PERMANENT",
		Id:   &agentID,
		Metadata: EnrollMetadata{
			UserProvided: []byte("{}"),
			Local:        []byte("{}"),
		},
		ReplaceToken: &replaceToken,
	}
	verCon := mustBuildConstraints("8.9.0")
	cfg := &config.Server{}
	cfg.InitDefaults()
	c, _ := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
	bulker := ftesting.NewMockBulk()
	et, _ := NewEnrollerT(verCon, cfg, bulker, c)

	source := fmt.Sprintf(`{"active":true,"agent":{"id":"1234","version":"8.9.0"},"type":"PERMANENT","policy_id":"1234","replace_token":"%s"}`, replaceHash)
	bulker.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&es.ResultT{
		HitsT: es.HitsT{
			Hits: []es.HitT{{
				ID:     "1234",
				Index:  dl.FleetAgents,
				Source: []byte(source),
			}},
		},
	}, nil)
	_, err = et._enroll(ctx, rb, zlog, req, "5678", []string{}, "8.9.0")
	if !errors.Is(err, ErrAgentNotReplaceable) {
		t.Fatal("should have got error ErrAgentNotReplaceable")
	}
}

// replaceUpdateDoc extracts the doc body from the first Update call on the mock bulker.
func replaceUpdateDoc(t *testing.T, bulker *ftesting.MockBulk) map[string]any {
	t.Helper()
	var updateBody []byte
	for _, c := range bulker.Calls {
		if c.Method == "Update" {
			updateBody = c.Arguments.Get(3).([]byte)
			break
		}
	}
	require.NotEmpty(t, updateBody, "no Update call on bulker")
	var doc struct {
		Doc map[string]any `json:"doc"`
	}
	require.NoError(t, json.Unmarshal(updateBody, &doc))
	return doc.Doc
}

func TestEnrollWithAgentIDExistingActive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rb := &rollback.Rollback{}
	zlog := zerolog.Logger{}
	agentID := "1234"
	replaceToken := "replace_token"
	var pbkdf2Cfg config.PBKDF2
	pbkdf2Cfg.InitDefaults()
	replaceHash, err := hashReplaceToken(replaceToken, pbkdf2Cfg)
	if err != nil {
		t.Fatalf("error generating bcrypt hash: %v", err)
	}
	req := &EnrollRequest{
		Type: "PERMANENT",
		Id:   &agentID,
		Metadata: EnrollMetadata{
			UserProvided: []byte("{}"),
			Local:        []byte("{}"),
		},
		ReplaceToken: &replaceToken,
	}
	verCon := mustBuildConstraints("8.9.0")
	cfg := &config.Server{}
	cfg.InitDefaults()
	c, _ := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
	bulker := ftesting.NewMockBulk()
	et, _ := NewEnrollerT(verCon, cfg, bulker, c)

	source := fmt.Sprintf(`{"active":true,"agent":{"id":"1234","version":"8.9.0"},"type":"PERMANENT","policy_id":"1234","replace_token":"%s"}`, replaceHash)
	bulker.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&es.ResultT{
		HitsT: es.HitsT{
			Hits: []es.HitT{{
				ID:     "1234",
				Index:  dl.FleetAgents,
				Source: []byte(source),
			}},
		},
	}, nil)
	bulker.On("APIKeyRead", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		&apikey.APIKeyMetadata{ID: "1234"}, nil)
	bulker.On("APIKeyInvalidate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	bulker.On("APIKeyCreate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		&apikey.APIKey{
			ID:  "1234",
			Key: "1234",
		}, nil)
	bulker.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		nil)
	resp, _ := et._enroll(ctx, rb, zlog, req, "1234", []string{}, "8.9.0")

	if resp.Action != "created" {
		t.Fatal("enroll failed")
	}
	if resp.Item.Id != agentID {
		t.Fatalf("agent ID should have been %s (not %s)", agentID, resp.Item.Id)
	}

	doc := replaceUpdateDoc(t, bulker)
	assert.Equal(t, "my-policy", doc[dl.FieldPolicyBaseID])
	assert.NotContains(t, doc, dl.FieldUpgradedAt)
}

// TestEnrollWithAgentIDExistingActive_VersionedPolicy covers replace-enrollment of an
// agent that has been reassigned to a version-specific policy variant (e.g. "my-policy#9.6")
// by Kibana's version-specific policy assignment task. Enrollment API keys are only ever
// bound to the base policy, so the enrolling agent presents the base policy ID while the
// stored agent document carries the versioned one. The replace must compare base policy
// IDs, otherwise the agent can never re-enroll after its container/pod is recreated.
func TestEnrollWithAgentIDExistingActive_VersionedPolicy(t *testing.T) {
	ctx := t.Context()
	rb := &rollback.Rollback{}
	zlog := zerolog.Logger{}
	agentID := "1234"
	replaceToken := "replace_token"
	var pbkdf2Cfg config.PBKDF2
	pbkdf2Cfg.InitDefaults()
	replaceHash, err := hashReplaceToken(replaceToken, pbkdf2Cfg)
	require.NoError(t, err)
	req := &EnrollRequest{
		Type: "PERMANENT",
		Id:   &agentID,
		Metadata: EnrollMetadata{
			UserProvided: []byte("{}"),
			Local:        []byte("{}"),
		},
		ReplaceToken: &replaceToken,
	}
	verCon := mustBuildConstraints("8.9.0")
	cfg := &config.Server{}
	cfg.InitDefaults()
	c, _ := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
	bulker := ftesting.NewMockBulk()
	et, _ := NewEnrollerT(verCon, cfg, bulker, c)

	// Agent document carries the version-specific policy ID; the enrollment key is
	// bound to the base policy.
	source := fmt.Sprintf(`{"active":true,"agent":{"id":"1234","version":"8.9.0"},"type":"PERMANENT","policy_id":"my-policy#9.6","replace_token":"%s"}`, replaceHash)
	bulker.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&es.ResultT{
		HitsT: es.HitsT{
			Hits: []es.HitT{{
				ID:     "1234",
				Index:  dl.FleetAgents,
				Source: []byte(source),
			}},
		},
	}, nil)
	bulker.On("APIKeyRead", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		&apikey.APIKeyMetadata{ID: "1234"}, nil)
	bulker.On("APIKeyInvalidate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	bulker.On("APIKeyCreate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		&apikey.APIKey{
			ID:  "1234",
			Key: "1234",
		}, nil)
	bulker.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		nil)
	resp, err := et._enroll(ctx, rb, zlog, req, "my-policy", []string{}, "8.9.0")
	if err != nil {
		t.Fatalf("enroll should have succeeded for versioned policy with base enrollment key, got: %v", err)
	}

	if resp.Action != "created" {
		t.Fatal("enroll failed")
	}
	if resp.Item.Id != agentID {
		t.Fatalf("agent ID should have been %s (not %s)", agentID, resp.Item.Id)
	}

	doc := replaceUpdateDoc(t, bulker)
	assert.Equal(t, "my-policy", doc[dl.FieldPolicyBaseID])
	assert.NotContains(t, doc, dl.FieldUpgradedAt)
}

func TestEnrollWithAgentIDExistingActive_UpgradedAt(t *testing.T) {
	tests := []struct {
		name            string
		storedVersion   string
		enrollVersion   string
		useReplaceToken bool
		wantUpgradedAt  bool
	}{
		{
			name:            "version change stamps upgraded_at",
			storedVersion:   "8.9.0",
			enrollVersion:   "9.0.0",
			useReplaceToken: true,
			wantUpgradedAt:  true,
		},
		{
			name:            "downgrade stamps upgraded_at",
			storedVersion:   "9.0.0",
			enrollVersion:   "8.9.0",
			useReplaceToken: true,
			wantUpgradedAt:  true,
		},
		{
			name:            "same version does not stamp upgraded_at",
			storedVersion:   "8.9.0",
			enrollVersion:   "8.9.0",
			useReplaceToken: true,
			wantUpgradedAt:  false,
		},
		{
			name:            "enrollment-id re-enrollment without replace token does not stamp upgraded_at",
			storedVersion:   "8.9.0",
			enrollVersion:   "9.0.0",
			useReplaceToken: false,
			wantUpgradedAt:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			rb := &rollback.Rollback{}
			zlog := zerolog.Logger{}
			verCon := mustBuildConstraints("9.0.0")
			cfg := &config.Server{}
			cfg.InitDefaults()
			c, _ := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
			bulker := ftesting.NewMockBulk()
			et, _ := NewEnrollerT(verCon, cfg, bulker, c)

			var req *EnrollRequest
			var source string
			if tt.useReplaceToken {
				agentID := "1234"
				replaceToken := "replace_token"
				var pbkdf2Cfg config.PBKDF2
				pbkdf2Cfg.InitDefaults()
				replaceHash, err := hashReplaceToken(replaceToken, pbkdf2Cfg)
				require.NoError(t, err)
				req = &EnrollRequest{
					Type: "PERMANENT",
					Id:   &agentID,
					Metadata: EnrollMetadata{
						UserProvided: []byte("{}"),
						Local:        []byte("{}"),
					},
					ReplaceToken: &replaceToken,
				}
				source = fmt.Sprintf(`{"active":true,"agent":{"id":"1234","version":"%s"},"type":"PERMANENT","policy_id":"my-policy","replace_token":"%s"}`, tt.storedVersion, replaceHash)
				bulker.On("APIKeyRead", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&apikey.APIKeyMetadata{ID: "1234"}, nil)
				bulker.On("APIKeyInvalidate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
			} else {
				enrollmentID := "enrollment-123"
				req = &EnrollRequest{
					Type:         "PERMANENT",
					EnrollmentId: &enrollmentID,
					Metadata: EnrollMetadata{
						UserProvided: []byte("{}"),
						Local:        []byte("{}"),
					},
				}
				// Agent found by enrollment-id has already checked in, so it is not deleted.
				source = fmt.Sprintf(`{"active":true,"agent":{"id":"existing-id","version":"%s"},"type":"PERMANENT","policy_id":"my-policy","enrollment_id":"enrollment-123","last_checkin":"2024-01-01T00:00:00Z"}`, tt.storedVersion)
			}

			bulker.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&es.ResultT{
				HitsT: es.HitsT{Hits: []es.HitT{{ID: "1234", Index: dl.FleetAgents, Source: []byte(source)}}},
			}, nil)
			bulker.On("APIKeyCreate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&apikey.APIKey{ID: "1234", Key: "1234"}, nil)
			bulker.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

			resp, err := et._enroll(ctx, rb, zlog, req, "my-policy", []string{}, tt.enrollVersion)
			require.NoError(t, err)
			assert.Equal(t, "created", resp.Action)

			doc := replaceUpdateDoc(t, bulker)
			if tt.wantUpgradedAt {
				assert.Contains(t, doc, dl.FieldUpgradedAt)
				assert.NotEmpty(t, doc[dl.FieldUpgradedAt])
			} else {
				assert.NotContains(t, doc, dl.FieldUpgradedAt)
			}
		})
	}
}

func TestEnrollerT_retrieveStaticTokenEnrollmentToken(t *testing.T) {
	bulkerBuilder := func(policies ...model.Policy) func() bulk.Bulk {
		return func() bulk.Bulk {
			bulker := ftesting.NewMockBulk()

			hits := []es.HitT{}
			for _, p := range policies {
				b, _ := json.Marshal(p)
				hits = append(hits, es.HitT{
					Source: b,
				})
			}
			res := &es.ResultT{
				HitsT: es.HitsT{},
				Aggregations: map[string]es.Aggregation{
					"policy_id": {
						Buckets: []es.Bucket{
							{
								Aggregations: map[string]es.HitsT{
									"revision_idx": {
										Hits: hits,
									},
								},
							},
						},
					},
				},
			}
			bulker.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(res, nil)
			return bulker
		}
	}
	type fields struct {
		staticPolicyTokens config.StaticPolicyTokens
		bulker             func() bulk.Bulk
	}
	type args struct {
		enrollmentAPIKey *apikey.APIKey
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *model.EnrollmentAPIKey
		wantErr bool
	}{
		{
			name: "disabled",
			fields: fields{
				staticPolicyTokens: config.StaticPolicyTokens{
					Enabled: false,
				},
				bulker: bulkerBuilder(),
			},
			args: args{
				enrollmentAPIKey: &apikey.APIKey{},
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "found in es",
			fields: fields{
				staticPolicyTokens: config.StaticPolicyTokens{
					Enabled: true,
					PolicyTokens: []config.PolicyToken{
						{
							TokenKey: "abcdefg",
							PolicyID: "dummy-policy",
						},
					},
				},
				bulker: bulkerBuilder(model.Policy{
					PolicyID: "dummy-policy",
				}),
			},
			args: args{
				enrollmentAPIKey: &apikey.APIKey{
					Key: "abcdefg",
				},
			},
			want: &model.EnrollmentAPIKey{
				APIKey:   "abcdefg",
				Active:   true,
				PolicyID: "dummy-policy",
			},
			wantErr: false,
		},
		{
			name: "policy not found",
			fields: fields{
				staticPolicyTokens: config.StaticPolicyTokens{
					Enabled: true,
					PolicyTokens: []config.PolicyToken{
						{
							TokenKey: "abcdefg",
							PolicyID: "dummy-policy",
						},
					},
				},
				bulker: bulkerBuilder(),
			},
			args: args{
				enrollmentAPIKey: &apikey.APIKey{
					Key: "abcdefg",
				},
			},
			want:    &model.EnrollmentAPIKey{},
			wantErr: true,
		},
		{
			name: "static token not found",
			fields: fields{
				staticPolicyTokens: config.StaticPolicyTokens{
					Enabled: true,
					PolicyTokens: []config.PolicyToken{
						{
							TokenKey: "abcdefg",
							PolicyID: "dummy-policy",
						},
					},
				},
				bulker: bulkerBuilder(),
			},
			args: args{
				enrollmentAPIKey: &apikey.APIKey{
					Key: "idonotexists",
				},
			},
			want:    nil,
			wantErr: false, // Should not error as we want to search this in DB
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			et := &EnrollerT{
				cfg: &config.Server{
					StaticPolicyTokens: tt.fields.staticPolicyTokens,
				},
				bulker: tt.fields.bulker(),
			}
			got, err := et.retrieveStaticTokenEnrollmentToken(context.Background(), zerolog.Logger{}, tt.args.enrollmentAPIKey)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCreateFleetAgentVersionConflictSucceeds(t *testing.T) {
	bulker := ftesting.NewMockBulk()
	bulker.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return("", es.ErrElasticVersionConflict)

	err := createFleetAgent(t.Context(), bulker, "test-agent-id", model.Agent{}, false)
	assert.NoError(t, err)
}

func assertSyncEnrollParams(t *testing.T, req *http.Request) {
	t.Helper()
	require.Equal(t, "create", req.URL.Query().Get("op_type"), "op_type must be create to prevent duplicate documents")
	require.Equal(t, "wait_for", req.URL.Query().Get("refresh"), "refresh must be wait_for so the document is visible before the response is sent")
}

func TestCreateFleetAgentSyncWrite409Succeeds(t *testing.T) {
	mt := &MockTransport{}
	mt.RoundTripFn = func(req *http.Request) (*http.Response, error) {
		assertSyncEnrollParams(t, req)
		return &http.Response{
			StatusCode: http.StatusConflict,
			Body:       io.NopCloser(strings.NewReader(`{}`)),
			Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		}, nil
	}
	cli, err := elasticsearch.NewClient(elasticsearch.Config{Transport: mt})
	require.NoError(t, err)

	bulker := ftesting.NewMockBulk()
	bulker.On("Client").Return(cli)

	err = createFleetAgent(t.Context(), bulker, "test-agent-id", model.Agent{}, true)
	require.NoError(t, err)
}

func TestCreateFleetAgentSyncWriteErrorSurfaces(t *testing.T) {
	mt := &MockTransport{}
	mt.RoundTripFn = func(req *http.Request) (*http.Response, error) {
		assertSyncEnrollParams(t, req)
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader(`{}`)),
			Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		}, nil
	}
	cli, err := elasticsearch.NewClient(elasticsearch.Config{Transport: mt})
	require.NoError(t, err)

	bulker := ftesting.NewMockBulk()
	bulker.On("Client").Return(cli)

	err = createFleetAgent(t.Context(), bulker, "test-agent-id", model.Agent{}, true)
	require.Error(t, err)
}

func TestValidateEnrollRequest(t *testing.T) {
	t.Run("invalid json", func(t *testing.T) {
		req, err := validateRequest(context.Background(), strings.NewReader("not a json"))
		assert.Equal(t, "Bad request: unable to decode enroll request: invalid character 'o' in literal null (expecting 'u')", err.Error())
		assert.Nil(t, req)
	})
	t.Run("fips attribute in local metadata", func(t *testing.T) {
		req, err := validateRequest(context.Background(), strings.NewReader(`{"type": "PERMANENT", "metadata": {"local": {"elastic": {"agent": {"fips": true, "snapshot": false}}}}}`))
		assert.NoError(t, err)
		assert.Equal(t, PERMANENT, req.Type)
		assert.Equal(t, json.RawMessage(`{"elastic": {"agent": {"fips": true, "snapshot": false}}}`), req.Metadata.Local)
	})
}
