// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

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

func TestValidateEnrollRequest(t *testing.T) {
	t.Run("invalid json", func(t *testing.T) {
		req, err := validateRequest(context.Background(), strings.NewReader("not a json"))
		assert.Equal(t, "Bad request: unable to decode enroll request", err.Error())
		assert.Nil(t, req)
	})
	t.Run("fips attribute in local metadata", func(t *testing.T) {
		req, err := validateRequest(context.Background(), strings.NewReader(`{"type": "PERMANENT", "metadata": {"local": {"elastic": {"agent": {"fips": true, "snapshot": false}}}}}`))
		assert.NoError(t, err)
		assert.Equal(t, PERMANENT, req.Type)
		assert.Equal(t, json.RawMessage(`{"elastic": {"agent": {"fips": true, "snapshot": false}}}`), req.Metadata.Local)
	})
}
