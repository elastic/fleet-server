// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package api

import (
	"context"
	"reflect"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/rollback"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
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
	resp, _ := et._enroll(ctx, rb, zlog, req, "1234", "8.9.0")

	if resp.Action != "created" {
		t.Fatal("enroll failed")
	}

}
