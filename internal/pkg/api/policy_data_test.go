// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package api

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"github.com/stretchr/testify/assert"
)

func fullTestPolicyData() *model.PolicyData {
	return &model.PolicyData{
		Agent:      map[string]any{"monitoring": map[string]any{"enabled": true}},
		Connectors: map[string]any{"count": map[string]any{}},
		Exporters:  map[string]any{"elasticsearch/default": map[string]any{"endpoint": "https://es:9200"}},
		Extensions: map[string]any{"health_check": map[string]any{}},
		Fleet:      map[string]any{"hosts": []any{"https://fleet:8220"}},
		ID:         "policy-1",
		Inputs: []map[string]any{
			{"id": "input-1", "type": "logfile", "streams": []any{map[string]any{"id": "s1"}}},
		},
		OutputPermissions: json.RawMessage(`{"default":{"_fallback":{"cluster":["monitor"]}}}`),
		Outputs: map[string]map[string]any{
			"default": {"type": "elasticsearch", "api_key": "id:secret"},
		},
		Processors: map[string]any{"batch": map[string]any{}},
		Receivers:  map[string]any{"otlp": map[string]any{}},
		Revision:   7,
		SecretReferences: []model.SecretReferencesItems{
			{ID: "secret-1"},
		},
		Service: &model.Service{
			Extensions: []string{"health_check"},
			Pipelines: map[string]*model.PipelinesItem{
				"logs": {
					Receivers:  []string{"otlp"},
					Processors: []string{"batch"},
					Exporters:  []string{"elasticsearch/default"},
				},
			},
		},
		Signed: &model.Signed{
			Data:      "ZGF0YQ==",
			Signature: "c2ln",
		},
	}
}

func TestNewPolicyDataFromParsedPolicy(t *testing.T) {
	tests := []struct {
		name string
		pp   *policy.ParsedPolicy
		want PolicyData
	}{
		{
			name: "full parsed policy copies all shared fields",
			pp: &policy.ParsedPolicy{
				Policy: model.Policy{Data: fullTestPolicyData()},
			},
			want: PolicyData{
				Agent:      map[string]any{"monitoring": map[string]any{"enabled": true}},
				Connectors: map[string]any{"count": map[string]any{}},
				Exporters:  map[string]any{"elasticsearch/default": map[string]any{"endpoint": "https://es:9200"}},
				Extensions: map[string]any{"health_check": map[string]any{}},
				Fleet:      map[string]any{"hosts": []any{"https://fleet:8220"}},
				Id:         "policy-1",
				Inputs: []map[string]any{
					{"id": "input-1", "type": "logfile", "streams": []any{map[string]any{"id": "s1"}}},
				},
				OutputPermissions: json.RawMessage(`{"default":{"_fallback":{"cluster":["monitor"]}}}`),
				Outputs: map[string]any{
					"default": map[string]any{"type": "elasticsearch", "api_key": "id:secret"},
				},
				Processors: map[string]any{"batch": map[string]any{}},
				Receivers:  map[string]any{"otlp": map[string]any{}},
				Revision:   7,
				Service: &OtelConfigService{
					Extensions: []string{"health_check"},
					Pipelines: map[string]OtelConfigPipeline{
						"logs": {
							Receivers:  []string{"otlp"},
							Processors: []string{"batch"},
							Exporters:  []string{"elasticsearch/default"},
						},
					},
				},
				Signed: &ActionSignature{
					Data:      "ZGF0YQ==",
					Signature: "c2ln",
				},
			},
		},
		{
			name: "nil parsed policy returns zero policy data",
			pp:   nil,
			want: PolicyData{},
		},
		{
			name: "nil policy data returns zero policy data",
			pp:   &policy.ParsedPolicy{},
			want: PolicyData{},
		},
		{
			name: "empty outputs map becomes nil",
			pp: &policy.ParsedPolicy{
				Policy: model.Policy{
					Data: &model.PolicyData{
						ID:      "policy-empty-outputs",
						Outputs: map[string]map[string]any{},
					},
				},
			},
			want: PolicyData{
				Id: "policy-empty-outputs",
			},
		},
		{
			name: "nil service pipeline entry becomes zero pipeline",
			pp: &policy.ParsedPolicy{
				Policy: model.Policy{
					Data: &model.PolicyData{
						ID: "policy-service-nil-pipeline",
						Service: &model.Service{
							Pipelines: map[string]*model.PipelinesItem{
								"empty": nil,
							},
						},
					},
				},
			},
			want: PolicyData{
				Id: "policy-service-nil-pipeline",
				Service: &OtelConfigService{
					Pipelines: map[string]OtelConfigPipeline{
						"empty": {},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewPolicyDataFromParsedPolicy(tt.pp)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNewPolicyDataFromParsedPolicyCopiesAllSchemaFields(t *testing.T) {
	modelType := reflect.TypeFor[model.PolicyData]()
	wantModelFields := make([]string, 0, modelType.NumField())
	for field := range modelType.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "secret_references" {
			continue
		}
		wantModelFields = append(wantModelFields, name)
	}
	slices.Sort(wantModelFields)

	apiType := reflect.TypeFor[PolicyData]()
	wantAPIFields := make([]string, 0, apiType.NumField())
	for field := range apiType.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "secret_paths" {
			continue
		}
		wantAPIFields = append(wantAPIFields, name)
	}
	slices.Sort(wantAPIFields)

	assert.Equal(t, wantModelFields, wantAPIFields)

	pp := &policy.ParsedPolicy{
		Policy: model.Policy{Data: fullTestPolicyData()},
	}
	got := NewPolicyDataFromParsedPolicy(pp)

	gotVal := reflect.ValueOf(got)
	for i := range apiType.NumField() {
		field := apiType.Field(i)
		if field.Name == "SecretPaths" {
			continue
		}
		isZero := gotVal.Field(i).IsZero()
		assert.False(t, isZero, "field %s was not copied by NewPolicyDataFromParsedPolicy", field.Name)
	}
}
