// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package api

import (
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
)

// NewPolicyDataFromParsedPolicy returns a PolicyData populated from pp.
func NewPolicyDataFromParsedPolicy(pp *policy.ParsedPolicy) PolicyData {
	if pp == nil || pp.Policy.Data == nil {
		return PolicyData{}
	}

	src := pp.Policy.Data
	var outputs map[string]any
	if len(src.Outputs) > 0 {
		outputs = make(map[string]any, len(src.Outputs))
		for k, v := range src.Outputs {
			outputs[k] = v
		}
	}

	service := newOtelConfigService(src.Service)
	signed := newActionSignature(src.Signed)
	data := PolicyData{
		Agent:             src.Agent,
		Connectors:        src.Connectors,
		Exporters:         src.Exporters,
		Extensions:        src.Extensions,
		Fleet:             src.Fleet,
		Id:                src.ID,
		Inputs:            src.Inputs,
		OutputPermissions: src.OutputPermissions,
		Outputs:           outputs,
		Processors:        src.Processors,
		Receivers:         src.Receivers,
		Revision:          int(src.Revision),
		Service:           service,
		Signed:            signed,
	}
	return data
}

func newOtelConfigService(src *model.Service) *OtelConfigService {
	if src == nil {
		return nil
	}

	out := &OtelConfigService{
		Extensions: src.Extensions,
	}
	if len(src.Pipelines) > 0 {
		pipelines := make(map[string]OtelConfigPipeline, len(src.Pipelines))
		for k, v := range src.Pipelines {
			var item OtelConfigPipeline
			if v != nil {
				item.Exporters = v.Exporters
				item.Processors = v.Processors
				item.Receivers = v.Receivers
			}
			pipelines[k] = item
		}
		out.Pipelines = pipelines
	}

	return out
}

func newActionSignature(src *model.Signed) *ActionSignature {
	if src == nil {
		return nil
	}
	sig := &ActionSignature{
		Data:      src.Data,
		Signature: src.Signature,
	}
	return sig
}
