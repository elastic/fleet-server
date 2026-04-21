// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/open-telemetry/opamp-go/protobufs"
	"gopkg.in/yaml.v3"
)

// HashEffectiveConfig computes a SHA-256 hash of the pipeline topology fields from an
// OpAMP effective config. Only receivers, processors, exporters, connectors,
// service.pipelines, and service.extensions are included. Keys are sorted
// deterministically (yaml.v3 sorts map keys on Marshal) so identical topologies
// always produce the same hash regardless of key order or non-topology fields.
// Returns "" with no error when the config is nil or the body is empty.
func HashEffectiveConfig(effectiveConfig *protobufs.EffectiveConfig) (string, error) {
	if effectiveConfig.ConfigMap == nil || effectiveConfig.ConfigMap.ConfigMap[""] == nil {
		return "", nil
	}
	body := effectiveConfig.ConfigMap.ConfigMap[""].Body
	if len(body) == 0 {
		return "", nil
	}
	return hashConfigBody(body)
}

func hashConfigBody(body []byte) (string, error) {
	var full map[string]any
	if err := yaml.Unmarshal(body, &full); err != nil {
		return "", fmt.Errorf("unmarshal config for hashing: %w", err)
	}

	topology := make(map[string]any)
	for _, k := range []string{"receivers", "processors", "exporters", "connectors"} {
		if v, ok := full[k]; ok {
			topology[k] = v
		}
	}
	if svc, ok := full["service"].(map[string]any); ok {
		svcTopology := make(map[string]any)
		for _, k := range []string{"pipelines", "extensions"} {
			if v, ok := svc[k]; ok {
				svcTopology[k] = v
			}
		}
		if len(svcTopology) > 0 {
			topology["service"] = svcTopology
		}
	}

	// yaml.v3 sorts map keys alphabetically on Marshal → deterministic canonical form
	canonical, err := yaml.Marshal(topology)
	if err != nil {
		return "", fmt.Errorf("canonicalize config for hashing: %w", err)
	}

	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}
