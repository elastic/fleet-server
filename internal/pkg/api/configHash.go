// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"

	"github.com/open-telemetry/opamp-go/protobufs"
	"gopkg.in/yaml.v3"
)

// HashEffectiveConfig computes a SHA-256 hash of the pipeline topology fields
// across all config files in the OpAMP ConfigMap. Each file is processed in
// sorted key order so the hash is deterministic regardless of map iteration
// order. Only receivers, processors, exporters, connectors, service.pipelines,
// and service.extensions are included from each file. Keys within each file are
// sorted deterministically by yaml.v3 Marshal. Returns "" with no error when
// the config is nil or all files are empty.
func HashEffectiveConfig(effectiveConfig *protobufs.EffectiveConfig) (string, error) {
	if effectiveConfig == nil || effectiveConfig.ConfigMap == nil || len(effectiveConfig.ConfigMap.ConfigMap) == 0 {
		return "", nil
	}

	keys := slices.Sorted(maps.Keys(effectiveConfig.ConfigMap.ConfigMap))

	h := sha256.New()
	hasData := false
	for _, k := range keys {
		file := effectiveConfig.ConfigMap.ConfigMap[k]
		if file == nil || len(file.Body) == 0 {
			continue
		}
		topology, err := extractTopologyFields(file.Body)
		if err != nil {
			return "", err
		}
		canonical, err := yaml.Marshal(topology)
		if err != nil {
			return "", fmt.Errorf("canonicalize config %q for hashing: %w", k, err)
		}
		// Include the file key so differently-named files produce different hashes.
		// Null byte separator prevents "a"+"bc" colliding with "ab"+"c".
		fmt.Fprintf(h, "%s\x00", k)
		h.Write(canonical)
		hasData = true
	}

	if !hasData {
		return "", nil
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// extractTopologyFields parses a YAML config body and returns only the
// allowlisted topology keys: receivers, processors, exporters, connectors,
// service.pipelines, and service.extensions.
func extractTopologyFields(body []byte) (map[string]any, error) {
	var full map[string]any
	if err := yaml.Unmarshal(body, &full); err != nil {
		return nil, fmt.Errorf("unmarshal config for hashing: %w", err)
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
	return topology, nil
}
