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

// HashEffectiveConfig computes a SHA-256 hash of all config files in the OpAMP
// ConfigMap. Each file body is parsed and re-marshalled so that key ordering
// differences produce the same hash. Files are processed in sorted key order
// for determinism. Returns "" with no error when the config is nil or all
// files are empty.
//
// This hash describes what the collector is actually running (EffectiveConfig,
// reported by the collector in AgentToServer). It is stored as
// effective_config_hash on the .fleet-agents document.
//
// It is distinct from the RemoteConfig hash embedded in AgentToServer/
// ServerToAgent messages, which is the OpAMP protocol hash used to detect
// whether the collector has acknowledged and applied a config pushed by
// fleet-server.
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
		var parsed map[string]any
		if err := yaml.Unmarshal(file.Body, &parsed); err != nil {
			return "", fmt.Errorf("unmarshal config %q for hashing: %w", k, err)
		}
		canonical, err := yaml.Marshal(parsed)
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
