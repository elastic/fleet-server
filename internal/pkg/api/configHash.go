// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	"github.com/open-telemetry/opamp-go/protobufs"
	"gopkg.in/yaml.v3"
)

// parseConfigFiles parses every entry in the OpAMP ConfigMap from YAML into a
// map[string]any. The returned map is keyed by the ConfigMap entry name.
// Empty or nil entries are omitted. Call this once and pass the result to both
// HashEffectiveConfig and the redact/marshal path so the YAML is only parsed once.
func parseConfigFiles(ec *protobufs.EffectiveConfig) (map[string]map[string]any, error) {
	out := make(map[string]map[string]any)
	if ec == nil || ec.ConfigMap == nil {
		return out, nil
	}
	for k, file := range ec.ConfigMap.ConfigMap {
		if file == nil || len(file.Body) == 0 {
			continue
		}
		// Only parse YAML files; skip any other content type.
		// An empty content_type defaults to text/yaml per the OpAMP spec.
		if ct := file.ContentType; ct != "" && ct != "text/yaml" {
			continue
		}
		var parsed map[string]any
		if err := yaml.Unmarshal(file.Body, &parsed); err != nil {
			return nil, fmt.Errorf("unmarshal config %q for hashing: %w", k, err)
		}
		out[k] = parsed
	}
	return out, nil
}

// HashEffectiveConfig computes a SHA-256 hash of pre-parsed effective config
// files and returns the canonical JSON bytes for each file. Use parseConfigFiles
// to produce the input so YAML is only parsed once.
//
// Files are processed in sorted key order for determinism. Each file is
// canonicalised with json.Marshal (map keys sorted alphabetically), so key
// ordering differences in the original YAML do not affect the hash. The same
// canonical bytes are returned to the caller for storage — callers should
// redact parsedFiles before calling so the stored bytes are already redacted.
//
// Returns ("", nil, nil) when parsedFiles is empty.
//
// This hash describes what the collector is actually running (EffectiveConfig,
// reported by the collector in AgentToServer). It is stored as
// effective_config_hash on the .fleet-agents document.
//
// It is distinct from the RemoteConfig hash embedded in AgentToServer/
// ServerToAgent messages, which is the OpAMP protocol hash used to detect
// whether the collector has acknowledged and applied a config pushed by
// fleet-server.
func HashEffectiveConfig(parsedFiles map[string]map[string]any) (string, map[string]json.RawMessage, error) {
	if len(parsedFiles) == 0 {
		return "", nil, nil
	}

	keys := slices.Sorted(maps.Keys(parsedFiles))

	h := sha256.New()
	canonical := make(map[string]json.RawMessage, len(parsedFiles))
	for _, k := range keys {
		parsed := parsedFiles[k]
		if parsed == nil {
			continue
		}
		b, err := json.Marshal(parsed)
		if err != nil {
			return "", nil, fmt.Errorf("canonicalize config %q for hashing: %w", k, err)
		}
		canonical[k] = b
		// Include the file key so differently-named files produce different hashes.
		// Null byte separator prevents "a"+"bc" colliding with "ab"+"c".
		fmt.Fprintf(h, "%s\x00", k)
		h.Write(b)
	}

	if len(canonical) == 0 {
		return "", nil, nil
	}
	return hex.EncodeToString(h.Sum(nil)), canonical, nil
}
