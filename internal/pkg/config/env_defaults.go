// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"embed"
	"fmt"
	"io"
	"io/fs"
	"math"
	"runtime"
	"strings"
	"time"

	"github.com/pbnjay/memory"
	"github.com/rs/zerolog"

	"github.com/elastic/go-ucfg/yaml"
)

const (
	defaultCacheNumCounters = 500000           // 10x times expected count
	defaultCacheMaxCost     = 50 * 1024 * 1024 // 50MiB cache size

	defaultMaxConnections = 0 // no limit

	defaultActionInterval = 0 // no throttle
	defaultActionBurst    = 5

	defaultPolicyInterval = time.Millisecond * 5
	defaultPolicyBurst    = 1 // NOTE: burst 1 keeps the same behaviour as the previous throttle

	defaultCheckinInterval = time.Millisecond
	defaultCheckinBurst    = 1000
	defaultCheckinMax      = 0
	defaultCheckinMaxBody  = 1024 * 1024

	defaultArtifactInterval = time.Millisecond * 5
	defaultArtifactBurst    = 25
	defaultArtifactMax      = 50
	defaultArtifactMaxBody  = 0

	defaultEnrollInterval = time.Millisecond * 10
	defaultEnrollBurst    = 50
	defaultEnrollMax      = 100
	defaultEnrollMaxBody  = 1024 * 512

	defaultAckInterval = time.Millisecond * 10
	defaultAckBurst    = 50
	defaultAckMax      = 100
	defaultAckMaxBody  = 1024 * 1024 * 2

	defaultStatusInterval = time.Millisecond * 5
	defaultStatusBurst    = 25
	defaultStatusMax      = 50
	defaultStatusMaxBody  = 0

	defaultUploadStartInterval = time.Second * 2
	defaultUploadStartBurst    = 5
	defaultUploadStartMax      = 10
	defaultUploadStartMaxBody  = 1024 * 1024 * 5

	defaultUploadEndInterval = time.Second * 2
	defaultUploadEndBurst    = 5
	defaultUploadEndMax      = 10
	defaultUploadEndMaxBody  = 1024

	defaultUploadChunkInterval = time.Millisecond * 3
	defaultUploadChunkBurst    = 5
	defaultUploadChunkMax      = 10
	defaultUploadChunkMaxBody  = 1024 * 1024 * 4 // this is also enforced in handler, a chunk MUST NOT be larger than 4 MiB

	defaultFileDelivInterval = time.Millisecond * 100
	defaultFileDelivBurst    = 5
	defaultFileDelivMax      = 10
	defaultFileDelivMaxBody  = 0

	defaultPGPRetrievalInterval = time.Millisecond * 5
	defaultPGPRetrievalBurst    = 25
	defaultPGPRetrievalMax      = 50
	defaultPGPRetrievalMaxBody  = 0

	defaultAuditUnenrollInterval = time.Millisecond * 10
	defaultAuditUnenrollBurst    = 50
	defaultAuditUnenrollMax      = 100
	defaultAuditUnenrollMaxBody  = 1024
)

type valueRange struct {
	Min int `config:"min"`
	Max int `config:"max"`
}

type envLimits struct {
	Agents         valueRange           `config:"num_agents"`
	RecommendedRAM uint64               `config:"recommended_min_ram"`
	Server         *serverLimitDefaults `config:"server_limits"`
	Cache          *cacheLimits         `config:"cache_limits"`
}

func defaultEnvLimits() *envLimits {
	return &envLimits{
		Agents: valueRange{
			Min: 0,
			Max: int(getMaxInt()),
		},
		Server: defaultserverLimitDefaults(),
		Cache:  defaultCacheLimits(),
	}
}

type cacheLimits struct {
	NumCounters int64 `config:"num_counters"`
	MaxCost     int64 `config:"max_cost"`
}

func defaultCacheLimits() *cacheLimits {
	return &cacheLimits{
		NumCounters: defaultCacheNumCounters,
		MaxCost:     defaultCacheMaxCost,
	}
}

type limit struct {
	// Interval is the rate limiter's max frequency of requests (1s means 1req/s, 1ms means 1req/ms)
	// A rate of 0 disables the rate limiter
	Interval time.Duration `config:"interval"`
	// Burst is the rate limiter's burst allocation that allows for spikes of traffic.
	// Having a burst value > max is functionally setting it to the same as max.
	// A burst of 0 allows no requests.
	Burst int `config:"burst"`
	// Max is the total number of requests allowed to an endpoint.
	// A zero value disables the max limiter
	Max int64 `config:"max"`
	// MaxBody is the request body size limit.
	// Used in the ack, checkin, and enroll endpoints.
	// A zero value disabled the check.
	MaxBody int64 `config:"max_body_byte_size"`
}

type serverLimitDefaults struct {
	PolicyThrottle         time.Duration `config:"policy_throttle"` // deprecated: replaced by policy_limit
	MaxConnections         int           `config:"max_connections"`
	MaxFileStorageByteSize *uint64       `config:"max_file_storage_size"`

	ActionLimit        limit `config:"action_limit"`
	PolicyLimit        limit `config:"policy_limit"`
	CheckinLimit       limit `config:"checkin_limit"`
	ArtifactLimit      limit `config:"artifact_limit"`
	EnrollLimit        limit `config:"enroll_limit"`
	AckLimit           limit `config:"ack_limit"`
	StatusLimit        limit `config:"status_limit"`
	UploadStartLimit   limit `config:"upload_start_limit"`
	UploadEndLimit     limit `config:"upload_end_limit"`
	UploadChunkLimit   limit `config:"upload_chunk_limit"`
	DeliverFileLimit   limit `config:"file_delivery_limit"`
	GetPGPKeyLimit     limit `config:"pgp_retrieval_limit"`
	AuditUnenrollLimit limit `config:"audit_unenroll_limit"`
}

func defaultserverLimitDefaults() *serverLimitDefaults {
	return &serverLimitDefaults{
		MaxConnections: defaultMaxConnections,
		ActionLimit: limit{
			Interval: defaultActionInterval,
			Burst:    defaultActionBurst,
		},
		PolicyLimit: limit{
			Interval: defaultPolicyInterval,
			Burst:    defaultPolicyBurst,
		},
		CheckinLimit: limit{
			Interval: defaultCheckinInterval,
			Burst:    defaultCheckinBurst,
			Max:      defaultCheckinMax,
			MaxBody:  defaultCheckinMaxBody,
		},
		ArtifactLimit: limit{
			Interval: defaultArtifactInterval,
			Burst:    defaultArtifactBurst,
			Max:      defaultArtifactMax,
			MaxBody:  defaultArtifactMaxBody,
		},
		EnrollLimit: limit{
			Interval: defaultEnrollInterval,
			Burst:    defaultEnrollBurst,
			Max:      defaultEnrollMax,
			MaxBody:  defaultEnrollMaxBody,
		},
		AckLimit: limit{
			Interval: defaultAckInterval,
			Burst:    defaultAckBurst,
			Max:      defaultAckMax,
			MaxBody:  defaultAckMaxBody,
		},
		StatusLimit: limit{
			Interval: defaultStatusInterval,
			Burst:    defaultStatusBurst,
			Max:      defaultStatusMax,
			MaxBody:  defaultStatusMaxBody,
		},
		UploadStartLimit: limit{
			Interval: defaultUploadStartInterval,
			Burst:    defaultUploadStartBurst,
			Max:      defaultUploadStartMax,
			MaxBody:  defaultUploadStartMaxBody,
		},
		UploadEndLimit: limit{
			Interval: defaultUploadEndInterval,
			Burst:    defaultUploadEndBurst,
			Max:      defaultUploadEndMax,
			MaxBody:  defaultUploadEndMaxBody,
		},
		UploadChunkLimit: limit{
			Interval: defaultUploadChunkInterval,
			Burst:    defaultUploadChunkBurst,
			Max:      defaultUploadChunkMax,
			MaxBody:  defaultUploadChunkMaxBody,
		},
		DeliverFileLimit: limit{
			Interval: defaultFileDelivInterval,
			Burst:    defaultFileDelivBurst,
			Max:      defaultFileDelivMax,
			MaxBody:  defaultFileDelivMaxBody,
		},
		GetPGPKeyLimit: limit{
			Interval: defaultPGPRetrievalInterval,
			Burst:    defaultPGPRetrievalBurst,
			Max:      defaultPGPRetrievalMax,
			MaxBody:  defaultPGPRetrievalMaxBody,
		},
		AuditUnenrollLimit: limit{
			Interval: defaultAuditUnenrollInterval,
			Burst:    defaultAuditUnenrollBurst,
			Max:      defaultAuditUnenrollMax,
			MaxBody:  defaultAuditUnenrollMaxBody,
		},
	}
}

var defaults []*envLimits

//go:embed defaults/*.yml
var defaultsFS embed.FS

func init() {
	err := fs.WalkDir(defaultsFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f, err := defaultsFS.Open(path)
		if err != nil {
			return fmt.Errorf("unable to open embedded file %s: %w", path, err)
		}
		p, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf("unable to read embedded file %s: %w", path, err)
		}
		cfg, err := yaml.NewConfig(p, DefaultOptions...)
		if err != nil {
			return fmt.Errorf("cannot read spec from %s: %w", path, err)
		}
		l := defaultEnvLimits()
		if err := cfg.Unpack(&l, DefaultOptions...); err != nil {
			return fmt.Errorf("cannot unpack spec from %s: %w", path, err)
		}
		defaults = append(defaults, l)
		return nil
	})
	if err != nil {
		panic(err)
	}
}

// loadLimits loads cache and server_limit settings based on the passed agentLimit number.
// If agentLimit < 0 the default settings are used.
// If agentLimit > 0 the settings from the matching default/*.yml file are used based off agent count.
// If agentLimit == 0 then the settings from default/*.yml are used based off system memory.
// If a lookup fails, default settings are used.
func loadLimits(log *zerolog.Logger, agentLimit int) *envLimits {
	if agentLimit < 0 {
		return defaultEnvLimits()
	} else if agentLimit == 0 {
		return memEnvLimits(log)
	}
	for _, l := range defaults {
		// get nearest limits for configured agent numbers
		if l.Agents.Min <= agentLimit && agentLimit <= l.Agents.Max {
			log.Info().Msgf("Using system limits for %d to %d agents for a configured value of %d agents", l.Agents.Min, l.Agents.Max, agentLimit)
			ramSize := memory.TotalMemory() / 1024 / 1024
			if ramSize < l.RecommendedRAM {
				log.Warn().Msgf("Detected %d MB of system RAM, which is lower than the recommended amount (%d MB) for the configured agent limit", ramSize, l.RecommendedRAM)
			}
			return l
		}
	}
	log.Info().Msgf("No applicable limit for %d agents, using default.", agentLimit)
	return defaultEnvLimits()
}

// memMB returns the system total memory in MB
// It wraps memory.TotalMemory() so that we can replace the var in unit tests.
var memMB func() uint64 = func() uint64 {
	return memory.TotalMemory() / 1024 / 1024
}

func memEnvLimits(log *zerolog.Logger) *envLimits {
	mem := memMB()
	k := 0
	var recRAM uint64
	for i, l := range defaults {
		if mem >= l.RecommendedRAM && l.RecommendedRAM > recRAM {
			k = i
			recRAM = l.RecommendedRAM
		}
	}
	if recRAM == 0 {
		log.Warn().Uint64("memory_mb", mem).Msg("No settings with recommended ram found, using default.")
		return defaultEnvLimits()
	}
	log.Info().Uint64("memory_mb", mem).Uint64("recommended_mb", recRAM).Msg("Found settings with recommended ram.")
	return defaults[k]
}

func getMaxInt() int64 {
	if strings.HasSuffix(runtime.GOARCH, "64") {
		return math.MaxInt64
	}
	return math.MaxInt32
}
