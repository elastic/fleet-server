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

	"github.com/elastic/go-ucfg/yaml"
	"github.com/pbnjay/memory"
	"github.com/rs/zerolog/log"
)

const (
	defaultCacheNumCounters = 500000           // 10x times expected count
	defaultCacheMaxCost     = 50 * 1024 * 1024 // 50MiB cache size

	defaultMaxConnections = 0 // no limit
	defaultPolicyThrottle = time.Millisecond * 5

	defaultActionInterval = 0 // no throttle
	defaultActionBurst    = 5

	defaultCheckinInterval = time.Millisecond
	defaultCheckinBurst    = 1000
	defaultCheckinMax      = 0
	defaultCheckinMaxBody  = 1024 * 1024

	defaultArtifactInterval = time.Millisecond * 5
	defaultArtifactBurst    = 25
	defaultArtifactMax      = 50
	defaultArtifactMaxBody  = 0

	defaultEnrollInterval = time.Millisecond * 10
	defaultEnrollBurst    = 100
	defaultEnrollMax      = 50
	defaultEnrollMaxBody  = 1024 * 512

	defaultAckInterval = time.Millisecond * 10
	defaultAckBurst    = 100
	defaultAckMax      = 50
	defaultAckMaxBody  = 1024 * 1024 * 2

	defaultStatusInterval = time.Millisecond * 5
	defaultStatusBurst    = 25
	defaultStatusMax      = 50
	defaultStatusMaxBody  = 0

	defaultUploadStartInterval = time.Second * 3
	defaultUploadStartBurst    = 8
	defaultUploadStartMax      = 3
	defaultUploadStartMaxBody  = 1024 * 1024 * 5

	defaultUploadEndInterval = time.Second * 2
	defaultUploadEndBurst    = 5
	defaultUploadEndMax      = 2
	defaultUploadEndMaxBody  = 1024

	defaultUploadChunkInterval = time.Millisecond * 3
	defaultUploadChunkBurst    = 10
	defaultUploadChunkMax      = 5
	defaultUploadChunkMaxBody  = 1024 * 1024 * 4 // this is also enforced in handler, a chunk MAY NOT be larger than 4 MiB

	defaultFileDelivInterval = time.Millisecond * 100
	defaultFileDelivBurst    = 8
	defaultFileDelivMax      = 5
	defaultFileDelivMaxBody  = 1024 * 1024 * 5

	defaultPGPRetrievalInterval = time.Millisecond * 10
	defaultPGPRetrievalBurst    = 100
	defaultPGPRetrievalMax      = 50
)

type valueRange struct {
	Min int `config:"min"`
	Max int `config:"max"`
}

type envLimits struct {
	Agents         valueRange           `config:"num_agents"`
	RecommendedRAM int                  `config:"recommended_min_ram"`
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
	Interval time.Duration `config:"interval"`
	Burst    int           `config:"burst"`
	Max      int64         `config:"max"`
	MaxBody  int64         `config:"max_body_byte_size"`
}

type serverLimitDefaults struct {
	PolicyThrottle time.Duration `config:"policy_throttle"`
	MaxConnections int           `config:"max_connections"`

	ActionLimit      limit `config:"action_limit"`
	CheckinLimit     limit `config:"checkin_limit"`
	ArtifactLimit    limit `config:"artifact_limit"`
	EnrollLimit      limit `config:"enroll_limit"`
	AckLimit         limit `config:"ack_limit"`
	StatusLimit      limit `config:"status_limit"`
	UploadStartLimit limit `config:"upload_start_limit"`
	UploadEndLimit   limit `config:"upload_end_limit"`
	UploadChunkLimit limit `config:"upload_chunk_limit"`
	DeliverFileLimit limit `config:"file_delivery_limit"`
	GetPGPKeyLimit   limit `config:"pgp_retrieval_limit"`
}

func defaultserverLimitDefaults() *serverLimitDefaults {
	return &serverLimitDefaults{
		PolicyThrottle: defaultPolicyThrottle,
		MaxConnections: defaultMaxConnections,

		ActionLimit: limit{
			Interval: defaultActionInterval,
			Burst:    defaultActionBurst,
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
			MaxBody:  0,
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

func loadLimits(agentLimit int) *envLimits {
	return loadLimitsForAgents(agentLimit)
}

func loadLimitsForAgents(agentLimit int) *envLimits {
	if agentLimit == 0 {
		return defaultEnvLimits()
	}
	for _, l := range defaults {
		// get nearest limits for configured agent numbers
		if l.Agents.Min < agentLimit && agentLimit <= l.Agents.Max {
			log.Info().Msgf("Using system limits for %d to %d agents for a configured value of %d agents", l.Agents.Min, l.Agents.Max, agentLimit)
			ramSize := int(memory.TotalMemory() / 1024 / 1024)
			if ramSize < l.RecommendedRAM {
				log.Warn().Msgf("Detected %d MB of system RAM, which is lower than the recommended amount (%d MB) for the configured agent limit", ramSize, l.RecommendedRAM)
			}
			return l
		}
	}
	log.Info().Msgf("No applicable limit for %d agents, using default.", agentLimit)
	return defaultEnvLimits()
}

func getMaxInt() int64 {
	if strings.HasSuffix(runtime.GOARCH, "64") {
		return math.MaxInt64
	}
	return math.MaxInt32
}
