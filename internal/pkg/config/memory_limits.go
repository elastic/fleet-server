// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package config

import (
	"math"
	"os"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"

	"github.com/pbnjay/memory"
	"github.com/rs/zerolog"
)

const (
	// checkinLongPollBytes is an upper estimate of the memory that one long-poll
	// check-in uses with its TLS connection, measured with check-in bodies of
	// 10 KB.
	checkinLongPollBytes = 101 * 1024

	// checkinIdleConnBytes is an upper estimate of the memory of the idle
	// keep-alive TLS connection that an agent keeps open for acks.
	checkinIdleConnBytes = 32 * 1024
)

// memSource is the source of the memory value that sets the limits.
type memSource string

const (
	// memSourceGoMemLimit is GOMEMLIMIT, from the environment or from server.runtime.memory_limit.
	memSourceGoMemLimit memSource = "GOMEMLIMIT"
	// memSourceCgroup is the memory of the container.
	memSourceCgroup memSource = "cgroup"
	// memSourceHost is the total memory of the host.
	memSourceHost memSource = "host"
)

var (
	// hostMemMB returns the total RAM of the host in MiB.
	hostMemMB func() uint64 = hostMemoryMB
	// cgroupMemMB returns the memory limit of the cgroup in MiB.
	cgroupMemMB func() (uint64, bool) = cgroupMemoryLimitMB
)

func memEnvLimits(log *zerolog.Logger, in *Input) *envLimits {
	fromMemory := in.Server.Features.LimitsFromMemory
	var rt Runtime
	if fromMemory.Enabled {
		rt = in.Server.Runtime
	}
	mem, source := availableMemoryMB(rt)
	limits := limitsFromTier(mem)
	if limits == nil {
		log.Warn().Uint64("memory_mb", mem).Str("memory_source", string(source)).Msg("No settings with recommended ram found, using default.")
		return defaultEnvLimits()
	}

	gogc := gcPercent(rt)
	if fromMemory.Enabled {
		limits = limitsFromMemory(limits, mem, fromMemory.MemoryPercent, gogc, in.Cache.MaxCost)
	}
	log.Info().Uint64("memory_mb", mem).Str("memory_source", string(source)).Int("gogc", gogc).Uint64("recommended_mb", limits.RecommendedRAM).
		Int64("checkin_limit_max", limits.Server.CheckinLimit.Max).Msg("Found settings with recommended ram.")
	return limits
}

// limitsFromTier copies the limits of the largest tier that mem allows.
func limitsFromTier(mem uint64) *envLimits {
	var tier *envLimits
	var recRAM uint64
	for _, l := range defaults {
		if mem >= l.RecommendedRAM && l.RecommendedRAM > recRAM {
			tier, recRAM = l, l.RecommendedRAM
		}
	}
	if tier == nil {
		return nil
	}
	return tier.clone()
}

// limitsFromMemory calculates the limits that depend on the available memory.
func limitsFromMemory(tier *envLimits, mem uint64, memoryPercent, gogc int, cacheMaxCost int64) *envLimits {
	checkinMax := checkinMaxFromMemory(tier, mem, memoryPercent, gogc, cacheMaxCost)
	maxConnections := maxConnectionsFromCheckinMax(tier, checkinMax)

	limits := tier.clone()
	limits.Server.CheckinLimit.Max = checkinMax
	limits.Server.MaxConnections = maxConnections

	return limits
}

// checkinMaxFromMemory returns the checkin_limit.max that the memory allows for the tier limits.
func checkinMaxFromMemory(limits *envLimits, mem uint64, memoryPercent, gogc int, cacheMaxCost int64) int64 {
	// Skip the calculation when there is no check-in limit.
	tierMax := limits.Server.CheckinLimit.Max
	if tierMax <= 0 {
		return tierMax
	}

	// Skip the calculation when memory_percent is not a valid percentage.
	if memoryPercent <= 0 || memoryPercent > 100 {
		return tierMax
	}

	// Keep the tier limit if no tier matches the host RAM.
	hostLimits := limitsFromTier(hostMemMB())
	if hostLimits == nil {
		return tierMax
	}

	// Keep GOGC percent of headroom above the live heap, or 100% when the GC is off.
	growth := int64(gogc)
	if growth < 0 {
		growth = 100
	}

	// Use the configured cache size or the cache of the tier if it is not set.
	cache := cacheMaxCost
	if cache == 0 {
		cache = limits.Cache.MaxCost
	}

	// live is the heap that Fleet Server can keep in use and still fit in its
	// share of the memory when the heap grows before the next GC.
	live := int64(min(mem, math.MaxInt32)) * 1024 * 1024 * int64(memoryPercent) / (100 + growth)

	// The cache and the agents share the live heap, so the limit is the number
	// of agents that fit in what the cache leaves.
	checkinMax := (live - cache) / (checkinLongPollBytes + checkinIdleConnBytes)

	// Never go above the limit of the tier for the host RAM.
	checkinMax = min(checkinMax, hostLimits.Server.CheckinLimit.Max)

	// If the memory allows fewer check-ins than the tier, keep the tier limit.
	checkinMax = max(checkinMax, tierMax)
	return checkinMax
}

// maxConnectionsFromCheckinMax returns the max_connections that checkinMax needs for the tier limits.
func maxConnectionsFromCheckinMax(limits *envLimits, checkinMax int64) int {
	// Keep the max_connections of the tier when there is no check-in limit.
	tierMax := limits.Server.CheckinLimit.Max
	if tierMax <= 0 {
		return limits.Server.MaxConnections
	}

	// Agents can hold more than one connection, so grow max_connections with the check-in limit.
	maxConnections := int(int64(limits.Server.MaxConnections) * checkinMax / tierMax)
	return maxConnections
}

// gcPercent returns the GOGC value that Fleet Server uses.
func gcPercent(rt Runtime) int {
	if rt.GCPercent != 0 {
		return rt.GCPercent
	}
	s := []metrics.Sample{{Name: "/gc/gogc:percent"}}
	metrics.Read(s)
	if s[0].Value.Kind() != metrics.KindUint64 {
		return -1
	}
	// The runtime reports GOGC=off as the largest uint64.
	v := s[0].Value.Uint64()
	if v > math.MaxInt32 {
		return -1
	}
	return int(v)
}

// hostMemoryMB returns the total RAM of the host in MiB. In a container it
// returns the RAM of the host and not the memory limit of the container.
func hostMemoryMB() uint64 {
	return memory.TotalMemory() / 1024 / 1024
}

// cgroupMemoryLimitMB reads the container memory limit from cgroup files.
// It tries cgroup v2 first, then cgroup v1. This only checks the cgroup mount
// root, so it does not account for limits imposed by nested cgroups. Returns
// (0, false) when no applicable limit is found (unlimited, missing file, or
// parse error).
func cgroupMemoryLimitMB() (uint64, bool) {
	if mb, ok := readCgroupMemoryFile("/sys/fs/cgroup/memory.max"); ok {
		return mb, true
	}
	return readCgroupMemoryFile("/sys/fs/cgroup/memory/memory.limit_in_bytes")
}

// readCgroupMemoryFile parses a cgroup memory limit file and returns the
// value in MiB. Returns (0, false) when the file doesn't exist, contains
// "max" (unlimited), or the value is at or above cgroup v1's page-aligned
// unlimited sentinel.
func readCgroupMemoryFile(path string) (uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(data))
	if s == "max" {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n >= cgroupV1UnlimitedMemoryLimit() {
		return 0, false
	}
	return n / 1024 / 1024, true
}

// cgroupV1UnlimitedMemoryLimit is the value cgroup v1 exposes for an
// unrestricted memory limit: MaxInt64 rounded down to the system page size.
func cgroupV1UnlimitedMemoryLimit() uint64 {
	pageSize := int64(os.Getpagesize())
	return uint64(math.MaxInt64 / pageSize * pageSize) //nolint:gosec // the page-aligned result is always non-negative
}

// systemMemoryMB returns the cgroup memory limit in MiB and its source. Outside
// a container it returns the host RAM.
func systemMemoryMB() (uint64, memSource) {
	if mb, ok := cgroupMemMB(); ok {
		return mb, memSourceCgroup
	}
	return hostMemMB(), memSourceHost
}

// availableMemoryMB returns the memory that Fleet Server can use in MiB.
func availableMemoryMB(rt Runtime) (uint64, memSource) {
	limit := rt.MemoryLimit
	if limit <= 0 {
		limit = debug.SetMemoryLimit(-1)
	}
	// math.MaxInt64 turns the Go memory limit off.
	if limit > 0 && limit != math.MaxInt64 {
		return uint64(limit) / 1024 / 1024, memSourceGoMemLimit
	}
	return systemMemoryMB()
}
