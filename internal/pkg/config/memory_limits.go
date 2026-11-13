// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package config

import (
	"cmp"
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

	// maxMemCheckinLimit caps the checkin_limit.max calculated from the memory
	// when Fleet Server detects more memory than it can use.
	maxMemCheckinLimit = 100_000

	// fleetMemoryPercent is the percentage of the memory that Fleet Server plans
	// to use. The rest is left for Elastic Agent and the other processes that
	// share the container and its GOMEMLIMIT, such as APM Server in the
	// Integrations Server on ECH.
	fleetMemoryPercent = 75
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

// memMB returns available memory in MiB and its source.
// It is a var so that unit tests can replace it.
var memMB func() (uint64, memSource) = availableMemoryMB

// cgroupMemMB returns the cgroup memory limit in MiB.
// It is a var so that unit tests can replace it.
var cgroupMemMB func() (uint64, bool) = cgroupMemoryLimitMB

func memEnvLimits(log *zerolog.Logger, in *Input) *envLimits {
	fromMemory := in.Server.Features.CheckinLimitFromMemory
	// Without checkin_limit_from_memory, select the tier as before, without server.runtime.
	var rt Runtime
	if fromMemory {
		rt = in.Server.Runtime
	}
	mem, source := memoryMB(rt)
	gogc := gcPercent(rt)
	k := 0
	var recRAM uint64
	for i, l := range defaults {
		if mem >= l.RecommendedRAM && l.RecommendedRAM > recRAM {
			k = i
			recRAM = l.RecommendedRAM
		}
	}
	if recRAM == 0 {
		log.Warn().Uint64("memory_mb", mem).Str("memory_source", string(source)).Msg("No settings with recommended ram found, using default.")
		return defaultEnvLimits()
	}

	l := defaults[k]
	if fromMemory {
		l = memCheckinLimits(l, mem, gogc, in.Cache.MaxCost)
	}
	log.Info().Uint64("memory_mb", mem).Str("memory_source", string(source)).Int("gogc", gogc).Uint64("recommended_mb", recRAM).
		Int64("checkin_limit_max", l.Server.CheckinLimit.Max).Msg("Found settings with recommended ram.")
	return l
}

// memoryMB returns the memory that Fleet Server can use, in MiB, and its source.
func memoryMB(rt Runtime) (uint64, memSource) {
	switch {
	case rt.MemoryLimit == math.MaxInt64:
		// math.MaxInt64 turns the Go memory limit off so the current limit does not apply.
		return systemMemoryMB()
	case rt.MemoryLimit > 0:
		return uint64(rt.MemoryLimit) / 1024 / 1024, memSourceGoMemLimit
	}
	return memMB()
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

// memCheckinLimits returns a copy of the tier l with a checkin_limit.max
// calculated from the memory.
func memCheckinLimits(l *envLimits, memMB uint64, gogc int, cacheMaxCost int64) *envLimits {
	// Keep no limit when the tier has none (checkin_limit.max is 0).
	tierMax := l.Server.CheckinLimit.Max
	if tierMax <= 0 {
		return l
	}

	// The heap grows by the GOGC percentage above the live heap before the GC
	// runs. Keep half of the memory free when the GC is off because only the
	// memory limit stops it.
	growth := int64(gogc)
	if growth < 0 {
		growth = 100
	}

	// Use the configured cache size or the cache of the tier if it is not set.
	cache := cmp.Or(cacheMaxCost, l.Cache.MaxCost)

	// Divide the live heap that the cache does not use by the memory of one agent.
	live := int64(memMB) * 1024 * 1024 * fleetMemoryPercent / (100 + growth) //nolint:gosec // memory in MiB is far below MaxInt64
	checkinMax := (live - cache) / (checkinLongPollBytes + checkinIdleConnBytes)

	// If the memory allows fewer check-ins than the tier, keep the tier value for
	// backward compatibility.
	checkinMax = max(min(checkinMax, maxMemCheckinLimit), tierMax)

	// Change a copy so that the embedded tier stays the same.
	srv := *l.Server
	srv.CheckinLimit.Max = checkinMax
	// Keep the ratio so that max_connections does not limit check-ins first.
	srv.MaxConnections = int(int64(srv.MaxConnections) * checkinMax / tierMax)
	c := *l
	c.Server = &srv
	return &c
}

// availableMemoryMB returns available memory in MiB and its source using this priority order:
//  1. GOMEMLIMIT, if explicitly set
//  2. cgroup memory limit (v2, then v1), for containers without an explicit GOMEMLIMIT
//  3. host total RAM, for non-containerised deployments
func availableMemoryMB() (uint64, memSource) {
	limit := debug.SetMemoryLimit(-1)
	if limit > 0 && limit != math.MaxInt64 {
		return uint64(limit) / 1024 / 1024, memSourceGoMemLimit
	}
	return systemMemoryMB()
}

// systemMemoryMB returns the cgroup memory limit in MiB and its source. Outside
// a container it returns the host RAM.
func systemMemoryMB() (uint64, memSource) {
	if mb, ok := cgroupMemMB(); ok {
		return mb, memSourceCgroup
	}
	return memory.TotalMemory() / 1024 / 1024, memSourceHost
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
