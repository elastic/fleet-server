// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package config

import (
	"math"
	"os"
	"runtime/debug"
	"strconv"
	"testing"

	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
	"github.com/pbnjay/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemEnvLimitsTier(t *testing.T) {
	testCases := []struct {
		Name             string
		MemoryMB         uint64
		ExpectedAgentMax int
	}{
		{
			Name:             "use default limits below every tier",
			MemoryMB:         200,
			ExpectedAgentMax: math.MaxInt,
		},
		{
			Name:             "select lower tier 1 MiB below recommended_min_ram",
			MemoryMB:         4047,
			ExpectedAgentMax: 5000,
		},
		{
			Name:             "select tier at its recommended_min_ram",
			MemoryMB:         4048,
			ExpectedAgentMax: 10_000,
		},
		{
			Name:             "select largest tier above every tier",
			MemoryMB:         65_536,
			ExpectedAgentMax: math.MaxInt,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			setMemory(t, tc.MemoryMB, memSourceCgroup)
			log := testlog.SetLogger(t)

			l := memEnvLimits(&log, &Input{})

			require.Equal(t, tc.ExpectedAgentMax, l.Agents.Max)
		})
	}
}

func TestMemEnvLimitsFeatureFlag(t *testing.T) {
	setGOGC(t, 100)
	setMemory(t, 4096, memSourceCgroup)
	log := testlog.SetLogger(t)

	off := memEnvLimits(&log, &Input{Server: Server{Runtime: Runtime{MemoryLimit: 2048 * mib}}}).Server.CheckinLimit.Max
	on := memEnvLimits(&log, memInput(Runtime{})).Server.CheckinLimit.Max

	require.Equal(t, int64(10_000), off, "checkin_limit_from_memory off must keep the tier limit of the detected memory")
	require.Greater(t, on, off, "checkin_limit_from_memory on must calculate the limit from memory")
}

func TestMemEnvLimitsRuntime(t *testing.T) {
	setGOGC(t, 100)
	checkinMax := func(t *testing.T, memoryMB uint64, source memSource, rt Runtime) int64 {
		t.Helper()
		setMemory(t, memoryMB, source)
		log := testlog.SetLogger(t)
		return memEnvLimits(&log, memInput(rt)).Server.CheckinLimit.Max
	}
	baseline := checkinMax(t, 4096, memSourceCgroup, Runtime{})

	t.Run("reserve memory from GOMEMLIMIT like from cgroup", func(t *testing.T) {
		require.Equal(t, baseline, checkinMax(t, 4096, memSourceGoMemLimit, Runtime{}))
	})

	t.Run("use default GOGC when gc_percent turns GC off", func(t *testing.T) {
		require.Equal(t, baseline, checkinMax(t, 4096, memSourceCgroup, Runtime{GCPercent: -1}))
	})

	t.Run("use gc_percent as GOGC", func(t *testing.T) {
		fromSetting := checkinMax(t, 4096, memSourceCgroup, Runtime{GCPercent: 20})
		setGOGC(t, 20)
		require.Equal(t, checkinMax(t, 4096, memSourceCgroup, Runtime{}), fromSetting)
	})

	t.Run("use memory_limit before detected memory", func(t *testing.T) {
		fromSetting := checkinMax(t, 16_384, memSourceCgroup, Runtime{MemoryLimit: 4_000_000_000})
		require.Equal(t, checkinMax(t, 4_000_000_000/mib, memSourceCgroup, Runtime{}), fromSetting)
	})

	t.Run("ignore current Go memory limit when memory_limit turns it off", func(t *testing.T) {
		prev := debug.SetMemoryLimit(128 * mib)
		t.Cleanup(func() { debug.SetMemoryLimit(prev) })
		prevCgroup := cgroupMemMB
		cgroupMemMB = func() (uint64, bool) { return 4096, true }
		t.Cleanup(func() { cgroupMemMB = prevCgroup })
		log := testlog.SetLogger(t)

		require.Equal(t, baseline, memEnvLimits(&log, memInput(Runtime{MemoryLimit: math.MaxInt64})).Server.CheckinLimit.Max)
	})
}

func TestGCPercent(t *testing.T) {
	t.Run("use gc_percent before runtime GOGC", func(t *testing.T) {
		setGOGC(t, 50)
		require.Equal(t, 20, gcPercent(Runtime{GCPercent: 20}))
	})

	t.Run("read runtime GOGC", func(t *testing.T) {
		setGOGC(t, 50)
		require.Equal(t, 50, gcPercent(Runtime{}))
	})

	t.Run("report GC off as -1", func(t *testing.T) {
		setGOGC(t, -1)
		require.Equal(t, -1, gcPercent(Runtime{}))
	})
}

func TestMemCheckinLimits(t *testing.T) {
	// perAgent is the memory of one agent with its long poll and idle connection.
	perAgent := int64(checkinLongPollBytes + checkinIdleConnBytes)

	// expectedCheckinMax applies the formula to memoryMB and gogc.
	expectedCheckinMax := func(memoryMB, gogc, cacheMaxCost int64) int64 {
		return (memoryMB*mib*fleetMemoryPercent/(100+gogc) - cacheMaxCost) / perAgent
	}

	testCases := []struct {
		Name               string
		TierCheckinMax     int64
		MemoryMB           uint64
		GOGC               int
		CacheMaxCost       int64
		ExpectedCheckinMax int64
	}{
		{
			Name:               "calculate limit from memory with default GOGC",
			TierCheckinMax:     1000,
			MemoryMB:           4096,
			GOGC:               100,
			ExpectedCheckinMax: expectedCheckinMax(4096, 100, defaultCacheMaxCost),
		},
		{
			Name:               "calculate limit from memory with GOGC=20",
			TierCheckinMax:     1000,
			MemoryMB:           4096,
			GOGC:               20,
			ExpectedCheckinMax: expectedCheckinMax(4096, 20, defaultCacheMaxCost),
		},
		{
			Name:               "use default GOGC when GC is off",
			TierCheckinMax:     1000,
			MemoryMB:           4096,
			GOGC:               -1,
			ExpectedCheckinMax: expectedCheckinMax(4096, 100, defaultCacheMaxCost),
		},
		{
			Name:               "use configured cache instead of tier cache",
			TierCheckinMax:     1000,
			MemoryMB:           4096,
			GOGC:               100,
			CacheMaxCost:       512 * mib,
			ExpectedCheckinMax: expectedCheckinMax(4096, 100, 512*mib),
		},
		{
			Name:               "keep tier limit when formula gives less",
			TierCheckinMax:     20_000,
			MemoryMB:           4096,
			GOGC:               100,
			ExpectedCheckinMax: 20_000,
		},
		{
			Name:               "cap limit when formula gives more than maximum",
			TierCheckinMax:     1000,
			MemoryMB:           262_144,
			GOGC:               100,
			ExpectedCheckinMax: maxMemCheckinLimit,
		},
		{
			Name:               "keep no limit when tier has none",
			MemoryMB:           4096,
			GOGC:               100,
			ExpectedCheckinMax: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			tier := defaultEnvLimits()
			tier.Server.CheckinLimit.Max = tc.TierCheckinMax

			l := memCheckinLimits(tier, tc.MemoryMB, tc.GOGC, tc.CacheMaxCost)

			require.Equal(t, tc.ExpectedCheckinMax, l.Server.CheckinLimit.Max)
			require.Equal(t, tc.TierCheckinMax, tier.Server.CheckinLimit.Max, "memCheckinLimits changed the tier")
		})
	}

	t.Run("keep max_connections ratio of tier", func(t *testing.T) {
		tier := defaultEnvLimits()
		tier.Server.CheckinLimit.Max = 1000
		tier.Server.MaxConnections = 3000

		l := memCheckinLimits(tier, 4096, 100, 0)

		require.Equal(t, 3*int(l.Server.CheckinLimit.Max), l.Server.MaxConnections)
	})
}

func TestAvailableMemoryMB(t *testing.T) {
	t.Run("uses GOMEMLIMIT when set", func(t *testing.T) {
		const setLimit = int64(256 * 1024 * 1024) // 256 MiB
		prev := debug.SetMemoryLimit(setLimit)
		t.Cleanup(func() { debug.SetMemoryLimit(prev) })

		got, source := availableMemoryMB()
		assert.Equal(t, uint64(256), got)
		assert.Equal(t, memSourceGoMemLimit, source)
	})

	t.Run("uses cgroup limit when GOMEMLIMIT is unset", func(t *testing.T) {
		prev := debug.SetMemoryLimit(math.MaxInt64)
		t.Cleanup(func() { debug.SetMemoryLimit(prev) })
		prevCgroup := cgroupMemMB
		cgroupMemMB = func() (uint64, bool) { return 128, true }
		t.Cleanup(func() { cgroupMemMB = prevCgroup })

		got, source := availableMemoryMB()
		assert.Equal(t, uint64(128), got)
		assert.Equal(t, memSourceCgroup, source)
	})

	t.Run("falls back to host RAM when GOMEMLIMIT and cgroup are both unset", func(t *testing.T) {
		prev := debug.SetMemoryLimit(math.MaxInt64)
		t.Cleanup(func() { debug.SetMemoryLimit(prev) })
		prevCgroup := cgroupMemMB
		cgroupMemMB = func() (uint64, bool) { return 0, false }
		t.Cleanup(func() { cgroupMemMB = prevCgroup })

		got, source := availableMemoryMB()
		assert.Equal(t, memory.TotalMemory()/1024/1024, got)
		assert.Equal(t, memSourceHost, source)
	})
}

func TestReadCgroupMemoryFile(t *testing.T) {
	writeFile := func(t *testing.T, content string) string {
		t.Helper()
		f, err := os.CreateTemp(t.TempDir(), "cgroup-memory-*")
		require.NoError(t, err)
		_, err = f.WriteString(content)
		require.NoError(t, err)
		require.NoError(t, f.Close())
		return f.Name()
	}

	t.Run("returns MiB for a valid byte limit", func(t *testing.T) {
		path := writeFile(t, "134217728\n") // 128 MiB
		mb, ok := readCgroupMemoryFile(path)
		assert.True(t, ok)
		assert.Equal(t, uint64(128), mb)
	})

	t.Run("returns false for 'max' (unlimited)", func(t *testing.T) {
		path := writeFile(t, "max\n")
		_, ok := readCgroupMemoryFile(path)
		assert.False(t, ok)
	})

	t.Run("returns false for the cgroup v1 unlimited sentinel", func(t *testing.T) {
		path := writeFile(t, strconv.FormatUint(cgroupV1UnlimitedMemoryLimit(), 10)+"\n")
		_, ok := readCgroupMemoryFile(path)
		assert.False(t, ok)
	})

	t.Run("returns false when file does not exist", func(t *testing.T) {
		_, ok := readCgroupMemoryFile("/nonexistent/cgroup/memory.max")
		assert.False(t, ok)
	})

	t.Run("returns false for invalid content", func(t *testing.T) {
		path := writeFile(t, "not-a-number\n")
		_, ok := readCgroupMemoryFile(path)
		assert.False(t, ok)
	})
}

const mib = 1024 * 1024

// setMemory makes memMB return memoryMB and source until the test ends.
func setMemory(t *testing.T, memoryMB uint64, source memSource) {
	t.Helper()
	prev := memMB
	memMB = func() (uint64, memSource) { return memoryMB, source }
	t.Cleanup(func() { memMB = prev })
}

// memInput returns an input with rt and the check-in limit from memory turned on.
func memInput(rt Runtime) *Input {
	return &Input{Server: Server{Runtime: rt, Features: FeatureFlags{CheckinLimitFromMemory: true}}}
}

// setGOGC sets the GOGC of the runtime until the test ends.
func setGOGC(t *testing.T, gogc int) {
	t.Helper()
	prev := debug.SetGCPercent(gogc)
	t.Cleanup(func() { debug.SetGCPercent(prev) })
}
