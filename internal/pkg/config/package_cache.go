package config

import (
	"os"
	"path/filepath"
	"time"
)

// PackageCache is the configuration for the package cache
type PackageCache struct {
	Enabled         bool          `config:"enabled"`
	Cache           string        `config:"cache"`
	RetentionPeriod time.Duration `config:"retention_period"`
	UpstreamURI     string        `config:"upstreamURI"`
	BandwidthLimit  float64       `config:"bandwidth_limit"`
	ConcurrentLimit int64         `config:"concurrent_limit"`
}

// InitDefaults initializes the DownloadCache as disabled.
func (d *PackageCache) InitDefaults() {
	cwd, err := os.Getwd()
	if err != nil {
		// something really wrong here
		panic(err)
	}
	d.Enabled = false
	d.Cache = filepath.Join(cwd, "fleet-package-cache")
	d.RetentionPeriod = time.Duration(-1)
	d.UpstreamURI = "https://artifacts.elastic.co/downloads"
	d.BandwidthLimit = -1
	d.ConcurrentLimit = -1
}
