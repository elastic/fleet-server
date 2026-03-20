// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build e2e

package e2e

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// SearchResp is the response body for the artifacts search API
type SearchResp struct {
	Packages map[string]Artifact `json:"packages"`
}

// Artifact describes an elastic artifact available through the API.
type Artifact struct {
	URL string `json:"url"`
	//SHAURL       string `json:"sha_url"`      // Unused
	//Type         string `json:"type"`         // Unused
	//Architecture string `json:"architecture"` // Unused
}

// agentCacheDir returns the directory used to cache downloaded elastic-agent archives.
func agentCacheDir() string {
	return filepath.Join(os.TempDir(), "fleet-server-e2e")
}

// downloadElasticAgent searches the artifacts API for the snapshot version
// specified by ELASTICSEARCH_VERSION and returns a ReadCloser for the
// elastic-agent archive matching the current OS and architecture.
//
// The archive is cached on disk. The remote .sha512 file is fetched first; if
// it matches the cached file's checksum the download is skipped.
func downloadElasticAgent(ctx context.Context, t *testing.T, client *http.Client) io.ReadCloser {
	t.Helper()
	// Use version associated with latest DRA instead of fleet-server's version to avoid breaking on fleet-server version bumps
	draVersion, ok := os.LookupEnv("ELASTICSEARCH_VERSION")
	if !ok || draVersion == "" {
		t.Fatal("ELASTICSEARCH_VERSION is not set")
	}
	draSplit := strings.Split(draVersion, "-")
	if len(draSplit) == 3 {
		draVersion = draSplit[0] + "-" + draSplit[2] // remove hash
	} else if len(draSplit) > 3 {
		t.Fatalf("Unsupported ELASTICSEARCH_VERSION format, expected 3 segments got: %v", draSplit)
	}
	t.Logf("Using ELASTICSEARCH_VERSION=%s for agent download", draVersion)

	req, err := http.NewRequestWithContext(ctx, "GET", "https://artifacts-api.elastic.co/v1/search/"+draVersion, nil)
	if err != nil {
		t.Fatalf("failed to create search request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to query artifacts API: %v", err)
	}

	var body SearchResp
	err = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("failed to decode artifacts API response: %v", err)
	}

	fType := "tar.gz"
	if runtime.GOOS == "windows" {
		fType = "zip"
	}
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}
	if arch == "arm64" && runtime.GOOS == "darwin" {
		arch = "aarch64"
	}

	fileName := fmt.Sprintf("elastic-agent-%s-%s-%s.%s", draVersion, runtime.GOOS, arch, fType)
	pkg, ok := body.Packages[fileName]
	if !ok {
		t.Fatalf("unable to find package download for fileName=%s", fileName)
	}

	cacheDir := agentCacheDir()
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		t.Fatalf("failed to create cache dir: %v", err)
	}
	cachePath := filepath.Join(cacheDir, fileName)

	// Fetch the remote SHA512 checksum (small file, always fetched).
	remoteSHA := fetchRemoteSHA512(ctx, t, client, pkg.URL+".sha512")

	// If the cached file exists and matches, use it directly.
	if localSHA, err := sha512OfFile(cachePath); err == nil && strings.EqualFold(localSHA, remoteSHA) {
		t.Logf("Using cached elastic-agent from %s", cachePath)
		f, err := os.Open(cachePath)
		if err != nil {
			t.Fatalf("failed to open cached elastic-agent: %v", err)
		}
		return f
	}

	// Download to a temp file first so a partial download never poisons the cache.
	t.Logf("Downloading elastic-agent from %s", pkg.URL)
	tmp, err := os.CreateTemp(cacheDir, fileName+".tmp-*")
	if err != nil {
		t.Fatalf("failed to create temp file for download: %v", err)
	}
	tmpName := tmp.Name()

	req, err = http.NewRequestWithContext(ctx, "GET", pkg.URL, nil)
	if err != nil {
		tmp.Close()
		os.Remove(tmpName)
		t.Fatalf("failed to create download request: %v", err)
	}
	downloadResp, err := client.Do(req)
	if err != nil {
		tmp.Close()
		os.Remove(tmpName)
		t.Fatalf("failed to download elastic-agent: %v", err)
	}
	defer downloadResp.Body.Close()

	h := sha512.New()
	if _, err := io.Copy(tmp, io.TeeReader(downloadResp.Body, h)); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		t.Fatalf("failed to write elastic-agent download: %v", err)
	}
	tmp.Close()

	// Verify the downloaded file's checksum before caching.
	downloadedSHA := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(downloadedSHA, remoteSHA) {
		os.Remove(tmpName)
		t.Fatalf("elastic-agent checksum mismatch: got %s, want %s", downloadedSHA, remoteSHA)
	}

	if err := os.Rename(tmpName, cachePath); err != nil {
		os.Remove(tmpName)
		t.Fatalf("failed to move downloaded file to cache: %v", err)
	}

	f, err := os.Open(cachePath)
	if err != nil {
		t.Fatalf("failed to open cached elastic-agent after download: %v", err)
	}
	return f
}

// fetchRemoteSHA512 downloads the .sha512 file at url and returns the hex checksum.
// The .sha512 file format is "<hex>  <filename>" (sha512sum output), so only the
// first whitespace-delimited field is returned.
func fetchRemoteSHA512(ctx context.Context, t *testing.T, client *http.Client, url string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		t.Fatalf("failed to create sha512 request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to fetch sha512 file: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read sha512 file: %v", err)
	}
	return strings.Fields(string(data))[0]
}

// sha512OfFile returns the hex-encoded SHA-512 checksum of the file at path.
func sha512OfFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
