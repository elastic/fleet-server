// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	tst "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/sync/semaphore"
)

type mockBulker struct {
	tst.MockBulk
	apiErr error
}

func (m *mockBulker) ApiKeyAuth(ctx context.Context, key bulk.ApiKey) (*bulk.SecurityInfo, error) { //nolint:stylecheck // is a bulk.Bulk interface method
	return &bulk.SecurityInfo{Enabled: true}, m.apiErr
}

type mockVerifier struct {
	mock.Mock
}

func (m *mockVerifier) Verify(path string) error {
	args := m.Called(path)
	return args.Error(0)
}

// prep a temp dir with the following non-empty files:
//    artifact/package
//    artifact/package.sha512
//    artifact/package.asc
func prepDownloadsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	err := os.Mkdir(filepath.Join(dir, "artifact"), 0750)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "artifact", "package")
	err = os.WriteFile(path, []byte("testing"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(path+".asc", []byte("testing"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(path+".sha512", []byte("testing"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// return a test server that responds for downloads/artifact/test and downloads/complex/path/to/artifact/test
func testUpstreamServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasPrefix(req.URL.Path, "/downloads/artifact/test") {
			t.Logf("request status: 200 path: %s", req.URL.Path)
			_, _ = w.Write([]byte("Hello, World!"))
			return
		}
		if strings.HasPrefix(req.URL.Path, "/downloads/complex/path/to/artifact/test") {
			t.Logf("request status: 200 path: %s", req.URL.Path)
			_, _ = w.Write([]byte("hello, world!"))
			return
		}
		w.WriteHeader(500)
		t.Logf("request status: 500 path: %s", req.URL.Path)
	}))
}

func TestNewDownloader(t *testing.T) {
	t.Run("directory creation with limiters", func(t *testing.T) {
		dir := t.TempDir()
		d, err := NewDownloader(&config.Server{
			PackageCache: config.PackageCache{
				Enabled:         true,
				Cache:           filepath.Join(dir, "downloads"),
				BandwidthLimit:  float64(100),
				ConcurrentLimit: int64(100),
			},
		}, nil, nil)
		assert.NoError(t, err)
		assert.NotNil(t, d.bandwidthLimit)
		assert.NotNil(t, d.concurrentLimit)

		fi, err := os.Stat(filepath.Join(dir, "downloads"))
		assert.NoError(t, err)
		assert.True(t, fi.IsDir(), "expected file info to indicate directory")
	})

	t.Run("no directory creation no limiters no package clearing", func(t *testing.T) {
		dir := prepDownloadsDir(t)
		d, err := NewDownloader(&config.Server{
			PackageCache: config.PackageCache{
				Enabled:         true,
				Cache:           dir,
				BandwidthLimit:  float64(-1),
				ConcurrentLimit: int64(-1),
			},
		}, nil, nil)
		assert.NoError(t, err)
		assert.Nil(t, d.bandwidthLimit)
		assert.Nil(t, d.concurrentLimit)

		_, err = os.Stat(filepath.Join(dir, "artifact", "package"))
		assert.NoError(t, err)
		_, err = os.Stat(filepath.Join(dir, "artifact", "package.sha512"))
		assert.NoError(t, err)
		_, err = os.Stat(filepath.Join(dir, "artifact", "package.asc"))
		assert.NoError(t, err)
	})

	t.Run("old package clearing", func(t *testing.T) {
		dir := prepDownloadsDir(t)
		time.Sleep(time.Millisecond)
		d, err := NewDownloader(&config.Server{
			PackageCache: config.PackageCache{
				Enabled:         true,
				Cache:           dir,
				RetentionPeriod: time.Nanosecond,
				BandwidthLimit:  float64(-1),
				ConcurrentLimit: int64(-1),
			},
		}, nil, nil)
		assert.NoError(t, err)
		assert.Nil(t, d.bandwidthLimit)
		assert.Nil(t, d.concurrentLimit)

		_, err = os.Stat(filepath.Join(dir, "artifact", "package"))
		assert.ErrorIs(t, err, fs.ErrNotExist)
		_, err = os.Stat(filepath.Join(dir, "artifact", "package.sha512"))
		assert.ErrorIs(t, err, fs.ErrNotExist)
		_, err = os.Stat(filepath.Join(dir, "artifact", "package.asc"))
		assert.ErrorIs(t, err, fs.ErrNotExist)
	})
}

func Test_Downloader_serve(t *testing.T) {
	t.Run("downloader disabled", func(t *testing.T) {
		d := &Downloader{enabled: false}
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://example.com/api/downloads/artifact/package", nil)

		err := d.serve(w, req, "artifact/package")
		assert.ErrorIs(t, err, ErrDisabled)
	})

	t.Run("concurrency limit reached", func(t *testing.T) {
		l := semaphore.NewWeighted(int64(1))
		if !l.TryAcquire(1) {
			t.Fatal("unable to get semaphore")
		}
		d := &Downloader{
			enabled:         true,
			concurrentLimit: l,
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://example.com/api/downloads/artifact/package", nil)

		err := d.serve(w, req, "artifact/package")
		assert.ErrorIs(t, err, limit.ErrRateLimit)
	})

	t.Run("not authorized", func(t *testing.T) {
		cache, err := cache.New(cache.Config{NumCounters: 100, MaxCost: 100000})
		if err != nil {
			t.Fatal(err)
		}
		b := &mockBulker{apiErr: ErrAPIKeyNotEnabled}

		d := &Downloader{
			enabled:         true,
			cache:           cache,
			bulker:          b,
			concurrentLimit: semaphore.NewWeighted(1),
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://example.com/api/downloads/artifact/package", nil)
		req.Header.Set("Authorization", "ApiKey aWQ6a2V5")

		err = d.serve(w, req, "artifact/package")
		assert.ErrorIs(t, err, ErrAPIKeyNotEnabled)
	})

	t.Run("package exists", func(t *testing.T) {
		cache, err := cache.New(cache.Config{NumCounters: 100, MaxCost: 100000})
		if err != nil {
			t.Fatal(err)
		}
		b := &mockBulker{}

		dir := prepDownloadsDir(t)
		d := &Downloader{
			enabled:         true,
			cache:           cache,
			bulker:          b,
			fs:              os.DirFS(dir),
			root:            dir,
			lock:            &sync.RWMutex{},
			concurrentLimit: semaphore.NewWeighted(1),
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://example.com/api/downloads/artifact/package", nil)
		req.Header.Set("Authorization", "ApiKey aWQ6a2V5")

		err = d.serve(w, req, "artifact/package")
		assert.NoError(t, err)

		res := w.Result()
		assert.Equal(t, 200, res.StatusCode)

		p, err := io.ReadAll(res.Body)
		assert.NoError(t, err)
		assert.Equal(t, []byte("testing"), p)
		assert.NoError(t, res.Body.Close())
	})

	t.Run("package does not exist", func(t *testing.T) {
		cache, err := cache.New(cache.Config{NumCounters: 100, MaxCost: 100000})
		if err != nil {
			t.Fatal(err)
		}
		b := &mockBulker{}

		dir := prepDownloadsDir(t)
		path := filepath.Join(dir, "artifact", "test")

		server := testUpstreamServer(t)
		defer server.Close()
		url, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}

		v := &mockVerifier{}
		v.On("Verify", path).Return(nil)

		d := &Downloader{
			enabled:         true,
			cache:           cache,
			bulker:          b,
			ctx:             context.Background(),
			upstreamURI:     url,
			fs:              os.DirFS(dir),
			root:            dir,
			lock:            &sync.RWMutex{},
			concurrentLimit: semaphore.NewWeighted(1),
			verifier:        v,
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://example.com/api/downloads/artifact/test", nil)
		req.Header.Set("Authorization", "ApiKey aWQ6a2V5")

		err = d.serve(w, req, "artifact/test")
		assert.NoError(t, err)
		v.AssertExpectations(t)

		res := w.Result()
		assert.Equal(t, 200, res.StatusCode)

		p, err := io.ReadAll(res.Body)
		assert.NoError(t, err)
		assert.Equal(t, []byte("Hello, World!"), p)
		assert.NoError(t, res.Body.Close())

		_, err = os.Stat(path)
		assert.NoError(t, err)
		_, err = os.Stat(path + ".asc")
		assert.NoError(t, err)
		_, err = os.Stat(path + ".sha512")
		assert.NoError(t, err)
	})

	t.Run("package does not exist complex path", func(t *testing.T) {
		cache, err := cache.New(cache.Config{NumCounters: 100, MaxCost: 100000})
		if err != nil {
			t.Fatal(err)
		}
		b := &mockBulker{}

		dir := prepDownloadsDir(t)
		path := filepath.Join(dir, "complex", "path", "to", "artifact", "test")

		server := testUpstreamServer(t)
		defer server.Close()
		url, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}

		v := &mockVerifier{}
		v.On("Verify", path).Return(nil)

		d := &Downloader{
			enabled:         true,
			cache:           cache,
			bulker:          b,
			ctx:             context.Background(),
			upstreamURI:     url,
			fs:              os.DirFS(dir),
			root:            dir,
			lock:            &sync.RWMutex{},
			concurrentLimit: semaphore.NewWeighted(1),
			verifier:        v,
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://example.com/api/downloads/complex/path/to/artifact/test", nil)
		req.Header.Set("Authorization", "ApiKey aWQ6a2V5")

		err = d.serve(w, req, "complex/path/to/artifact/test")
		assert.NoError(t, err)
		v.AssertExpectations(t)

		res := w.Result()
		assert.Equal(t, 200, res.StatusCode)

		p, err := io.ReadAll(res.Body)
		assert.NoError(t, err)
		assert.Equal(t, []byte("hello, world!"), p)
		assert.NoError(t, res.Body.Close())

		_, err = os.Stat(path)
		assert.NoError(t, err)
		_, err = os.Stat(path + ".asc")
		assert.NoError(t, err)
		_, err = os.Stat(path + ".sha512")
		assert.NoError(t, err)
	})

	t.Run("package retrieval fails", func(t *testing.T) {
		cache, err := cache.New(cache.Config{NumCounters: 100, MaxCost: 100000})
		if err != nil {
			t.Fatal(err)
		}
		b := &mockBulker{}

		dir := prepDownloadsDir(t)
		path := filepath.Join(dir, "test", "test")

		server := testUpstreamServer(t)
		defer server.Close()
		url, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}

		d := &Downloader{
			enabled:         true,
			cache:           cache,
			bulker:          b,
			ctx:             context.Background(),
			upstreamURI:     url,
			fs:              os.DirFS(dir),
			root:            dir,
			lock:            &sync.RWMutex{},
			concurrentLimit: semaphore.NewWeighted(1),
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://example.com/api/downloads/test/test", nil)
		req.Header.Set("Authorization", "ApiKey aWQ6a2V5")

		err = d.serve(w, req, "test/test")
		var retErr *RetrievalError
		assert.ErrorAs(t, err, &retErr)

		_, err = os.Stat(path)
		assert.ErrorIs(t, err, fs.ErrNotExist)
		_, err = os.Stat(path + ".asc")
		assert.ErrorIs(t, err, fs.ErrNotExist)
		_, err = os.Stat(path + ".sha512")
		assert.ErrorIs(t, err, fs.ErrNotExist)
	})
}

func Test_Downloader_packageExists(t *testing.T) {
	t.Run("package exists", func(t *testing.T) {
		dir := prepDownloadsDir(t)

		d := Downloader{
			fs:   os.DirFS(dir),
			root: dir,
			lock: &sync.RWMutex{},
		}
		err := d.packageExists("artifact/package")
		assert.NoError(t, err)
	})

	t.Run("package does not exist", func(t *testing.T) {
		dir := prepDownloadsDir(t)

		d := Downloader{
			fs:   os.DirFS(dir),
			root: dir,
			lock: &sync.RWMutex{},
		}
		err := d.packageExists("artifact/test")
		assert.ErrorIs(t, err, fs.ErrNotExist)
	})

	t.Run("package is empty", func(t *testing.T) {
		dir := prepDownloadsDir(t)
		err := os.WriteFile(filepath.Join(dir, "artifact", "test"), []byte(""), 0600)
		if err != nil {
			t.Fatal(err)
		}

		d := Downloader{
			fs:   os.DirFS(dir),
			root: dir,
			lock: &sync.RWMutex{},
		}
		err = d.packageExists("artifact/test")
		assert.ErrorContains(t, err, "has length 0")
	})
}

func Test_Downloader_getPackage(t *testing.T) {
	t.Run("retrieval of package and verification succeeds", func(t *testing.T) {
		server := testUpstreamServer(t)
		defer server.Close()
		url, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}

		dir := prepDownloadsDir(t)
		path := filepath.Join(dir, "artifact", "test")

		v := &mockVerifier{}
		v.On("Verify", path).Return(nil)

		d := Downloader{
			ctx:         context.Background(),
			upstreamURI: url,
			fs:          os.DirFS(dir),
			root:        dir,
			lock:        &sync.RWMutex{},
			verifier:    v,
		}
		err = d.getPackage("artifact/test")
		assert.NoError(t, err)
		v.AssertExpectations(t)

		_, err = os.Stat(path)
		assert.NoError(t, err)
		_, err = os.Stat(path + ".asc")
		assert.NoError(t, err)
		_, err = os.Stat(path + ".sha512")
		assert.NoError(t, err)
	})

	t.Run("package verification fails", func(t *testing.T) {
		server := testUpstreamServer(t)
		defer server.Close()
		url, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}

		dir := prepDownloadsDir(t)
		path := filepath.Join(dir, "artifact", "test")

		v := &mockVerifier{}
		v.On("Verify", path).Return(ErrChecksumMismatch)

		d := Downloader{
			ctx:         context.Background(),
			upstreamURI: url,
			fs:          os.DirFS(dir),
			root:        dir,
			lock:        &sync.RWMutex{},
			verifier:    v,
		}
		err = d.getPackage("artifact/test")
		assert.ErrorIs(t, err, ErrChecksumMismatch)
		v.AssertExpectations(t)

		_, err = os.Stat(path)
		assert.ErrorIs(t, err, fs.ErrNotExist)
		_, err = os.Stat(path + ".asc")
		assert.ErrorIs(t, err, fs.ErrNotExist)
		_, err = os.Stat(path + ".sha512")
		assert.ErrorIs(t, err, fs.ErrNotExist)
	})

	t.Run("package retrieval fails", func(t *testing.T) {
		server := testUpstreamServer(t)
		defer server.Close()
		url, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}

		dir := prepDownloadsDir(t)
		path := filepath.Join(dir, "test", "test")

		v := &mockVerifier{}

		d := Downloader{
			ctx:         context.Background(),
			upstreamURI: url,
			fs:          os.DirFS(dir),
			root:        dir,
			lock:        &sync.RWMutex{},
			verifier:    v,
		}
		err = d.getPackage("test/test")
		var retErr *RetrievalError
		assert.ErrorAs(t, err, &retErr)
		v.AssertNotCalled(t, "Verify")

		_, err = os.Stat(path)
		assert.ErrorIs(t, err, fs.ErrNotExist)
		_, err = os.Stat(path + ".asc")
		assert.ErrorIs(t, err, fs.ErrNotExist)
		_, err = os.Stat(path + ".sha512")
		assert.ErrorIs(t, err, fs.ErrNotExist)
	})
}

func Test_Downloader_startDeletionTimer(t *testing.T) {
	dir := prepDownloadsDir(t)
	path := filepath.Join(dir, "artifact", "package")
	d := &Downloader{
		ctx:  context.Background(),
		lock: &sync.RWMutex{},
	}

	d.startDeletionTimer(time.Nanosecond, path)
	_, err := os.Stat(path)
	assert.ErrorIs(t, err, fs.ErrNotExist)
	_, err = os.Stat(path + ".asc")
	assert.ErrorIs(t, err, fs.ErrNotExist)
	_, err = os.Stat(path + ".sha512")
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func Test_Downloader_removeFile(t *testing.T) {
	t.Run("test package deletion", func(t *testing.T) {
		dir := prepDownloadsDir(t)
		path := filepath.Join(dir, "artifact", "package")
		d := &Downloader{
			lock: &sync.RWMutex{},
		}

		err := d.removeFile(path)
		assert.NoError(t, err)

		_, err = os.Stat(path)
		assert.ErrorIs(t, err, fs.ErrNotExist)
		_, err = os.Stat(path + ".asc")
		assert.ErrorIs(t, err, fs.ErrNotExist)
		_, err = os.Stat(path + ".sha512")
		assert.ErrorIs(t, err, fs.ErrNotExist)
	})

	t.Run("test single file deletion", func(t *testing.T) {
		dir := prepDownloadsDir(t)
		path := filepath.Join(dir, "artifact", "package")
		d := &Downloader{
			lock: &sync.RWMutex{},
		}

		err := d.removeFile(path + ".asc")
		assert.NoError(t, err)

		_, err = os.Stat(path + ".asc")
		assert.ErrorIs(t, err, fs.ErrNotExist)
		_, err = os.Stat(path)
		assert.NoError(t, err)
		_, err = os.Stat(path + ".sha512")
		assert.NoError(t, err)
	})

	t.Run("test non-existent file deletion", func(t *testing.T) {
		dir := prepDownloadsDir(t)
		path := filepath.Join(dir, "artifact", "package")
		d := &Downloader{
			lock: &sync.RWMutex{},
		}

		err := d.removeFile(path + ".fake")
		assert.NoError(t, err)

		_, err = os.Stat(path)
		assert.NoError(t, err)
		_, err = os.Stat(path + ".asc")
		assert.NoError(t, err)
		_, err = os.Stat(path + ".sha512")
		assert.NoError(t, err)
	})
}
