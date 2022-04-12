package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
)

// ErrDisabled is returned if the download hander endpoint is called when it's not enabled.
var ErrDisabled = errors.New("endpoint disabled")

// RetrievalError is an error type that indicates that there was an issue with the http request to retrieve a package from the upstream source.
type RetrievalError struct {
	url string
	err error
}

func (e RetrievalError) Error() string {
	return fmt.Sprintf("failed to retrieve %q err: %v", e.url, e.err)
}

func (e RetrievalError) Unwrap() error {
	return e.err
}

// Downloader will download and cache packages in order to serve them to agents on request.
// If a package that is not in the cache is requested, the server will download and verify it before serving it.
// If a retention period is configured then packages will be deleted from the cache after that period has elapsed.
// If a bandwidth limit is set, all packages are written with a shared rate.Limiter; the server will block writes to try to keep under the limit.
// agents that download may take more time as a result.
// If a concurrent access limit is set, the server will return a 429 if there are too many concurrent requests.
type Downloader struct {
	enabled     bool
	ctx         context.Context
	cancel      context.CancelFunc
	upstreamURI *url.URL

	fs   fs.FS
	root string
	lock *sync.RWMutex // lock file operations to try to make sure that only one attempt to download a package at once

	retention       time.Duration
	bandwidthLimit  *rate.Limiter
	concurrentLimit *semaphore.Weighted
	verifier        Verifier
}

// NewDownloader create a new downloader from config.
func NewDownloader(cfg *config.Server) (*Downloader, error) {
	var err error
	d := &Downloader{}
	if !cfg.PackageCache.Enabled {
		return d, nil
	}

	d.enabled = true
	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.upstreamURI, err = url.Parse(cfg.PackageCache.UpstreamURI)
	if err != nil {
		return nil, fmt.Errorf("unable to parse upstreamURI: %w", err)
	}

	// add filesystem
	d.fs = os.DirFS(cfg.PackageCache.Cache)
	fi, err := fs.Stat(d.fs, ".")
	if errors.Is(err, fs.ErrNotExist) {
		err = os.MkdirAll(cfg.PackageCache.Cache, 0750)
		if err != nil {
			return nil, fmt.Errorf("unable to create downloads dir %q: %w", cfg.PackageCache.Cache, err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("unable to open downloads dir %q: %w", cfg.PackageCache.Cache, err)
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("downloads %q is not a directory", cfg.PackageCache.Cache)
	}
	d.root = cfg.PackageCache.Cache
	d.lock = &sync.RWMutex{}
	d.retention = cfg.PackageCache.RetentionPeriod

	// if there is a retention period, need to check if existing packages are too old
	if d.retention > 0 {
		// filepath.WalkDir is used instead of fs.WalkDir as we want to be able to access the full file path.
		err := filepath.WalkDir(d.root, func(fPath string, entry fs.DirEntry, err error) error {
			if err != nil {
				log.Error().Err(err).Str("path", fPath).Msg("unable to scan")
			}
			if entry.IsDir() {
				return nil
			}

			// compare modtime against retention
			fi, err := entry.Info()
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			since := time.Since(fi.ModTime())
			if since >= d.retention {
				if err := d.removeFile(fPath); err != nil {
					log.Error().Err(err).Str("path", fPath).Msg("unable to remove file")
				}
			} else {
				go d.startDeletionTimer(d.retention-since, fPath)
			}
			return nil
		})
		if err != nil {
			log.Error().Err(err).Msg("scanning package cache failed")
		}
	}

	d.bandwidthLimit = rate.NewLimiter(rate.Limit(cfg.PackageCache.BandwidthLimit), int(cfg.PackageCache.BandwidthLimit)) // TODO configurable burst limit
	if cfg.PackageCache.BandwidthLimit < 0 {
		d.bandwidthLimit = nil
	}
	d.concurrentLimit = semaphore.NewWeighted(cfg.PackageCache.ConcurrentLimit)
	if cfg.PackageCache.ConcurrentLimit < 0 {
		d.concurrentLimit = nil
	}
	d.verifier = NewVerifier(nil) // TODO load Elastic's PGP key
	return d, nil
}

// closeFile will close the file and log any errors encountered
func closeFile(f fs.File) {
	if err := f.Close(); err != nil {
		fi, _ := f.Stat()
		log.Warn().Err(err).Str("file_name", fi.Name()).Msg("unable to close file")
	}
}

// Stop will cancel the downloader context to trigger an end to all ongoing operations.
// The rate limiter will stop accepting waits and return an error
// Any requests to the upstreamURI will be cancelled, and all cache retention goroutines are halted.
func (d *Downloader) Stop() {
	d.cancel()
}

// handleDownload is the httprouter handler for a cached packages.
func (rt Router) handleDownload(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	reqID := r.Header.Get(logger.HeaderRequestID)
	//start := time.Now()
	var (
		aName = ps.ByName("artifact")
		pName = ps.ByName("package")
	)
	zlog := log.With().
		Str(ECSHTTPRequestID, reqID).
		Str("remoteAddr", r.RemoteAddr).
		Logger()

	err := rt.dl.serve(w, r, aName, pName)
	if err != nil {
		resp := NewHTTPErrResp(err)
		zlog.WithLevel(resp.Level).Err(err).
			Msg("download request failed")
		if err := resp.Write(w); err != nil {
			zlog.Error().Err(err).Msg("failed writing error response")
		}
	}
}

// serve will serve packages using go's fileserver implementation using the enabled limiters.
func (d *Downloader) serve(w http.ResponseWriter, r *http.Request, aName, pName string) error {
	if !d.enabled {
		return ErrDisabled // return a 404
	}
	// check concurrent limit
	if d.concurrentLimit != nil {
		ok := d.concurrentLimit.TryAcquire(1)
		if !ok {
			return limit.ErrRateLimit // return a 429
		}
		defer d.concurrentLimit.Release(1)
	}

	// check if file exists
	if err := d.packageExists(aName, pName); err != nil {
		//get packages
		if err := d.getPackage(aName, pName); err != nil {
			return err // return 503
		}
	}

	// Wrap the response writer with the limiter and serve
	wr := limit.WrapResponseWriter(d.ctx, w, d.bandwidthLimit)
	h := http.StripPrefix("/api/downloads", http.FileServer(http.FS(d.fs)))
	d.lock.RLock()
	defer d.lock.RUnlock()
	h.ServeHTTP(wr, r)
	return nil
}

// packageExists will return an error if the requested package does not exist in the cache, or if the cached package has a size of 0
func (d *Downloader) packageExists(aName, pName string) error {
	d.lock.RLock()
	defer d.lock.RUnlock()
	// fs.Stat will reject any attempts to stat a path with ..
	// this is good as it prevents requests attempting to gather non-cached files
	fi, err := fs.Stat(d.fs, filepath.Join(aName, pName))
	if err != nil {
		return err
	}
	if fi.Size() < 1 {
		return fmt.Errorf("package %q has length 0", filepath.Join(aName, pName))
	}
	return nil
}

// getPackage will cache the requested package using the upstreamURI as a source.
// if the requested package is not an ".asc" or ".sha512" file then the associated files are downloaded and the package is verified.
// All files are removed if an error is encountered.
func (d *Downloader) getPackage(aName, pName string) error {
	// sanity check file path
	filePath := filepath.Clean(filepath.Join(d.root, aName, pName))
	if !strings.HasPrefix(filePath, d.root) {
		return fmt.Errorf("filepath invalid %q is not in package cache %q", filePath, d.root)
	}

	url, err := d.upstreamURI.Parse(path.Join(aName, pName))
	if err != nil {
		return fmt.Errorf("unable to build url from %q: %w", path.Join(aName, pName), err)
	}

	err = d.getFile(url.String(), filePath)
	if err != nil {
		return err
	}

	// verify download (using sha and asc)
	if !strings.HasSuffix(pName, ".asc") && !strings.HasSuffix(pName, ".sha512") {
		url, _ = d.upstreamURI.Parse(path.Join(aName, pName+".asc"))
		err = d.getFile(url.String(), filePath+".asc")
		if err != nil {
			if rErr := d.removeFile(filePath); rErr != nil {
				log.Error().Err(rErr).Msg("unable to remove file")
			}
			return err
		}
		url, _ = d.upstreamURI.Parse(path.Join(aName, pName+".sha512"))
		err = d.getFile(url.String(), filePath+".sha512")
		if err != nil {
			if rErr := d.removeFile(filePath); rErr != nil {
				log.Error().Err(rErr).Msg("unable to remove file")
			}
			return err
		}
		err = d.verifier.Verify(filePath)
		if err != nil {
			if rErr := d.removeFile(filePath); rErr != nil {
				log.Error().Err(rErr).Msg("unable to remove file")
			}
			return fmt.Errorf("package verification failed: %w", err)
		}
	}

	// delete package later
	if d.retention > 0 {
		go d.startDeletionTimer(d.retention, filePath)
	}

	return nil
}

// startDeletionTimer will call removeFile on path after dur
func (d *Downloader) startDeletionTimer(dur time.Duration, path string) {
	t := time.NewTimer(dur)
	select {
	case <-t.C:
		if err := d.removeFile(path); err != nil {
			log.Error().Err(err).Msg("unable to remove file")
		}
	case <-d.ctx.Done():
		t.Stop()
	}
}

// removeFile wraps remove with the filesystem lock
func (d *Downloader) removeFile(path string) error {
	d.lock.Lock()
	defer d.lock.Unlock()
	return remove(path)
}

// remove will remove path ignoring any ErrNotExist errors
// If path does not end in .asc or .sha512, then the .asc and .sha512 files are removed as well
func remove(path string) error {
	err := os.Remove(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if !strings.HasSuffix(path, ".asc") && !strings.HasSuffix(path, ".sha512") {
		if err := remove(path + ".asc"); err != nil {
			return err
		}
		if err := remove(path + ".sha512"); err != nil {
			return err
		}
	}
	return nil
}

// getFile retrieves the file at url and writes the body to path.
// If path contains subdirs they are created as well.
// The file is opened with create/write/truncate flags.
func (d *Downloader) getFile(url, path string) error {
	d.lock.Lock()
	defer d.lock.Unlock()
	rErr := &RetrievalError{url: url}

	// TODO maybe check if the path exists?
	err := os.MkdirAll(filepath.Dir(path), 0750)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		rErr.err = fmt.Errorf("failed to create directories: %w", err)
		return rErr
	}

	// TODO build an http client with httpcommon for proxy/tls support?
	client := &http.Client{}
	req, err := http.NewRequestWithContext(d.ctx, "GET", url, nil)
	if err != nil {
		rErr.err = fmt.Errorf("unable to create request: %w", err)
		return rErr
	}
	resp, err := client.Do(req)
	if err != nil {
		rErr.err = err
		return rErr
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != 200 {
		rErr.err = fmt.Errorf("response status %d", resp.StatusCode)
		return rErr
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		rErr.err = fmt.Errorf("unable to create file %q: %w", path, err)
		return rErr
	}
	defer closeFile(file)
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		rErr.err = fmt.Errorf("unable to write file %q: %w", path, err)
		return rErr
	}
	return nil
}
