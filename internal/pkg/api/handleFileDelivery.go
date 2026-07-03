// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/textproto"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/file"
	"github.com/elastic/fleet-server/v7/internal/pkg/file/delivery"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/go-elasticsearch/v8"
)

var (
	ErrBadRange                = errors.New("range not satisfiable")
	ErrClientFileForbidden     = errors.New("agent not authorized for library")
	ErrFileForDeliveryNotFound = errors.New("unable to retrieve file")
	ErrLibraryFileNotFound     = fmt.Errorf("%w from library", ErrFileForDeliveryNotFound)
	ErrTargetFileNotFound      = fmt.Errorf("%w for agent", ErrFileForDeliveryNotFound)

	// allowlist of clients to use file-library functionality
	// prevents arbitrary index reading unless integration opts in
	KnownProductOriginFileUsers = map[string]string{
		"endpoint-security": "endpoint",
	}
)

const HTTPProductOriginHeader = "X-elastic-product-origin"

type FileDeliveryT struct {
	bulker    bulk.Bulk
	cache     cache.Cache
	deliverer *delivery.Deliverer
	authAgent func(*http.Request, *string, bulk.Bulk, cache.Cache) (*model.Agent, error) // injectable for testing purposes
}

func NewFileDeliveryT(cfg *config.Server, bulker bulk.Bulk, chunkClient *elasticsearch.Client, cache cache.Cache) *FileDeliveryT {
	return &FileDeliveryT{
		bulker:    bulker,
		cache:     cache,
		deliverer: delivery.New(chunkClient, bulker, cfg.Limits.MaxFileStorageByteSize),
		authAgent: authAgent,
	}
}

func (ft *FileDeliveryT) handleSendFile(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, fileID string) error {
	agent, err := ft.authAgent(r, nil, ft.bulker, ft.cache)
	if err != nil {
		return err
	}

	// determine storage place for file lookup Can be either in integration libraries ( ?source=X ) OR agent-targeted, fleet-owned stream
	var info file.MetaDoc
	var idx string
	libStorageSrc := sanitizedIndexInput(r.URL.Query().Get("source"))
	if libStorageSrc != "" {
		// determine integration client for library file
		clientSrc := sanitizedIndexInput(r.Header.Get(HTTPProductOriginHeader))
		if clientSrc == "" {
			return fmt.Errorf("%w: Client not specified", ErrClientFileForbidden)
		}
		integration, ok := KnownProductOriginFileUsers[clientSrc]
		if !ok {
			return ErrClientFileForbidden
		}
		info, idx, err = ft.deliverer.FindLibraryFile(r.Context(), fileID, integration, libStorageSrc)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrLibraryFileNotFound, err)
		}
	} else {
		// file is not stored in wide-distribution, is limited to intended agents
		info, idx, err = ft.deliverer.FindFileForAgent(r.Context(), fileID, agent.Agent.ID)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrTargetFileNotFound, err)
		}
	}

	chunks, err := ft.deliverer.LocateChunks(r.Context(), zlog, fileID, idx)
	if errors.Is(err, delivery.ErrNoFile) {
		w.WriteHeader(http.StatusNotFound)
		return err
	}
	if err != nil {
		return err
	}
	w.Header().Set("Accept-Ranges", "bytes")

	// Send partial content if Range is requested
	ranges, err := parseRange(r.Header.Get("Range"), info.File.Size)
	if err != nil {
		w.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(info.File.Size, 10))
		return fmt.Errorf("%w: %w", ErrBadRange, err)
	}
	if sumRangesSize(ranges) > info.File.Size {
		// ignore bad-math or bad-acting client range requests, serve as normal
		ranges = nil
	}

	if len(ranges) > 0 {
		return ft.sendFileAsRanges(zlog, w, r, fileID, info, chunks, ranges)
	}
	// no ranges requested, send 200 response with all content
	return ft.sendFullFile(zlog, w, r, fileID, info, chunks)
}

func (ft *FileDeliveryT) sendFullFile(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, fileID string, info file.MetaDoc, chunks []file.ChunkInfo) error {
	// set headers before writing any chunks!

	// if mime_type was provided, set as Content-Type, otherwise fall back to octet-stream
	w.Header().Set("Content-Type", "application/octet-stream")
	if info.File.MimeType != "" {
		w.Header().Set("Content-Type", info.File.MimeType)
	}

	if info.File.Size > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(info.File.Size, 10))
	}

	if info.File.Hash != nil && info.File.Hash.SHA2 != "" {
		w.Header().Set("X-File-SHA2", info.File.Hash.SHA2)
	}

	// stream the chunks out
	return ft.deliverer.SendChunks(r.Context(), zlog, w, chunks, fileID, nil, nil)
}

func sanitizedIndexInput(s string) string {
	r := regexp.MustCompile(`[*?"<>\\/,|#]`) // bad characters
	return r.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "")
}

func (ft *FileDeliveryT) sendFileAsRanges(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, fileID string, info file.MetaDoc, chunks []file.ChunkInfo, ranges []httpRange) error {
	if len(ranges) > 1 {
		return errors.New("multipart ranges not supported")
	}
	ra := ranges[0]

	sort.SliceStable(chunks, func(i, j int) bool {
		return chunks[i].Pos < chunks[j].Pos
	})

	// reduce to fetch only required chunks.
	// Int64 Floor division used intentionally for index math
	chunkIdxStart := ra.start / info.File.ChunkSize
	chunkIdxStop := (ra.start + ra.length - 1) / info.File.ChunkSize
	chunks = chunks[chunkIdxStart : chunkIdxStop+1]

	// if supporting multiple ranges, this becomes multipart/byteranges !
	w.Header().Set("Content-Type", "application/octet-stream")
	if info.File.MimeType != "" {
		w.Header().Set("Content-Type", info.File.MimeType)
	}
	w.Header().Set("Content-Range", ra.contentRange(info.File.Size))
	w.Header().Set("Content-Length", strconv.FormatInt(ra.length, 10))

	w.WriteHeader(http.StatusPartialContent)

	startOffset := uint64(ra.start % info.File.ChunkSize)
	endOffset := uint64(((ra.start + ra.length - 1) % info.File.ChunkSize) + 1)
	return ft.deliverer.SendChunks(r.Context(), zlog, w, chunks, fileID, &startOffset, &endOffset)
}

/*
 * HTTP Range parsing
 *
 * modified from Go source http/fs.go
 * see NOTICE.txt for license
 */

// errNoOverlap is returned by serveContent's parseRange if first-byte-pos of
// all of the byte-range-spec values is greater than the content size.
var errNoOverlap = errors.New("invalid range: failed to overlap")

// httpRange specifies the byte range to be sent to the client.
type httpRange struct {
	start, length int64
}

func (r httpRange) contentRange(size int64) string {
	return fmt.Sprintf("bytes %d-%d/%d", r.start, r.start+r.length-1, size)
}

// parseRange parses a Range header string as per RFC 7233.
// errNoOverlap is returned if none of the ranges overlap.
func parseRange(s string, size int64) ([]httpRange, error) {
	if s == "" {
		return nil, nil // header not present
	}
	const b = "bytes="
	if !strings.HasPrefix(s, b) {
		return nil, errors.New("invalid range")
	}
	var ranges []httpRange
	noOverlap := false
	for ra := range strings.SplitSeq(s[len(b):], ",") {
		ra = textproto.TrimString(ra)
		if ra == "" {
			continue
		}
		start, end, ok := strings.Cut(ra, "-")
		if !ok {
			return nil, errors.New("invalid range")
		}
		start, end = textproto.TrimString(start), textproto.TrimString(end)
		var r httpRange
		if start == "" {
			// If no start is specified, end specifies the
			// range start relative to the end of the file,
			// and we are dealing with <suffix-length>
			// which has to be a non-negative integer as per
			// RFC 7233 Section 2.1 "Byte-Ranges".
			if end == "" || end[0] == '-' {
				return nil, errors.New("invalid range")
			}
			i, err := strconv.ParseInt(end, 10, 64)
			if i < 0 || err != nil {
				return nil, errors.New("invalid range")
			}
			if i > size {
				i = size
			}
			r.start = size - i
			r.length = size - r.start
		} else {
			i, err := strconv.ParseInt(start, 10, 64)
			if err != nil || i < 0 {
				return nil, errors.New("invalid range")
			}
			if i >= size {
				// If the range begins after the size of the content,
				// then it does not overlap.
				noOverlap = true
				continue
			}
			r.start = i
			if end == "" {
				// If no end is specified, range extends to end of the file.
				r.length = size - r.start
			} else {
				i, err := strconv.ParseInt(end, 10, 64)
				if err != nil || r.start > i {
					return nil, errors.New("invalid range")
				}
				if i >= size {
					i = size - 1
				}
				r.length = i - r.start + 1
			}
		}
		ranges = append(ranges, r)
	}
	if noOverlap && len(ranges) == 0 {
		// The specified ranges did not overlap with the content.
		return nil, errNoOverlap
	}
	return ranges, nil
}

func sumRangesSize(ranges []httpRange) int64 {
	var size int64 = 0
	for _, ra := range ranges {
		size += ra.length
	}
	return size
}
