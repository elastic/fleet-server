// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package uploader

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/file"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/gofrs/uuid/v5"
	"go.elastic.co/apm/v2"
)

var (
	ErrInvalidUploadID  = errors.New("active upload not found with this ID, it may be expired")
	ErrFileSizeTooLarge = errors.New("this file exceeds the maximum allowed file size")
	ErrMissingChunks    = errors.New("file data incomplete, not all chunks were uploaded")
	ErrHashMismatch     = errors.New("hash does not match")
	ErrUploadExpired    = errors.New("upload has expired")
	ErrUploadStopped    = errors.New("upload has stopped")
	ErrInvalidChunkNum  = errors.New("invalid chunk number")

	ErrPayloadRequired  = errors.New("upload start payload required")
	ErrFileSizeRequired = errors.New("file.size is required")
	ErrInvalidFileSize  = errors.New("invalid filesize")
	ErrFieldRequired    = errors.New("field required")

	ErrPayloadSizeTooLarge = errors.New("payload size too large")
)

type Uploader struct {
	cache     cache.Cache // cache of file metadata doc info
	sizeLimit int64
	timeLimit time.Duration

	chunkClient *elasticsearch.Client
	bulker      bulk.Bulk
}

func New(chunkClient *elasticsearch.Client, bulker bulk.Bulk, cache cache.Cache, sizeLimit int64, timeLimit time.Duration) *Uploader {
	return &Uploader{
		chunkClient: chunkClient,
		bulker:      bulker,
		sizeLimit:   sizeLimit,
		timeLimit:   timeLimit,
		cache:       cache,
	}
}

// Start an upload operation
func (u *Uploader) Begin(ctx context.Context, namespaces []string, data JSDict) (file.Info, error) {
	vSpan, _ := apm.StartSpan(ctx, "validateFileInfo", "validate")
	if data == nil {
		vSpan.End()
		return file.Info{}, ErrPayloadRequired
	}

	/*
		Validation and Input parsing
	*/

	// make sure all required fields are present and non-empty
	if err := validateUploadPayload(data); err != nil {
		vSpan.End()
		return file.Info{}, err
	}

	size, _ := data.Int64("file", "size")
	if size > u.sizeLimit {
		vSpan.End()
		return file.Info{}, ErrFileSizeTooLarge
	}

	uid, err := uuid.NewV4()
	vSpan.End()
	if err != nil {
		return file.Info{}, fmt.Errorf("unable to generate upload operation ID: %w", err)
	}
	id := uid.String()

	// grab required fields that were checked already in validation step
	agentID, _ := data.Str("agent_id")
	actionID, _ := data.Str("action_id")
	source, _ := data.Str("src")
	docID := fmt.Sprintf("%s.%s", actionID, agentID)

	info := file.Info{
		ID:         id,
		DocID:      docID,
		AgentID:    agentID,
		ActionID:   actionID,
		Namespaces: namespaces,
		ChunkSize:  file.MaxChunkSize,
		Source:     source,
		Total:      size,
		Status:     file.StatusAwaiting,
		Start:      time.Now(),
	}
	chunkCount := info.Total / info.ChunkSize
	if info.Total%info.ChunkSize > 0 {
		chunkCount += 1
	}
	info.Count = int(chunkCount)

	/*
		Enrich document with additional server-side fields
	*/

	if err := data.Put(info.ChunkSize, "file", "ChunkSize"); err != nil {
		return file.Info{}, err
	}
	if err := data.Put(info.Status, "file", "Status"); err != nil {
		return file.Info{}, err
	}
	if err := data.Put(id, "upload_id"); err != nil {
		return file.Info{}, err
	}
	if err := data.Put(info.Start.UnixMilli(), "upload_start"); err != nil {
		return file.Info{}, err
	}
	if err := data.Put(info.Start.UnixMilli(), "@timestamp"); err != nil {
		return file.Info{}, err
	}
	if err := data.Put(info.Namespaces, "namespaces"); err != nil {
		return file.Info{}, err
	}

	/*
		Write to storage
	*/
	doc, err := json.Marshal(data)
	if err != nil {
		return file.Info{}, err
	}
	_, err = CreateFileDoc(ctx, u.bulker, doc, source, docID)
	if err != nil {
		return file.Info{}, err
	}

	return info, nil
}

func (u *Uploader) Chunk(ctx context.Context, uplID string, chunkNum int, chunkHash string) (file.Info, file.ChunkInfo, error) {
	// find the upload, details, and status associated with the file upload
	info, err := u.GetUploadInfo(ctx, uplID)
	if err != nil {
		return file.Info{}, file.ChunkInfo{}, err
	}

	/*
		Verify Chunk upload can proceed
	*/

	if info.Expired(u.timeLimit) {
		return file.Info{}, file.ChunkInfo{}, ErrUploadExpired
	}
	if !info.StatusCanUpload() {
		return file.Info{}, file.ChunkInfo{}, ErrUploadStopped
	}
	if chunkNum < 0 || chunkNum >= info.Count {
		return file.Info{}, file.ChunkInfo{}, ErrInvalidChunkNum
	}

	return info, file.ChunkInfo{
		Pos:  chunkNum,
		BID:  info.DocID,
		Last: chunkNum == info.Count-1,
		Size: int(info.ChunkSize),
		SHA2: chunkHash,
	}, nil
}

func validateUploadPayload(info JSDict) error {

	required := [][]string{
		{"file", "name"},
		{"file", "mime_type"},
		{"action_id"},
		{"agent_id"},
		{"src"},
	}

	for _, fields := range required {
		if value, ok := info.Str(fields...); !ok || strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required: %w", strings.Join(fields, "."), ErrFieldRequired)
		}
	}

	if size, ok := info.Int64("file", "size"); !ok {
		return ErrFileSizeRequired
	} else if size <= 0 {
		return fmt.Errorf("file.size: %d: %w", size, ErrInvalidFileSize)
	}
	return nil
}

// GetUploadInfo searches for Upload Metadata document in local memory cache if available
// otherwise, fetches from elasticsearch and caches for next use
func (u *Uploader) GetUploadInfo(ctx context.Context, uploadID string) (file.Info, error) {
	span, ctx := apm.StartSpan(ctx, "getFileInfo", "process")
	defer span.End()
	// Fetch metadata doc, if not cached
	info, exist := u.cache.GetUpload(uploadID)
	if exist {
		return info, nil
	}

	// not found in cache, try fetching
	info, err := file.GetInfo(ctx, u.bulker, UploadHeaderIndexPattern, uploadID)
	if err != nil {
		return file.Info{}, fmt.Errorf("unable to retrieve upload info: %w", err)
	}
	u.cache.SetUpload(uploadID, info)
	return info, nil
}
