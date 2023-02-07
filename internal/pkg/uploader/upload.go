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
	"github.com/elastic/fleet-server/v7/internal/pkg/uploader/upload"
	"github.com/elastic/go-elasticsearch/v8"

	"github.com/google/uuid"
)

const (
	// specification-designated maximum
	MaxChunkSize = 4194304 // 4 MiB
)

var (
	ErrInvalidUploadID  = errors.New("active upload not found with this ID, it may be expired")
	ErrFileSizeTooLarge = errors.New("this file exceeds the maximum allowed file size")
	ErrMissingChunks    = errors.New("file data incomplete, not all chunks were uploaded")
	ErrHashMismatch     = errors.New("hash does not match")
	ErrUploadExpired    = errors.New("upload has expired")
	ErrUploadStopped    = errors.New("upload has stopped")
	ErrInvalidChunkNum  = errors.New("invalid chunk number")
)

type FileData struct {
	Size      int64  `json:"size"`
	ChunkSize int64  `json:"ChunkSize"`
	Status    string `json:"Status"`
}

type FileMetaDoc struct {
	ActionID string    `json:"action_id"`
	AgentID  string    `json:"agent_id"`
	Source   string    `json:"src"`
	File     FileData  `json:"file"`
	UploadID uuid.UUID `json:"upload_id"`
	Start    time.Time `json:"upload_start"`
}

// custom unmarshaller to make unix-epoch values work
func (f *FileMetaDoc) UnmarshalJSON(b []byte) error {
	type InnerFile FileMetaDoc // type alias to prevent recursion into this func
	// override the field to parse as an int, then manually convert to time.time
	var tmp struct {
		InnerFile
		Start int64 `json:"upload_start"`
	}
	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}

	*f = FileMetaDoc(tmp.InnerFile) // copy over all fields
	f.Start = time.UnixMilli(tmp.Start)
	return nil
}

type ChunkInfo struct {
	Pos  int  // Ordered chunk position in file
	Last bool // Is this the final chunk in the file
	SHA2 string
	Size int
	BID  string // base id, matches metadata doc's _id
}

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
func (u *Uploader) Begin(ctx context.Context, data JSDict) (upload.Info, error) {
	if data == nil {
		return upload.Info{}, errors.New("upload start payload required")
	}

	/*
		Validation and Input parsing
	*/

	// make sure all required fields are present and non-empty
	if err := validateUploadPayload(data); err != nil {
		return upload.Info{}, err
	}

	size, _ := data.Int64("file", "size")
	if size > u.sizeLimit {
		return upload.Info{}, ErrFileSizeTooLarge
	}

	uid, err := uuid.NewRandom()
	if err != nil {
		return upload.Info{}, fmt.Errorf("unable to generate upload operation ID: %w", err)
	}

	// grab required fields that were checked already in validation step
	agentID, _ := data.Str("agent_id")
	actionID, _ := data.Str("action_id")
	source, _ := data.Str("src")
	docID := fmt.Sprintf("%s.%s", actionID, agentID)

	info := upload.Info{
		ID:        uid,
		DocID:     docID,
		AgentID:   agentID,
		ActionID:  actionID,
		ChunkSize: MaxChunkSize,
		Source:    source,
		Total:     size,
		Status:    upload.StatusAwaiting,
		Start:     time.Now(),
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
		return upload.Info{}, err
	}
	if err := data.Put(info.Status, "file", "Status"); err != nil {
		return upload.Info{}, err
	}

	id := uid.String()
	if err := data.Put(id, "upload_id"); err != nil {
		return upload.Info{}, err
	}
	if err := data.Put(info.Start.UnixMilli(), "upload_start"); err != nil {
		return upload.Info{}, err
	}

	/*
		Write to storage
	*/
	doc, err := json.Marshal(data)
	if err != nil {
		return upload.Info{}, err
	}
	_, err = CreateFileDoc(ctx, u.bulker, doc, source, docID)
	if err != nil {
		return upload.Info{}, err
	}

	return info, nil
}

func (u *Uploader) Chunk(ctx context.Context, uplID string, chunkNum int, chunkHash string) (upload.Info, ChunkInfo, error) {
	// find the upload, details, and status associated with the file upload
	info, err := u.GetUploadInfo(ctx, uplID)
	if err != nil {
		return upload.Info{}, ChunkInfo{}, err
	}

	/*
		Verify Chunk upload can proceed
	*/

	if info.Expired(u.timeLimit) {
		return upload.Info{}, ChunkInfo{}, ErrUploadExpired
	}
	if !info.StatusCanUpload() {
		return upload.Info{}, ChunkInfo{}, ErrUploadStopped
	}
	if chunkNum < 0 || chunkNum >= info.Count {
		return upload.Info{}, ChunkInfo{}, ErrInvalidChunkNum
	}

	return info, ChunkInfo{
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
			return fmt.Errorf("%s is required", strings.Join(fields, "."))
		}
	}

	if size, ok := info.Int64("file", "size"); !ok {
		return errors.New("file.size is required")
	} else if size <= 0 {
		return fmt.Errorf("invalid file.size: %d", size)
	}
	return nil
}

// GetUploadInfo searches for Upload Metadata document in local memory cache if available
// otherwise, fetches from elasticsearch and caches for next use
func (u *Uploader) GetUploadInfo(ctx context.Context, uploadID string) (upload.Info, error) {
	// Fetch metadata doc, if not cached
	info, exist := u.cache.GetUpload(uploadID)
	if exist {
		return info, nil
	}

	// not found in cache, try fetching
	info, err := FetchUploadInfo(ctx, u.bulker, uploadID)
	if err != nil {
		return upload.Info{}, fmt.Errorf("unable to retrieve upload info: %w", err)
	}
	u.cache.SetUpload(uploadID, info)
	return info, nil
}
