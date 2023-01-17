// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upload

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/gofrs/uuid"
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

// the only valid values of upload status according to storage spec
type Status string

const (
	StatusAwaiting Status = "AWAITING_UPLOAD"
	StatusProgress Status = "UPLOADING"
	StatusDone     Status = "READY"
	StatusFail     Status = "UPLOAD_ERROR"
	StatusDel      Status = "DELETED"
)

type Info struct {
	ID        string // upload operation identifier. Used to identify the upload process
	DocID     string // document ID of the uploaded file and chunks
	Source    string // which integration is performing the upload
	AgentID   string
	ActionID  string
	ChunkSize int64
	Total     int64
	Count     int
	Start     time.Time
	Status    Status
}

// convenience functions for computing current "Status" based on the fields
func (i Info) Expired(timeout time.Duration) bool { return time.Now().After(i.Start.Add(timeout)) }
func (i Info) StatusCanUpload() bool { // returns true if more chunks can be uploaded. False if the upload process has completed (with or without error)
	return !(i.Status == StatusFail || i.Status == StatusDone || i.Status == StatusDel)
}

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
	UploadID string    `json:"upload_id"`
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
	//FirstReceived bool
}

type Uploader struct {
	metaCache map[string]Info // cache of file metadata doc info
	mu        sync.RWMutex    // lock for the above
	// @todo: cache eviction so it's not unbounded growth
	// @todo: cache refresh so status is accurate
	sizeLimit int64         // @todo: what if configuration changes? is this recreated with another New()?
	timeLimit time.Duration // @todo: same as above

	chunkClient *elasticsearch.Client
	bulker      bulk.Bulk
}

func New(chunkClient *elasticsearch.Client, bulker bulk.Bulk, sizeLimit int64, timeLimit time.Duration) *Uploader {
	return &Uploader{
		chunkClient: chunkClient,
		bulker:      bulker,
		sizeLimit:   sizeLimit,
		timeLimit:   timeLimit,
		metaCache:   make(map[string]Info),
	}
}

// Start an upload operation
func (u *Uploader) Begin(ctx context.Context, data JSDict) (Info, error) {
	if data == nil {
		return Info{}, errors.New("upload start payload required")
	}

	/*
		Validation and Input parsing
	*/

	// make sure all required fields are present and non-empty
	if err := validateUploadPayload(data); err != nil {
		return Info{}, err
	}

	size, _ := data.Int64("file", "size")
	if size > u.sizeLimit {
		return Info{}, ErrFileSizeTooLarge
	}

	uid, err := uuid.NewV4()
	if err != nil {
		return Info{}, fmt.Errorf("unable to generate upload operation ID: %w", err)
	}
	id := uid.String()

	// grab required fields that were checked already in validation step
	agentID, _ := data.Str("agent_id")
	actionID, _ := data.Str("action_id")
	source, _ := data.Str("src")
	docID := fmt.Sprintf("%s.%s", actionID, agentID)

	info := Info{
		ID:        id,
		DocID:     docID,
		AgentID:   agentID,
		ActionID:  actionID,
		ChunkSize: MaxChunkSize,
		Source:    source,
		Total:     size,
		Status:    StatusAwaiting,
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
		return Info{}, err
	}
	if err := data.Put(info.Status, "file", "Status"); err != nil {
		return Info{}, err
	}
	if err := data.Put(id, "upload_id"); err != nil {
		return Info{}, err
	}
	if err := data.Put(info.Start.UnixMilli(), "upload_start"); err != nil {
		return Info{}, err
	}

	/*
		Write to storage
	*/
	doc, err := json.Marshal(data)
	if err != nil {
		return Info{}, err
	}
	_, err = CreateFileDoc(ctx, u.bulker, doc, source, docID)
	if err != nil {
		return Info{}, err
	}

	return info, nil
}

func (u *Uploader) Chunk(ctx context.Context, uplID string, chunkNum int, chunkHash string) (Info, ChunkInfo, error) {
	// find the upload, details, and status associated with the file upload
	info, err := u.GetUploadInfo(ctx, uplID)
	if err != nil {
		return Info{}, ChunkInfo{}, err
	}

	/*
		Verify Chunk upload can proceed
	*/

	if info.Expired(u.timeLimit) {
		return Info{}, ChunkInfo{}, ErrUploadExpired
	}
	if !info.StatusCanUpload() {
		return Info{}, ChunkInfo{}, ErrUploadStopped
	}
	if chunkNum < 0 || chunkNum >= info.Count {
		return Info{}, ChunkInfo{}, ErrInvalidChunkNum
	}

	return info, ChunkInfo{
		Pos: chunkNum,
		BID: info.DocID,
		//FirstReceived: false, // @todo
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

	//@todo: valid action?
	//@todo: valid src? will that make future expansion harder and require FS updates? maybe just validate the index exists

	if size, ok := info.Int64("file", "size"); !ok {
		return errors.New("file.size is required")
	} else if size <= 0 {
		return fmt.Errorf("invalid file.size: %d", size)
	}
	return nil
}

// Searches for Upload Metadata document in local memory cache if available
// otherwise, fetches from elasticsearch and caches for next use
func (u *Uploader) GetUploadInfo(ctx context.Context, uploadID string) (Info, error) {
	// Fetch metadata doc, if not cached
	u.mu.RLock()
	info, exist := u.metaCache[uploadID]
	u.mu.RUnlock() // not deferred since this must be clear before we gain a write lock below
	if exist {
		return info, nil
	}

	// not found in cache, try fetching
	info, err := FetchUploadInfo(ctx, u.bulker, uploadID)
	if err != nil {
		return Info{}, fmt.Errorf("unable to retrieve upload info: %w", err)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.metaCache[uploadID] = info
	return info, nil
}
