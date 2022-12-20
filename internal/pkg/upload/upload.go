// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upload

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/throttle"
	"github.com/elastic/go-elasticsearch/v7"
	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
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

type Uploader struct {
	metaCache map[string]Info // simple read-cache of file metadata doc info
	mu        sync.RWMutex    // lock for the above
	sizeLimit int64           // @todo: what if configuration changes? is this recreated with another New()?
	timeLimit time.Duration   // @todo: same as above

	// @todo: some es credentials
	chunkClient *elasticsearch.Client
	bulker      bulk.Bulk
}

type Info struct {
	ID        string // upload operation identifier. Used to identify the upload process
	DocID     string // document ID of the uploaded file and chunks
	Source    string // which integration is performing the upload
	ChunkSize int64
	Total     int64
	Count     int
	Start     time.Time
	Status    Status
}

// convenience functions for computing current "Status" based on the fields
func (i Info) Expired(timeout time.Duration) bool { return i.Start.Add(timeout).After(time.Now()) }
func (i Info) StatusCanUpload() bool { // returns true if more chunks can be uploaded. False if the upload process has completed (with or without error)
	return !(i.Status == StatusFail || i.Status == StatusDone || i.Status == StatusDel)
}

type ChunkInfo struct {
	ID            int
	FirstReceived bool
	Final         bool
	Upload        Info
	Hash          string
	Token         *throttle.Token
}

func New(chunkClient *elasticsearch.Client, bulker bulk.Bulk, sizeLimit int64, timeLimit time.Duration) *Uploader {
	return &Uploader{
		chunkClient: chunkClient,
		bulker:      bulker,
		sizeLimit:   sizeLimit,
		timeLimit:   timeLimit,
	}
}

// Start an upload operation, as long as the max concurrent has not been reached
// returns the upload ID
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
		ChunkSize: MaxChunkSize,
		Source:    source,
		Total:     size,
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
	if err := data.Put(string(StatusAwaiting), "file", "Status"); err != nil {
		return Info{}, err
	}
	if err := data.Put(id, "upload_id"); err != nil {
		return Info{}, err
	}
	if err := data.Put(time.Now().UnixMilli(), "upload_start"); err != nil {
		return Info{}, err
	}

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

func (u *Uploader) Chunk(ctx context.Context, uplID string, chunkID int, chunkHash string) (ChunkInfo, error) {

	// Fetch metadata doc, if not cached
	//u.mu.RLock()
	//defer u.mu.RUnlock()
	info, exist := u.metaCache[uplID]
	if !exist {
		//u.mu.Lock()
		//defer u.mu.Unlock()
		// fetch and write

		var err error
		info, err = u.GetUploadInfo(ctx, uplID)
		if err != nil {
			return ChunkInfo{}, fmt.Errorf("unable to retrieve upload info: %w", err)
		}
		u.metaCache[uplID] = info
	}

	if info.Expired(u.timeLimit) {
		return ChunkInfo{}, ErrUploadExpired
	}
	if !info.StatusCanUpload() {
		return ChunkInfo{}, ErrUploadStopped
	}
	if chunkID < 0 || chunkID >= info.Count {
		return ChunkInfo{}, ErrInvalidChunkNum
	}

	return ChunkInfo{
		ID:            chunkID,
		FirstReceived: false, // @todo
		Final:         chunkID == info.Count-1,
		Upload:        info,
		Hash:          chunkHash,
		//Token:         token,
	}, nil
}

func (u *Uploader) Complete(id string, transitHash string, bulker bulk.Bulk) (Info, error) {
	info, valid := u.metaCache[id]
	if !valid {
		return Info{}, ErrInvalidUploadID
	}

	ok, err := u.allChunksPresent(info, bulker)
	if err != nil {
		return Info{}, err
	}
	if !ok {
		return Info{}, ErrMissingChunks
	}

	ok, err = u.verifyChunkData(info, transitHash, bulker)
	if err != nil {
		return Info{}, err
	}
	if !ok {
		return Info{}, errors.New("file contents did not pass validation")
	}

	return info, nil
}

func (u *Uploader) cleanupOperation(uplID string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.metaCache, uplID)
}

func (u *Uploader) cancel(uplID string) error {
	u.cleanupOperation(uplID)

	// @todo: delete any uploaded chunks from ES
	// leave header doc and mark failed?
	return nil
}

func (u *Uploader) finalize(uplID string) error {
	u.cleanupOperation(uplID)
	// @todo: write Status:READY here?
	return nil
}

func (u *Uploader) allChunksPresent(info Info, bulker bulk.Bulk) (bool, error) {
	hits, err := ListChunkIDs(context.TODO(), bulker, info.Source, info.DocID)
	if err != nil {
		log.Warn().Err(err).Msg("error listing chunks")
		return false, err
	}
	if len(hits) != info.Count {
		log.Warn().Int("expectedCount", info.Count).Int("received", len(hits)).Interface("hits", hits).Msg("mismatch number of chunks")
		return false, nil
	}

	ids := make(map[int]bool, len(hits))
	for _, h := range hits {
		chunkID := strings.TrimPrefix(h.ID, info.DocID+".")
		ival, err := strconv.Atoi(chunkID)
		if err != nil {
			log.Warn().Err(err).Str("chunkID", h.ID).Str("docID", info.DocID).Str("parsedChunkInt", chunkID).Interface("hits", hits).Msg("unable to convert to int value")
			return false, err
		}
		ids[ival] = true
	}

	for i := 0; i < info.Count; i++ {
		if got, exists := ids[i]; !got || !exists {
			log.Warn().Int("expected", i).Interface("hits", hits).Msg("mismatch chunk")
			return false, nil
		}
	}
	return true, nil
}

func (u *Uploader) verifyChunkData(info Info, transitHash string, bulker bulk.Bulk) (bool, error) {
	// verify all chunks except last are info.ChunkSize size
	// verify last: false (or field excluded) for all except final chunk
	// verify final chunk is last: true
	// verify hash

	for i := 0; i < info.Count; i++ {
		chunk, err := GetChunk(context.TODO(), bulker, info.Source, info.DocID, i)
		if err != nil {
			return false, err
		}
		if err != nil {
			return false, err
		}
		if i < info.Count-1 {
			if chunk.Last {
				log.Debug().Int("chunkID", i).Msg("non-final chunk was incorrectly marked last")
				return false, nil
			}
			if len(chunk.Data) != int(info.ChunkSize) {
				log.Debug().Int64("requiredSize", info.ChunkSize).Int("chunkID", i).Int("gotSize", len(chunk.Data)).Msg("chunk was undersized")
				return false, nil
			}
		} else {
			if !chunk.Last {
				log.Debug().Int("chunkID", i).Msg("final chunk was not marked as final")
				return false, nil
			}
			if len(chunk.Data) == 0 {
				log.Debug().Int("chunkID", i).Msg("final chunk was 0 size")
				return false, nil
			}
		}

		/*
			if info.Hasher != nil {
				_, err = io.Copy(info.Hasher, bytes.NewReader(chunk.Data))
				if err != nil {
					return false, err
				}
			}
		*/
	}

	/*
		if info.Hasher != nil {
			fullHash := hex.EncodeToString(info.Hasher.Sum(nil))
			if fullHash != info.HashSum {
				return false, ErrHashMismatch
			}
		}
	*/
	return true, nil
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

// retrieves upload metadata info from elasticsearch
// which may be locally cached
func (u *Uploader) GetUploadInfo(ctx context.Context, uploadID string) (Info, error) {
	results, err := GetFileDoc(ctx, u.bulker, uploadID)
	if err != nil {
		return Info{}, err
	}
	if len(results) == 0 {
		return Info{}, ErrInvalidUploadID
	}
	if len(results) > 1 {
		return Info{}, fmt.Errorf("unable to locate upload record, got %d records, expected 1", len(results))
	}

	var fi FileMetaDoc
	if err := json.Unmarshal(results[0].Source, &fi); err != nil {
		return Info{}, fmt.Errorf("file meta doc parsing error: %w", err)
	}

	// calculate number of chunks required
	cnt := fi.File.Size / fi.File.ChunkSize
	if fi.File.Size%fi.File.ChunkSize > 0 {
		cnt += 1
	}

	return Info{
		ID:        fi.UploadID,
		Source:    fi.Source,
		DocID:     results[0].ID,
		ChunkSize: fi.File.ChunkSize,
		Total:     fi.File.Size,
		Count:     int(cnt),
		Start:     fi.Start,
		Status:    Status(fi.File.Status),
	}, nil
}

type FileMetaDoc struct {
	ActionID string     `json:"action_id"`
	AgentID  string     `json:"agent_id"`
	Source   string     `json:"src"`
	File     FileData   `json:"file"`
	Contents []FileData `json:"contents"`
	UploadID string     `json:"upload_id"`
	Start    time.Time  `json:"upload_start"`
}
type FileData struct {
	Size      int64  `json:"size"`
	ChunkSize int64  `json:"ChunkSize"`
	Status    string `json:"Status"`
	Name      string `json:"name"`
	Mime      string `json:"mime_type"`
	Hash      struct {
		SHA256 string `json:"sha256"`
		MD5    string `json:"md5"`
	} `json:"hash"`
}
