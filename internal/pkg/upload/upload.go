// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/go-elasticsearch/v8"
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
func (i Info) Expired(timeout time.Duration) bool { return time.Now().After(i.Start.Add(timeout)) }
func (i Info) StatusCanUpload() bool { // returns true if more chunks can be uploaded. False if the upload process has completed (with or without error)
	return !(i.Status == StatusFail || i.Status == StatusDone || i.Status == StatusDel)
}

type ChunkInfo struct {
	Pos  int  // Ordered chunk position in file
	Last bool // Is this the final chunk in the file
	SHA2 string
	Size int
	BID  string // base id, matches metadata doc's _id
	//FirstReceived bool
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

func (u *Uploader) Chunk(ctx context.Context, uplID string, chunkNum int, chunkHash string) (Info, ChunkInfo, error) {

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
			return Info{}, ChunkInfo{}, fmt.Errorf("unable to retrieve upload info: %w", err)
		}
		u.metaCache[uplID] = info
	}

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

func (u *Uploader) Complete(ctx context.Context, id string, transitHash string) (Info, error) {
	info, valid := u.metaCache[id]
	if !valid {
		return Info{}, ErrInvalidUploadID
	}

	chunks, err := GetChunkInfos(ctx, u.bulker, info.DocID)
	if err != nil {
		return Info{}, err
	}
	if !u.allChunksPresent(info, chunks) {
		return Info{}, ErrMissingChunks
	}
	if !u.verifyChunkInfo(info, chunks, transitHash) {
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

func (u *Uploader) allChunksPresent(info Info, chunks []ChunkInfo) bool {
	// check overall count
	if len(chunks) != info.Count {
		log.Warn().Int("expectedCount", info.Count).Int("received", len(chunks)).Interface("chunks", chunks).Msg("mismatch number of chunks")
		return false
	}

	// now ensure all positions are accounted for, no gaps, etc
	sort.Slice(chunks, func(i, j int) bool {
		return chunks[i].Pos < chunks[j].Pos
	})

	for i, c := range chunks {
		if c.Pos != i {
			log.Warn().Int("expected", i).Interface("chunk", c).Msg("chunk position doesn't match. May be a gap in uploaded file")
			return false
		}
	}

	return true
}

func (u *Uploader) verifyChunkInfo(info Info, chunks []ChunkInfo, transitHash string) bool {
	// verify all chunks except last are info.ChunkSize size
	// verify last: false (or field excluded) for all except final chunk
	// verify final chunk is last: true
	// verify hash

	hasher := sha256.New()

	for i, chunk := range chunks {
		if i < info.Count-1 {
			if chunk.Last {
				log.Debug().Int("chunkID", i).Msg("non-final chunk was incorrectly marked last")
				return false
			}
			if chunk.Size != int(info.ChunkSize) {
				log.Debug().Int64("requiredSize", info.ChunkSize).Int("chunkID", i).Int("gotSize", chunk.Size).Msg("chunk was undersized")
				return false
			}
		} else {
			if !chunk.Last {
				log.Debug().Int("chunkID", i).Msg("final chunk was not marked as final")
				return false
			}
			if chunk.Size == 0 {
				log.Debug().Int("chunkID", i).Msg("final chunk was 0 size")
				return false
			}
			if chunk.Size > int(info.ChunkSize) {
				log.Debug().Int("chunk-size", chunk.Size).Int("maxsize", int(info.ChunkSize)).Msg("final chunk was oversized")
				return false
			}
		}

		rawHash, err := hex.DecodeString(chunk.SHA2)
		if err != nil {
			log.Warn().Err(err).Msg("error decoding chunk hash")
			return false
		}

		if n, err := hasher.Write(rawHash); err != nil {
			log.Error().Err(err).Msg("error computing transitHash from component chunk hashes")
			return false
		} else if n != len(rawHash) {
			log.Error().Int("wrote", n).Int("expected", len(rawHash)).Msg("transitHash calculation failure, could not write to hasher")
			return false
		}
	}

	calcHash := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(transitHash, calcHash) {
		log.Warn().Str("provided-hash", transitHash).Str("calc-hash", calcHash).Msg("file upload streaming hash does not match")
		return false
	}

	return true
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

type FileMetaDoc struct {
	ActionID string    `json:"action_id"`
	AgentID  string    `json:"agent_id"`
	Source   string    `json:"src"`
	File     FileData  `json:"file"`
	UploadID string    `json:"upload_id"`
	Start    time.Time `json:"upload_start"`
}

// custom unmarshaller to make unix-epoch values
// work
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
