// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upload

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
)

const (
	//these should be configs probably
	uploadRequestTimeout = time.Hour
	chunkProgressTimeout = time.Hour / 4

	// specification-designated maximum
	MaxChunkSize = 4194304 // 4 MiB
)

var (
	ErrMaxConcurrentUploads = errors.New("the max number of concurrent uploads has been reached")
	ErrInvalidUploadID      = errors.New("active upload not found with this ID, it may be expired")

	//@todo: explicit error for expired uploads
)

type upload struct {
	complete  chan<- struct{}
	chunkRecv chan<- struct{}
	begun     bool
	Info      Info
}

type Uploader struct {
	current       map[string]upload
	mu            sync.Mutex
	parallelLimit int
}

type Info struct {
	ID        string
	ChunkSize int64
	Total     int64
	Count     int
}

type ChunkInfo struct {
	ID            int
	FirstReceived bool
	Final         bool
	Upload        Info
}

func New(limit int) *Uploader {
	return &Uploader{
		parallelLimit: limit,
		current:       make(map[string]upload, limit),
	}
}

// Start an upload operation, as long as the max concurrent has not been reached
// returns the upload ID
func (u *Uploader) Begin(size int64) (Info, error) {
	if len(u.current) >= u.parallelLimit {
		return Info{}, ErrMaxConcurrentUploads
	}

	uid, err := uuid.NewV4()
	if err != nil {
		return Info{}, fmt.Errorf("unable to generate upload operation ID: %w", err)
	}
	id := uid.String()

	total := time.NewTimer(uploadRequestTimeout)
	chunkT := time.NewTimer(chunkProgressTimeout)
	chunkRecv := make(chan struct{})
	complete := make(chan struct{})
	// total timer could also be achieved with context deadline and cancelling

	go func() {
		for {
			select {
			case <-total.C: // entire upload operation timed out
				log.Trace().Str("uploadID", id).Msg("upload operation timed out")
				// stop and drain chunk timer
				if !chunkT.Stop() {
					<-chunkT.C
				}
				u.cancel(id)
				return
			case <-chunkT.C: // no chunk progress within chunk timer, expire operation
				log.Trace().Str("uploadID", id).Msg("upload operation chunk activity timed out")
				// stop and drain total timer
				if !total.Stop() {
					<-total.C
				}
				u.cancel(id)
				return
			case <-chunkRecv: // chunk activity, update chunk timer
				if !chunkT.Stop() {
					<-chunkT.C
				}
				chunkT.Reset(chunkProgressTimeout)
			case <-complete: // upload operation complete, clean up
				if !chunkT.Stop() {
					<-chunkT.C
				}
				if !total.Stop() {
					<-total.C
				}
				u.finalize(id)
				return
			}
		}
	}()
	info := Info{
		ID:        id,
		ChunkSize: MaxChunkSize,
		Total:     size,
	}
	cnt := info.Total / info.ChunkSize
	if info.Total%info.ChunkSize > 0 {
		cnt += 1
	}
	info.Count = int(cnt)
	u.current[id] = upload{
		complete:  complete,
		chunkRecv: chunkRecv,
		Info:      info,
	}
	return info, nil
}

func (u *Uploader) Chunk(uplID string, chunkID int) (ChunkInfo, error) {
	u.mu.Lock()
	upl, valid := u.current[uplID]
	if !valid {
		u.mu.Unlock()
		return ChunkInfo{}, ErrInvalidUploadID
	}
	upl.chunkRecv <- struct{}{}
	if !upl.begun {
		upl.begun = true
	}
	u.current[uplID] = upl
	u.mu.Unlock()

	return ChunkInfo{
		ID:            chunkID,
		FirstReceived: upl.begun,
		Final:         chunkID == upl.Info.Count-1,
		Upload:        upl.Info,
	}, nil
}

func (u *Uploader) Complete(id string) (string, error) {
	if _, valid := u.current[id]; !valid {
		return "", ErrInvalidUploadID
	}
	// @todo: verify chunks
	// verify hashes, etc
	u.current[id].complete <- struct{}{}
	return "", nil
}

func (u *Uploader) cancel(uplID string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.current, uplID)
	// @todo: delete any uploaded chunks from ES
	// leave header doc and mark failed?
	return nil
}

func (u *Uploader) finalize(uplID string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.current, uplID)
	// @todo: write Status:READY here?
	return nil
}
