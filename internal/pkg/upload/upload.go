// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upload

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/throttle"
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
	opToken       *throttle.Token
	chunkThrottle *throttle.Throttle
	complete      chan<- struct{}
	chunkRecv     chan<- struct{}
	begun         bool
	Info          Info
}

type Uploader struct {
	current            map[string]upload
	mu                 sync.Mutex
	opThrottle         *throttle.Throttle
	parallelChunkLimit int
}

type Info struct {
	ID        string // upload operation identifier. Ephemeral, just used for the upload process
	DocID     string // document ID of the uploaded file and chunks
	Source    string // which integration is performing the upload
	ChunkSize int64
	Total     int64
	Count     int
}

type ChunkInfo struct {
	ID            int
	FirstReceived bool
	Final         bool
	Upload        Info
	Token         *throttle.Token
}

func New(opLimit int, chunkLimit int) *Uploader {
	return &Uploader{
		parallelChunkLimit: chunkLimit,
		opThrottle:         throttle.NewThrottle(opLimit),
		current:            make(map[string]upload, opLimit),
	}
}

// Start an upload operation, as long as the max concurrent has not been reached
// returns the upload ID
func (u *Uploader) Begin(size int64, docID string, source string) (Info, error) {
	if size <= 0 {
		return Info{}, errors.New("invalid file size")
	}

	uid, err := uuid.NewV4()
	if err != nil {
		return Info{}, fmt.Errorf("unable to generate upload operation ID: %w", err)
	}
	id := uid.String()

	token := u.opThrottle.Acquire(id, 300*time.Hour)
	if token == nil {
		return Info{}, ErrMaxConcurrentUploads
	}

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
		DocID:     docID,
		ChunkSize: MaxChunkSize,
		Source:    source,
		Total:     size,
	}
	cnt := info.Total / info.ChunkSize
	if info.Total%info.ChunkSize > 0 {
		cnt += 1
	}
	info.Count = int(cnt)
	u.current[id] = upload{
		opToken:       token,
		chunkThrottle: throttle.NewThrottle(u.parallelChunkLimit),
		complete:      complete,
		chunkRecv:     chunkRecv,
		Info:          info,
	}
	return info, nil
}

func (u *Uploader) Chunk(uplID string, chunkID int) (ChunkInfo, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	upl, valid := u.current[uplID]
	if !valid {
		return ChunkInfo{}, ErrInvalidUploadID
	}
	if chunkID < 0 || chunkID >= upl.Info.Count {
		return ChunkInfo{}, errors.New("invalid chunk number")
	}

	token := upl.chunkThrottle.Acquire(strconv.Itoa(chunkID), time.Hour)
	if token == nil {
		return ChunkInfo{}, ErrMaxConcurrentUploads
	}
	upl.chunkRecv <- struct{}{}
	if !upl.begun {
		upl.begun = true
	}
	u.current[uplID] = upl

	return ChunkInfo{
		ID:            chunkID,
		FirstReceived: upl.begun,
		Final:         chunkID == upl.Info.Count-1,
		Upload:        upl.Info,
		Token:         token,
	}, nil
}

func (u *Uploader) Complete(id string) (Info, error) {
	info, valid := u.current[id]
	if !valid {
		return Info{}, ErrInvalidUploadID
	}
	// @todo: verify chunks
	// verify hashes, etc
	u.current[id].complete <- struct{}{}
	return info.Info, nil
}

func (u *Uploader) cleanupOperation(uplID string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if upload, ok := u.current[uplID]; ok {
		if upload.opToken != nil {
			upload.opToken.Release()
		}
	}
	delete(u.current, uplID)
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
