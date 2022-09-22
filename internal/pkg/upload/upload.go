// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upload

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
)

const (
	//these should be configs probably
	uploadRequestTimeout = time.Hour
	chunkProgressTimeout = time.Hour / 4
)

var (
	ErrMaxConcurrentUploads = errors.New("the max number of concurrent uploads has been reached")
	ErrInvalidUploadID      = errors.New("active upload not found with this ID, it may be expired")
)

type upload struct {
	complete  chan<- struct{}
	chunkRecv chan<- struct{}
}

type Uploader struct {
	current       map[string]upload
	parallelLimit int
}

func New(limit int) *Uploader {
	return &Uploader{
		parallelLimit: limit,
		current:       make(map[string]upload, limit),
	}
}

// Start an upload operation, as long as the max concurrent has not been reached
// returns the upload ID
func (u *Uploader) Begin() (string, error) {
	if len(u.current) >= u.parallelLimit {
		return "", ErrMaxConcurrentUploads
	}

	uid, err := uuid.NewV4()
	if err != nil {
		return "", fmt.Errorf("unable to generate upload operation ID: %w", err)
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
				delete(u.current, id)
				return
			case <-chunkT.C: // no chunk progress within chunk timer, expire operation
				log.Trace().Str("uploadID", id).Msg("upload operation chunk activity timed out")
				// stop and drain total timer
				if !total.Stop() {
					<-total.C
				}
				delete(u.current, id)
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
				delete(u.current, id)
				return
			}
		}
	}()
	u.current[id] = upload{
		complete:  complete,
		chunkRecv: chunkRecv,
	}
	return id, nil
}

func (u *Uploader) Chunk(uplID string, chunknum int, body io.ReadCloser) (string, error) {
	if body == nil {
		return "", errors.New("body is required")
	}
	defer body.Close()
	if _, valid := u.current[uplID]; !valid {
		return "", ErrInvalidUploadID
	}
	u.current[uplID].chunkRecv <- struct{}{}

	_, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}

	return "", nil
}

func (u *Uploader) Complete(id string) (string, error) {
	if _, valid := u.current[id]; !valid {
		return "", ErrInvalidUploadID
	}
	u.current[id].complete <- struct{}{}
	return "", nil
}
