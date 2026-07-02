// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package file

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

const (
	// specification-designated maximum
	MaxChunkSize = 4194304 // 4 MiB
)

var (
	ErrInvalidID = errors.New("file not found with this ID, it may have been removed")
)

// Status represents the only valid values of upload status according to storage spec
type Status string

const (
	StatusAwaiting Status = "AWAITING_UPLOAD"
	StatusProgress Status = "UPLOADING"
	StatusDone     Status = "READY"
	StatusFail     Status = "UPLOAD_ERROR"
	StatusDel      Status = "DELETED"
)

type FileData struct {
	Hash      *Hash  `json:"hash,omitempty"`
	Status    string `json:"Status"`
	MimeType  string `json:"mime_type,omitempty"`
	Size      int64  `json:"size"`
	ChunkSize int64  `json:"ChunkSize"`
}

type Hash struct {
	SHA2 string `json:"sha256,omitempty"`
}

type MetaDoc struct {
	ActionID   string    `json:"action_id"`
	AgentID    string    `json:"agent_id"`
	Source     string    `json:"src"`
	File       FileData  `json:"file"`
	UploadID   string    `json:"upload_id"`
	Start      time.Time `json:"upload_start"`
	Namespaces []string  `json:"namespaces"`
}

// custom unmarshaller to make unix-epoch values work
func (m *MetaDoc) UnmarshalJSON(b []byte) error {
	type InnerFile MetaDoc // type alias to prevent recursion into this func
	// override the field to parse as an int, then manually convert to time.time
	var tmp struct {
		InnerFile
		Start int64 `json:"upload_start"`
	}
	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}

	*m = MetaDoc(tmp.InnerFile) // copy over all fields
	m.Start = time.UnixMilli(tmp.Start)
	return nil
}

type ChunkInfo struct {
	SHA2       string
	BID        string // base id, matches metadata doc's _id
	Index      string
	ID         string // chunk _id
	Namespaces []string
	Pos        int // Ordered chunk position in file
	Size       int
	Last       bool // Is this the final chunk in the file
}

type Info struct {
	Start      time.Time
	ID         string // upload operation identifier. Used to identify the upload process
	DocID      string // document ID of the uploaded file and chunks
	Source     string // which integration is performing the upload
	AgentID    string
	ActionID   string
	Status     Status
	Namespaces []string
	ChunkSize  int64
	Total      int64
	Count      int
}

// convenience functions for computing current "Status" based on the fields
func (i Info) Expired(timeout time.Duration) bool { return time.Now().After(i.Start.Add(timeout)) }
func (i Info) StatusCanUpload() bool { // returns true if more chunks can be uploaded. False if the upload process has completed (with or without error)
	return i.Status != StatusFail && i.Status != StatusDone && i.Status != StatusDel
}

type Chunk struct {
	BID  string `json:"bid"`
	SHA2 string `json:"sha2"`
	Data []byte `json:"data"`
	model.ESDocument

	Last bool `json:"last"`
}
