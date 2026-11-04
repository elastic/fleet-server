// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package store keeps an in-memory, immutable snapshot of the feature flags definitions index
// and keeps it in sync with Elasticsearch.
package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/definitions"
	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/eval"
)

// DocVersion identifies a revision of a document within one index.
// A recreated index can reuse _seq_no and _primary_term for a different _source,
// so a version matches only together with Snapshot.IndexUUID.
type DocVersion struct {
	SeqNo       int64
	PrimaryTerm int64
}

// docEntry is a document of the definitions index. doc is nil when the source could not be parsed;
// the entry is still kept so the document count matches the index.
type docEntry struct {
	version    DocVersion
	sourceHash [32]byte
	doc        *definitions.Document
	flag       *eval.Flag
}

// Snapshot is an immutable view of the definitions index. It must not be modified once published.
type Snapshot struct {
	// Version identifies the content of the snapshot. Snapshots with the same documents,
	// document versions and index UUID have the same Version, also across Fleet Server instances.
	Version string
	// IndexUUID is the Elasticsearch index the documents were read from.
	// An empty value means the snapshot was not loaded from an index.
	IndexUUID string

	flags                 map[string]*eval.Flag
	flagsByApp            map[string][]*eval.Flag
	credentialsByHash     map[string]*definitions.Credential
	credentialsByClientID map[string]*definitions.Credential
	apps                  map[string]*definitions.App
	environments          map[string]*definitions.Environment
	docs                  map[string]docEntry
}

// DocCount returns the number of documents of the index the snapshot was built from.
func (s *Snapshot) DocCount() int {
	return len(s.docs)
}

// Flag returns the flag with key, or nil.
func (s *Snapshot) Flag(key string) *eval.Flag {
	return s.flags[key]
}

// FlagsForApp returns the flags assigned to app, sorted by key.
func (s *Snapshot) FlagsForApp(app string) []*eval.Flag {
	return s.flagsByApp[app]
}

// CredentialBySDKKeyHash returns the credential whose SDK key has the given hex SHA-256 hash, or nil.
func (s *Snapshot) CredentialBySDKKeyHash(hash string) *definitions.Credential {
	return s.credentialsByHash[hash]
}

// CredentialByClientID returns the credential with the given client ID, or nil.
func (s *Snapshot) CredentialByClientID(clientID string) *definitions.Credential {
	return s.credentialsByClientID[clientID]
}

// App returns the app with key, or nil.
func (s *Snapshot) App(key string) *definitions.App {
	return s.apps[key]
}

// Environment returns the environment with key, or nil.
func (s *Snapshot) Environment(key string) *definitions.Environment {
	return s.environments[key]
}

// Store holds the current snapshot. It is safe for concurrent use.
type Store struct {
	current atomic.Pointer[Snapshot]
}

// New returns a store that is not ready until the first snapshot is published.
func New() *Store {
	return &Store{}
}

// Load returns the current snapshot, or nil until the initial load has finished.
func (s *Store) Load() *Snapshot {
	return s.current.Load()
}

// Ready reports whether the initial load has finished.
func (s *Store) Ready() bool {
	return s.current.Load() != nil
}

func (s *Store) publish(snap *Snapshot) {
	s.current.Store(snap)
}

// RawDoc is a document as fetched from Elasticsearch.
type RawDoc struct {
	ID      string
	Version DocVersion
	Source  json.RawMessage
}

// parseDoc parses a raw document, compiling flags. Invalid sources yield an entry without document.
func parseDoc(raw RawDoc) docEntry {
	entry := docEntry{version: raw.Version, sourceHash: sha256.Sum256(raw.Source)}
	// UseNumber keeps integers larger than 2^53 exact. The default decoder turns them into float64.
	dec := json.NewDecoder(bytes.NewReader(raw.Source))
	dec.UseNumber()
	var doc definitions.Document
	if err := dec.Decode(&doc); err != nil {
		return entry
	}
	entry.doc = &doc
	if doc.Type == definitions.TypeFlag && doc.Flag != nil {
		entry.flag = eval.Compile(doc.Flag)
	}
	return entry
}

// NewSnapshot builds a snapshot from raw documents.
func NewSnapshot(raws ...RawDoc) *Snapshot {
	docs := make(map[string]docEntry, len(raws))
	for _, raw := range raws {
		docs[raw.ID] = parseDoc(raw)
	}
	return buildSnapshot(docs, "")
}

// buildSnapshot derives the lookup maps from docs. Documents are visited in _id order so that
// duplicate keys, which Kibana prevents, resolve deterministically.
func buildSnapshot(docs map[string]docEntry, indexUUID string) *Snapshot {
	s := &Snapshot{
		flags:                 map[string]*eval.Flag{},
		flagsByApp:            map[string][]*eval.Flag{},
		credentialsByHash:     map[string]*definitions.Credential{},
		credentialsByClientID: map[string]*definitions.Credential{},
		apps:                  map[string]*definitions.App{},
		environments:          map[string]*definitions.Environment{},
		docs:                  docs,
	}
	ids := make([]string, 0, len(docs))
	for id := range docs {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	h := sha256.New()
	h.Write([]byte(indexUUID))
	h.Write([]byte{0})
	for _, id := range ids {
		e := docs[id]
		h.Write([]byte(id))
		h.Write([]byte{0})
		h.Write([]byte(strconv.FormatInt(e.version.SeqNo, 10)))
		h.Write([]byte{0})
		h.Write([]byte(strconv.FormatInt(e.version.PrimaryTerm, 10)))
		h.Write([]byte{0})
		h.Write(e.sourceHash[:])
		h.Write([]byte{0})

		if e.doc == nil {
			continue
		}
		switch e.doc.Type {
		case definitions.TypeFlag:
			if e.flag != nil && e.flag.Key != "" {
				if _, dup := s.flags[e.flag.Key]; !dup {
					s.flags[e.flag.Key] = e.flag
				}
			}
		case definitions.TypeCredential:
			c := e.doc.Credential
			if c == nil {
				continue
			}
			if c.SDKKeyHash != "" {
				if _, dup := s.credentialsByHash[c.SDKKeyHash]; !dup {
					s.credentialsByHash[c.SDKKeyHash] = c
				}
			}
			if c.ClientID != "" {
				if _, dup := s.credentialsByClientID[c.ClientID]; !dup {
					s.credentialsByClientID[c.ClientID] = c
				}
			}
		case definitions.TypeApp:
			if a := e.doc.App; a != nil && a.Key != "" {
				if _, dup := s.apps[a.Key]; !dup {
					s.apps[a.Key] = a
				}
			}
		case definitions.TypeEnvironment:
			if env := e.doc.Environment; env != nil && env.Key != "" {
				if _, dup := s.environments[env.Key]; !dup {
					s.environments[env.Key] = env
				}
			}
		}
	}
	s.Version = hex.EncodeToString(h.Sum(nil))[:32]
	s.IndexUUID = indexUUID

	for _, f := range s.flags {
		for app := range uniqueStrings(f.Def.Apps) {
			s.flagsByApp[app] = append(s.flagsByApp[app], f)
		}
	}
	for app := range s.flagsByApp {
		slices.SortFunc(s.flagsByApp[app], func(a, b *eval.Flag) int { return strings.Compare(a.Key, b.Key) })
	}
	return s
}

func uniqueStrings(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		out[s] = struct{}{}
	}
	return out
}
