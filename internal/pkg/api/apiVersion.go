// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

var (
	ErrInvalidAPIVersionFormat = errors.New("invalid version format")
	ErrUnsupportedAPIVersion   = errors.New("version is not supported")
)

const (
	ElasticAPIVersionHeader = "Elastic-Api-Version"
	DefaultVersion          = "2023-06-01"
)

var SupportedVersions = []string{DefaultVersion}

var isValidVersionRegex = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

type apiVersion struct {
	supportedVersions []string
	defaultVersion    string
}

func NewAPIVersion() *apiVersion {
	return &apiVersion{
		supportedVersions: SupportedVersions,
		defaultVersion:    DefaultVersion,
	}
}

func (a *apiVersion) validateVersionFormat(version string) error {
	if !isValidVersionRegex.MatchString(version) {
		return fmt.Errorf("received \"%s\", expected a valid date string formatted as YYYY-MM-DD. %w", version, ErrInvalidAPIVersionFormat)
	}

	return nil
}

func (a *apiVersion) isVersionSupported(version string) bool {
	for _, vers := range a.supportedVersions {
		if vers == version {
			return true
		}
	}
	return false
}

func (a *apiVersion) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		headerValue := r.Header.Get(ElasticAPIVersionHeader)
		if headerValue != "" {
			err := a.validateVersionFormat(headerValue)
			if err != nil {
				w.Header().Add(ElasticAPIVersionHeader, a.defaultVersion)
				ErrorResp(w, r, err)
				return
			}

			if !a.isVersionSupported(headerValue) {
				w.Header().Add(ElasticAPIVersionHeader, a.defaultVersion)
				ErrorResp(w, r, fmt.Errorf("received %q, is not supported. supported versions are: [%s] %w", headerValue, strings.Join(a.supportedVersions, ", "), ErrUnsupportedAPIVersion))
				return
			}
			w.Header().Set(ElasticAPIVersionHeader, headerValue)
		} else {
			w.Header().Set(ElasticAPIVersionHeader, a.defaultVersion)
		}

		next.ServeHTTP(w, r)
	})
}
