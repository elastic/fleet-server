// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/docker/go-units"
)

func parseDownloadRate(jsonDownloadRate json.RawMessage) (*float64, error) {
	var fDownloadRate float64
	err := json.Unmarshal(jsonDownloadRate, &fDownloadRate)
	if err == nil {
		return &fDownloadRate, nil
	}

	// Handle string download_rate with format human_unitps
	var rawDownloadRate string
	err = json.Unmarshal(jsonDownloadRate, &rawDownloadRate)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling download_rate: %w", err)
	}
	if rawDownloadRate != "" {
		downloadRate, err := units.FromHumanSize(strings.TrimSuffix(rawDownloadRate, "ps"))
		if err != nil {
			return nil, fmt.Errorf("error converting download_rate from human size: %w", err)
		}
		fDownloadRate := float64(downloadRate)
		return &fDownloadRate, nil
	}

	return nil, nil
}

func (t *UpgradeMetadataDownloading) UnmarshalJSON(b []byte) error {
	object := make(map[string]json.RawMessage)
	err := json.Unmarshal(b, &object)
	if err != nil {
		return err
	}

	if raw, found := object["download_rate"]; found {
		downloadRate, err := parseDownloadRate(raw)
		if err != nil {
			return err
		}
		t.DownloadRate = downloadRate
		delete(object, "download_rate")
	}

	if raw, found := object["download_percent"]; found {
		err = json.Unmarshal(raw, &t.DownloadPercent)
		if err != nil {
			return fmt.Errorf("error reading 'download_percent': %w", err)
		}
		delete(object, "download_percent")
	}

	if raw, found := object["retry_error_msg"]; found {
		err = json.Unmarshal(raw, &t.RetryErrorMsg)
		if err != nil {
			return fmt.Errorf("error reading 'retry_error_msg': %w", err)
		}
		delete(object, "retry_error_msg")
	}

	if raw, found := object["retry_until"]; found {
		err = json.Unmarshal(raw, &t.RetryUntil)
		if err != nil {
			return fmt.Errorf("error reading 'retry_until': %w", err)
		}
		delete(object, "retry_until")
	}

	return err
}
