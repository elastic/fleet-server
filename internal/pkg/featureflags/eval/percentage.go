// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package eval

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
)

var bucketCount = big.NewInt(100)

// Bucket returns the stable bucket, in [0, 100), of segmentationKey for flagName.
// It is sha256(flagName + ":" + segmentationKey) modulo 100.
func Bucket(segmentationKey string, flagName string) int {
	hash := sha256.Sum256([]byte(flagName + ":" + segmentationKey))
	hashInt := new(big.Int)
	hashInt.SetString(hex.EncodeToString(hash[:]), 16)
	return int(hashInt.Mod(hashInt, bucketCount).Int64())
}

// IsEnabledByPercentage reports whether segmentationKey falls in the first percentage buckets of flagName.
func IsEnabledByPercentage(segmentationKey string, flagName string, percentage int) bool {
	if percentage <= 0 {
		return false
	}
	if percentage >= 100 {
		return true
	}
	return Bucket(segmentationKey, flagName) < percentage
}

// pickWeighted returns the index of the weight whose cumulative range contains bucket.
// With weights [10, 90], buckets 0-9 pick index 0, which is what IsEnabledByPercentage(key, flag, 10) reports.
func pickWeighted(bucket int, weights []int) int {
	cumulative := 0
	for i, w := range weights {
		cumulative += w
		if bucket < cumulative {
			return i
		}
	}
	return -1
}
