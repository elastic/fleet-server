// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package env

import (
	"os"
	"strconv"
	"time"
)

func GetStr(key, defaultVal string) string {
	val, ok := os.LookupEnv(key)
	if !ok {
		val = defaultVal
	}
	return val
}

func GetBool(key string, defaultVal bool) bool {
	val := defaultVal

	if valS, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(valS); err == nil {
			val = b
		}
	}
	return val
}

func GetUint64(key string, defaultVal uint64) uint64 {
	val := defaultVal

	if valS, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseUint(valS, 10, 64); err == nil {
			val = b
		}
	}
	return val
}

func GetInt(key string, defaultVal int) int {
	val := defaultVal

	if valS, ok := os.LookupEnv(key); ok {
		if b, err := strconv.Atoi(valS); err == nil {
			val = b
		}
	}
	return val
}

func GetDur(key string, defaultVal time.Duration) time.Duration {
	val := defaultVal

	if valS, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(valS); err == nil {
			val = d
		}
	}
	return val
}

func GetSecond(key string, defaultVal int) time.Duration {
	return time.Duration(GetInt(key, defaultVal)) * time.Second
}

func LogPretty() bool {
	return GetBool("LOG_PRETTY", false)
}

func LogLevel(defaultVal string) string {
	return GetStr("LOG_LEVEL", defaultVal)
}

func ServerReadTimeout(defaultVal int) time.Duration {
	return GetSecond("SERVER_READ_TIMEOUT", defaultVal)
}

func ServerWriteTimeout(defaultVal int) time.Duration {
	return GetSecond("SERVER_WRITE_TIMEOUT", defaultVal)
}

func ServerBind(defaultVal string) string {
	return GetStr("SERVER_BIND", defaultVal)
}

func ServerMaxHeaderByteSize(defaultVal int) int {
	return GetInt("SERVER_MAX_HEADER_SIZE", defaultVal)
}

func ServerRateLimitBurst(defaultVal int) int {
	return GetInt("SERVER_RATE_LIMIT_BURST", defaultVal)
}

func ServerRateLimitInterval(defaultVal time.Duration) time.Duration {
	return GetDur("SERVER_RATE_LIMIT_INTERVAL", defaultVal)
}

func KeyFile(defaultVal string) string {
	return GetStr("SERVER_KEY_FILE", defaultVal)
}

func CertFile(defaultVal string) string {
	return GetStr("SERVER_CERT_FILE", defaultVal)
}

func ESUrl(defaultVal string) string {
	return GetStr("ES_URL", defaultVal)
}

func ESUsername(defaultVal string) string {
	return GetStr("ES_USER", defaultVal)
}

func ESPassword(defaultVal string) string {
	return GetStr("ES_PASS", defaultVal)
}

func ESSkipVerify(defaultVal bool) bool {
	return GetBool("ES_SKIPVERIFY", defaultVal)
}

func ESMaxConnsPerHost(defaultVal int) int {
	return GetInt("ES_MAXCONNSPERHOST", defaultVal)
}

func ApiKeyTTL(defaultVal time.Duration) time.Duration {
	return GetDur("APIKEY_TTL", defaultVal)
}

func LongPollTimeout(defaultVal int) time.Duration {
	return GetSecond("LONGPOLL_TIMEOUT", defaultVal)
}

func CheckinTimeout(defaultVal int) time.Duration {
	return GetSecond("CHECKIN_TIMEOUT", defaultVal)
}

func ProfileBind(defaultVal string) string {
	return GetStr("PROFILE_BIND", defaultVal)
}

func PolicyThrottle(defaultVal time.Duration) time.Duration {
	return GetDur("POLICY_THROTTLE", defaultVal)
}

func BulkFlushInterval(defaultVal time.Duration) time.Duration {
	return GetDur("BULK_FLUSH_INTERVAL", defaultVal)
}

func MaxEnrollPending(defaultVal uint64) uint64 {
	return GetUint64("MAX_ENROLL_PENDING", defaultVal)
}

func BulkCheckinFlushInterval(defaultVal time.Duration) time.Duration {
	return GetDur("BULK_CHECKIN_FLUSH_INTERVAL", defaultVal)
}
