package testing

import (
	"os"
	"strings"
)

// IsFIPS140Only returns true if GODEBUG=fips140=only is set. Note that
// we only set GODEBUG=fips140=only while testing.
func IsFIPS140Only() bool {
	// NOTE: This only checks env var; at the time of writing fips140 can only be set via env
	// other GODEBUG settings can be set via embedded comments or in go.mod, we may need to account for this in the future.
	s := os.Getenv("GODEBUG")
	return strings.Contains(s, "fips140=only")
}
