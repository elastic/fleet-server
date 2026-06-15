# FIPS support

**NOTE: FIPS Support is in-progress**

The fleet-server can be built in a FIPS capable mode using Go's built-in FIPS 140-3 support via `GOFIPS140=certified`.
This is pure Go and does not require an external crypto provider or CGO.

## Build changes

FIPS builds require the `requirefips` build tag and `GOFIPS140=certified` set at compile time.

The `FIPS=true` env var is used by the magefile as the FIPS toggle.
When set, the magefile automatically applies the `requirefips` tag and sets `GOFIPS140=certified` for all build and test targets.

## Usage

Binaries produced with `FIPS=true` will allow FIPS-approved algorithms at runtime when `GODEBUG=fips140=on` or enfoce them when `GODEBUG=fips140=only` is set.

- `GODEBUG=fips140=on` - enables FIPS mode, falls back to non-FIPS for unsupported operations
- `GODEBUG=fips140=only` - enforces strict FIPS mode, panics if a non-FIPS operation is attempted

The FIPS docker image sets `GODEBUG=fips140=on` by default.

## Testing

Two unit test targets are available for FIPS testing:

- `FIPS=true mage test:unit` - runs unit tests compiled with `requirefips` and `GOFIPS140=certified`
- `FIPS=true mage test:unitFIPSOnly` - runs the above with `GODEBUG=fips140=only` enforced at runtime

Note: `test:unitFIPSOnly` also sets `GODEBUG=tlsmlkem=0` to disable X25519MLKEM768, which is not FIPS-approved.
