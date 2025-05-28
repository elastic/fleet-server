# FIPS support

**NOTE: FIPS Support is in-progress**

The fleet-server can be built in a FIPS capable mode.
This forces the use of a FIPS provider to handle any cryptographic calls.

Currently FIPS is provided by compiling with the [microsoft/go](https://github.com/microsoft/go) distribution.
This toolchain must be present for local compilation.

## Build changes

As we are using micrsoft/go as a base we follow their conventions.

<<<<<<< HEAD
The buildtag `requirefips` is passed when FIPS is enabled/required.
Additionally when compiling `GOEXPERIMENT=systemcrypto` is specified.
=======
Our FIPS changes require the `requirefips` and `ms_tls13kdf` buildtags.
When compiling `GOEXPERIMENT=systemcrypto` and `CGO_ENABLED=1` must be set.
>>>>>>> db5f46b (Convert Makefile to magefile.go (#4912))

The `FIPS=true` env var is used by our magefile as the FIPS toggle.
This env var applies to all targets, at a minimum the `requirefips` and `ms_tls13kdf` tags will be set.
For targets that compile binaries, the `GOEXPERIMENT=systemcrypto` and `CGO_ENABLED=1` env vars are set.

<<<<<<< HEAD
- `make multipass` - Provision a multipass VM with the Microsoft/go toolchain. See [Multipass VM Usage](#multipass-vm-usage) for additional details.
- `make local` - Compile a fleet-server targetting the machine's GOOS/GOARCH with FIPS enabled
- `make cover-*` - Compile a coverage and fips enabled fleet-server for e2e tests
- `make test-unit` - Run unit tests passing the `requirefips` build tag.
- `make benchmark` - Run benchmarks passing the `requirefips` build tag.
- `make release-*` - Compile a release binary with FIPS enabled. Will have the name fleet-server-$VERSION-$OS-$ARCH-fips
- `make package-target` - Will package a FIPS enabled release and produce the sha512 checksum for it.
- `make build-releaser` - Will create the fleet-server builder image based on Microsoft's FIPS enabled golang image.
- `make docker-release` - Runs `make release` to produce FIPS enabled binaries in a FIPS docker container.
- `make docker-cover-e2e-binaries` - Will produce coverage and FIPS enabled binaries for e2e tests from within the same docker container that `build-release` makes
=======
For developer conveniance, running `FIPS=true mage multipass` will provision a multipass VM with the Microsoft/go toolchain.
See [Multipass VM Usage](#multipass-vm-usage) for additional details.
>>>>>>> db5f46b (Convert Makefile to magefile.go (#4912))

### Multipass VM Usage

A Multipass VM created with `FIPS=true mage multipass` is able to compile FIPS enabled golang programs, but is not able to run them.
When you try to run one the following error occurs:
```
GOFIPS=1 ./bin/fleet-server -c fleet-server.yml
panic: opensslcrypto: can't enable FIPS mode for OpenSSL 3.0.13 30 Jan 2024: openssl: FIPS mode not supported by any provider

goroutine 1 [running]:
crypto/internal/backend.init.1()
	/usr/local/go/src/crypto/internal/backend/openssl_linux.go:85 +0x210
```

In order to be  able to run a FIPS enabled binary, openssl must have a fips provider.
Openssl [provides instructions on how to do this](https://github.com/openssl/openssl/blob/master/README-FIPS.md).

A TLDR for our multipass container is:

1. Download and compile the FIPS provider for openssl in the VM by running:
```
wget https://github.com/openssl/openssl/releases/download/openssl-3.0.13/openssl-3.0.13.tar.gz
tar -xzf openssl-3.0.13.tar.gz
cd openssl-3.0.13
./Configure enable-fips
make test
sudo make install_fips
sudo openssl fipsinstall -out /usr/local/ssl/fipsmodule.cnf -module /usr/local/lib/ossl-modules/fips.so
```

2. Copy the `fips.so` module to the system library, in order to find the location run:
```
openssl version -m
```

On my VM I would copy the `fips.so` module with:
```
sudo cp /usr/local/lib/ossl-modules/fips.so /usr/lib/aarch64-linux-gnu/ossl-modules/fips.so
```

3. Create an openssl.cnf for the program to use with the contents:
```
config_diagnostics = 1
openssl_conf = openssl_init

.include /usr/local/ssl/fipsmodule.cnf

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
fips = fips_sect
base = base_sect

[base_sect]
activate = 1

[algorithm_sect]
default_properties = fips=yes
```

4. Run the program with the `OPENSSL_CONF=openssl.cnf` and `GOFIPS=1` env vars, i.e.,
```
OPENSSL_CONF=./openssl.cnf GOFIPS=1 ./bin/fleet-server -c fleet-server.yml
23:48:47.871 INF Boot fleet-server args=["-c","fleet-server.yml"] commit=55104f6f ecs.version=1.6.0 exe=./bin/fleet-server pid=65037 ppid=5642 service.name=fleet-server service.type=fleet-server version=9.0.0
i...
```

## Usage

<<<<<<< HEAD
A FIPS enabled binary should be ran with the env var `GOFIPS=1` set.
The system/image is required to have a FIPS compliant provider available.
=======
Binaries produced with the `FIPS=true` env var will panic on startup if they cannot find a FIPS provider.
The system/image is required to have a FIPS provider available.
>>>>>>> db5f46b (Convert Makefile to magefile.go (#4912))
