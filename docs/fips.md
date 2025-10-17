# FIPS support

**NOTE: FIPS Support is in-progress**

The fleet-server can be built in a FIPS capable mode.
This forces the use of a FIPS provider to handle any cryptographic calls.

Currently FIPS is provided by compiling with the [microsoft/go](https://github.com/microsoft/go) distribution.
This toolchain must be present for local compilation.

## Build changes

As we are using micrsoft/go as a base we follow their conventions.

Our FIPS changes require the `requirefips` build tag.
When compiling `GOEXPERIMENT=systemcrypto` and `CGO_ENABLED=1` must be set.
Additionally the `MS_GOTOOLCHAIN_TELEMETRY_ENABLED=0` env var is set to disable telemetry for [microsoft/go](https://github.com/microsoft/go).

The `FIPS=true` env var is used by our magefile as the FIPS toggle.
This env var applies to all targets, at a minimum the `requirefips` tag will be set.
For targets that compile binaries, the `GOEXPERIMENT=systemcrypto` and `CGO_ENABLED=1` env vars are set.

For developer conveniance, running `FIPS=true mage multipass` will provision a multipass VM with the Microsoft/go toolchain.
See [Multipass VM Usage](#multipass-vm-usage) for additional details.

### Multipass VM Usage

A Multipass VM created with `FIPS=true mage multipass` is able to compile FIPS enabled golang programs, but is not able to run them.
When you try to run one the following error occurs:
```
GODEBUG=fips140=on ./bin/fleet-server -c fleet-server.yml
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

4. Run the program with the `OPENSSL_CONF=openssl.cnf` and `GODEBUG=fips140=on` env vars, i.e.,
```
OPENSSL_CONF=./openssl.cnf GODEBUG=fips140=on ./bin/fleet-server -c fleet-server.yml
23:48:47.871 INF Boot fleet-server args=["-c","fleet-server.yml"] commit=55104f6f ecs.version=1.6.0 exe=./bin/fleet-server pid=65037 ppid=5642 service.name=fleet-server service.type=fleet-server version=9.0.0
i...
```

## Usage

Binaries produced with the `FIPS=true` env var will panic on startup if they cannot find a FIPS provider.
The system/image is required to have a FIPS provider available.
