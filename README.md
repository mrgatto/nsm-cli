# Nitro Security Module (NSM) Cli

This is a command line tool for AWS Nitro Security Module.

Nitro Enclaves only support Linux, so this package is not intended to be used on other OSs or architectures outside enclaves.

All outputs are _JSON_ format.


## Build

```shell script
rustup target install x86_64-unknown-linux-musl
cargo build --release --target=x86_64-unknown-linux-musl
```

or (not required Rust and musl-gcc installed): 

```shell script
docker run -v $PWD:/volume --rm -t clux/muslrust cargo build --release
```

## Usage

```console
Nitro Security Module Cli

USAGE:
    nsm-cli [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    attestation     Create an AttestationDoc and sign it with it's private key to ensure authenticity
    describe-nsm    Returns capabilities and version of the connected NitroSecureModule
    describe-pcr    Read data from PlatformConfigurationRegister at some index
    get-random      Returns number of bytes of entropy
    help            Prints this message or the help of the given subcommand(s)
```

## Outputs examples

TODO

## Attestation document validation

[examples](examples)