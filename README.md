# Nitro Security Module (NSM) Cli

This is a command line tool for AWS Nitro Security Module.

Nitro Enclaves only support Linux OSs, so this package is not intended to be used on other OSs or architectures.

All outputs are _JSON_ format.

## Build

```shell script
rustup target install x86_64-unknown-linux-musl
cargo build --release --target=x86_64-unknown-linux-musl
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
    describe-nsm    Return capabilities and version of the connected NitroSecureModule
    describe-pcr    Read data from PlatformConfigurationRegister at some index
    help            Prints this message or the help of the given subcommand(s)
```


