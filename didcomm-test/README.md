# didcomm-test

Standalone DIDComm connectivity test harness. Part of the
[Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace.

## Overview

`didcomm-test` is a diagnostic binary that mimics the VTA TEE key generation
and DIDComm messaging flow. It is used to verify end-to-end DIDComm
connectivity without deploying a full VTA instance.

The test harness:

1. Generates ephemeral Ed25519 keys (mimicking TEE key derivation).
2. Resolves DIDs via the Affinidi DID resolver cache.
3. Sends and receives DIDComm v2 messages through a mediator.

## Usage

```sh
cargo run --package didcomm-test -- --mediator-did <DID> --mediator-url <URL>
```

## License

Apache-2.0
