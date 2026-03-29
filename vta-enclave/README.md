# vta-enclave

VTA binary for [AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/)
(TEE mode). Part of the
[Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace.

## Overview

`vta-enclave` is a dedicated binary that runs the VTA service inside an AWS
Nitro Enclave. It depends on `vta-service` as a library and adds TEE-specific
bootstrap logic:

- **KMS integration** -- decrypts the master seed using AWS KMS with attestation-based
  key policies.
- **Vsock transport** -- communicates with the parent EC2 instance via vsock for
  storage, logging, and network proxying.
- **Attestation** -- leverages Nitro Enclave attestation documents for secure
  key release.

This crate is not intended for use outside of Nitro Enclave deployments. For
local/dev/cloud deployments, use `vta-service` directly.

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `rest` | Yes | Enable the REST API thread |
| `didcomm` | Yes | Enable the DIDComm messaging thread |
| `webvh` | No | `did:webvh` creation support |
| `vsock-store` | No | Vsock-proxied storage (for enclave persistence) |
| `vsock-log` | No | Forward tracing logs over vsock to the parent instance |

## Building

The enclave binary must be built on a Linux host (vsock requires Linux):

```sh
cargo build --package vta-enclave --release --features rest,didcomm,vsock-store,vsock-log
```

See the [deployment guide](../deploy/nitro/) for full enclave image build
instructions.

## License

Apache-2.0
