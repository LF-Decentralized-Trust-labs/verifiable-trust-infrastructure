# vta-cli-common

Shared CLI command handlers and rendering helpers for VTA CLIs. Part of the
[Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace.

## Overview

`vta-cli-common` provides the shared command implementations and TUI rendering
used by both the [CNM CLI](../cnm-cli/) (multi-community) and
[PNM CLI](../pnm-cli/) (single-VTA) clients:

- **Command handlers** -- shared implementations for keys, contexts, ACL, auth,
  config, backup, and health commands.
- **TUI rendering** -- `ratatui`-based table and detail views for terminal
  output.

This crate is a library dependency of the CLI binaries and is not intended to
be used directly.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
vta-cli-common = "0.2"
```

## License

Apache-2.0
