# Simple Safe

A simple & decentralized CLI for Safe Accounts.

Functionality:

- 🚀 Deploy a Safe Account
- 📝 Build a Safe Transaction
- 🔏 Sign a Safe Transaction
- ⚙️ Execute a Safe Transaction
- 🪪 Authenticate with Ethereum keyfile

Benefits:

- ✅ Runs in the terminal
- ✅ No Terms of Use to accept
- ✅ No Privacy Policy to accept
- ✅ All commands can be scripted
- ✅ No reliance on centralized services
- ✅ No need for chain to be officially supported

Pre-requisites:

- JSON-RPC node on an EVM-compatible chain.
- The chain implements EIP-1559 (London hard-fork).
- Safe contracts have been deployed on chain. See the instructions in the
  [safe-global/safe-smart-account](https://github.com/safe-global/safe-smart-account)
  repo. To deploy to canonical addresses, it is recommended to make use of the
  Safe Singleton Factory.

Limitations:

- Only tested with Safe Accounts v1.4.1.
- Only deploys Safe Accounts v1.4.1 (latest).
- Only tested on Linux operating systems.
- Not all Safe functionality is implemented yet.
- Error handling is basic and not user friendly.

## Quick Start

Install Simple Safe using `pipx`:

```sh
pipx install git+ssh://git@github.com/clearmatics/simple-safe.git
```

For convenience, set the environment variable `SAFE_RPC` to the JSON-RPC node
URL:

```sh
export SAFE_RPC=http://localhost:8545
```

Use the `--help` option to explore the tool's subcommands:

```console
$ safe --help

Usage: safe [OPTIONS] COMMAND [ARGS]...

  A simple & decentralized CLI for Safe Accounts.

Options:
  -h, --help  Show this message and exit.

Commands:
  build    Build transaction data.
  deploy   Deploy a new Safe Account.
  exec     Execute a signed Safe Transaction.
  hash     Compute hash of Safe Transaction.
  inspect  Inspect a Safe Account.
  preview  Preview a Safe Transaction.
  sign     Sign a Safe Transaction.
```
