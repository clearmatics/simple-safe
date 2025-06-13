# Simple Safe

A simple & decentralized CLI for Safe Accounts.

Functionality:

- 🚀 deploy a Safe Account
- 📝 build a Safe Transaction
- 🔏 sign a Safe Transaction
- ⚙️ execute a Safe Transaction
- 🪪 authenticate with Ethereum keyfile

Benefits:

- ✅ runs in the terminal
- ✅ no Terms of Use to accept
- ✅ no Privacy Policy to accept
- ✅ all commands can be scripted
- ✅ not reliant on centralized services
- ✅ no need for chain to be officially supported

Limitations:

- ⏳ still a work in progress
- ⚠️ error handling is not user friendly

## Quick Start

To get started, you will need:

- [ ] a chain that implements EIP-1559
- [ ] a JSON-RPC endpoint
- [ ] [Safe contracts](https://github.com/safe-global/safe-smart-account)
      already deployed (preferably at
      [canonical addresses](https://github.com/safe-global/safe-singleton-factory?tab=readme-ov-file#how-to-get-the-singleton-deployed-to-your-network))

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
  build    Build a Safe Transaction.
  deploy   Deploy a new Safe Account.
  encode   Encode smart contract call data.
  exec     Execute a signed Safe Transaction.
  hash     Compute hash of Safe Transaction.
  inspect  Inspect a Safe Account.
  preview  Preview a Safe Transaction.
  sign     Sign a Safe Transaction.
```
