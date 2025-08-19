# Simple Safe

A simple Web3-native CLI for Safe multisig wallets.

Main functionality:

- `🚀` deploy a new Safe account
- `🔍` inspect a Safe account
- `📝` build a Safe transaction
- `🔏` sign a Safe transaction
- `🌐` execute a Safe transaction
- `🔌` build and sign offline
- `🪪` authenticate with a Trezor
- `🪪` authenticate with a keyfile

Safe transaction types:

- `📐` custom transactions
- `📡` smart contract call
- `🪙` ERC-20 token call
- `📦` batch transactions (via MultiSend)
- `✨` contract deployment (via CreateCall)

Benefits:

- `💻` runs in the terminal
- `🤖` all commands can be scripted
- `✅` works with any EIP-1559 EVM chain
- `🚫` does not collect your data
- `🚫` does not impose any Terms of Use
- `🚫` does not require centralized services

## Getting started

👉 _To get the most out of Simple Safe, familiarize yourself with the
[Safe Protocol](https://github.com/safe-global/safe-smart-account/blob/v1.4.1/docs/overview.md)
summary and Safe's extensive
[Safe Smart Accounts](https://docs.safe.global/advanced/smart-account-overview)
documentation._

Before you get started, you will need:

- Python 3.11 or later
- the [pipx package manager](https://pipx.pypa.io/stable/installation/)
- an EVM-compatible chain that supports EIP-1559
- an Ethereum JSON-RPC endpoint over HTTP (not Websocket)
- [Safe Smart Account](https://github.com/safe-global/safe-smart-account)
  contracts deployed (preferably at
  [canonical addresses](https://github.com/safe-global/safe-singleton-factory?tab=readme-ov-file#how-to-get-the-singleton-deployed-to-your-network))

Install Simple Safe using `pipx`:

```sh
pipx install simple-safe
```

Upgrade Simple Safe to the latest version using `pipx`:

```sh
pipx upgrade simple-safe
```

⚠️ If upgrading from an earlier version installed from Github (pre-`0.3.0`),
switch to PyPI releases with:

```sh
pipx install --force simple-safe
```

For convenience, set the environment variable `SAFE_RPC` to the JSON-RPC node
URL:

```sh
export SAFE_RPC=http://localhost:8545
```

Use the `--help` option to explore Simple Safe commands:

```console
$ safe --help

Usage: safe [OPTIONS] COMMAND [ARGS]...

  A simple Web3-native CLI for Safe multisig wallets.

Options:
  --version   print version info and exit
  -h, --help  show this message and exit

Commands:
  build       Build a Safe transaction.
  deploy      Deploy a new Safe account.
  encode      Encode contract call data.
  exec        Execute a signed Safe transaction.
  hash        Compute a Safe transaction hash.
  help        Browse the documentation.
  inspect     Inspect a Safe account.
  precompute  Compute a Safe address offline.
  preview     Preview a Safe transaction.
  sign        Sign a Safe transaction.
```

## Authentication

For signing messages and transactions, Simple Safe currently supports
authenticating with a Trezor device (more secure) or a local encrypted keyfile
(less secure).

### Trezor authentication

Before using a Trezor device with Simple Safe, ensure it is running the latest
firmware version, or a firmware version that is supported by
[trezorlib](https://github.com/trezor/trezor-firmware/blob/main/python/README.md#firmware-version-requirements).

To authenticate with a connected and unlocked Trezor device, pass the
`--trezor ACCOUNT` option to the relevant command, where `ACCOUNT` is either:

- the _full derivation path_ of the account, for example: `m/44h/60h/0h/0/123`
- the _index of the account_ at the default Trezor derivation prefix for
  Ethereum coins `m/44h/60h/0h/0`, for example: `123`

The following two options are equivalent:

- `--trezor 123`
- `--trezor m/44h/60h/0h/0/123`

### Local keyfile authentication

To authenticate with a local encrypted keyfile, pass the `--keyfile PATH`
option, where `PATH` is the relative or absolute path of the encrypted keyfile
to use.
