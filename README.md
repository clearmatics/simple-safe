# Simple Safe

A simple Web3-native CLI for Safe accounts.

Functionality:

<div>
<code>🚀</code> Deploy a Safe account<br/>
<code>📝</code> Build a Safe transaction<br/>
<code>🔏</code> Sign a Safe transaction<br/>
<code>⚙️</code> Execute a Safe transaction<br/>
<code>🔌</code> Build and sign offline<br/>
<code>🪪</code> Authenticate with a Trezor<br/>
<code>🪪</code> Authenticate with a keyfile<br/>
</div><br/>

Benefits:

<div>
<code>✅</code> Runs in the terminal<br/>
<code>✅</code> No Terms of Use to accept<br/>
<code>✅</code> No Privacy Policy to accept<br/>
<code>✅</code> All commands can be scripted<br/>
<code>✅</code> Not reliant on centralized services<br/>
<code>✅</code> No need for chain to be officially supported<br/>
</div>

## Getting started

You will need:

- [ ] an EVM-compatible chain that supports EIP-1559
- [ ] a JSON-RPC endpoint over HTTP (not Websocket)
- [ ] the [Safe contracts](https://github.com/safe-global/safe-smart-account)
      deployed (preferably at
      [canonical addresses](https://github.com/safe-global/safe-singleton-factory?tab=readme-ov-file#how-to-get-the-singleton-deployed-to-your-network))
- [ ] an understanding of the
      [Safe Protocol](https://github.com/safe-global/safe-smart-account/blob/v1.4.1/docs/overview.md)
      and
      [Safe Smart Accounts](https://docs.safe.global/advanced/smart-account-overview)

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

  A simple Web3-native CLI for Safe accounts.

Options:
  --version   print version info and exit
  -h, --help  show this message and exit

Commands:
  build       Build a Safe transaction.
  deploy      Deploy a new Safe account.
  encode      Encode contract call data.
  exec        Execute a signed Safe transaction.
  hash        Compute hash of Safe transaction.
  inspect     Inspect a Safe account.
  precompute  Compute a Safe address offline.
  preview     Preview a Safe transaction.
  sign        Sign a Safe transaction.
```

## Authentication

Simple Safe supports the following authentication methods for signing messages
and transactions:

- Trezor device
- local keyfile

### Trezor authentication

Before using a Trezor device with Simple Safe, ensure it is running the latest
firmware version, or a firmware version that is supported by
[trezorlib](https://github.com/trezor/trezor-firmware/blob/main/python/README.md#firmware-version-requirements).

To authenticate with a connected Trezor device, pass the `--trezor ACCOUNT`
option to the relevant command, where `ACCOUNT` is either:

- the _full derivation path_ of the account, for example: `m/44h/60h/0h/123`
- the _index of the account_ at the default Trezor derivation prefix for
  Ethereum coins `m/44h/60h/0h`, for example: `123`

The following two options are equivalent:

- `--trezor 123`
- `--trezor m/44h/60h/0h/123`

### Local keyfile authentication

To authenticate with a local keyfile, pass the `--keyfile PATH` option, where
`PATH` is the relative or absolute path of the encrypted keyfile to use.
