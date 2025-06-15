# Simple Safe

A simple & decentralized CLI for Safe accounts.

Functionality:

`🚀` Deploy a Safe account<br/>
`📝` Build a Safe transaction<br/>
`🔏` Sign a Safe transaction<br/>
`⚙️` Execute a Safe transaction<br/>
`🔌` Build and sign offline<br/>
`🪪` Authenticate with a keyfile<br/>

Benefits:

`✅` Runs in the terminal<br/>
`✅` No Terms of Use to accept<br/>
`✅` No Privacy Policy to accept<br/>
`✅` All commands can be scripted<br/>
`✅` Not reliant on centralized services<br/>
`✅` No need for chain to be officially supported<br/>

## Quick Start

To get started, you will need:

- [ ] EVM-compatible chain that implements EIP-1559
- [ ] JSON-RPC endpoint over HTTP (not Websocket)
- [ ] [Safe contracts](https://github.com/safe-global/safe-smart-account)
      deployed (preferably at
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

  A simple & decentralized CLI for Safe accounts.

Options:
  -h, --help  show this message and exit

Commands:
  build    Build a Safe transaction.
  deploy   Deploy a new Safe account.
  encode   Encode smart contract call data.
  exec     Execute a signed Safe transaction.
  hash     Compute hash of Safe transaction.
  inspect  Inspect a Safe account.
  preview  Preview a Safe transaction.
  sign     Sign a Safe transaction.
```
