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
