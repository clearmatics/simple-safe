A simple & decentralized CLI for Safe Accounts.

Benefits:

- ✅ No Terms of Use to accept
- ✅ No Privacy Policy to accept
- ✅ No reliance on centralized services
- ✅ No need for chain to be officially supported
- ✅ Runs in the terminal
- ✅ All commands can be scripted

Functionality:

- 🚀 Deploy Safe Account
- 📝 Build a SafeTx
- 🔏 Sign a SafeTx
- ⚙️ Execute a SafeTx
- 🪪 Authenticate with Ethereum keyfile

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
