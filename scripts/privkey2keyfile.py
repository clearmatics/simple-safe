#!/usr/bin/env -S uv run
#
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "eth-account",
# ]
# ///

"""Create an encrypted keyfile from a private key.

usage: privkey2keyfile.py"""

import json
import sys
from getpass import getpass

from eth_account import Account
from hexbytes import HexBytes


def create_keyfile():
    privkey = HexBytes(getpass(prompt="Private Key: "))
    keydata = Account.encrypt(
        private_key=privkey,
        password=getpass(),
    )
    print(json.dumps(keydata, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 1:
        print(__doc__)
        sys.exit(1)
    create_keyfile(*sys.argv[1:])
