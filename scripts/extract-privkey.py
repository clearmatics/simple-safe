#!/usr/bin/env -S uv run
#
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "eth-account",
# ]
# ///

"""Extract a private key from a keyfile with a blank password.

usage: extract-privkey.py <keyfile>"""

import sys
from eth_account import Account
from eth_account.messages import encode_defunct


def extract_privkey(keyfile: str, password: str = ""):
    with open(keyfile) as kd:
        keydata = kd.read()
    privkey = Account.decrypt(keydata, password=password)
    account = Account.from_key(privkey)
    print(f"account={account.address}")
    print(f"privkey={privkey.hex()}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    extract_privkey(*sys.argv[1:])
