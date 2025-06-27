import logging
import sys
from getpass import getpass
from typing import Any, Optional, Protocol, cast

import click
from eth_account import Account
from eth_account.datastructures import SignedTransaction
from eth_account.signers.local import LocalAccount
from eth_account.types import TransactionDictType
from eth_typing import ChecksumAddress
from web3.types import TxParams

from .console import make_status_logger

logger = logging.getLogger(__name__)
status = make_status_logger(logger)


class Authenticator(Protocol):
    address: ChecksumAddress

    def sign_transaction(self, params: TxParams) -> SignedTransaction: ...

    def sign_typed_data(self, data: dict[str, Any]) -> bytes: ...


class KeyfileAuthenticator:
    account: LocalAccount

    def __init__(self, keyfile: str):
        self.keyfile = keyfile
        password = getpass(prompt=f"[{self.keyfile}] password: ", stream=sys.stderr)
        with status("Decrypting keyfile..."):
            with click.open_file(self.keyfile) as kf:
                keydata = kf.read()
            privkey = Account.decrypt(keydata, password=password)
            self.account = Account.from_key(privkey)
            self.address = self.account.address

    def __repr__(self):
        return (
            f"Keyfile Authenticator: keyfile='{self.keyfile}', account='{self.address}'"
        )

    def sign_transaction(self, params: TxParams) -> SignedTransaction:
        with status("Signing Web3 transaction..."):
            return self.account.sign_transaction(cast(TransactionDictType, params))

    def sign_typed_data(self, data: dict[str, Any]) -> bytes:
        with status("Signing typed data..."):
            return self.account.sign_typed_data(full_message=data).signature


def get_authenticator(
    keyfile: Optional[str],
) -> Authenticator:
    if keyfile is None:
        raise RuntimeError("No keyfile supplied.")
    auth = KeyfileAuthenticator(keyfile)
    logger.info(f"Using {auth}")
    return auth
