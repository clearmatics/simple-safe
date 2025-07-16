import logging
import sys
from getpass import getpass
from typing import TYPE_CHECKING, Any, Optional, Protocol, cast

import click
from hexbytes import HexBytes

from .console import make_status_logger

if TYPE_CHECKING:
    from eth_account.datastructures import SignedTransaction
    from eth_account.signers.local import LocalAccount
    from eth_account.types import TransactionDictType
    from eth_typing import ChecksumAddress
    from trezorlib.messages import Features
    from web3.types import TxParams


logger = logging.getLogger(__name__)
status = make_status_logger(logger)

TREZOR_DEFAULT_PREFIX = "m/44h/60h/0h/0"


class Authenticator(Protocol):
    address: "ChecksumAddress"

    def sign_transaction(self, params: "TxParams") -> "SignedTransaction": ...

    def sign_typed_data(self, data: dict[str, Any]) -> bytes: ...


class KeyfileAuthenticator:
    account: "LocalAccount"

    def __init__(self, keyfile: str):
        from eth_account import Account

        self.keyfile = keyfile
        password = getpass(prompt=f"[{self.keyfile}] password: ", stream=sys.stderr)
        with status("Decrypting keyfile..."):
            with click.open_file(self.keyfile) as kf:
                keydata = kf.read()
            privkey = Account.decrypt(keydata, password=password)
            self.account = Account.from_key(privkey)
            self.address = self.account.address

    def __repr__(self):
        return f"keyfile: {self.keyfile}"

    def sign_transaction(self, params: "TxParams") -> "SignedTransaction":
        with status("Signing Web3 transaction..."):
            return self.account.sign_transaction(cast("TransactionDictType", params))

    def sign_typed_data(self, data: dict[str, Any]) -> bytes:
        with status("Signing typed data..."):
            return self.account.sign_typed_data(full_message=data).signature


class TrezorAuthenticator:
    def __init__(self, path_str: str):
        import trezorlib.ethereum as trezor_eth
        from eth_utils.address import to_checksum_address
        from trezorlib.client import get_default_client
        from trezorlib.exceptions import Cancelled
        from trezorlib.tools import parse_path
        from trezorlib.transport import DeviceIsBusy

        try:
            self.path = parse_path(path_str)
        except ValueError as exc:
            raise click.ClickException(
                f"Invalid Trezor BIP32 derivation path '{path_str}'."
            ) from exc

        try:
            self.client = get_default_client()
        except DeviceIsBusy as exc:
            raise click.ClickException("Device in use by another process.") from exc
        except Exception as exc:
            raise click.ClickException(
                "No Trezor device found. Check device is connected, unlocked, and detected by OS."
            ) from exc
        device_info = self.device_info(self.client.features)
        logger.info(f"Connected to Trezor: {device_info}")

        try:
            address_str = trezor_eth.get_address(self.client, self.path)
        except Cancelled as exc:
            raise click.Abort() from exc

        self.address = to_checksum_address(address_str)
        self.path_str = path_str

    def device_info(self, features: "Features") -> str:
        model = str(features.model) or "1"
        label = features.label or "(none)"
        return f"model='{model}', device_id='{features.device_id}', label='{label}'"

    def sign_transaction(self, params: "TxParams") -> "SignedTransaction":
        assert "chainId" in params
        assert "data" in params
        assert "gas" in params
        assert "maxFeePerGas" in params
        assert "maxPriorityFeePerGas" in params
        assert "nonce" in params
        assert "to" in params
        assert "value" in params
        import trezorlib.ethereum as trezor_eth

        v_int, r_bytes, s_bytes = trezor_eth.sign_tx_eip1559(
            self.client,
            self.path,
            nonce=params["nonce"],
            gas_limit=params["gas"],
            to=str(params["to"]),
            value=params["value"],
            data=HexBytes(params["data"]),
            chain_id=params["chainId"],
            max_gas_fee=int(params["maxFeePerGas"]),
            max_priority_fee=int(params["maxPriorityFeePerGas"]),
        )
        from eth_account._utils.legacy_transactions import (
            encode_transaction,
        )
        from eth_account.typed_transactions.typed_transaction import TypedTransaction
        from eth_account.types import TransactionDictType
        from eth_utils.conversions import to_int
        from eth_utils.crypto import keccak

        r_int = to_int(r_bytes)
        s_int = to_int(s_bytes)
        tx_unsigned = TypedTransaction.from_dict(cast(TransactionDictType, params))
        tx_encoded = encode_transaction(tx_unsigned, vrs=(v_int, r_int, s_int))
        txhash = keccak(tx_encoded)
        return SignedTransaction(
            raw_transaction=HexBytes(tx_encoded),
            hash=HexBytes(txhash),
            r=r_int,
            s=s_int,
            v=v_int,
        )

    def sign_typed_data(self, data: dict[str, Any]) -> bytes:
        import trezorlib.ethereum as trezor_eth

        sigdata = trezor_eth.sign_typed_data(self.client, self.path, data)
        return sigdata.signature

    def __repr__(self):
        return f"trezor: {self.path_str}"


def validate_authenticator(
    keyfile: Optional[str],
    trezor: Optional[str],
) -> Authenticator:
    if trezor and keyfile:
        raise click.ClickException("Expected at most one authentication method.")
    elif keyfile:
        auth = KeyfileAuthenticator(keyfile)
    elif trezor:
        if trezor.isdigit():
            index = int(trezor)
            path_str = f"{TREZOR_DEFAULT_PREFIX}/{index}"
        else:
            path_str = trezor
        auth = TrezorAuthenticator(path_str)
    else:
        raise click.ClickException("No authentication method provided.")
    logger.info(f"Using authenticator: {auth}")
    return auth
