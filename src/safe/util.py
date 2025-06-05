from typing import Any, cast

from eth_account.messages import (
    _hash_eip191_message,  # pyright: ignore[reportPrivateUsage]
    encode_typed_data,
)
from eth_typing import URI, ChecksumAddress
from hexbytes import HexBytes
from pydantic import BaseModel
from safe_eth.eth import EthereumClient
from safe_eth.safe import SafeTx


def as_checksum(checksum_str: str) -> ChecksumAddress:
    return cast(ChecksumAddress, checksum_str)


def eip712_json_encoder(obj: Any):
    if isinstance(obj, HexBytes):
        return obj.to_0x_hex()
    raise TypeError(f"Cannot serialize object of {type(obj)}")


def hash_eip712_data(data: Any) -> HexBytes:  # using eth_account
    encoded = encode_typed_data(full_message=data)
    return HexBytes(_hash_eip191_message(encoded))


def eip712_data_to_safetx(
    message: Any, rpc: str | None = None, version: str | None = None
) -> SafeTx:
    if not (rpc or version):
        raise RuntimeError("eip712_data_to_safetx: 'rpc' or 'version' required")
    elif rpc:
        client = EthereumClient(URI(rpc))
    else:
        client = EthereumClient()
    return SafeTx(
        ethereum_client=client,
        safe_address=message["domain"]["verifyingContract"],
        to=message["message"]["to"],
        value=message["message"]["value"],
        data=HexBytes(message["message"]["data"]),
        operation=message["message"]["operation"],
        safe_tx_gas=message["message"]["safeTxGas"],
        base_gas=message["message"]["dataGas"],  # supports version < 1
        gas_price=message["message"]["gasPrice"],
        gas_token=message["message"]["gasToken"],
        refund_receiver=message["message"]["refundReceiver"],
        signatures=None,
        safe_nonce=message["message"]["nonce"],
        safe_version=version if version else None,
        chain_id=message["domain"].get("chainId"),
    )


def serialize(model: BaseModel):
    return model.model_dump_json(indent=2)
