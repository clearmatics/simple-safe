from typing import cast

from eth_typing import ChecksumAddress
from pydantic import BaseModel
from web3.types import TxParams


def as_checksum(checksum_str: str) -> ChecksumAddress:
    return cast(ChecksumAddress, checksum_str)


def normalize_txparams(txparams: TxParams) -> dict[str, str]:
    # Address Pyright 'reportTypedDictNotRequiredAccess' error due to TxParams
    # fields being optional
    assert "from" in txparams
    assert "chainId" in txparams
    assert "nonce" in txparams
    assert "to" in txparams
    assert "value" in txparams
    assert "gas" in txparams
    assert "maxFeePerGas" in txparams
    assert "maxPriorityFeePerGas" in txparams
    assert "data" in txparams
    normalized: dict[str, str] = {
        "From": str(txparams["from"]),
        "Chain ID": str(txparams["chainId"]),
        "Nonce": str(txparams["nonce"]),
        "To": str(txparams["to"]),
        "Value": str(txparams["value"]),
        "Estimated Gas": str(txparams["gas"]),
        "Max Fee": str(txparams["maxFeePerGas"]),
        "Max Priority Fee": str(txparams["maxPriorityFeePerGas"]),
        "Data": str(txparams["data"]),
    }
    return normalized


def serialize(model: BaseModel):
    return model.model_dump_json(indent=2)
