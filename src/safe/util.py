from typing import cast

from eth_typing import ChecksumAddress
from pydantic import BaseModel


def as_checksum(checksum_str: str) -> ChecksumAddress:
    return cast(ChecksumAddress, checksum_str)


def serialize(model: BaseModel):
    return model.model_dump_json(indent=2)
