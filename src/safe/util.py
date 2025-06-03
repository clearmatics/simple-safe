from typing import cast

from eth_typing import ChecksumAddress
from pydantic import BaseModel
from rich.table import Table


def as_checksum(checksum_str: str) -> ChecksumAddress:
    return cast(ChecksumAddress, checksum_str)


def serialize(model: BaseModel):
    return model.model_dump_json(indent=2)


def mktable():
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column("Field", justify="right", style="bold", no_wrap=True)
    table.add_column("Value")
    return table
