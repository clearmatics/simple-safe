from typing import cast

from eth_typing import ChecksumAddress
from pydantic import BaseModel
from rich import box
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

RICH_TABLE_BOX: box.Box = box.Box(
    " ── \n"  # top
    "    \n"  # head
    " ── \n"  # head_row
    "    \n"  # mid
    "    \n"  # row
    "    \n"  # foot_row
    "    \n"  # foot
    "    \n"  # bottom
)


def as_checksum(checksum_str: str) -> ChecksumAddress:
    return cast(ChecksumAddress, checksum_str)


def serialize(model: BaseModel):
    return model.model_dump_json(indent=2)


def mktable(title: str):
    table = Table(
        title=Padding(title, (0, 0, 0, 1)),
        title_justify="full",
        show_header=False,
        box=RICH_TABLE_BOX,
        pad_edge=False,
    )
    table.add_column("Field", justify="right", style="bold", no_wrap=True)
    table.add_column("Value", no_wrap=False)
    return table


def overflow(text: str) -> Text:
    return Text(text, overflow="fold")
