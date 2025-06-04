from rich.box import Box
from rich.console import Console
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

console = Console()

RICH_TABLE_BOX: Box = Box(
    " ── \n"  # top
    "    \n"  # head
    " ── \n"  # head_row
    "    \n"  # mid
    "    \n"  # row
    "    \n"  # foot_row
    "    \n"  # foot
    "    \n"  # bottom
)


def print_kvtable(title: str, data: dict[str, str]) -> None:
    table = Table(
        title=Padding(title, (0, 0, 0, 1)),  # pyright: ignore[reportArgumentType]
        title_justify="full",
        show_header=False,
        box=RICH_TABLE_BOX,
        pad_edge=False,
    )
    table.add_column("Field", justify="right", style="bold", no_wrap=True)
    table.add_column("Value", no_wrap=False)
    for key, val in data.items():
        table.add_row(key, Text(val, overflow="fold"))
    console.print(table)
    console.print()
