import json
from datetime import datetime, timezone
from typing import Any, Optional

import rich
from rich.box import Box
from rich.console import Group, RenderableType
from rich.highlighter import JSONHighlighter
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from safe_eth.safe import SafeOperationEnum
from web3.contract.contract import ContractFunction
from web3.types import Timestamp, TxParams, TxReceipt

from .util import SafeTxData, hexbytes_json_encoder


rich.reconfigure(stderr=True)
console = rich.get_console()


CUSTOM_BOX: Box = Box(
    "    \n"  # top
    "    \n"  # head
    "    \n"  # head_row
    "    \n"  # mid
    " ── \n"  # row
    "    \n"  # foot_row
    "    \n"  # foot
    "    \n"  # bottom
)


def get_json_data_renderable(
    data: dict[str, Any], indent: Optional[int] = None
) -> Text:
    return JSONHighlighter()(
        json.dumps(
            data,
            default=hexbytes_json_encoder,
            indent=indent,
        )
    )


def get_kvtable(*args: dict[str, RenderableType]) -> Table:
    table = Table(
        title_style="bold",
        show_header=False,
        box=CUSTOM_BOX,
    )
    table.add_column("Field", justify="right", style="bold", no_wrap=True)
    table.add_column("Value", no_wrap=False)
    for idx, arg in enumerate(args):
        for key, val in arg.items():
            # Wrap all strings in a Text with overflow.
            if isinstance(val, str):
                table.add_row(key, Text(val, overflow="fold"))
            else:
                table.add_row(key, val)
        if len(args) > 1 and idx < len(args) - 1:
            table.add_section()
    return table


def print_kvtable(title: str, subtitle: str, *args: dict[str, RenderableType]) -> None:
    table = get_kvtable(*args)
    panel = Panel(
        table,
        title=title,
        title_align="left",
        subtitle=subtitle,
        subtitle_align="right",
        border_style="bold",
    )
    console.print(panel)


def print_safetx(safetxdata: SafeTxData) -> None:
    table = get_kvtable(
        {
            "Address": safetxdata.safetx.safe_address,
            "Chain ID": str(safetxdata.safetx.chain_id),
            "Safe Nonce": str(safetxdata.safetx.safe_nonce),
            "To": str(safetxdata.safetx.to),
            "Operation": f"{safetxdata.safetx.operation} ({SafeOperationEnum(safetxdata.safetx.operation).name})",
            "Value": str(safetxdata.safetx.value),
            "Gas": str(safetxdata.safetx.safe_tx_gas),
            "Data": safetxdata.safetx.data.to_0x_hex(),
        },
        {
            f"Signature[{i}]": signer
            for (i, signer) in enumerate(safetxdata.safetx.signers)
        },
        {
            "SafeTx Preimage": safetxdata.preimage.to_0x_hex(),
            "SafeTx Hash": safetxdata.hash.to_0x_hex(),
        },
    )
    group = Group(
        Padding(get_json_data_renderable(safetxdata.payload), (1, 0)),
        Rule(style="default on default"),
        table,
    )
    panel = Panel(
        group,
        title="Safe Transaction",
        title_align="left",
        border_style="bold",
    )
    console.print(panel)


def print_web3_call_data(function: ContractFunction) -> None:
    argdata: dict[str, RenderableType] = {}
    for i, arg in enumerate(function.arguments):
        if function.argument_types[i] == "bytes":
            arg_str = arg.to_0x_hex()
        else:
            arg_str = str(arg)
        argdata[function.argument_names[i]] = arg_str

    print_kvtable(
        "Web3 Call Data",
        "",
        {
            "Contract": function.address,
            "Function": function.signature,
            "Selector": function.selector,
            "ABI": get_json_data_renderable(dict(function.abi)),
        },
        argdata,
    )


def print_web3_tx_params(value: TxParams) -> None:
    # Silence Pyright 'reportTypedDictNotRequiredAccess' error due to
    # TxParams fields being optional.
    assert "from" in value
    assert "chainId" in value
    assert "nonce" in value
    assert "to" in value
    assert "value" in value
    assert "gas" in value
    assert "maxFeePerGas" in value
    assert "maxPriorityFeePerGas" in value
    assert "data" in value
    print_kvtable(
        "Web3 Transaction Parameters",
        "",
        {
            "From": str(value["from"]),
            "Chain ID": str(value["chainId"]),
            "Web3 Nonce": str(value["nonce"]),
            "To": str(value["to"]),
            "Value": str(value["value"]),
            "Gas": str(value["gas"]),
            "Max Fee": str(value["maxFeePerGas"]),
            "Max Pri Fee": str(value["maxPriorityFeePerGas"]),
            "Data": str(value["data"]),
        },
    )


def print_web3_tx_receipt(timestamp: Optional[Timestamp], txreceipt: TxReceipt) -> None:
    timestamp_str = (
        datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
        if timestamp
        else ""
    )
    print_kvtable(
        "Web3 Transaction Receipt",
        "",
        {
            "Web3Tx Hash": txreceipt["transactionHash"].to_0x_hex(),
            "Block": str(txreceipt["blockNumber"]),
            "Timestamp": timestamp_str,
            "Gas Used": str(txreceipt["gasUsed"]),
            "Effective Gas Price": str(txreceipt["effectiveGasPrice"]),
            "Status": str(txreceipt["status"]),
        },
    )
