import json
import sys
import typing
from datetime import datetime, timezone
from getpass import getpass
from importlib.metadata import version
from typing import Any, Optional, Sequence, cast

from eth_typing import ChecksumAddress
import rich
from click import Context, Parameter
from eth_typing.abi import ABIElement
from eth_utils.abi import get_abi_input_names
from rich.box import HORIZONTALS, ROUNDED, Box
from rich.console import Console, Group, RenderableType
from rich.highlighter import JSONHighlighter
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from safe_eth.safe import SafeOperationEnum
from web3.contract.contract import ContractFunction
from web3.types import Timestamp, TxParams, TxReceipt

from .abi import Function
from .characters import CHECK, CROSS
from .util import SafeTxData, SignatureData, hexbytes_json_encoder

custom_theme = Theme({
    "ok": "green",
    "panel_ok": "green bold italic",
    "info": "dim cyan",
    "important": "cyan bold",
    "warning": "magenta",
    "danger": "bold red",
    "panel_danger": "red bold italic",
})

rich.reconfigure(stderr=True, theme=custom_theme)
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


def get_keyfile_password(address: ChecksumAddress, keyfile: str) -> str:
    return getpass(prompt=f"[{keyfile}] {address} password: ", stream=sys.stderr)


def get_kvtable(*args: dict[str, RenderableType], draw_divider: bool = True) -> Table:
    table = Table(
        show_edge=False,
        show_header=False,
        box=CUSTOM_BOX,
    )
    table.add_column("Field", justify="right", style="bold", no_wrap=True)
    table.add_column("Value", no_wrap=False)
    for idx, arg in enumerate(args):
        for key, val in arg.items():
            # Wrap all strings in a Text with overflow.
            if isinstance(val, str):
                table.add_row(key, Text.from_markup(val, overflow="fold"))
            else:
                table.add_row(key, val)
        if len(args) > 1 and idx < len(args) - 1:
            if draw_divider:
                table.add_section()
            else:
                table.add_row("", "")
    return table


def get_output_console(output: Optional[typing.TextIO] = None) -> Console:
    """Return a Console suitable for printing results.

    The Console must not insert hard wraps, which Rich normally inserts by
    default. This is important when piping or writing text-encoded data to a
    file such as a hexadecimal string or a JSON object.
    """
    return Console(file=output if output else sys.stdout, soft_wrap=True)


def get_panel(
    title: str, subtitle: str, renderable: RenderableType, **kwargs: Any
) -> Panel:
    base_config = dict(
        title=title,
        title_align="left",
        subtitle=subtitle,
        subtitle_align="right",
        border_style="bold italic",
        padding=(1, 1),
    )
    base_config.update(**kwargs)
    return Panel(renderable, box=ROUNDED, **base_config)  # pyright: ignore[reportArgumentType]


def print_function_matches(matches: Sequence[Function]):
    table = Table(
        show_edge=False,
        show_header=True,
        header_style="default",
        box=HORIZONTALS,
    )
    table.add_column("Selector", no_wrap=True)
    table.add_column("Signature")
    table.add_column("Arguments")
    for match in matches:
        fn_abi = cast(ABIElement, match.abi)
        if fn_abi["type"] == "fallback":
            arguments = []
        else:
            arguments = [
                arg if arg else "<unnamed>" for arg in get_abi_input_names(fn_abi)
            ]
        table.add_row(
            match.selector.to_0x_hex(),
            Text(match.sig, overflow="fold"),
            Text(", ".join(arguments), overflow="fold"),
        )
    panel = get_panel("ABI Function Matches", f"[ matches={len(matches)} ]", table)
    console.print(panel)


def print_kvtable(
    title: str,
    subtitle: str,
    *args: dict[str, RenderableType],
    draw_divider: bool = True,
) -> None:
    table = get_kvtable(*args, draw_divider=draw_divider)
    console.print(get_panel(title, subtitle, table))


def print_safetx(safetxdata: SafeTxData) -> None:
    safetx = safetxdata.safetx
    table_data = [
        {
            "Safe Address": safetx.safe_address,
            "Chain ID": str(safetx.chain_id),
            "Safe Nonce": str(safetx.safe_nonce),
            "To Address": str(safetx.to),
            "Operation": f"{safetx.operation} ({SafeOperationEnum(safetx.operation).name})",
            "Value": str(safetx.value),
            "SafeTx Gas": str(safetx.safe_tx_gas),
            "Data": safetx.data.to_0x_hex(),
        }
    ]
    if safetx.gas_price > 0:
        table_data.append({
            "Gas Price": str(safetx.gas_price),
            "Gas Token": safetx.gas_token,
            "Refund Receiver": safetx.refund_receiver,
        })
    table_data.append({
        "SafeTx Preimage": safetxdata.preimage.to_0x_hex(),
        "SafeTx Hash": safetxdata.hash.to_0x_hex(),
    })
    table = get_kvtable(*table_data)
    group = Group(
        get_json_data_renderable(safetxdata.payload),
        Rule(style="default on default"),
        table,
    )
    console.print(get_panel("Safe Transaction", "", group))


def print_signatures(
    sigdata: list[SignatureData],
    threshold: int,
) -> None:
    sigout: list[dict[str, RenderableType]] = []
    num_good, num_invalid, num_unknown = 0, 0, 0
    for sig in sigdata:
        row: dict[str, RenderableType] = {}
        row["File"] = sig.path
        if sig.sigtype:
            row["Type"] = sig.sigtype.lstrip("SafeSignature") + " Signature"
        row["Signature"] = sig.sigbytes.to_0x_hex() + (
            f" [ok]{CHECK} VALID[/ok]"
            if sig.valid
            else f" [danger]{CROSS} INVALID[/danger]"
        )
        if sig.address:
            row["ECRecover"] = f"{sig.address}" + (
                f" [ok]{CHECK} OWNER[/ok]"
                if sig.is_owner
                else f" [danger]{CROSS} OWNER[/danger]"
            )
        if sig.valid and sig.is_owner:
            num_good += 1
        if not sig.valid:
            num_invalid += 1
        elif not sig.is_owner:
            num_unknown += 1
        sigout.append(row)
    sigtable = get_kvtable(
        *sigout,
        draw_divider=True,
    )
    executable = num_good >= threshold and num_good == len(sigdata)
    if executable:
        summary = f"[{CHECK} EXECUTABLE]"
    elif num_invalid == 1:
        summary = f"[{CROSS} INVALID SIGNATURE]"
    elif num_invalid > 1:
        summary = f"[{CROSS} INVALID SIGNATURES]"
    elif num_unknown == 1:
        summary = f"[{CROSS} UNKNOWN SIGNATURE]"
    elif num_unknown > 1:
        summary = f"[{CROSS} UNKNOWN SIGNATURES]"
    else:
        summary = f"[{CROSS} INSUFFICIENT SIGNATURES]"
    console.print(
        get_panel(
            "Signatures",
            summary,
            sigtable,
            border_style="panel_ok" if executable else "panel_danger",
        )
    )


def print_version(ctx: Context, param: Parameter, value: Optional[bool]) -> None:
    if not value or ctx.resilient_parsing:
        return

    get_output_console().print(
        f"Simple Safe v{version('simple_safe')}", highlight=False
    )
    ctx.exit()


def print_web3_call_data(function: ContractFunction, calldata: str) -> None:
    argdata: dict[str, RenderableType] = {}
    for i, arg in enumerate(function.arguments):
        if function.argument_types[i] == "bytes":
            arg_str = arg.to_0x_hex()
        else:
            arg_str = str(arg)
        argdata[function.argument_names[i]] = arg_str

    print_kvtable(
        "Call Data Encoder",
        "",
        {
            "Selector": function.selector,
            "Function": function.signature,
            "ABI": get_json_data_renderable(dict(function.abi)),
        },
        argdata,
        {
            "ABI Encoding": calldata,
        },
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
    success = txreceipt["status"] == 1
    table_data: list[dict[str, RenderableType]] = [
        {
            "Web3Tx Hash": txreceipt["transactionHash"].to_0x_hex(),
            "Block": str(txreceipt["blockNumber"]),
            "Timestamp": timestamp_str,
            "Gas Used": str(txreceipt["gasUsed"]),
            "Effective Gas Price": str(txreceipt["effectiveGasPrice"]),
            "Status": str(txreceipt["status"]) + (" (OK)" if success else " (ERROR)"),
        }
    ]
    if "contractAddress" in txreceipt and txreceipt["contractAddress"]:
        table_data.append({
            "Contract Address": txreceipt["contractAddress"],
        })
    table = get_kvtable(*table_data)
    panel = get_panel(
        "Web3 Transaction Receipt",
        "",
        table,
        border_style="panel_ok" if success else "panel_danger",
    )
    console.print(panel)
