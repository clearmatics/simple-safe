import logging
import os
import sys
import typing
from datetime import datetime, timezone
from importlib.metadata import version
from typing import TYPE_CHECKING, Any, Optional, Sequence, cast

from click import Context, Parameter
from hexbytes import HexBytes

from .abi import Function
from .chaindata import ChainData
from .constants import (
    DEFAULT_CREATECALL_ADDRESS,
    DEFAULT_FALLBACK_ADDRESS,
    DEFAULT_PROXYFACTORY_ADDRESS,
    DEFAULT_SAFE_SINGLETON_ADDRESS,
    DEFAULT_SAFEL2_SINGLETON_ADDRESS,
    SYMBOL_CAUTION,
    SYMBOL_CHECK,
    SYMBOL_CROSS,
    SYMBOL_WARNING,
)
from .types import (
    ContractCall,
    DeployParams,
    Safe,
    SafeOperation,
    SafeTx,
    SafeVariant,
    SignatureData,
)
from .util import (
    format_gwei_value,
    format_hexbytes,
    format_native_value,
    hexbytes_json_encoder,
)

if TYPE_CHECKING:
    from eth_typing import ChecksumAddress
    from eth_typing.abi import ABIElement
    from rich.console import Console, RenderableType
    from rich.panel import Panel
    from rich.table import Table
    from web3.types import Timestamp, TxParams, TxReceipt

    from .auth import Authenticator


logger = logging.getLogger(__name__)

# Constants
JSON_INDENT_LEVEL = 2
SAFE_DEBUG = True if "SAFE_DEBUG" in os.environ else False


def activate_logging():
    from rich.logging import RichHandler

    if SAFE_DEBUG:
        level = logging.NOTSET
    else:
        level = logging.INFO
    format = "<%(name)s.%(funcName)s> %(message)s"
    logging.basicConfig(
        level=level,
        format=format,
        datefmt="[%X]",
        handlers=[RichHandler()],
    )


def parse_argdata(
    args: tuple[Any, ...], argtypes: list[str], argnames: list[str]
) -> dict[str, "RenderableType"]:
    argdata: list[tuple[str, str, "RenderableType"]] = []
    for i, val in enumerate(args):
        if isinstance(val, HexBytes):
            val_str = format_hexbytes(val)
        else:
            val_str = str(val)
        argdata.append((argtypes[i], argnames[i], val_str))
    return {
        r"[secondary]" + f"{argtype}[/secondary] {argname}": val
        for (argtype, argname, val) in argdata
    }


def get_json_data_renderable(
    data: dict[str, Any], pretty: bool = False
) -> "RenderableType":
    from rich.json import JSON

    return JSON.from_data(
        data,
        default=hexbytes_json_encoder,
        indent=2 if pretty else None,
    )


def get_kvtable(
    *args: dict[str, "RenderableType"], draw_divider: bool = True
) -> "Table":
    from rich.box import Box
    from rich.table import Table
    from rich.text import Text

    custom_box: Box = Box(
        "    \n"  # top
        "    \n"  # head
        "    \n"  # head_row
        "    \n"  # mid
        " ── \n"  # row
        "    \n"  # foot_row
        "    \n"  # foot
        "    \n"  # bottom
    )
    table = Table(
        show_edge=False,
        show_header=False,
        box=custom_box,
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


def get_output_console(output: Optional[typing.TextIO] = None) -> "Console":
    """Return a Console suitable for printing results.

    The Console must not insert hard wraps, which Rich normally inserts by
    default. This is important when piping or writing text-encoded data to a
    file such as a hexadecimal string or a JSON object.
    """
    from rich.console import Console

    return Console(file=output if output else sys.stdout, soft_wrap=True)


def get_panel(
    title: str, subtitle: str, renderable: "RenderableType", **kwargs: Any
) -> "Panel":
    from rich.box import ROUNDED
    from rich.panel import Panel

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


def make_status_logger(logger: logging.Logger):
    def status_logger(message: str):
        import rich

        console = rich.get_console()
        logger.info(message, stacklevel=2)
        return console.status(message)

    return status_logger


def print_function_matches(matches: Sequence[Function]):
    import rich
    from eth_utils.abi import get_abi_input_names
    from rich.box import HORIZONTALS
    from rich.table import Table
    from rich.text import Text

    console = rich.get_console()

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
        fn_abi = cast("ABIElement", match.abi)
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
    *args: dict[str, "RenderableType"],
    draw_divider: bool = True,
) -> None:
    import rich

    console = rich.get_console()
    table = get_kvtable(*args, draw_divider=draw_divider)
    console.print(get_panel(title, subtitle, table))


def print_line_if_tty(console: "Console", output: Optional[typing.TextIO]):
    if not output and sys.stdout.isatty():
        console.line()


def print_createcall_info(
    *,
    address: "ChecksumAddress",
    method: str,
    operation: int,
    init_code: HexBytes,
    value: int,
    deployer_address: "ChecksumAddress",
    computed_address: "ChecksumAddress",
    deployer_nonce: Optional[int] = None,
    salt: Optional[HexBytes] = None,
    chaindata: Optional[ChainData] = None,
):
    from web3.types import Wei

    data: dict[str, "RenderableType"] = {
        "Deployer": deployer_address,
    }
    if method == "CREATE":
        data["Deployer Nonce"] = str(deployer_nonce)
    else:
        assert salt is not None
        data["Salt"] = HexBytes(salt).to_0x_hex()
    data["Init Code"] = format_hexbytes(init_code)

    print_kvtable(
        "CreateCall Deployment Parameters",
        "",
        {
            "CreateCall": address
            + (
                f" [ok]{SYMBOL_CHECK} CANONICAL[/ok]"
                if address == DEFAULT_CREATECALL_ADDRESS
                else ""
            ),
            "Deploy Method": method,
            "Value": format_native_value(Wei(value), chaindata),
            "Operation": f"{operation} ({SafeOperation(operation).name})",
        },
        data,
        {"Computed Address": computed_address},
    )


def print_safe_deploy_info(data: DeployParams, safe_address: "ChecksumAddress"):
    variant = {
        SafeVariant.SAFE: "Safe.sol (without events)",
        SafeVariant.SAFE_L2: "SafeL2.sol (emits events)",
        SafeVariant.UNKNOWN: "unknown",
    }[data.variant]
    base_params: dict[str, "RenderableType"] = {
        "Proxy Factory": data.proxy_factory
        + (
            f" [ok]{SYMBOL_CHECK} CANONICAL[/ok]"
            if data.proxy_factory == DEFAULT_PROXYFACTORY_ADDRESS
            else ""
        ),
        "Singleton": data.singleton
        + (
            f" [ok]{SYMBOL_CHECK} CANONICAL[/ok]"
            if data.singleton
            in (DEFAULT_SAFE_SINGLETON_ADDRESS, DEFAULT_SAFEL2_SINGLETON_ADDRESS)
            else ""
        ),
        "Safe Variant": variant,
        "Salt Nonce": HexBytes(data.salt_nonce).to_0x_hex(),
    }
    if data.chain_id is not None:
        base_params["Chain ID"] = str(data.chain_id)
    print_kvtable(
        "Safe Deployment Parameters",
        "",
        base_params,
        {
            f"Owners({len(data.owners)})": ", ".join(data.owners),
            "Threshold": str(data.threshold),
            "Fallback Handler": data.fallback
            + (
                f" [ok]{SYMBOL_CHECK} DEFAULT[/ok]"
                if data.fallback == DEFAULT_FALLBACK_ADDRESS
                else ""
            ),
        },
        {
            "Safe Address": f"{safe_address}",
        },
    )


def print_safetxdata(
    safe: Safe,
    safetx: SafeTx,
    safetx_hash: HexBytes,
    chaindata: Optional[ChainData] = None,
) -> None:
    from web3.types import Wei

    table_data: list[dict[str, "RenderableType"]] = []
    table_data.append(
        {
            "Safe Address": safe.safe_address,
            "Chain ID": str(safe.chain_id),
            "Safe Nonce": str(safe.safe_nonce),
            "To Address": str(safetx.to),
            "Operation": f"{safetx.operation} ({SafeOperation(safetx.operation).name})",
            "Value": format_native_value(Wei(safetx.value), chaindata),
            "Gas Limit": format_gwei_value(Wei(safetx.safe_tx_gas)),
            "Data": format_hexbytes(safetx.data),
        }
    )
    if safetx.gas_price > 0:
        table_data.append(
            {
                "Gas Price": format_gwei_value(Wei(safetx.gas_price)),
                "Gas Token": safetx.gas_token,
                "Refund Receiver": safetx.refund_receiver,
            }
        )
    table_data.append(
        {
            "SafeTx Hash": safetx_hash.to_0x_hex(),
        }
    )
    print_kvtable("Safe Transaction", "", *table_data)


def print_signatures(
    sigdata: list[SignatureData],
    threshold: Optional[int],
    offline: bool,
) -> None:
    import rich

    console = rich.get_console()
    sigout: list[dict[str, "RenderableType"]] = []
    num_good, num_invalid, num_unknown = 0, 0, 0
    for sig in sigdata:
        row: dict[str, "RenderableType"] = {}
        row["File"] = sig.path
        if sig.sigtype:
            row["Type"] = sig.sigtype.lstrip("SafeSignature") + " Signature"
        row["Signature"] = sig.sigbytes.to_0x_hex() + (
            f" [ok]{SYMBOL_CHECK} VALID[/ok]"
            if sig.valid
            else f" [danger]{SYMBOL_CROSS} INVALID[/danger]"
        )
        if sig.address:
            if sig.is_owner is True:
                owner = f" [ok]{SYMBOL_CHECK} OWNER[/ok]"
            elif sig.is_owner is False:
                owner = f" [danger]{SYMBOL_CROSS} OWNER[/danger]"
            else:
                owner = f" [caution]{SYMBOL_CAUTION} UNVERIFIED[/caution]"
            row["ECRecover"] = f"{sig.address}" + owner
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
    executable = (
        (threshold is not None)
        and (num_good >= threshold)
        and (num_good == len(sigdata))
    )
    if offline:
        summary = ""
        border_style = "panel_caution"
    elif executable:
        summary = f"[{SYMBOL_CHECK} EXECUTABLE]"
        border_style = "panel_ok"
    else:
        border_style = "panel_danger"
        if num_invalid == 1:
            summary = f"[{SYMBOL_CROSS} INVALID SIGNATURE]"
        elif num_invalid > 1:
            summary = f"[{SYMBOL_CROSS} INVALID SIGNATURES]"
        elif num_unknown == 1:
            summary = f"[{SYMBOL_CROSS} UNKNOWN SIGNATURE]"
        elif num_unknown > 1:
            summary = f"[{SYMBOL_CROSS} UNKNOWN SIGNATURES]"
        else:
            summary = f"[{SYMBOL_CROSS} INSUFFICIENT SIGNATURES]"
    console.print(
        get_panel(
            "Signatures",
            summary,
            sigtable,
            border_style=border_style,
        )
    )
    if offline:
        console.line()
        logger.warning(
            f"{SYMBOL_WARNING} Cannot verify whether signers are owners when offline."
        )


def print_version(ctx: Context, param: Parameter, value: Optional[bool]) -> None:
    if not value or ctx.resilient_parsing:
        return

    get_output_console().print(
        f"Simple Safe v{version('simple_safe')}", highlight=False
    )
    ctx.exit()


def print_web3_call_data(
    function: ContractCall, calldata: HexBytes, title: str = "Call Data Encoder"
) -> None:
    argdata: list[tuple[str, str, "RenderableType"]] = []
    for i, argval in enumerate(function.args):
        if isinstance(argval, HexBytes):
            argval_str = format_hexbytes(argval)
        else:
            argval_str = str(argval)
        argdata.append((function.argtypes[i], function.argnames[i], argval_str))

    function_signature = function.signature
    if (
        "stateMutability" in function.abi
        and function.abi["stateMutability"] == "payable"
    ):
        function_signature += " [green]💲Payable[/green]"

    metadata: dict[str, "RenderableType"] = {}
    metadata["Function"] = function_signature
    if function.selector:
        metadata["Selector"] = function.selector

    print_kvtable(
        title,
        "",
        metadata,
        parse_argdata(
            function.args,
            list(function.argtypes),
            list(function.argnames),
        ),
        {
            "ABI Encoding": format_hexbytes(calldata),
        },
    )


def print_web3_tx_fees(
    params: "TxParams",
    offline: bool,
    gasprice: Optional[int],
    chaindata: Optional[ChainData],
) -> None:
    from web3.types import Wei

    # Silence Pyright 'reportTypedDictNotRequiredAccess' error due to
    # TxParams fields being optional.
    assert "gas" in params
    assert "maxFeePerGas" in params
    if not offline:
        assert gasprice is not None
        est_fee = format_native_value(Wei(params["gas"] * gasprice), chaindata)
        table_data = {
            "Current Gas Price": format_gwei_value(Wei(gasprice)),
            "Estimated Fees": est_fee,
        }
    else:
        table_data: dict[str, "RenderableType"] = {}
    table_data["Maximum Fees"] = format_native_value(
        Wei(params["gas"] * int(params["maxFeePerGas"])), chaindata
    )
    print_kvtable(
        "Web3 Transaction Fees",
        "",
        table_data,
    )


def print_web3_tx_params(
    params: "TxParams",
    auth: "Authenticator",
    gas_estimate: Optional[int],
    chaindata: Optional[ChainData] = None,
) -> None:
    from web3.types import Wei

    # Silence Pyright 'reportTypedDictNotRequiredAccess' error due to
    # TxParams fields being optional.
    assert "chainId" in params
    assert "nonce" in params
    assert "to" in params
    assert "value" in params
    assert "gas" in params
    assert "maxFeePerGas" in params
    assert "maxPriorityFeePerGas" in params
    assert "data" in params
    print_kvtable(
        "Web3 Transaction Parameters",
        "",
        {
            "From Address": auth.address + r" [secondary]\[" + f"{auth}][/secondary]",
            "Chain ID": str(params["chainId"]),
            "Nonce": str(params["nonce"]),
            "To Address": str(params["to"]),
            "Value": format_native_value(params["value"], chaindata),
            "Gas Limit": str(params["gas"])
            + (
                f" [caution]{SYMBOL_CAUTION} LESS THAN ESTIMATED GAS[/caution]"
                if gas_estimate is not None and params["gas"] < gas_estimate
                else ""
            ),
            "Total Fees": "Max "
            + format_gwei_value(
                Wei(int(params["maxFeePerGas"])), units=("Wei/Gas", "Gwei/Gas")
            ),
            "Priority Fee": "Max "
            + format_gwei_value(
                Wei(int(params["maxPriorityFeePerGas"])), units=("Wei/Gas", "Gwei/Gas")
            ),
            "Data": format_hexbytes(HexBytes(params["data"])),
        },
    )


def print_web3_tx_receipt(
    timestamp: Optional["Timestamp"],
    txreceipt: "TxReceipt",
    chaindata: Optional[ChainData],
) -> None:
    import rich
    from web3.types import Wei

    console = rich.get_console()

    timestamp_str = (
        datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
        if timestamp
        else ""
    )
    success = txreceipt["status"] == 1
    table_data: list[dict[str, "RenderableType"]] = [
        {
            "Web3Tx Hash": txreceipt["transactionHash"].to_0x_hex(),
            "Status": str(txreceipt["status"])
            + (" (SUCCESS)" if success else " (FAILURE)"),
            "Block": str(txreceipt["blockNumber"]),
            "Timestamp": timestamp_str,
            "Gas Used": str(txreceipt["gasUsed"]),
            "Effective Gas Price": format_gwei_value(txreceipt["effectiveGasPrice"]),
            "Transaction Fees": format_native_value(
                Wei(txreceipt["gasUsed"] * txreceipt["effectiveGasPrice"]), chaindata
            ),
        }
    ]
    if "contractAddress" in txreceipt and txreceipt["contractAddress"]:
        table_data.append(
            {
                "Contract Address": txreceipt["contractAddress"],
            }
        )
    table = get_kvtable(*table_data)
    panel = get_panel(
        "Web3 Transaction Receipt",
        "",
        table,
        border_style="panel_ok" if success else "panel_danger",
    )
    console.print(panel)
