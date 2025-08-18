import json
import logging
import pdb
import secrets
import shutil
import sys
import typing
from decimal import Decimal
from importlib.resources import files
from types import TracebackType
from typing import (
    TYPE_CHECKING,
    Any,
    Optional,
    cast,
)

import click
from hexbytes import (
    HexBytes,
)

from . import params
from .abi import find_function, parse_args
from .auth import authenticator
from .chaindata import FALLBACK_DECIMALS, fetch_chaindata
from .click import Group
from .console import (
    SAFE_DEBUG,
    activate_logging,
    confirm,
    get_json_data_renderable,
    get_output_console,
    make_status_logger,
    print_createcall_info,
    print_kvtable,
    print_line_if_tty,
    print_safe_deploy_info,
    print_safetxdata,
    print_signatures,
    print_version,
    print_web3_call_data,
)
from .constants import DEFAULT_CREATECALL_ADDRESS, SALT_SENTINEL
from .params import optgroup
from .types import (
    ContractCall,
    MultiSendTxInput,
    SafeInfo,
    SafeOperation,
    SafeTx,
)
from .util import (
    compute_safe_address,
    format_native_value,
    hash_eip712_data,
    load_csv_file,
    make_offline_web3,
    parse_signatures,
    query_safe_info,
    scale_decimal_value,
    silence_logging,
    to_checksum_address,
    to_json,
)
from .validation import (
    CLIOption,
    validate_batch_options,
    validate_decimal_value,
    validate_deploy_options,
    validate_rpc_option,
    validate_safe,
    validate_safetxfile,
    validate_web3tx_options,
)
from .workflows import (
    build_batch_safetx,
    build_contract_call_safetx,
    handle_function_match_failure,
    process_contract_call_web3tx,
)

if TYPE_CHECKING:
    from eth_typing import URI, ABIConstructor
    from web3 import Web3

# ┌───────┐
# │ Setup │
# └───────┘

logger = logging.getLogger(__name__)
status = make_status_logger(logger)


def handle_crash(
    exc_type: type[BaseException],
    exc_value: BaseException,
    exc_traceback: TracebackType | None,
) -> None:
    import rich
    from rich.traceback import Traceback

    def format_error(err: str, msg: str) -> str:
        return f"[bold][red]{err}[/red]:[/bold] {msg}"

    console = rich.get_console()
    if not SAFE_DEBUG:
        from web3.exceptions import ContractLogicError

        if exc_type is ContractLogicError:
            exc = cast(ContractLogicError, exc_value)
            message = format_error(exc_type.__name__, f"{exc.message} ({exc.data})")
        else:
            if isinstance(exc_value, click.Abort):
                message = r"[bold][yellow]Aborted[/yellow][/bold]"
            elif isinstance(exc_value, click.ClickException):
                message = format_error("Error", exc_value.format_message())
            else:
                message = format_error(exc_type.__name__, str(exc_value))
        console.print(message)
    else:
        rich_traceback = Traceback.from_exception(
            exc_type,
            exc_value,
            exc_traceback,
            suppress=[click],
            show_locals=True,
        )
        console.print(rich_traceback)
        pdb.post_mortem(exc_traceback)


sys.excepthook = handle_crash

# ┌──────┐
# │ Main │
# └──────┘


@click.group(
    cls=Group,
    context_settings=dict(
        show_default=True,
        max_content_width=shutil.get_terminal_size().columns,
        help_option_names=["-h", "--help"],
    ),
)
@click.option(
    "--version",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
    help="print version info and exit",
)
def safe():
    """A simple Web3-native CLI for Safe accounts."""
    import rich
    from rich.theme import Theme

    custom_theme = Theme(
        {
            "ok": "green",
            "danger": "red",
            "caution": "yellow",
            "panel_ok": "green bold italic",
            "panel_caution": "yellow bold italic",
            "panel_danger": "red bold italic",
            "secondary": "grey50",
        }
    )
    rich.reconfigure(stderr=True, theme=custom_theme)
    if SAFE_DEBUG:
        activate_logging()


def main():
    # Invoke main() manually in order to apply custom exception formatting
    # <https://click.palletsprojects.com/en/stable/exceptions/>
    safe.main(standalone_mode=False)


# ┌──────────┐
# │ Commands │
# └──────────┘


# Convention for `safe build` subcommand options:
# 1. --safe
# 2. (command-specific non-tx options)
# Safe transaction:
# 3. (command-specific tx options)
# 4. --data (if applicable)
# 5. --value (if applicable)
# 6. --operation (if applicable)
@safe.group()
def build():
    """Build a Safe transaction."""
    pass


@build.command(name="call")
@params.make_option(params.safe_address_option_info)
@params.make_option(params.abi_option_info)
@optgroup.group("Safe transaction")
@optgroup.option(
    "--contract",
    "contract_str",
    metavar="ADDRESS",
    required=True,
    help="contract call address",
)
@params.make_option(params.value_option_info, cls=optgroup.option)
@params.make_option(params.operation_option_info, cls=optgroup.option)
@params.build_safetx
@params.output_file
@click.argument("function", metavar="FUNCTION")
@click.argument("str_args", metavar="[ARGUMENT]...", nargs=-1)
@params.common
def build_call(
    abi_file: str,
    chain_id: Optional[int],
    contract_str: str,
    function: str,
    operation: int,
    output: Optional[typing.TextIO],
    pretty: bool,
    rpc: Optional[str],
    safe_address: str,
    safe_nonce: Optional[int],
    safe_version: Optional[str],
    str_args: list[str],
    value_str: str,
) -> None:
    """Build a contract call Safe transaction.

    FUNCTION is the function's name, 4-byte selector, or full signature.
    """
    with status("Building Safe transaction..."):
        import rich

        offline = rpc is None
        w3: "Web3" = validate_rpc_option(rpc) if not offline else make_offline_web3()
        safe, _ = validate_safe(
            safe_address=to_checksum_address(safe_address),
            offline=offline,
            chain_id=chain_id,
            safe_nonce=safe_nonce,
            safe_version=safe_version,
            w3=w3,
        )
        with open(abi_file, "r") as f:
            abi = json.load(f)
        contract = w3.eth.contract(abi=abi)
        value = validate_decimal_value(value_str)
        safetx = build_contract_call_safetx(
            w3=w3,
            contract=contract,
            address=to_checksum_address(contract_str),
            fn_identifier=function,
            str_args=str_args,
            safe=safe,
            value=value,
            operation=SafeOperation(operation).value,
        )
    if not params.quiet_mode:
        console = rich.get_console()
        print_line_if_tty(console, output)
    output_console = get_output_console(output)
    output_console.print(
        get_json_data_renderable(safetx.to_eip712_message(safe), pretty),
    )


@build.command(name="custom")
@params.make_option(params.safe_address_option_info)
@optgroup.group("Safe transaction")
@optgroup.option("--to", "to_str", metavar="ADDRESS", help="destination address")
@optgroup.option("--data", default="0x", help="call data payload")
@params.make_option(params.value_option_info, cls=optgroup.option)
@params.make_option(params.operation_option_info, cls=optgroup.option)
@params.build_batch_safetx(delegatecall=True)
@params.build_safetx
@params.output_file
@params.common
@click.pass_context
def build_custom(
    context: click.Context,
    batch: Optional[str],
    chain_id: Optional[int],
    data: str,
    delegatecall: bool,
    multisend: Optional[str],
    operation: int,
    output: Optional[typing.TextIO],
    pretty: bool,
    rpc: Optional[str],
    safe_address: str,
    safe_nonce: Optional[int],
    safe_version: Optional[str],
    to_str: Optional[str],
    value_str: str,
) -> None:
    """Build a custom Safe transaction.

    This command supports batch transactions using Safe's MultiSend and
    MultiSendCallOnly contracts. Activate batch mode by passing the --batch
    option to specify a CSV file of transaction data. The CSV file must
    start with a header row, with each subsequent row representing a discrete
    transaction.

    Values for all the `Safe transaction` parameters must be provided, either as
    options on the command line, or as values in CSV file columns matching the
    option name, or as the default value in the case of options with defaults.
    When parameters are passed as command line options, they apply to each of
    batched transactions. The order of CSV columns is not important because
    fields are matched by column name. Any other columns are ignored.
    """
    with status(f"Building Safe{' batch' if batch else ''} transaction..."):
        import rich
        from web3.constants import CHECKSUM_ADDRESSS_ZERO

        console = rich.get_console()
        offline = rpc is None
        w3: "Web3" = validate_rpc_option(rpc) if not offline else make_offline_web3()
        safe, _ = validate_safe(
            safe_address=to_checksum_address(safe_address),
            offline=offline,
            chain_id=chain_id,
            safe_nonce=safe_nonce,
            safe_version=safe_version,
            w3=w3,
        )
        chaindata = fetch_chaindata(safe.chain_id)
        decimals = chaindata.decimals if chaindata else FALLBACK_DECIMALS

        if batch:
            colnames, rows = load_csv_file(batch)
            cli_options = [
                CLIOption(
                    "to",
                    to_str,
                    context.get_parameter_source("to_str"),
                ),
                CLIOption(
                    "data",
                    data,
                    context.get_parameter_source("data"),
                ),
                CLIOption(
                    "value",
                    value_str,
                    context.get_parameter_source("value_str"),
                ),
                CLIOption(
                    "operation",
                    operation,
                    context.get_parameter_source("operation"),
                ),
            ]
            validate_batch_options(cli_options, colnames)

            def row_parser(i: int, row: dict[str, Any]) -> MultiSendTxInput:
                return MultiSendTxInput(
                    to=to_checksum_address(row.get("to", to_str)),
                    data=HexBytes(row.get("data", data)),
                    value=scale_decimal_value(
                        validate_decimal_value(row.get("value", value_str)), decimals
                    ),
                    operation=SafeOperation(int(row.get("operation", operation))).value,
                )

            safetx = build_batch_safetx(
                w3=w3,
                safe=safe,
                multisend=multisend,
                delegatecall=delegatecall,
                chaindata=chaindata,
                row_parser=row_parser,
                rows=rows,
            )

        else:
            if to_str is None:
                raise click.ClickException("Missing option '--to'.")
            safetx = SafeTx(
                to=to_checksum_address(to_str),
                value=scale_decimal_value(validate_decimal_value(value_str), decimals),
                data=HexBytes(data),
                operation=SafeOperation(operation).value,
                safe_tx_gas=0,
                base_gas=0,
                gas_price=0,
                gas_token=CHECKSUM_ADDRESSS_ZERO,
                refund_receiver=CHECKSUM_ADDRESSS_ZERO,
            )

        eip712_data = safetx.to_eip712_message(safe)

    if not params.quiet_mode:
        print_line_if_tty(console, output)
    output_console = get_output_console(output)
    output_console.print(get_json_data_renderable(eip712_data, pretty))


@build.command(name="deploy")
@params.make_option(params.safe_address_option_info)
@params.make_option(params.abi_option_info)
@click.option(
    "--code",
    "code_file",
    type=click.Path(exists=True),
    required=True,
    help="contract bytecode in hex format",
)
@click.option(
    "--method",
    type=click.Choice(["CREATE", "CREATE2"]),
    default="CREATE2",
    help="contract deployment method",
)
@click.option(
    "--createcall",
    "createcall_str",
    metavar="ADDRESS",
    help="use a non-canonical CreateCall address",
)
@optgroup.group("CREATE deployment")
@optgroup.option(
    "--deployer-nonce",
    "deployer_nonce",
    type=int,
    help="deployer nonce as override or when offline",
)
@optgroup.group("CREATE2 deployment")
@optgroup.option(
    "--salt",
    "salt_str",
    type=str,
    metavar="BYTES32",
    default=SALT_SENTINEL,
    help="CREATE2 salt value",
)
@optgroup.group("Safe transaction")
@params.make_option(params.value_option_info, cls=optgroup.option)
@params.make_option(params.operation_option_info, cls=optgroup.option)
@params.build_safetx
@params.output_file
@click.argument("str_args", metavar="[ARGUMENT]...", nargs=-1)
@params.common
def build_deploy(
    abi_file: str,
    chain_id: Optional[int],
    code_file: str,
    createcall_str: Optional[str],
    deployer_nonce: Optional[int],
    method: str,
    operation: int,
    output: Optional[typing.TextIO],
    pretty: bool,
    rpc: Optional[str],
    safe_address: str,
    safe_nonce: Optional[int],
    safe_version: Optional[str],
    salt_str: str,
    str_args: list[str],
    value_str: str,
):
    """Build a contract deployment Safe transaction.

    The contract is deployed using Safe's CreateCall library contract, which
    provides CREATE and CREATE2 deployment methods. When the Safe transaction
    operation is a CALL the deployer is the CreateCall contract, whereas when it
    is a DELEGATECALL the deployer is the Safe address. When offline and using
    the CREATE method, the nonce of the deployer must be provided.

    The tx value is passed to the constructor and will appear as a field in
    the Safe transaction message and as one of the arguments to the relevant
    CreateCall "perform" function.

    The positional ARGUMENTs are the constructor arguments for the deployed
    contract.
    """
    with status("Building Safe transaction..."):
        import rich
        from eth_abi.abi import encode as abi_encode
        from eth_typing import ABIFunction, HexStr
        from web3._utils.contracts import encode_abi
        from web3.constants import CHECKSUM_ADDRESSS_ZERO
        from web3.types import Nonce
        from web3.utils import get_create_address
        from web3.utils.abi import get_abi_element
        from web3.utils.address import get_create2_address

        offline = rpc is None
        w3: "Web3" = validate_rpc_option(rpc) if not offline else make_offline_web3()
        safe, _ = validate_safe(
            safe_address=to_checksum_address(safe_address),
            offline=offline,
            chain_id=chain_id,
            safe_nonce=safe_nonce,
            safe_version=safe_version,
            w3=w3,
        )

        if method == "CREATE":
            if salt_str != SALT_SENTINEL:
                raise click.ClickException(
                    "CREATE deployment method incompatible with --salt option."
                )
            if offline and (deployer_nonce is None):
                raise click.ClickException(
                    "Missing --deployer-nonce for CREATE deployment when offline."
                )
        else:
            if deployer_nonce:
                raise click.ClickException("Deployer nonce is not used in CREATE2.")

        value = validate_decimal_value(value_str)
        SafeOperation(operation)  # validate operation value
        createcall_address = to_checksum_address(
            createcall_str if createcall_str else DEFAULT_CREATECALL_ADDRESS
        )

        chaindata = fetch_chaindata(safe.chain_id)
        decimals = chaindata.decimals if chaindata else FALLBACK_DECIMALS
        value_scaled = scale_decimal_value(value, decimals)

        # Constructor call
        with open(abi_file, "r") as f:
            target_abi = json.load(f)
        with open(code_file, "r") as f:
            target_bytecode = HexBytes(f.read())
        constructor_abi = cast(
            "ABIConstructor",
            get_abi_element(target_abi, abi_element_identifier="constructor"),
        )
        constructor_args = parse_args(constructor_abi, str_args)
        constructor_call = ContractCall(constructor_abi, constructor_args)
        constructor_data = HexBytes(
            abi_encode(constructor_call.argtypes, constructor_args)
        )
        init_code = HexBytes(HexBytes(target_bytecode) + constructor_data)

        # CreateCall args
        salt = None
        if method == "CREATE":
            createcall_func = "performCreate(uint256,bytes)"  # selector 0x4c8c9ea1
            createcall_args = (value_scaled, init_code)
        else:
            createcall_func = (
                "performCreate2(uint256,bytes,bytes32)"  # selector 0x4847be6f
            )
            if salt_str == SALT_SENTINEL:
                salt = HexBytes(secrets.token_bytes(32))
            else:
                salt = HexBytes(salt_str)
                if len(salt) != 32:
                    raise click.ClickException(
                        f"Invalid salt value. Need exactly 32 bytes but received {len(salt)} bytes instead."
                    )
            createcall_args = (value_scaled, init_code, salt)

        # CreateCall call
        createcall_abifile = files("simple_safe.abis").joinpath("CreateCall.abi")
        with createcall_abifile.open("r") as f:
            createcall_abi = json.load(f)
        createcall_fn_abi = cast(
            "ABIFunction", get_abi_element(createcall_abi, createcall_func)
        )
        createcall_call = ContractCall(createcall_fn_abi, createcall_args)
        createcall_data = HexBytes(
            encode_abi(
                w3,
                createcall_fn_abi,
                createcall_args,
                cast("HexStr", createcall_call.selector),
            )
        )

        # Compute address
        deployer_address = (
            createcall_address
            if operation == SafeOperation.CALL.value
            else safe.safe_address
        )
        if method == "CREATE":
            if deployer_nonce is None:
                deployer_nonce = w3.eth.get_transaction_count(
                    deployer_address
                    if operation == SafeOperation.CALL.value
                    else safe.safe_address
                )
            computed_address = get_create_address(
                deployer_address, Nonce(deployer_nonce)
            )
        else:
            assert salt is not None
            computed_address = get_create2_address(
                deployer_address,
                cast("HexStr", salt.to_0x_hex()),
                cast("HexStr", init_code.to_0x_hex()),
            )

        # SafeTx
        safetx = SafeTx(
            to=createcall_address,
            value=value_scaled,
            data=createcall_data,
            operation=operation,
            safe_tx_gas=0,
            base_gas=0,
            gas_price=0,
            gas_token=CHECKSUM_ADDRESSS_ZERO,
            refund_receiver=CHECKSUM_ADDRESSS_ZERO,
        )

    console = rich.get_console()

    if not params.quiet_mode:
        console.line()
        print_web3_call_data(
            constructor_call, constructor_data, "Constructor Data Encoder"
        )
        console.line()
        print_createcall_info(
            address=createcall_address,
            method=method,
            operation=operation,
            init_code=init_code,
            value=value_scaled,
            deployer_address=deployer_address,
            computed_address=computed_address,
            deployer_nonce=deployer_nonce,
            salt=salt,
            chaindata=chaindata,
        )
        console.line()
        print_web3_call_data(
            createcall_call, createcall_data, "CreateCall Data Encoder"
        )
        print_line_if_tty(console, output)

    output_console = get_output_console(output)
    output_console.print(
        get_json_data_renderable(safetx.to_eip712_message(safe), pretty),
    )


@build.command(name="erc20-call")
@params.make_option(params.safe_address_option_info)
@optgroup.group("Safe transaction")
@optgroup.option(
    "--token",
    "token_str",
    metavar="ADDRESS",
    help="ERC-20 token address",
)
@params.build_batch_safetx(delegatecall=False)
@params.build_safetx
@params.output_file
@click.argument("function", metavar="FUNCTION")
@click.argument("str_args", metavar="[ARGUMENT]...", nargs=-1)
@params.common
@click.pass_context
def build_erc20_call(
    context: click.Context,
    batch: Optional[str],
    chain_id: Optional[int],
    function: str,
    multisend: Optional[str],
    output: Optional[typing.TextIO],
    pretty: bool,
    rpc: Optional[str],
    safe_address: str,
    safe_nonce: Optional[int],
    safe_version: Optional[str],
    str_args: list[str],
    token_str: Optional[str],
) -> None:
    """Build an ERC-20 token Safe transaction.

    FUNCTION is the function's name, 4-byte selector, or full signature.

    This command supports batch transactions using Safe's MultiSend and
    MultiSendCallOnly contracts. Activate batch mode by passing the --batch
    option to specify a CSV file of transaction data. The CSV file must
    start with a header row, with each subsequent row representing a discrete
    transaction.

    Values for all the `Safe transaction` parameters and the ARGUMENTs to the
    named FUNCTION must be provided, as either as options on the command line,
    or as values in CSV file columns matching the option name, or as the default
    value in the case of options with defaults. When parameters are passed as
    command line options, they apply to each of batched transactions. To specify
    ARGUMENTs in the CSV file, use the column name `arg:INDEX` (example:
    `arg:1`) or `arg:NAME` (example: `arg:to`), where `INDEX` is the 1-based
    index of the argument and `NAME` is the corresponding ARGUMENT name as
    it appears in the contract ABI. The order of CSV columns is not important
    because fields are matched by column name. Any other columns are ignored.
    """
    with status("Building Safe transaction..."):
        import rich
        from safe_eth.eth.contracts import get_erc20_contract

        offline = rpc is None
        w3: "Web3" = validate_rpc_option(rpc) if not offline else make_offline_web3()
        safe, _ = validate_safe(
            safe_address=to_checksum_address(safe_address),
            offline=offline,
            chain_id=chain_id,
            safe_nonce=safe_nonce,
            safe_version=safe_version,
            w3=w3,
        )
        if (not batch) and (token_str is None):
            raise click.ClickException("Missing option '--token'.")
        cli_options = [
            CLIOption(
                "token",
                token_str,
                context.get_parameter_source("token_str"),
            )
        ]

        def row_parser(_: int, row: dict[str, Any]) -> MultiSendTxInput:
            return MultiSendTxInput(
                to=to_checksum_address(row.get("token", token_str)),
                value=0,
                operation=SafeOperation.CALL.value,
            )

        safetx = build_contract_call_safetx(
            w3=w3,
            contract=get_erc20_contract(w3),
            address=to_checksum_address(token_str) if token_str else None,
            fn_identifier=function,
            str_args=str_args,
            safe=safe,
            value=Decimal(0),
            operation=SafeOperation.CALL.value,
            batch=batch,
            cli_options=cli_options,
            multisend=multisend,
            parent_row_parser=row_parser if batch else None,
        )

    if not params.quiet_mode:
        console = rich.get_console()
        print_line_if_tty(console, output)
    output_console = get_output_console(output)
    output_console.print(
        get_json_data_renderable(safetx.to_eip712_message(safe), pretty),
    )


@build.command(name="safe-call")
@params.make_option(params.safe_address_option_info)
@optgroup.group("Safe transaction")
@params.make_option(params.value_option_info, cls=optgroup.option)
@params.build_safetx
@params.output_file
@click.argument("function", metavar="FUNCTION")
@click.argument("str_args", metavar="[ARGUMENT]...", nargs=-1)
@params.common
def build_safe_call(
    chain_id: Optional[int],
    function: str,
    output: Optional[typing.TextIO],
    pretty: bool,
    rpc: Optional[str],
    safe_address: str,
    safe_nonce: Optional[int],
    safe_version: Optional[str],
    str_args: list[str],
    value_str: str,
) -> None:
    """Build a Safe transaction to call the Safe.

    FUNCTION is the function's name, 4-byte selector, or full signature.
    """
    with status("Building Safe transaction..."):
        import rich

        offline = rpc is None
        w3: "Web3" = validate_rpc_option(rpc) if not offline else make_offline_web3()
        safe, contract = validate_safe(
            safe_address=to_checksum_address(safe_address),
            offline=offline,
            chain_id=chain_id,
            safe_nonce=safe_nonce,
            safe_version=safe_version,
            w3=w3,
        )
        value = validate_decimal_value(value_str)
        safetx = build_contract_call_safetx(
            w3=w3,
            contract=contract,
            address=contract.address,
            fn_identifier=function,
            str_args=str_args,
            safe=safe,
            value=value,
            operation=SafeOperation.CALL.value,
        )
    if not params.quiet_mode:
        console = rich.get_console()
        print_line_if_tty(console, output)
    output_console = get_output_console(output)
    output_console.print(
        get_json_data_renderable(safetx.to_eip712_message(safe), pretty),
    )


@safe.command()
@params.deployment(precompute=False)
@params.web3tx()
@params.authentication
@params.force
@params.output_file
@params.common
def deploy(
    chain_id: Optional[int],
    chain_specific: bool,
    custom_proxy_factory: Optional[str],
    custom_singleton: Optional[str],
    fallback: Optional[str],
    force: bool,
    gas_limit: Optional[int],
    keyfile: Optional[str],
    max_fee: Optional[str],
    max_pri_fee: Optional[str],
    nonce: Optional[int],
    owners: list[str],
    output: Optional[typing.TextIO],
    rpc: Optional[str],
    salt_nonce: str,
    sign_only: bool,
    threshold: int,
    trezor: Optional[str],
    without_events: bool,
):
    """Deploy a new Safe account.

    The Safe account is deployed with CREATE2, which makes it possible to
    own the same address on different chains. If this is not desirable, pass the
    --chain-specific option to include the chain ID in the CREATE2 salt derivation.

    The account uses the 'SafeL2.sol' implementation by default, which
    emits events. To use the gas-saving 'Safe.sol' variant instead, pass
    --without-events.
    """
    offline = rpc is None
    with status("Checking Safe deployment parameters..."):
        import rich
        from safe_eth.eth.contracts import get_proxy_factory_V1_4_1_contract

        console = rich.get_console()
        w3: "Web3" = validate_rpc_option(rpc) if not offline else make_offline_web3()
        txopts = validate_web3tx_options(
            w3=w3,
            chain_id=chain_id,
            gas_limit=gas_limit,
            nonce=nonce,
            max_fee=max_fee,
            max_pri_fee=max_pri_fee,
            sign_only=sign_only,
            offline=offline,
        )
        data = validate_deploy_options(
            chain_id=chain_id if chain_specific else None,
            chain_specific=chain_specific,
            custom_proxy_factory=custom_proxy_factory,
            custom_singleton=custom_singleton,
            fallback=fallback,
            owners=owners,
            salt_nonce=salt_nonce,
            threshold=threshold,
            without_events=without_events,
        )
        initializer, address = compute_safe_address(
            proxy_factory=data.proxy_factory,
            singleton=data.singleton,
            salt_nonce=data.salt_nonce,
            owners=data.owners,
            threshold=data.threshold,
            fallback=data.fallback,
            chain_id=data.chain_id,
        )

        proxy_factory_contract = get_proxy_factory_V1_4_1_contract(
            w3, data.proxy_factory
        )
        proxy_factory_method = (
            proxy_factory_contract.functions.createProxyWithNonce
            if not data.chain_id
            else proxy_factory_contract.functions.createChainSpecificProxyWithNonce
        )
        deployment_call = ContractCall(
            proxy_factory_method.abi, (data.singleton, initializer, data.salt_nonce)
        )

        if not offline:
            if w3.eth.get_code(address) != b"":
                raise click.ClickException(
                    f"Safe account computed address {address} already contains code."
                )

    if not params.quiet_mode:
        console.line()
        print_safe_deploy_info(data, address)
        console.line()

    if not force and not confirm("Prepare Web3 transaction?", default=False):
        raise click.Abort()

    with authenticator(keyfile, trezor) as auth:
        process_contract_call_web3tx(
            w3,
            contract_abi=proxy_factory_contract.abi,
            contract_call=deployment_call,
            contract_address=data.proxy_factory,
            auth=auth,
            force=force,
            sign_only=sign_only,
            output=output,
            txopts=txopts,
            offline=offline,
        )


@safe.command()
@params.make_option(params.abi_option_info)
@params.output_file
@click.argument("function", metavar="FUNCTION")
@click.argument("str_args", metavar="[ARGUMENT]...", nargs=-1)
@params.common
def encode(
    abi_file: str,
    function: str,
    output: Optional[typing.TextIO],
    str_args: list[str],
) -> None:
    """Encode contract call data.

    FUNCTION is the function's name, 4-byte selector, or full signature.
    """
    with status("Building call data..."):
        import rich
        from web3 import Web3

        console = rich.get_console()

        with open(abi_file, "r") as f:
            abi = json.load(f)
        match, partials = find_function(abi, function)
        if match is None:
            handle_function_match_failure(function, partials)
        assert match is not None

        w3 = Web3()
        contract = w3.eth.contract(abi=abi)
        fn_obj = contract.get_function_by_selector(match.selector)
        args = parse_args(fn_obj.abi, str_args)
        calldata = contract.encode_abi(match.sig, args)
    if not params.quiet_mode:
        print_line_if_tty(console, output)
    output_console = get_output_console(output)
    output_console.print(calldata)


@safe.command()
@optgroup.group("Safe parameters")
@params.make_option(
    params.safe_version_option_info,
    cls=optgroup.option,
    help="Safe version (required if no RPC provided)",
)
@params.web3tx()
@params.make_option(
    params.value_option_info,
)
@params.authentication
@params.force
@click.argument("txfile", type=click.File("r"), required=True)
@params.sigfile(metavar="SIGFILE [SIGFILE]...")
@params.output_file
@params.common
def exec(
    chain_id: Optional[int],
    force: bool,
    gas_limit: Optional[int],
    keyfile: str,
    max_fee: Optional[str],
    max_pri_fee: Optional[str],
    nonce: Optional[int],
    output: Optional[typing.TextIO],
    rpc: Optional[str],
    safe_version: Optional[str],
    sigfiles: list[str],
    sign_only: bool,
    trezor: Optional[str],
    txfile: typing.TextIO,
    value_str: str,
):
    """Execute a signed Safe transaction.

    A SIGFILE must be a valid owner signature.
    """
    with status("Loading Safe transaction..."):
        import rich
        from safe_eth.safe.safe_signature import SafeSignature

        console = rich.get_console()
        offline = rpc is None

        if not sigfiles:
            raise click.ClickException(
                "Missing one or more signature files. Cannot execute SafeTx without signatures."
            )

        w3: "Web3" = validate_rpc_option(rpc) if not offline else make_offline_web3()
        txopts = validate_web3tx_options(
            w3=w3,
            chain_id=chain_id,
            gas_limit=gas_limit,
            nonce=nonce,
            max_fee=max_fee,
            max_pri_fee=max_pri_fee,
            sign_only=sign_only,
            offline=offline,
        )
        safe, safetx, contract = validate_safetxfile(
            w3=w3,
            txfile=txfile,
            offline=offline,
            w3_chain_id=txopts.chain_id,
            safe_version=safe_version,
        )

        chaindata = fetch_chaindata(safe.chain_id)
        decimals = chaindata.decimals if chaindata else FALLBACK_DECIMALS
        value = validate_decimal_value(value_str)
        value_scaled = scale_decimal_value(value, decimals)

        if offline:
            safe_info = SafeInfo()
        else:
            safe_info = query_safe_info(contract)

        safetx_hash, safetx_preimage = safetx.hash(safe), safetx.preimage(safe)
        sigdata = parse_signatures(
            safetx_hash, safetx_preimage, sigfiles, safe_info.owners
        )

    with status("Retrieving chainlist data..."):
        chaindata = fetch_chaindata(safe.chain_id)

    if not params.quiet_mode:
        console.line()
        print_safetxdata(safe, safetx, safetx_hash, chaindata)
        console.line()
        print_signatures(sigdata, safe_info.threshold, offline)

    sigs: list[SafeSignature] = []

    for sd in sigdata:
        if not isinstance(sd.sig, SafeSignature):
            continue
        if sd.valid:
            if offline or sd.is_owner:
                sigs.append(sd.sig)
    if len(sigs) < len(sigdata):
        raise click.ClickException(
            "Cannot execute SafeTx with invalid or unknown signatures."
        )
    if not offline:
        assert safe_info.threshold is not None and safe_info.threshold > 0
        if len(sigs) < safe_info.threshold:
            raise click.ClickException(
                "Insufficient valid owner signatures to execute."
            )
    exported_signatures = SafeSignature.export_signatures(sigs)

    if not params.quiet_mode:
        console.line()
    if not force:
        if not confirm("Prepare Web3 transaction?", default=False):
            raise click.Abort()

    exec_call = ContractCall(
        contract.functions.execTransaction.abi,
        (
            safetx.to,
            safetx.value,
            safetx.data,
            safetx.operation,
            safetx.safe_tx_gas,
            safetx.base_gas,
            safetx.gas_price,
            safetx.gas_token,
            safetx.refund_receiver,
            exported_signatures,
        ),
    )

    with authenticator(keyfile, trezor) as auth:
        process_contract_call_web3tx(
            w3,
            contract_abi=contract.abi,
            contract_call=exec_call,
            contract_address=contract.address,
            auth=auth,
            force=force,
            sign_only=sign_only,
            output=output,
            txopts=txopts,
            offline=offline,
            value=value_scaled,
        )


@safe.command()
@click.argument("txfile", type=click.File("r"), required=True)
@params.common
def hash(txfile: typing.TextIO) -> None:
    """Compute hash of Safe transaction."""
    safetx_json = txfile.read()
    safetx_data = json.loads(safetx_json)
    safetx_hash = hash_eip712_data(safetx_data)
    output_console = get_output_console()
    output_console.print(safetx_hash.to_0x_hex())


@safe.command()
def help():
    """Browse the documentation."""
    from rich.console import Console
    from rich.markdown import Markdown

    console = Console()
    readme = files("simple_safe.docs").joinpath("README.md")
    with readme.open("r") as f:
        md = f.read()
    with console.pager(styles=True, links=True):
        console.print(Markdown(md, code_theme="native"))


@safe.command()
@params.rpc(click.option, required=True)
@click.argument("address")
@params.common
def inspect(address: str, rpc: str):
    """Inspect a Safe account."""
    with status("Retrieving Safe account data..."):
        import rich
        from safe_eth.eth import EthereumClient
        from safe_eth.safe import Safe
        from web3.types import Wei

        console = rich.get_console()
        checksum_addr = to_checksum_address(address)
        client = EthereumClient(cast("URI", rpc))
        try:
            safeobj = Safe(checksum_addr, client)  # type: ignore[abstract]
            block = client.w3.eth.block_number
            # Silence safe_eth.eth.ethereum_client WARNING message:
            # "Multicall not supported for this network"
            with silence_logging():
                info = safeobj.retrieve_all_info(block)
        except Exception as exc:
            raise click.ClickException(str(exc)) from exc
        balance = client.w3.eth.get_balance(checksum_addr, block_identifier=block)

    with status("Retrieving chainlist data..."):
        chaindata = fetch_chaindata(client.w3.eth.chain_id)

    console.line()

    print_kvtable(
        "Safe Account",
        f"[Block {str(block)}]",
        {
            "Safe Address": info.address,
            "Version": info.version,
            f"Owners({len(info.owners)})": ", ".join(info.owners),
            "Threshold": str(info.threshold),
            "Safe Nonce": str(info.nonce),
            "Fallback Handler": info.fallback_handler,
            "Singleton": info.master_copy,
            "Guard": info.guard,
            "Modules": ", ".join(info.modules) if info.modules else "<none>",
        },
        {
            "Balance": format_native_value(Wei(balance), chaindata),
        },
    )


@safe.command()
@params.deployment(precompute=True)
@params.output_file
@params.common
def precompute(
    chain_id: Optional[int],
    chain_specific: bool,
    custom_proxy_factory: Optional[str],
    custom_singleton: Optional[str],
    fallback: Optional[str],
    output: Optional[typing.TextIO],
    owners: list[str],
    salt_nonce: str,
    threshold: int,
    without_events: bool,
):
    """Compute a Safe address offline."""
    import rich

    console = rich.get_console()
    data = validate_deploy_options(
        chain_id=chain_id,
        chain_specific=chain_specific,
        custom_proxy_factory=custom_proxy_factory,
        custom_singleton=custom_singleton,
        fallback=fallback,
        owners=owners,
        salt_nonce=salt_nonce,
        threshold=threshold,
        without_events=without_events,
    )
    _, address = compute_safe_address(
        proxy_factory=data.proxy_factory,
        singleton=data.singleton,
        salt_nonce=data.salt_nonce,
        owners=data.owners,
        threshold=data.threshold,
        fallback=data.fallback,
        chain_id=data.chain_id,
    )

    console.line()
    if not params.quiet_mode:
        print_safe_deploy_info(data, address)
        print_line_if_tty(console, output=None)

    output_console = get_output_console(output)
    output_console.print(address)


@safe.command()
@optgroup.group("Preview online")
@params.rpc(optgroup.option)
@optgroup.group("Preview offline")
@params.safe_version
@click.argument("txfile", type=click.File("r"), required=True)
@params.sigfile(metavar="[SIGFILE]...")
@params.common
def preview(
    rpc: Optional[str],
    safe_version: Optional[str],
    sigfiles: list[str],
    txfile: typing.TextIO,
):
    """Preview a Safe transaction.

    A SIGFILE must be a valid owner signature.
    """
    with status("Loading Safe transaction..."):
        import rich

        console = rich.get_console()
        offline = rpc is None

        w3: "Web3" = validate_rpc_option(rpc) if not offline else make_offline_web3()
        safe, safetx, contract = validate_safetxfile(
            w3=w3,
            txfile=txfile,
            offline=offline,
            w3_chain_id=None if offline else w3.eth.chain_id,
            safe_version=safe_version,
        )
        safetx_hash, safetx_preimage = safetx.hash(safe), safetx.preimage(safe)
        if sigfiles:
            if offline:
                safe_info = SafeInfo()
            else:
                safe_info = query_safe_info(contract)
            sigdata = parse_signatures(
                safetx_hash, safetx_preimage, sigfiles, safe_info.owners
            )
        else:
            sigdata = []
            safe_info = SafeInfo()

    with status("Retrieving chainlist data..."):
        chaindata = fetch_chaindata(safe.chain_id)

    console.line()
    print_safetxdata(safe, safetx, safetx_hash, chaindata)

    if sigfiles:
        console.line()
        print_signatures(
            sigdata,
            safe_info.threshold,
            offline,
        )


@safe.command()
@optgroup.group("Sign online")
@params.rpc(optgroup.option)
@optgroup.group("Sign offline")
@params.safe_version
@params.authentication
@params.output_file
@params.force
@click.argument("txfile", type=click.File("r"), required=True)
@params.common
def sign(
    force: bool,
    keyfile: str,
    output: Optional[typing.TextIO],
    rpc: Optional[str],
    safe_version: Optional[str],
    trezor: Optional[str],
    txfile: typing.TextIO,
):
    """Sign a Safe transaction."""
    with status("Loading Safe transaction..."):
        import rich
        from safe_eth.safe.safe_signature import SafeSignature

        console = rich.get_console()
        offline = rpc is None
        w3: "Web3" = validate_rpc_option(rpc) if not offline else make_offline_web3()
        safe, safetx, _ = validate_safetxfile(
            w3=w3,
            txfile=txfile,
            offline=offline,
            w3_chain_id=None if offline else w3.eth.chain_id,
            safe_version=safe_version,
        )
        safetx_hash, _ = safetx.hash(safe), safetx.preimage(safe)

    with status("Retrieving chainlist data..."):
        chaindata = fetch_chaindata(safe.chain_id)

    if not params.quiet_mode:
        console.line()
        print_safetxdata(safe, safetx, safetx_hash, chaindata)
        console.line()

    if not force and not confirm("Sign Safe transaction?", default=False):
        raise click.Abort()

    data = safetx.to_eip712_message(safe)
    logger.info(f"EIP-712 Data: {to_json(data)}")
    with authenticator(keyfile, trezor) as auth:
        sigbytes = auth.sign_typed_data(data)
    sigobj = SafeSignature.parse_signature(sigbytes, safetx_hash)[0]
    # This is only needed for non-EOA signature, which are not yet supported:
    signature = sigobj.export_signature()

    if not params.quiet_mode:
        print_line_if_tty(console, output=None)
    output_console = get_output_console(output)
    output_console.print(signature.to_0x_hex())
