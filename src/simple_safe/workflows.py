"""Common logic for command implementations."""

import json
import logging
import time
from dataclasses import asdict
from decimal import Decimal
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Optional,
    Sequence,
    TextIO,
    Type,
    cast,
)

import click
from hexbytes import (
    HexBytes,
)

from . import params
from .abi import Function, find_function, parse_args
from .auth import Authenticator
from .chaindata import FALLBACK_DECIMALS, ChainData, fetch_chaindata
from .console import (
    confirm,
    get_json_data_renderable,
    get_output_console,
    make_status_logger,
    print_batch_safetx,
    print_function_matches,
    print_line_if_tty,
    print_web3_call_data,
    print_web3_tx_fees,
    print_web3_tx_params,
    print_web3_tx_receipt,
)
from .constants import (
    DEFAULT_MULTISEND_ADDRESS,
    DEFAULT_MULTISEND_CALLONLY_ADDRESS,
    SYMBOL_WARNING,
)
from .types import (
    BatchTxInfo,
    ContractCall,
    MultiSendTxInput,
    Safe,
    SafeOperation,
    SafeTx,
    Web3TxOptions,
)
from .util import (
    load_csv_file,
    make_multisendtx,
    make_web3tx,
    scale_decimal_value,
    signed_tx_to_dict,
    to_checksum_address,
    to_json,
    web3tx_receipt_json_encoder,
)
from .validation import (
    CLIOption,
    validate_batch_options,
    validate_funcarg_columns,
)

if TYPE_CHECKING:
    from eth_typing import ABI, ChecksumAddress
    from web3 import Web3
    from web3.contract import Contract
    from web3.types import TxParams, Wei

logger = logging.getLogger(__name__)
status = make_status_logger(logger)


def build_contract_call_safetx(
    *,
    w3: "Web3",
    contract: "Contract | Type[Contract]",
    address: Optional["ChecksumAddress"],
    fn_identifier: str,
    str_args: list[str],
    safe: Safe,
    value: Decimal,
    operation: int,
    batch: Optional[str] = None,
    delegatecall: bool = False,
    cli_options: Optional[list[CLIOption]] = None,
    multisend: Optional[str] = None,
    parent_row_parser: Optional[
        Callable[[int, dict[str, str]], MultiSendTxInput]
    ] = None,
) -> SafeTx:
    """Print a SafeTx that represents a contract call."""
    import rich
    from eth_typing import ABIFunction
    from eth_utils.abi import (
        get_abi_input_names,
    )
    from web3.constants import CHECKSUM_ADDRESSS_ZERO

    match, partials = find_function(contract.abi, fn_identifier)
    if match is None:
        handle_function_match_failure(fn_identifier, partials)
    assert match is not None

    fn_obj = contract.get_function_by_selector(match.selector)

    chaindata = fetch_chaindata(safe.chain_id)
    decimals = chaindata.decimals if chaindata else FALLBACK_DECIMALS
    value_scaled = scale_decimal_value(value, decimals)

    argnames = list(map(str, get_abi_input_names(cast("ABIFunction", match.abi))))
    if str_args and len(str_args) != len(argnames):
        raise click.ClickException(
            f"Function '{match.sig}' takes {len(argnames)} "
            f"arguments but {len(str_args)} " + "argument was"
            if len(str_args) == 1
            else "arguments were" + " provided."
        )

    if batch:
        assert cli_options is not None
        assert parent_row_parser is not None

        colnames, rows = load_csv_file(batch)

        validate_batch_options(cli_options, colnames)

        if not str_args:
            validate_funcarg_columns(colnames, argnames)
            for arg_i, name in enumerate(argnames):
                iform, nform = f"arg:{1 + arg_i}", f"arg:{name}"
                if (iform in colnames) and (nform in colnames):
                    raise click.ClickException(
                        f"Duplicate columns '{iform}' and '{nform}' refer to the same argument."
                    )

        def row_parser(row_i: int, row: dict[str, str]) -> MultiSendTxInput:
            argvals = list(str_args)
            if not argvals:
                for arg_i, name in enumerate(argnames):
                    iform, nform = f"arg:{1 + arg_i}", f"arg:{name}"
                    argval = str(
                        row.get(iform) if (iform in colnames) else row.get(nform)
                    )
                    assert argval is not None, f"missing {name}"
                    argvals.append(argval)
            args = parse_args(fn_obj.abi, argvals)
            txdata = HexBytes(contract.encode_abi(match.sig, args))

            logger.info(
                f"Row {1 + row_i} Data: func={match.name} args={to_json(args)} -> {txdata.to_0x_hex()}"
            )
            return cast(
                MultiSendTxInput,
                {
                    "value": value_scaled,
                    "operation": operation,
                    **parent_row_parser(row_i, row),
                    "data": txdata,
                },
            )

        return build_batch_safetx(
            w3=w3,
            safe=safe,
            multisend=multisend,
            delegatecall=delegatecall,
            chaindata=chaindata,
            row_parser=row_parser,
            rows=rows,
        )

    else:
        assert address is not None

        args = parse_args(fn_obj.abi, str_args)
        calldata = HexBytes(contract.encode_abi(match.sig, args))

        console = rich.get_console()
        if not params.quiet_mode:
            console.line()
            print_web3_call_data(ContractCall(fn_obj.abi, args), calldata)

        return SafeTx(
            to=address,
            value=value_scaled,
            data=calldata,
            operation=SafeOperation(operation).value,
            safe_tx_gas=0,
            base_gas=0,
            gas_price=0,
            gas_token=CHECKSUM_ADDRESSS_ZERO,
            refund_receiver=CHECKSUM_ADDRESSS_ZERO,
        )


def build_batch_safetx(
    *,
    w3: "Web3",
    safe: Safe,
    multisend: "Optional[str]",
    delegatecall: bool,
    chaindata: Optional[ChainData],
    rows: list[dict[str, Any]],
    row_parser: Callable[[int, dict[str, str]], MultiSendTxInput],
) -> SafeTx:
    """Create a batch SafeTx."""
    import rich
    from safe_eth.eth.contracts import get_multi_send_contract
    from web3.constants import CHECKSUM_ADDRESSS_ZERO

    batch_info = BatchTxInfo()
    txs: list[bytes] = []
    for i, row in enumerate(list(rows)):
        try:
            txinput = row_parser(i, row)
            assert "to" in txinput
            assert "data" in txinput
            assert "value" in txinput
            assert "operation" in txinput

            tx = make_multisendtx(**txinput)
            if txinput["operation"] == SafeOperation.DELEGATECALL.value:
                if not delegatecall:
                    raise click.ClickException(
                        "Processing DELEGATECALL transaction but --delegatecall not set."
                    )
                batch_info.delegatecalls += 1
        except Exception as exc:
            message = f"Row {1 + i}: " + (
                f"{type(exc).__name__}: {exc}."
                if not isinstance(exc, click.ClickException)
                else str(exc)
            )
            raise click.ClickException(message) from exc
        batch_info.to_addresses.add(txinput["to"])
        batch_info.count += 1
        batch_info.total_value += txinput["value"]
        logger.info(f"Row {1 + i}: {to_json(txinput)} -> '0x{tx.hex()}'")
        txs.append(tx)

    if multisend:
        batch_info.contract_address = to_checksum_address(multisend)
    else:
        batch_info.contract_address = to_checksum_address(
            DEFAULT_MULTISEND_ADDRESS
            if batch_info.delegatecalls > 0
            else DEFAULT_MULTISEND_CALLONLY_ADDRESS
        )

    logger.info(f"Batch Stats: {to_json(asdict(batch_info))}")

    multisend_data = b"".join(txs)
    logger.info(f"MultiSend Payload: '0x{multisend_data.hex()}'")

    contract = get_multi_send_contract(w3, batch_info.contract_address)
    calldata = HexBytes(contract.encode_abi("multiSend(bytes)", [multisend_data]))
    logger.info(f"MultiSend Call Data: '0x{calldata.hex()}'")

    safetx = SafeTx(
        to=contract.address,
        value=0,
        data=calldata,
        operation=SafeOperation.DELEGATECALL.value,
        safe_tx_gas=0,
        base_gas=0,
        gas_price=0,
        gas_token=CHECKSUM_ADDRESSS_ZERO,
        refund_receiver=CHECKSUM_ADDRESSS_ZERO,
    )

    console = rich.get_console()
    if not params.quiet_mode:
        console.line()
        print_batch_safetx(batch_info, multisend_data, chaindata)

    if batch_info.delegatecalls > 0:
        if not params.quiet_mode:
            console.line()
        logger.warning(
            f"{SYMBOL_WARNING} Batch Safe transaction contains "
            "DELEGATECALLs with unrestricted access to the Safe"
        )
    return safetx


def handle_function_match_failure(
    identifier: str, partial_matches: Sequence[Function]
) -> None:
    import rich

    console = rich.get_console()
    if len(partial_matches) == 0:
        raise click.ClickException(f"No matches for function '{identifier}'.")
    console.line()
    print_function_matches(partial_matches)
    console.line()
    if len(partial_matches) == 1:
        raise click.ClickException(
            f"No match for function '{identifier}'. Did you mean '{partial_matches[0].name}'?"
        )
    else:
        raise click.ClickException(
            "Matched multiple functions. Please specify unique identifier."
        )


def process_contract_call_web3tx(
    w3: "Web3",
    *,
    contract_abi: "ABI",
    contract_call: ContractCall,
    contract_address: "ChecksumAddress",
    auth: Authenticator,
    force: bool,
    sign_only: bool,
    output: Optional[TextIO],
    txopts: "Web3TxOptions",
    offline: bool,
    value: int = 0,
):
    with status("Building Web3 transaction..."):
        import rich
        from web3._utils.contracts import prepare_transaction

        console = rich.get_console()
        tx_value: Wei = cast("Wei", value)
        tx_data = prepare_transaction(
            contract_address,
            w3,
            abi_element_identifier=contract_call.signature,
            contract_abi=contract_abi,
            abi_callable=contract_call.abi,
            transaction=cast("TxParams", {"value": tx_value}),
            fn_args=contract_call.args,
            fn_kwargs=None,
        ).get("data")
        assert tx_data is not None
        tx, gas_estimate = make_web3tx(
            w3,
            offline=offline,
            from_=auth.address,
            to=contract_address,
            txopts=txopts,
            data=tx_data,
            value=tx_value,
        )

    assert "data" in tx
    if not params.quiet_mode:
        console.line()
        print_web3_call_data(contract_call, HexBytes(tx["data"]))

    assert "chainId" in tx
    with status("Retrieving chainlist data..."):
        chaindata = fetch_chaindata(tx["chainId"])
        gasprice = None if offline else w3.eth.gas_price

    if not params.quiet_mode:
        console.line()
        print_web3_tx_params(tx, auth, gas_estimate, chaindata)
        console.line()
        print_web3_tx_fees(tx, offline, gasprice, chaindata)

    if (
        not offline
        and (txopts.gas_limit is not None)
        and (gas_estimate is not None)
        and txopts.gas_limit < gas_estimate
    ):
        console.line()
        logger.warning(
            f"{SYMBOL_WARNING} Transaction likely to fail because "
            f"custom gas limit {txopts.gas_limit} is less than "
            f"estimated gas {gas_estimate}."
        )

    if not params.quiet_mode:
        console.line()
    prompt = ("Sign" if sign_only else "Execute") + " Web3 transaction?"
    if not force and not confirm(prompt, default=False):
        raise click.Abort()

    signed_tx = auth.sign_transaction(tx)
    signed_tx_dict = signed_tx_to_dict(signed_tx)
    logger.info(f"Signed Web3Tx: {signed_tx_dict}")
    output_console = get_output_console(output)

    if sign_only:
        if not params.quiet_mode:
            print_line_if_tty(console, output)
        output_console.print(get_json_data_renderable(signed_tx_dict))
    else:
        with status("Executing Web3 transaction..."):
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

        with status("Waiting for Web3 transaction receipt..."):
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        logger.info(
            f"Web3Tx Receipt: {json.dumps(tx_receipt, default=web3tx_receipt_json_encoder)}"
        )
        block_number = tx_receipt["blockNumber"]
        with status(f"Retrieving block {block_number} headers..."):
            MAX_ATTEMPTS = 5
            for attempt in range(1, 1 + MAX_ATTEMPTS):
                try:
                    timestamp = w3.eth.get_block(
                        block_number, full_transactions=False
                    ).get("timestamp")
                    break
                except Exception as exc:
                    logger.info(
                        f"{type(exc).__name__} (attempt {attempt}/{MAX_ATTEMPTS}): {exc}"
                    )
                    time.sleep(attempt)
            else:
                raise click.ClickException(
                    f"Failed to obtain block {block_number} info from RPC node after {MAX_ATTEMPTS} attempts."
                )

        if not params.quiet_mode:
            console.line()
            print_web3_tx_receipt(timestamp, tx_receipt, chaindata)
            print_line_if_tty(console, output)

        output_console.print(tx_hash.to_0x_hex())
