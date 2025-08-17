"""Common logic for command implementations."""

import json
import logging
import time
from decimal import Decimal
from typing import (
    TYPE_CHECKING,
    Optional,
    Sequence,
    TextIO,
    cast,
)

import click
from hexbytes import (
    HexBytes,
)

from . import params
from .abi import Function, find_function, parse_args
from .auth import Authenticator
from .chaindata import FALLBACK_DECIMALS, fetch_chaindata
from .console import (
    confirm,
    get_json_data_renderable,
    get_output_console,
    make_status_logger,
    print_function_matches,
    print_line_if_tty,
    print_web3_call_data,
    print_web3_tx_fees,
    print_web3_tx_params,
    print_web3_tx_receipt,
)
from .constants import SYMBOL_WARNING
from .types import (
    ContractCall,
    Safe,
    SafeOperation,
    SafeTx,
    Web3TxOptions,
)
from .util import (
    make_web3tx,
    scale_decimal_value,
    signed_tx_to_dict,
    web3tx_receipt_json_encoder,
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
    contract: "Contract",
    fn_identifier: str,
    str_args: list[str],
    safe: Safe,
    value: Decimal,
    operation: int,
) -> SafeTx:
    """Print a SafeTx that represents a contract call."""
    import rich
    from web3.constants import CHECKSUM_ADDRESSS_ZERO

    match, partials = find_function(contract.abi, fn_identifier)
    if match is None:
        handle_function_match_failure(fn_identifier, partials)
    assert match is not None

    fn_obj = contract.get_function_by_selector(match.selector)
    args = parse_args(fn_obj.abi, str_args)
    calldata = HexBytes(contract.encode_abi(match.sig, args))

    chaindata = fetch_chaindata(safe.chain_id)
    decimals = chaindata.decimals if chaindata else FALLBACK_DECIMALS

    console = rich.get_console()
    if not params.quiet_mode:
        console.line()
        print_web3_call_data(ContractCall(fn_obj.abi, args), calldata)
        console.line()

    return SafeTx(
        to=contract.address,
        value=scale_decimal_value(value, decimals),
        data=calldata,
        operation=SafeOperation(operation).value,
        safe_tx_gas=0,
        base_gas=0,
        gas_price=0,
        gas_token=CHECKSUM_ADDRESSS_ZERO,
        refund_receiver=CHECKSUM_ADDRESSS_ZERO,
    )


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
