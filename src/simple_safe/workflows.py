import logging
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

from simple_safe.util import scale_decimal_value

from .abi import Function, find_function, parse_args
from .auth import Authenticator
from .chaindata import FALLBACK_DECIMALS, fetch_chaindata
from .console import (
    get_json_data_renderable,
    get_output_console,
    make_status_logger,
    print_function_matches,
    print_web3_call_data,
    print_web3_tx_fees,
    print_web3_tx_params,
    print_web3_tx_receipt,
)
from .models import (
    Safe,
    SafeInfo,
    SafeTx,
    Web3TxOptions,
)

if TYPE_CHECKING:
    from eth_typing import ChecksumAddress, HexStr
    from web3 import Web3
    from web3.contract import Contract
    from web3.contract.contract import ContractFunction
    from web3.types import Nonce, TxParams, Wei

logger = logging.getLogger(__name__)
status = make_status_logger(logger)


def build_contract_call_safetx(
    *,
    w3: "Web3",
    contract: "Contract",
    fn_identifier: str,
    str_args: list[str],
    safe: Safe,
    value: str,
    output: Optional[TextIO],
):
    """Print a SafeTx that represents a contract call."""
    from safe_eth.safe import SafeOperationEnum
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

    safetx = SafeTx(
        to=contract.address,
        value=scale_decimal_value(value, decimals),
        data=calldata,
        operation=SafeOperationEnum.CALL.value,
        safe_tx_gas=0,
        base_gas=0,
        gas_price=0,
        gas_token=CHECKSUM_ADDRESSS_ZERO,
        refund_receiver=CHECKSUM_ADDRESSS_ZERO,
    )
    output_console = get_output_console(output)
    output_console.print(
        get_json_data_renderable(safetx.to_eip712_message(safe)),
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


def make_web3tx(
    w3: "Web3",
    *,
    from_: "ChecksumAddress",
    to: "ChecksumAddress",
    txopts: "Web3TxOptions",
    data: "bytes | HexStr",
    value: "Wei",
) -> "TxParams":
    from web3.types import TxParams

    assert txopts.chain_id is not None
    if (gas_limit := txopts.gas_limit) is None:
        gas_limit = w3.eth.estimate_gas({"to": to, "data": data})
    if (nonce := txopts.nonce) is None:
        nonce = w3.eth.get_transaction_count(from_, block_identifier="pending")
    if (max_pri_fee := txopts.max_pri_fee) is None:
        max_pri_fee = w3.eth.max_priority_fee
    if (max_fee := txopts.max_fee) is None:
        block = w3.eth.get_block("latest")
        assert "baseFeePerGas" in block
        max_fee = (2 * block["baseFeePerGas"]) + max_pri_fee
    tx = TxParams(
        type=2,
        to=to,
        chainId=txopts.chain_id,
        gas=gas_limit,
        nonce=cast("Nonce", nonce),
        maxFeePerGas=cast("Wei", max_fee),
        maxPriorityFeePerGas=cast("Wei", max_pri_fee),
        data=data,
        value=value,
    )
    logging.debug(f"Created Web3Tx: {tx}")
    return tx


def process_contract_call_web3tx(
    w3: "Web3",
    *,
    contractfn: "ContractFunction",
    auth: Authenticator,
    force: bool,
    sign_only: bool,
    output: Optional[TextIO],
    txopts: "Web3TxOptions",
    offline: bool,
):
    with status("Building Web3 transaction..."):
        import rich
        from eth_utils.abi import abi_to_signature
        from rich.prompt import Confirm
        from web3._utils.contracts import prepare_transaction

        console = rich.get_console()
        tx_value: Wei = cast("Wei", 0)  # be explicit about zero value
        abi_element_identifier = abi_to_signature(contractfn.abi)
        tx_data = prepare_transaction(
            contractfn.address,
            w3,
            abi_element_identifier=abi_element_identifier,
            contract_abi=contractfn.contract_abi,
            abi_callable=contractfn.abi,
            transaction=cast("TxParams", {"value": tx_value}),
            fn_args=contractfn.args,
            fn_kwargs=contractfn.kwargs,
        ).get("data")
        assert tx_data is not None
        tx = make_web3tx(
            w3,
            from_=auth.address,
            to=contractfn.address,
            txopts=txopts,
            data=tx_data,
            value=tx_value,
        )

    assert "data" in tx
    console.line()
    print_web3_call_data(contractfn, HexBytes(tx["data"]).to_0x_hex())

    assert "chainId" in tx
    with status("Retrieving chainlist data..."):
        chaindata = fetch_chaindata(tx["chainId"])
        gasprice = None if offline else w3.eth.gas_price

    console.line()
    print_web3_tx_params(tx, auth, chaindata)
    console.line()
    print_web3_tx_fees(tx, offline, gasprice, chaindata)

    console.line()
    prompt = ("Sign" if sign_only else "Execute") + " Web3 transaction?"
    if not force and not Confirm.ask(prompt, default=False):
        raise click.Abort()

    signed_tx = auth.sign_transaction(tx)
    output_console = get_output_console(output)

    if sign_only:
        console.line()
        output_console.print(get_json_data_renderable(signed_tx._asdict()))
    else:
        with status("Executing Web3 transaction..."):
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

        with status("Waiting for Web3 transaction receipt..."):
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        timestamp = w3.eth.get_block(
            tx_receipt["blockNumber"], full_transactions=False
        ).get("timestamp")

        console.line()
        print_web3_tx_receipt(timestamp, tx_receipt, chaindata)

        console.line()
        output_console.print(tx_hash.to_0x_hex())


def query_safe_info(safe_contract: "Contract"):
    return SafeInfo(
        owners=safe_contract.functions.getOwners().call(block_identifier="latest"),
        threshold=safe_contract.functions.getThreshold().call(
            block_identifier="latest"
        ),
    )
