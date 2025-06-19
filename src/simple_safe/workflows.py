import json
from decimal import Decimal
from typing import (
    Optional,
    Sequence,
)

import click
from eth_account import Account
from eth_typing import ChecksumAddress
from eth_utils.address import to_checksum_address
from hexbytes import (
    HexBytes,
)
from rich.prompt import Confirm
from safe_eth.eth import EthereumClient
from safe_eth.safe import SafeOperationEnum, SafeTx
from web3 import Web3
from web3.contract import Contract
from web3.contract.contract import ContractFunction
from web3.types import TxParams

from .abi import Function, find_function, parse_args
from .chain import FALLBACK_DECIMALS, fetch_chaindata
from .console import (
    console,
    get_keyfile_password,
    print_function_matches,
    print_web3_call_data,
    print_web3_tx_fees,
    print_web3_tx_params,
    print_web3_tx_receipt,
)

SAFE_CONTRACT_VERSIONS = (
    "0.0.1",
    "1.0.0",
    "1.1.1",
    "1.2.0",
    "1.3.0",
    "1.4.1",
)


def prepare_calltx(
    client: EthereumClient,
    contract: Contract,
    fn_identifier: str,
    str_args: list[str],
    safe: ChecksumAddress,
    value: str,
    safe_version: Optional[str],
    chain_id: Optional[int],
    safe_nonce: Optional[int],
) -> SafeTx:
    match, partials = find_function(contract.abi, fn_identifier)
    if match is None:
        handle_function_match_failure(fn_identifier, partials)
    assert match is not None

    fn_obj = contract.get_function_by_selector(match.selector)
    args = parse_args(fn_obj.abi, str_args)
    calldata = HexBytes(contract.encode_abi(match.sig, args))
    chaindata = fetch_chaindata(chain_id if chain_id else client.w3.eth.chain_id)
    decimals = chaindata.decimals if chaindata else FALLBACK_DECIMALS

    return SafeTx(
        ethereum_client=client,
        safe_address=safe,
        to=contract.address,
        value=int(Decimal(value).scaleb(decimals)),
        data=calldata,
        operation=SafeOperationEnum.CALL.value,
        safe_tx_gas=0,
        base_gas=0,
        gas_price=0,
        gas_token=None,
        refund_receiver=None,
        signatures=None,
        safe_nonce=safe_nonce,
        safe_version=safe_version,
        chain_id=chain_id,
    )


def execute_tx(w3: Web3, tx: TxParams, keyfile: str, force: bool) -> HexBytes:
    with console.status("Checking sender address..."):
        with click.open_file(keyfile) as kf:
            keydata = kf.read()
        sender_address = to_checksum_address(json.loads(keydata)["address"])
        tx["nonce"] = w3.eth.get_transaction_count(sender_address)
        tx["from"] = sender_address

    with console.status("Retrieving chain data..."):
        chaindata = fetch_chaindata(w3.eth.chain_id)
        gasprice = w3.eth.gas_price

    console.line()
    print_web3_tx_params(tx, gasprice, chaindata)
    console.line()
    print_web3_tx_fees(tx, gasprice, chaindata)

    console.line()
    if not force and not Confirm.ask("Execute Web3 transaction?", default=False):
        raise click.Abort()

    password = get_keyfile_password(sender_address, keyfile)

    with console.status("Loading account from keyfile..."):
        privkey = Account.decrypt(keydata, password=password)
        deployer_account = Account.from_key(privkey)

    with console.status("Executing Web3 transaction..."):
        signed_tx = deployer_account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

    with console.status("Waiting for Web3 transaction receipt..."):
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    timestamp = w3.eth.get_block(
        tx_receipt["blockNumber"], full_transactions=False
    ).get("timestamp")

    console.line()
    print_web3_tx_receipt(timestamp, tx_receipt, chaindata)
    return tx_hash


def execute_calltx(
    w3: Web3,
    contractfn: ContractFunction,
    keyfile: str,
    force: bool,
) -> HexBytes:
    with console.status("Building Web3 transaction..."):
        tx: TxParams = contractfn.build_transaction()
    assert "data" in tx
    console.line()
    print_web3_call_data(contractfn, HexBytes(tx["data"]).to_0x_hex())
    return execute_tx(w3, tx, keyfile, force)


def handle_function_match_failure(
    identifier: str, partial_matches: Sequence[Function]
) -> None:
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


def validate_safetx_options(
    safe_version: Optional[str],
    chain_id: Optional[int],
    safe_nonce: Optional[int],
    rpc: str,
):
    missing: list[str] = []
    if chain_id is None:
        missing.append("chain ID")
    if safe_nonce is None:
        missing.append("Safe nonce")
    if safe_version is None:
        missing.append("Safe version")
    elif safe_version not in SAFE_CONTRACT_VERSIONS:
        raise click.ClickException(
            f"Invalid or unsupported Safe version {safe_version}."
        )
    if len(missing) > 0 and not rpc:
        raise click.ClickException(
            f"Missing info for offline SafeTx: {', '.join(missing)}. "
        )
