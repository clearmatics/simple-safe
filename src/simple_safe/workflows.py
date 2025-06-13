import json
from decimal import Decimal
from getpass import getpass
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
from .console import (
    console,
    print_function_matches,
    print_web3_call_data,
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
    value_: str,
    version: Optional[str],
    chain_id: Optional[int],
    safe_nonce: Optional[int],
) -> SafeTx:
    matches = find_function(contract.abi, fn_identifier)
    if len(matches) != 1:
        handle_function_match_failure(fn_identifier, matches)

    fn_info = matches[0]
    fn_obj = contract.get_function_by_selector(matches[0].selector)
    try:
        args = parse_args(fn_obj.abi, str_args)
    except Exception as exc:
        raise click.ClickException(f"Error: {fn_info.sig}: {str(exc)}") from exc
    calldata = HexBytes(contract.encode_abi(fn_info.sig, args))

    return SafeTx(
        ethereum_client=client,
        safe_address=safe,
        to=contract.address,
        value=int(Decimal(value_) * 10**18),
        data=calldata,
        operation=SafeOperationEnum.CALL.value,
        safe_tx_gas=0,
        base_gas=0,
        gas_price=0,
        gas_token=None,
        refund_receiver=None,
        signatures=None,
        safe_nonce=safe_nonce,
        safe_version=version,
        chain_id=chain_id,
    )


def execute_tx(w3: Web3, tx: TxParams, keyfile: str, force: bool):
    with console.status("Checking sender address..."):
        with click.open_file(keyfile) as kf:
            keydata = kf.read()
        sender_address = to_checksum_address(json.loads(keydata)["address"])
        tx["nonce"] = w3.eth.get_transaction_count(sender_address)
        tx["from"] = sender_address

    console.line()
    print_web3_tx_params(tx)
    console.line()
    if not force and not Confirm.ask("Execute Web3 Transaction?", default=False):
        raise click.Abort()

    password = getpass()
    with console.status("Loading keyfile account..."):
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
    print_web3_tx_receipt(timestamp, tx_receipt)
    console.line()


def execute_calltx(
    w3: Web3,
    contractfn: ContractFunction,
    keyfile: str,
    force: bool,
):
    with console.status("Building Web3 transaction..."):
        try:
            tx: TxParams = contractfn.build_transaction()
        except Exception as exc:
            raise click.ClickException(str(exc)) from exc
    assert "data" in tx
    print_web3_call_data(contractfn, HexBytes(tx["data"]).to_0x_hex())
    execute_tx(w3, tx, keyfile, force)


def handle_function_match_failure(identifier: str, matches: Sequence[Function]) -> None:
    if len(matches) == 0:
        raise click.ClickException(f"No matches for function '{identifier}'.")
    if len(matches) > 1:
        console.line()
        print_function_matches(matches)
        console.line()
        raise click.ClickException(
            "Matched multiple function identifiers. Please use unique identifier."
        )


def validate_safetx_options(
    version: Optional[str],
    chain_id: Optional[int],
    safe_nonce: Optional[int],
    rpc: str,
):
    missing: list[str] = []
    if chain_id is None:
        missing.append("chain ID")
    if safe_nonce is None:
        missing.append("Safe nonce")
    if version is None:
        missing.append("Safe version")
    elif version not in SAFE_CONTRACT_VERSIONS:
        raise click.ClickException(f"Invalid or unsupported Safe version {version}.")
    if len(missing) > 0 and not rpc:
        raise click.ClickException(
            f"Missing info for offline SafeTx: {', '.join(missing)}. "
        )
