import json
from getpass import getpass
from typing import Sequence

import click
from eth_account import Account
from eth_utils.address import to_checksum_address
from rich.prompt import Confirm
from web3 import Web3
from web3.contract.contract import ContractFunction
from web3.types import TxParams

from .abi import Function
from .console import (
    console,
    print_function_matches,
    print_web3_call_data,
    print_web3_tx_params,
    print_web3_tx_receipt,
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


def execute_calltx(w3: Web3, contractfn: ContractFunction, keyfile: str, force: bool):
    with console.status("Building Web3 transaction..."):
        tx: TxParams = contractfn.build_transaction()
    console.line()
    print_web3_call_data(contractfn)
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
