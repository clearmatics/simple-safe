#!/usr/bin/env -S uv run --script

import json
import logging
import secrets
import shutil
import typing
from decimal import Decimal
from getpass import getpass
from typing import (
    Optional,
)

import click
from click_option_group import (
    optgroup,
)
from eth_account import Account
from eth_typing import (
    URI,
)
from eth_utils.address import to_checksum_address
from hexbytes import (
    HexBytes,
)
from rich.console import Console
from rich.json import JSON
from safe_eth.eth import EthereumClient
from safe_eth.eth.contracts import (
    get_proxy_factory_V1_4_1_contract,
    get_safe_V1_4_1_contract,
)
from safe_eth.eth.exceptions import EthereumClientException
from safe_eth.safe import InvalidMultisigTx, Safe, SafeOperationEnum, SafeTx
from safe_eth.safe.exceptions import SafeServiceException
from safe_eth.safe.safe_signature import SafeSignature
from web3 import Web3
from web3.constants import ADDRESS_ZERO
from web3.providers.auto import load_provider_from_uri

from . import option
from .console import (
    console,
    print_kvtable,
    print_web3_tx_receipt,
)
from .util import (
    as_checksum,
    eip712_data_to_safetx,
    hash_eip712_data,
    hexbytes_json_encoder,
)

DEPLOY_SAFE_VERSION = "1.4.1"
SALT_NONCE_SENTINEL = "random"
DEFAULT_PROXYFACTORY_ADDRESS = as_checksum("0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67")
DEFAULT_FALLBACK_ADDRESS = as_checksum("0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99")
DEFAULT_SAFEL2_SINGLETON_ADDRESS = as_checksum(
    "0x29fcB43b46531BcA003ddC8FCB67FFE91900C762"
)
DEFAULT_SAFE_SINGLETON_ADDRESS = as_checksum(
    "0x41675C099F32341bf84BFc5382aF534df5C7461a"
)

# Silence logs from `safe_eth` library.
logging.getLogger("safe_eth").setLevel(logging.CRITICAL)


# ┌──────┐
# │ Main │
# └──────┘


@click.group(
    context_settings=dict(
        show_default=True,
        max_content_width=shutil.get_terminal_size().columns,
        help_option_names=["-h", "--help"],
    )
)
def main():
    """A simple inteface to Safe Smart Accounts."""
    pass


# ┌──────────┐
# │ Commands │
# └──────────┘


@main.group()
def build():
    """Build a SafeTx for signing."""
    pass


@build.command(name="tx")
@option.account
@option.rpc
@click.option("--version", help="Safe Account version")
@click.option("--chain", "chain_id", type=int, metavar="ID", help="Chain ID")
@click.option("--nonce", type=int, help="nonce of the Safe Account")
@click.option(
    "--to", "to_str", metavar="ADDRESS", required=True, help="destination address"
)
@click.option("--value", "value_", default="0.0", help="tx value in decimals")
@click.option("--data", default="0x", help="optional call data payload")
@option.output_file
def build_tx(
    account: str,
    version: Optional[str],
    chain_id: Optional[int],
    nonce: Optional[int],
    to_str: str,
    value_: str,
    data: str,
    output: typing.TextIO | None,
    rpc: str,
) -> None:
    """Build a custom SafeTx.

    If the Chain ID, Safe version, or Safe nonce are not specified, the values
    will be fetched from the network.
    """
    client = EthereumClient(URI(rpc))
    safetx = SafeTx(
        ethereum_client=client,
        safe_address=to_checksum_address(account),
        to=to_checksum_address(to_checksum_address(to_str)),
        value=int(Decimal(value_) * 10**18),
        data=HexBytes(data),
        operation=SafeOperationEnum.CALL.value,
        safe_tx_gas=0,
        base_gas=0,
        gas_price=0,
        gas_token=None,
        refund_receiver=None,
        signatures=None,
        safe_nonce=nonce,
        safe_version=version,
        chain_id=chain_id,
    )
    output_console = Console(file=output) if output else console
    output_console.print(
        JSON.from_data(
            safetx.eip712_structured_data, default=hexbytes_json_encoder, indent=2
        )
    )


@main.command()
# pyright: reportUntypedFunctionDecorator=false
# pyright: reportUnknownMemberType=false
@option.web3tx
@option.authentication
@optgroup.group(
    "Safe configuration",
)
@optgroup.option(
    "--owner",
    "owners",
    required=True,
    multiple=True,
    metavar="ADDRESS",
    type=str,
    help="add an owner (repeat option to add more)",
)
@optgroup.option(
    "--threshold",
    type=int,
    default=1,
    help="number of required confirmations",
)
@optgroup.option(
    "--fallback",
    metavar="ADDRESS",
    help="custom Fallback Handler address",
)
@optgroup.group(
    "Deployment settings",
)
@optgroup.option(
    "--chain-specific",
    is_flag=True,
    default=False,
    help="account address will depend on Chain ID [default: no]",
)
@optgroup.option(
    "--salt-nonce",
    type=str,
    metavar="INTEGER",
    default=SALT_NONCE_SENTINEL,
    help="nonce used to generate CREATE2 salt",
)
@optgroup.option(
    "--without-events",
    is_flag=True,
    help="use implementation that does not emit events",
)
@optgroup.option(
    "--custom-singleton",
    metavar="ADDRESS",
    help="use non-canonical Safe Singleton address",
)
@optgroup.option(
    "--custom-proxy-factory",
    metavar="ADDRESS",
    help="use non-canonical ProxyFactory address",
)
def deploy(
    keyfile: str,
    rpc: str,
    owners: tuple[str],
    threshold: int,
    fallback: str,
    chain_specific: bool,
    salt_nonce: str,
    without_events: bool,
    custom_singleton: str,
    custom_proxy_factory: str,
):
    """Deploy a new Safe Account.

    The Safe Account is deployed with CREATE2, which makes it possible to
    own the same address on different chains. If this is not desirable, pass the
    --chain-specific option to include the Chain ID in the CREATE2 salt derivation.

    The account uses the 'SafeL2.sol' implementation by default, which
    emits events. To use the gas-saving 'Safe.sol' variant instead, pass
    --without-events.
    """
    w3 = Web3(load_provider_from_uri(URI(rpc)))

    if salt_nonce == SALT_NONCE_SENTINEL:
        salt_nonce_int = secrets.randbits(256)  # uint256
    else:
        salt_nonce_int = int(salt_nonce)
    owner_addresses = {to_checksum_address(owner) for owner in owners}
    if threshold <= 0:
        raise click.ClickException(f"Invalid threshold '{threshold}'.")
    elif threshold > len(owners):
        raise click.ClickException(
            f"Threshold '{threshold}' exceeds number of unique owners {len(owner_addresses)}."
        )
    if custom_singleton:
        if without_events:
            raise click.ClickException(
                "Option --without-events incompatible with --custom-singleton."
            )
        singleton_address = to_checksum_address(custom_singleton)
    elif without_events:
        singleton_address = DEFAULT_SAFE_SINGLETON_ADDRESS
    else:
        singleton_address = DEFAULT_SAFEL2_SINGLETON_ADDRESS
    fallback_address = (
        DEFAULT_FALLBACK_ADDRESS if not fallback else to_checksum_address(fallback)
    )
    proxy_factory_address = (
        DEFAULT_PROXYFACTORY_ADDRESS
        if not custom_proxy_factory
        else to_checksum_address(custom_proxy_factory)
    )

    safe_contract = get_safe_V1_4_1_contract(w3, singleton_address)
    initializer = HexBytes(
        safe_contract.encode_abi(
            "setup",
            [
                list(owner_addresses),
                threshold,
                ADDRESS_ZERO,
                b"",
                fallback_address,
                ADDRESS_ZERO,
                0,
                ADDRESS_ZERO,
            ],
        )
    )

    proxy_factory_contract = get_proxy_factory_V1_4_1_contract(
        w3, proxy_factory_address
    )
    proxy_factory_method = (
        proxy_factory_contract.functions.createProxyWithNonce
        if not chain_specific
        else proxy_factory_contract.functions.createChainSpecificProxyWithNonce
    )

    deployment_call = proxy_factory_method(
        singleton_address, initializer, salt_nonce_int
    )
    predicted_address = deployment_call.call()

    existing_code = w3.eth.get_code(predicted_address)
    if existing_code != b"":
        raise click.ClickException(
            f"Safe Account predicted address {predicted_address} already contains code."
        )

    console.line()
    print_kvtable(
        "Safe Deployment Parameters",
        "",
        {
            "Safe Account": f"{predicted_address} (predicted)",
            "Version": DEPLOY_SAFE_VERSION,
            f"Owners({len(owner_addresses)})": ", ".join(owner_addresses),
            "Threshold": str(threshold),
            "Fallback Handler": fallback_address,
            "Salt Nonce": str(salt_nonce_int),
            "Singleton": singleton_address,
            "Proxy Factory": proxy_factory_address,
        },
    )
    console.line()
    click.confirm("Prepare Web3 transaction?", abort=True)

    execute_calltx(w3, deployment_call, keyfile)


@main.command()
@option.authentication
@click.option(
    "--sigfile",
    "-g",
    "sigfiles",
    type=click.Path(exists=True),
    multiple=True,
    required=True,
    help="owner signature file",
)
@option.web3tx
@click.argument("txfile", type=click.File("r"), required=False)
def exec(
    keyfile: str,
    sigfiles: list[str],
    rpc: str,
    txfile: typing.BinaryIO | None,
):
    """Execute a signed SafeTx.

    Repeat the signature option to include all required signatures.
    """
    if not txfile:
        txfile = click.get_binary_stream("stdin")
    safetx_json = txfile.read()
    safetx_data = json.loads(safetx_json)
    safetx = eip712_data_to_safetx(safetx_data, rpc)

    with click.open_file(keyfile) as kf:
        keydata = kf.read()
    password = getpass()
    privkey = Account.decrypt(keydata, password=password)
    account = Account.from_key(privkey)

    sigobjs: list[SafeSignature] = []
    safetx_preimage = safetx.safe_tx_hash_preimage
    safetx_hash = safetx.safe_tx_hash
    for sigfile in sigfiles:
        with open(sigfile, "r") as sf:
            sigtext = sf.read().rstrip()
            sigbytes = HexBytes(sigtext)
        siglist = SafeSignature.parse_signature(sigbytes, safetx_hash, safetx_preimage)
        for sigobj in siglist:
            sigobjs.append(sigobj)
    safetx.signatures = SafeSignature.export_signatures(sigobjs)

    try:
        safetx.call(
            tx_sender_address=account.address,
            block_identifier="latest",
        )
        w3txhash, _ = safetx.execute(
            tx_sender_private_key=privkey.to_0x_hex(),
            block_identifier="latest",
        )
    except InvalidMultisigTx as exc:
        errormsg = (
            str(exc)
            + " <https://github.com/safe-global/safe-smart-account/blob/main/docs/error_codes.md>"
        )
        raise click.ClickException(errormsg) from exc
    except (EthereumClientException, SafeServiceException) as exc:
        raise click.ClickException(str(exc)) from exc

    with console.status("Waiting for transaction receipt..."):
        tx_receipt = safetx.ethereum_client.w3.eth.wait_for_transaction_receipt(
            w3txhash
        )
    timestamp = safetx.ethereum_client.w3.eth.get_block(
        tx_receipt["blockNumber"], full_transactions=False
    ).get("timestamp")

    console.line()
    print_web3_tx_receipt(timestamp, tx_receipt)


@main.command()
@click.argument("txfile", type=click.File("r"), required=False)
def hash(txfile: typing.BinaryIO | None) -> None:
    """Compute SafeTxHash of a SafeTx.

    TXFILE contains a SafeTx represented as an EIP-712 message, which can be
    created using the `build` command.
    """
    if not txfile:
        txfile = click.get_binary_stream("stdin")
    safetx_json = txfile.read()
    safetx_data = json.loads(safetx_json)
    safetx_hash = hash_eip712_data(safetx_data)
    console.print(safetx_hash.to_0x_hex())


@main.command()
@click.argument("address")
@option.rpc
def inspect(rpc: str, address: str):
    """Query Safe Account state."""
    checksum_addr = to_checksum_address(address)
    client = EthereumClient(URI(rpc))
    try:
        safeobj = Safe(checksum_addr, client)  # type: ignore[abstract]
        info = safeobj.retrieve_all_info()
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    # FIXME: batch the two requests so results are atomic
    block = client.w3.eth.block_number
    balance = client.w3.eth.get_balance(checksum_addr)
    console.line()
    print_kvtable(
        "Safe Account",
        f"Block {str(block)}",
        {
            "Safe Account": info.address,
            "Version": info.version,
            f"Owners({len(info.owners)})": ", ".join(info.owners),
            "Threshold": str(info.threshold),
            "Fallback Handler": info.fallback_handler,
            "Singleton": info.master_copy,
            "Guard": info.guard,
            "Modules": ", ".join(info.modules) if info.modules else "<none>",
        },
        {
            "Safe Nonce": str(info.nonce),
            "Balance": str(balance),
        },
    )
    console.line()


@main.command()
@option.authentication
@option.output_file
@click.argument("txfile", type=click.File("r"), required=False)
def sign(
    keyfile: str,
    output: typing.TextIO | None,
    txfile: typing.BinaryIO | None,
):
    """Sign a SafeTx.

    TXFILE contains a SafeTx represented as an EIP-712 message, which can be
    created using the `build` command.
    """
    if not txfile:
        txfile = click.get_binary_stream("stdin")
    safetx_json = txfile.read()
    safetx_data = json.loads(safetx_json)
    safetx_hash = hash_eip712_data(safetx_data)

    with click.open_file(keyfile) as kf:
        keydata = kf.read()
    password = getpass()
    privkey = Account.decrypt(keydata, password=password)
    account = Account.from_key(privkey)

    signedmsg = account.sign_typed_data(full_message=safetx_data)
    sigobj = SafeSignature.parse_signature(signedmsg.signature, safetx_hash)[0]
    signature = sigobj.export_signature()

    output_console = Console(file=output) if output else console
    output_console.print(signature.to_0x_hex())


if __name__ == "__main__":
    main()
