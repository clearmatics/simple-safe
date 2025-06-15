#!/usr/bin/env -S uv run --script

import json
import logging
import os
import secrets
import shutil
import sys
import typing
from decimal import Decimal
from getpass import getpass
from types import TracebackType
from typing import (
    Optional,
    cast,
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
from rich.json import JSON
from rich.prompt import Confirm
from rich.traceback import Traceback
from safe_eth.eth import EthereumClient
from safe_eth.eth.contracts import (
    get_erc20_contract,
    get_proxy_factory_V1_4_1_contract,
    get_safe_V1_4_1_contract,
)
from safe_eth.safe import Safe, SafeOperationEnum, SafeTx
from safe_eth.safe.safe_signature import SafeSignature
from web3 import Web3
from web3.constants import ADDRESS_ZERO
from web3.contract.contract import Contract
from web3.providers.auto import load_provider_from_uri

from . import params
from .abi import find_function, parse_args
from .console import (
    console,
    get_output_console,
    print_kvtable,
    print_safetx,
    print_signatures,
    print_version,
)
from .util import (
    as_checksum,
    hash_eip712_data,
    hexbytes_json_encoder,
    parse_signatures,
    reconstruct_safetx,
)
from .workflows import (
    SAFE_CONTRACT_VERSIONS,
    execute_calltx,
    handle_function_match_failure,
    prepare_calltx,
    validate_safetx_options,
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

# ┌───────┐
# │ Setup │
# └───────┘


# Silence logs from `safe_eth` library.
logging.getLogger("safe_eth").setLevel(logging.CRITICAL)


DEBUG = True if "SAFE_DEBUG" in os.environ else False


def handle_crash(
    exc_type: type[BaseException],
    exc_value: BaseException,
    exc_traceback: TracebackType | None,
) -> None:
    if not DEBUG:
        console.print(f"{exc_type.__name__}: {exc_value}")
    else:
        rich_traceback = Traceback.from_exception(
            exc_type,
            exc_value,
            exc_traceback,
            suppress=[click],
            show_locals=True,
        )
        console.print(rich_traceback)


sys.excepthook = handle_crash

# ┌──────┐
# │ Main │
# └──────┘


@click.group(
    context_settings=dict(
        show_default=True,
        max_content_width=shutil.get_terminal_size().columns,
        help_option_names=["-h", "--help"],
    ),
    add_help_option=False,
)
@click.option(
    "--version",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
    help="print version info and exit",
)
@params.help
def main():
    """A simple & decentralized CLI for Safe accounts."""
    pass


# ┌──────────┐
# │ Commands │
# └──────────┘


@main.group(add_help_option=False)
@params.help
def build():
    """Build a Safe transaction."""
    pass


@build.command(name="abi-call", add_help_option=False)
@click.option(
    "--abi",
    "abi_file",
    type=click.Path(exists=True),
    required=True,
    help="contract ABI in JSON format",
)
@click.option(
    "--contract",
    "contract_str",
    metavar="ADDRESS",
    required=True,
    help="contract call address",
)
@params.build_safetx
@params.safe
@params.output_file
@click.argument("identifier", metavar="FUNCTION")
@click.argument("str_args", metavar="[ARGUMENT]...", nargs=-1)
@params.help
def build_abi_call(
    abi_file: str,
    chain_id: Optional[int],
    contract_str: str,
    identifier: str,
    output: typing.TextIO | None,
    rpc: str,
    safe: str,
    safe_nonce: Optional[int],
    str_args: list[str],
    value_: str,
    safe_version: Optional[str],
) -> None:
    """Build a contract call Safe transaction from an ABI file.

    FUNCTION is the function's name, 4-byte selector, or full signature.
    """
    with console.status("Building Safe transaction..."):
        validate_safetx_options(
            safe_version=safe_version, chain_id=chain_id, safe_nonce=safe_nonce, rpc=rpc
        )
        with open(abi_file, "r") as f:
            abi = json.load(f)
        client = EthereumClient(URI(rpc))
        contract = client.w3.eth.contract(
            address=to_checksum_address(to_checksum_address(contract_str)), abi=abi
        )
        safetx = prepare_calltx(
            client=client,
            contract=contract,
            fn_identifier=identifier,
            str_args=str_args,
            safe=to_checksum_address(safe),
            value_=value_,
            safe_version=safe_version,
            chain_id=chain_id,
            safe_nonce=safe_nonce,
        )
    output_console = get_output_console(output)
    output_console.print(
        JSON.from_data(
            safetx.eip712_structured_data, default=hexbytes_json_encoder, indent=2
        )
    )


@build.command(name="custom", add_help_option=False)
@click.option(
    "--to", "to_str", metavar="ADDRESS", required=True, help="destination address"
)
@click.option("--data", default="0x", help="call data payload")
@params.build_safetx
@params.safe
@params.output_file
@params.help
def build_custom(
    chain_id: Optional[int],
    data: str,
    output: typing.TextIO | None,
    rpc: str,
    safe: str,
    safe_nonce: Optional[int],
    to_str: str,
    value_: str,
    safe_version: Optional[str],
) -> None:
    """Build a custom Safe transaction."""
    with console.status("Building Safe transaction..."):
        validate_safetx_options(
            safe_version=safe_version, chain_id=chain_id, safe_nonce=safe_nonce, rpc=rpc
        )
        client = EthereumClient(URI(rpc))
        safetx = SafeTx(
            ethereum_client=client,
            safe_address=to_checksum_address(safe),
            to=to_checksum_address(to_str),
            value=int(Decimal(value_) * 10**18),
            data=HexBytes(data),
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
    output_console = get_output_console(output)
    output_console.print(
        JSON.from_data(
            safetx.eip712_structured_data, default=hexbytes_json_encoder, indent=2
        )
    )


@build.command(name="erc20-call", add_help_option=False)
@click.option(
    "--token",
    "token_str",
    metavar="ADDRESS",
    required=True,
    help="ERC-20 token address",
)
@params.build_safetx
@params.safe
@params.output_file
@click.argument("identifier", metavar="FUNCTION")
@click.argument("str_args", metavar="[ARGUMENT]...", nargs=-1)
@params.help
def build_erc20_call(
    chain_id: Optional[int],
    identifier: str,
    output: typing.TextIO | None,
    rpc: str,
    safe: str,
    safe_nonce: Optional[int],
    str_args: list[str],
    token_str: str,
    value_: str,
    safe_version: Optional[str],
) -> None:
    """Build an ERC-20 contract call Safe transaction.

    FUNCTION is the function's name, 4-byte selector, or full signature.
    """
    with console.status("Building Safe transaction..."):
        validate_safetx_options(
            safe_version=safe_version, chain_id=chain_id, safe_nonce=safe_nonce, rpc=rpc
        )
        client = EthereumClient(URI(rpc))
        token_address = to_checksum_address(token_str)
        ERC20 = get_erc20_contract(client.w3, address=token_address)
        safetx = prepare_calltx(
            client=client,
            contract=ERC20,
            fn_identifier=identifier,
            str_args=str_args,
            safe=to_checksum_address(safe),
            value_=value_,
            safe_version=safe_version,
            chain_id=chain_id,
            safe_nonce=safe_nonce,
        )
    output_console = get_output_console(output)
    output_console.print(
        JSON.from_data(
            safetx.eip712_structured_data, default=hexbytes_json_encoder, indent=2
        )
    )


@build.command(name="safe-call", add_help_option=False)
@params.safe
@params.build_safetx
@params.output_file
@click.argument("identifier", metavar="FUNCTION")
@click.argument("str_args", metavar="[ARGUMENT]...", nargs=-1)
@params.help
def build_safe_call(
    chain_id: Optional[int],
    identifier: str,
    output: typing.TextIO | None,
    rpc: str,
    safe: str,
    safe_nonce: Optional[int],
    str_args: list[str],
    value_: str,
    safe_version: Optional[str],
) -> None:
    """Build a Safe transaction that calls the Safe account.

    FUNCTION is the function's name, 4-byte selector, or full signature.
    """
    with console.status("Building Safe transaction..."):
        validate_safetx_options(
            safe_version=safe_version, chain_id=chain_id, safe_nonce=safe_nonce, rpc=rpc
        )
        client = EthereumClient(URI(rpc))
        safe_address = to_checksum_address(safe)
        safe = Safe(safe_address, client)  # type: ignore[abstract]
        safe_contract = cast(
            Contract,
            safe.get_contract_fn()(client.w3, address=safe_address),  # pyright: ignore[reportAttributeAccessIssue]
        )
        safetx = prepare_calltx(
            client=client,
            contract=safe_contract,
            fn_identifier=identifier,
            str_args=str_args,
            safe=safe_address,
            value_=value_,
            safe_version=safe_version,
            chain_id=chain_id,
            safe_nonce=safe_nonce,
        )
    output_console = get_output_console(output)
    output_console.print(
        JSON.from_data(
            safetx.eip712_structured_data, default=hexbytes_json_encoder, indent=2
        ),
    )


@main.command(add_help_option=False)
# pyright: reportUntypedFunctionDecorator=false
# pyright: reportUnknownMemberType=false
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
    help="account address will depend on Chain ID",
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
@params.web3tx
@params.authentication
@params.rpc(click.option, required=True)
@params.force
@params.help
def deploy(
    chain_specific: bool,
    custom_proxy_factory: str,
    custom_singleton: str,
    fallback: str,
    force: bool,
    keyfile: str,
    owners: tuple[str],
    rpc: str,
    salt_nonce: str,
    threshold: int,
    without_events: bool,
):
    """Deploy a new Safe account.

    The Safe account is deployed with CREATE2, which makes it possible to
    own the same address on different chains. If this is not desirable, pass the
    --chain-specific option to include the Chain ID in the CREATE2 salt derivation.

    The account uses the 'SafeL2.sol' implementation by default, which
    emits events. To use the gas-saving 'Safe.sol' variant instead, pass
    --without-events.
    """
    with console.status("Preparing Safe deployment parameters..."):
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
        safe_contract = get_safe_V1_4_1_contract(w3)
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
        computed_address = deployment_call.call()

        existing_code = w3.eth.get_code(computed_address)
        if existing_code != b"":
            raise click.ClickException(
                f"Safe account computed address {computed_address} already contains code."
            )

    console.line()
    print_kvtable(
        "Safe Deployment Parameters",
        "",
        {
            "Safe Address": f"{computed_address} (computed)",
            "Version": DEPLOY_SAFE_VERSION,
            f"Owners({len(owner_addresses)})": ", ".join(owner_addresses),
            "Threshold": str(threshold),
            "Fallback Handler": fallback_address,
            "Salt Nonce": str(salt_nonce_int),
            "Singleton": singleton_address,
        },
        {
            "Proxy Factory": proxy_factory_address,
        },
    )
    console.line()
    if not force and not Confirm.ask("Prepare Web3 transaction?", default=False):
        raise click.Abort()

    console.line()
    execute_calltx(w3, deployment_call, keyfile, force)


@main.command(add_help_option=False)
@click.option(
    "--abi",
    "abi_file",
    type=click.Path(exists=True),
    required=True,
    help="contract ABI in JSON format",
)
@params.output_file
@click.argument("identifier", metavar="FUNCTION")
@click.argument("str_args", metavar="[ARGUMENT]...", nargs=-1)
@params.help
def encode(
    abi_file: str,
    identifier: str,
    output: typing.TextIO | None,
    str_args: list[str],
) -> None:
    """Encode contract call data.

    FUNCTION is the function's name, 4-byte selector, or full signature.
    """
    with console.status("Building call data..."):
        with open(abi_file, "r") as f:
            abi = json.load(f)
        match, partials = find_function(abi, identifier)
        if match is None:
            handle_function_match_failure(identifier, partials)
        assert match is not None

        w3 = Web3()
        contract = w3.eth.contract(abi=abi)
        fn_obj = contract.get_function_by_selector(match.selector)
        args = parse_args(fn_obj.abi, str_args)
        calldata = contract.encode_abi(match.sig, args)
    output_console = get_output_console(output)
    output_console.print(calldata)


@main.command(add_help_option=False)
@params.web3tx
@params.authentication
@params.rpc(click.option, required=True)
@params.force
@params.help
@click.argument("txfile", type=click.File("r"), required=True)
@params.sigfile
def exec(
    force: bool,
    keyfile: str,
    rpc: str,
    sigfiles: list[str],
    txfile: typing.TextIO,
):
    """Execute a signed Safe transaction.

    A SIGFILE must be a valid owner signature.
    """
    if not sigfiles:
        raise click.ClickException("Cannot execute SafeTx without signatures.")

    with console.status("Loading Safe transaction..."):
        client = EthereumClient(URI(rpc))
        safetxdata = reconstruct_safetx(client, txfile, version=None)
        safe = Safe(safetxdata.safetx.safe_address, safetxdata.safetx.ethereum_client)  # type: ignore[abstract]
        owners = safe.retrieve_owners()
        threshold = safe.retrieve_threshold()
        sigdata = parse_signatures(owners, safetxdata, sigfiles)

    console.line()
    print_safetx(safetxdata)
    console.line()
    print_signatures(sigdata, threshold)

    console.line()
    good: list[SafeSignature] = []
    for sd in sigdata:
        if not isinstance(sd.sig, SafeSignature):
            continue
        if sd.valid and sd.is_owner:
            good.append(sd.sig)
    if len(good) < len(sigdata):
        raise click.ClickException(
            "Cannot execute SafeTx with invalid or unknown signatures."
        )
    elif len(good) < threshold:
        raise click.ClickException("Insufficient valid owner signatures to execute.")

    safetxdata.safetx.signatures = SafeSignature.export_signatures(good)

    if not force:
        if not Confirm.ask("Prepare Web3 transaction?", default=False):
            raise click.Abort()

    console.line()
    execute_calltx(client.w3, safetxdata.safetx.w3_tx, keyfile, force)


@main.command(add_help_option=False)
@click.argument("txfile", type=click.File("r"), required=True)
@params.help
def hash(txfile: typing.TextIO) -> None:
    """Compute hash of Safe transaction."""
    safetx_json = txfile.read()
    safetx_data = json.loads(safetx_json)
    safetx_hash = hash_eip712_data(safetx_data)
    output_console = get_output_console()
    output_console.print(safetx_hash.to_0x_hex())


@main.command(add_help_option=False)
@params.rpc(click.option)
@click.argument("address")
@params.help
def inspect(address: str, rpc: str):
    """Inspect a Safe account."""
    with console.status("Retrieving Safe account data..."):
        checksum_addr = to_checksum_address(address)
        client = EthereumClient(URI(rpc))
        try:
            safeobj = Safe(checksum_addr, client)  # type: ignore[abstract]
            info = safeobj.retrieve_all_info()
        except Exception as exc:
            raise click.ClickException(str(exc)) from exc
        block = client.w3.eth.block_number
        balance = client.w3.eth.get_balance(checksum_addr, block_identifier=block)
    console.line()
    print_kvtable(
        "Safe account",
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
            "Balance": str(balance),
        },
    )
    console.line()


@main.command(add_help_option=False)
@params.rpc(click.option, required=True)
@params.help
@click.argument("txfile", type=click.File("r"), required=True)
@params.sigfile
def preview(
    rpc: str,
    sigfiles: list[str],
    txfile: typing.TextIO,
):
    """Preview a Safe transaction.

    A SIGFILE must be a valid owner signature.
    """
    with console.status("Loading Safe transaction..."):
        client = EthereumClient(URI(rpc))
        safetxdata = reconstruct_safetx(client, txfile, version=None)

    console.line()
    print_safetx(safetxdata)

    if sigfiles:
        safe = Safe(safetxdata.safetx.safe_address, safetxdata.safetx.ethereum_client)  # type: ignore[abstract]
        owners = safe.retrieve_owners()
        threshold = safe.retrieve_threshold()
        sigdata = parse_signatures(owners, safetxdata, sigfiles)
        console.line()
        print_signatures(sigdata, threshold)
    console.line()


@main.command(add_help_option=False)
@optgroup.group("Sign offline")
@params.safe_version
@optgroup.group("Sign online")
@params.rpc(optgroup.option)
@params.authentication
@params.output_file
@params.force
@click.argument("txfile", type=click.File("r"), required=True)
@params.help
def sign(
    force: bool,
    keyfile: str,
    output: typing.TextIO | None,
    rpc: str,
    txfile: typing.TextIO,
    safe_version: Optional[str],
):
    """Sign a Safe transaction."""
    with console.status("Loading Safe transaction..."):
        if not rpc and not safe_version:
            raise click.ClickException(
                "Cannot determine Safe version and no RPC URL provided."
            )
        elif safe_version is not None and safe_version not in SAFE_CONTRACT_VERSIONS:
            raise click.ClickException(
                f"Invalid or unsupported Safe version {safe_version}."
            )

        client = EthereumClient(URI(rpc))
        safetxdata = reconstruct_safetx(client, txfile, safe_version)

    console.line()
    print_safetx(safetxdata)
    console.line()

    if not force and not Confirm.ask("Sign Safe transaction?", default=False):
        raise click.Abort()

    with click.open_file(keyfile) as kf:
        keydata = kf.read()
    password = getpass(stream=sys.stderr)
    privkey = Account.decrypt(keydata, password=password)
    account = Account.from_key(privkey)

    signedmsg = account.sign_typed_data(full_message=safetxdata.payload)
    sigobj = SafeSignature.parse_signature(signedmsg.signature, safetxdata.hash)[0]
    signature = sigobj.export_signature()

    output_console = get_output_console(output)
    output_console.print(signature.to_0x_hex())


if __name__ == "__main__":
    main()
