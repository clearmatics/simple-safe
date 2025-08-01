import json
import logging
import shutil
import sys
import typing
from decimal import Decimal
from types import TracebackType
from typing import (
    TYPE_CHECKING,
    Optional,
    cast,
)

import click
from hexbytes import (
    HexBytes,
)
from rich.json import JSON
from rich.prompt import Confirm
from rich.traceback import Traceback

from . import params
from .abi import find_function, parse_args
from .auth import validate_authenticator
from .chain import FALLBACK_DECIMALS, fetch_chaindata
from .click import Group
from .console import (
    SAFE_DEBUG,
    activate_logging,
    console,
    get_output_console,
    make_status_logger,
    print_kvtable,
    print_safe_deploy_info,
    print_safetx,
    print_signatures,
    print_version,
)
from .params import optgroup
from .util import (
    compute_safe_address,
    format_native_value,
    hash_eip712_data,
    hexbytes_json_encoder,
    parse_signatures,
    reconstruct_safetx,
    silence_logging,
    to_checksum_address,
)
from .workflows import (
    SAFE_CONTRACT_VERSIONS,
    handle_function_match_failure,
    process_call_safetx,
    process_call_web3tx,
    validate_deploy_options,
    validate_safetx_options,
)

if TYPE_CHECKING:
    from eth_typing import URI

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
    from web3.exceptions import ContractLogicError

    if not SAFE_DEBUG:
        if exc_type is ContractLogicError:
            exc = cast(ContractLogicError, exc_value)
            console.print(
                f'[bold]{exc_type.__name__}[/bold]: "{exc.message}" ({exc.data})'
            )
        else:
            console.print(f"[bold]{exc_type.__name__}[/bold]: {exc_value}")
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
def main():
    """A simple Web3-native CLI for Safe accounts."""
    if SAFE_DEBUG:
        activate_logging()


# ┌──────────┐
# │ Commands │
# └──────────┘


@main.group()
def build():
    """Build a Safe transaction."""
    pass


@build.command(name="abi-call")
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
@params.safe_address
@params.output_file
@click.argument("identifier", metavar="FUNCTION")
@click.argument("str_args", metavar="[ARGUMENT]...", nargs=-1)
@params.common
def build_abi_call(
    abi_file: str,
    chain_id: Optional[int],
    contract_str: str,
    identifier: str,
    output: typing.TextIO | None,
    rpc: Optional[str],
    safe_address: str,
    safe_nonce: Optional[int],
    safe_version: Optional[str],
    str_args: list[str],
    value: str,
) -> None:
    """Build a contract call Safe transaction.

    FUNCTION is the function's name, 4-byte selector, or full signature.
    """
    with status("Building Safe transaction..."):
        validate_safetx_options(
            safe_version=safe_version, chain_id=chain_id, safe_nonce=safe_nonce, rpc=rpc
        )
        with open(abi_file, "r") as f:
            abi = json.load(f)
        from safe_eth.eth import EthereumClient

        client = EthereumClient(cast("URI", rpc))
        contract = client.w3.eth.contract(
            address=to_checksum_address(contract_str), abi=abi
        )
        process_call_safetx(
            client=client,
            contract=contract,
            fn_identifier=identifier,
            str_args=str_args,
            safe=to_checksum_address(safe),
            value=value,
            safe_version=safe_version,
            chain_id=chain_id,
            safe_nonce=safe_nonce,
            output=output,
        )


@build.command(name="custom")
@click.option(
    "--to", "to_str", metavar="ADDRESS", required=True, help="destination address"
)
@click.option("--data", default="0x", help="call data payload")
@params.build_safetx
@params.safe_address
@params.output_file
@params.common
def build_custom(
    chain_id: Optional[int],
    data: str,
    output: typing.TextIO | None,
    rpc: Optional[str],
    safe_address: str,
    safe_nonce: Optional[int],
    safe_version: Optional[str],
    to_str: str,
    value: str,
) -> None:
    """Build a custom Safe transaction."""
    with status("Building Safe transaction..."):
        validate_safetx_options(
            safe_version=safe_version, chain_id=chain_id, safe_nonce=safe_nonce, rpc=rpc
        )
        from safe_eth.eth import EthereumClient
        from safe_eth.safe import SafeOperationEnum, SafeTx

        client = EthereumClient(cast("URI", rpc))
        chaindata = fetch_chaindata(chain_id if chain_id else client.w3.eth.chain_id)
        decimals = chaindata.decimals if chaindata else FALLBACK_DECIMALS
        safetx = SafeTx(
            ethereum_client=client,
            safe_address=to_checksum_address(safe_address),
            to=to_checksum_address(to_str),
            value=int(Decimal(value).scaleb(decimals)),
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


@build.command(name="erc20-call")
@click.option(
    "--token",
    "token_str",
    metavar="ADDRESS",
    required=True,
    help="ERC-20 token address",
)
@params.build_safetx
@params.safe_address
@params.output_file
@click.argument("identifier", metavar="FUNCTION")
@click.argument("str_args", metavar="[ARGUMENT]...", nargs=-1)
@params.common
def build_erc20_call(
    chain_id: Optional[int],
    identifier: str,
    output: typing.TextIO | None,
    rpc: Optional[str],
    safe_address: str,
    safe_nonce: Optional[int],
    safe_version: Optional[str],
    str_args: list[str],
    token_str: str,
    value: str,
) -> None:
    """Build an ERC-20 token Safe transaction.

    FUNCTION is the function's name, 4-byte selector, or full signature.
    """
    with status("Building Safe transaction..."):
        from safe_eth.eth import EthereumClient
        from safe_eth.eth.contracts import get_erc20_contract

        validate_safetx_options(
            safe_version=safe_version, chain_id=chain_id, safe_nonce=safe_nonce, rpc=rpc
        )
        client = EthereumClient(cast("URI", rpc))
        token_address = to_checksum_address(token_str)
        ERC20 = get_erc20_contract(client.w3, address=token_address)
        process_call_safetx(
            client=client,
            contract=ERC20,
            fn_identifier=identifier,
            str_args=str_args,
            safe=to_checksum_address(safe),
            value=value,
            safe_version=safe_version,
            chain_id=chain_id,
            safe_nonce=safe_nonce,
            output=output,
        )


@build.command(name="safe-call")
@params.safe_address
@params.build_safetx
@params.output_file
@click.argument("identifier", metavar="FUNCTION")
@click.argument("str_args", metavar="[ARGUMENT]...", nargs=-1)
@params.common
def build_safe_call(
    chain_id: Optional[int],
    identifier: str,
    output: typing.TextIO | None,
    rpc: Optional[str],
    safe_address: str,
    safe_nonce: Optional[int],
    safe_version: Optional[str],
    str_args: list[str],
    value: str,
) -> None:
    """Build a Safe transaction to call the Safe.

    FUNCTION is the function's name, 4-byte selector, or full signature.
    """
    with status("Building Safe transaction..."):
        from safe_eth.eth import EthereumClient
        from safe_eth.safe import Safe
        from web3.contract.contract import Contract

        validate_safetx_options(
            safe_version=safe_version, chain_id=chain_id, safe_nonce=safe_nonce, rpc=rpc
        )
        client = EthereumClient(cast("URI", rpc))
        safe_address = to_checksum_address(safe_address)
        safe = Safe(safe_address, client)  # type: ignore[abstract]
        safe_contract = cast(
            Contract,
            safe.get_contract_fn()(client.w3, address=safe_address),  # pyright: ignore[reportUnknownMemberType, reportAttributeAccessIssue]
        )
        process_call_safetx(
            client=client,
            contract=safe_contract,
            fn_identifier=identifier,
            str_args=str_args,
            safe=safe_address,
            value=value,
            safe_version=safe_version,
            chain_id=chain_id,
            safe_nonce=safe_nonce,
            output=output,
        )


@main.command()
@params.deployment(precompute=False)
@params.web3tx
@params.authentication
@params.rpc(click.option, required=True)
@params.force
@params.output_file
@params.common
def deploy(
    chain_id: None,
    chain_specific: bool,
    custom_proxy_factory: Optional[str],
    custom_singleton: Optional[str],
    fallback: Optional[str],
    force: bool,
    keyfile: Optional[str],
    owners: list[str],
    output: typing.TextIO | None,
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
    with status("Preparing Safe deployment parameters..."):
        from web3 import Web3
        from web3.providers.auto import load_provider_from_uri

        w3 = Web3(load_provider_from_uri(cast("URI", rpc)))

        data = validate_deploy_options(
            chain_id=w3.eth.chain_id if chain_specific else None,
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
        from safe_eth.eth.contracts import (
            get_proxy_factory_V1_4_1_contract,
        )

        proxy_factory_contract = get_proxy_factory_V1_4_1_contract(
            w3, data.proxy_factory
        )
        proxy_factory_method = (
            proxy_factory_contract.functions.createProxyWithNonce
            if not data.chain_id
            else proxy_factory_contract.functions.createChainSpecificProxyWithNonce
        )
        deployment_call = proxy_factory_method(
            data.singleton, initializer, data.salt_nonce
        )
        existing_code = w3.eth.get_code(address)
        if existing_code != b"":
            raise click.ClickException(
                f"Safe account computed address {address} already contains code."
            )

    console.line()
    print_safe_deploy_info(data, address)
    console.line()
    if not force and not Confirm.ask("Prepare Web3 transaction?", default=False):
        raise click.Abort()

    auth = validate_authenticator(keyfile, trezor)
    process_call_web3tx(w3, deployment_call, auth, force, sign_only, output)


@main.command()
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
@params.common
def encode(
    abi_file: str,
    identifier: str,
    output: typing.TextIO | None,
    str_args: list[str],
) -> None:
    """Encode contract call data.

    FUNCTION is the function's name, 4-byte selector, or full signature.
    """
    with status("Building call data..."):
        with open(abi_file, "r") as f:
            abi = json.load(f)
        match, partials = find_function(abi, identifier)
        if match is None:
            handle_function_match_failure(identifier, partials)
        assert match is not None

        from web3 import Web3

        w3 = Web3()
        contract = w3.eth.contract(abi=abi)
        fn_obj = contract.get_function_by_selector(match.selector)
        args = parse_args(fn_obj.abi, str_args)
        calldata = contract.encode_abi(match.sig, args)
    output_console = get_output_console(output)
    output_console.print(calldata)


@main.command()
@params.web3tx
@params.authentication
@params.rpc(click.option, required=True)
@params.force
@click.argument("txfile", type=click.File("r"), required=True)
@params.sigfile
@params.output_file
@params.common
def exec(
    force: bool,
    keyfile: str,
    output: typing.TextIO | None,
    rpc: Optional[str],
    sigfiles: list[str],
    sign_only: bool,
    trezor: Optional[str],
    txfile: typing.TextIO,
):
    """Execute a signed Safe transaction.

    A SIGFILE must be a valid owner signature.
    """
    if not sigfiles:
        raise click.ClickException("Cannot execute SafeTx without signatures.")

    with status("Loading Safe transaction..."):
        from safe_eth.eth import EthereumClient
        from safe_eth.safe import Safe

        client = EthereumClient(cast("URI", rpc))
        safetxdata = reconstruct_safetx(client, txfile, version=None)
        safe = Safe(safetxdata.safetx.safe_address, safetxdata.safetx.ethereum_client)  # type: ignore[abstract]
        owners = safe.retrieve_owners()
        threshold = safe.retrieve_threshold()
        sigdata = parse_signatures(owners, safetxdata, sigfiles)

    with status("Retrieving chain data..."):
        chaindata = fetch_chaindata(safetxdata.safetx.chain_id)

    console.line()
    print_safetx(safetxdata, chaindata)
    console.line()
    print_signatures(sigdata, threshold)

    from safe_eth.safe.safe_signature import SafeSignature

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
        console.line()
        if not Confirm.ask("Prepare Web3 transaction?", default=False):
            raise click.Abort()

    auth = validate_authenticator(keyfile, trezor)
    process_call_web3tx(
        client.w3, safetxdata.safetx.w3_tx, auth, force, sign_only, output
    )


@main.command()
@click.argument("txfile", type=click.File("r"), required=True)
@params.common
def hash(txfile: typing.TextIO) -> None:
    """Compute hash of Safe transaction."""
    safetx_json = txfile.read()
    safetx_data = json.loads(safetx_json)
    safetx_hash = hash_eip712_data(safetx_data)
    output_console = get_output_console()
    output_console.print(safetx_hash.to_0x_hex())


@main.command()
@params.rpc(click.option, required=True)
@click.argument("address")
@params.common
def inspect(address: str, rpc: str):
    """Inspect a Safe account."""
    with status("Retrieving Safe account data..."):
        checksum_addr = to_checksum_address(address)
        from safe_eth.eth import EthereumClient
        from safe_eth.safe import Safe

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

    with status("Retrieving chain data..."):
        chaindata = fetch_chaindata(client.w3.eth.chain_id)

    console.line()

    from web3.types import Wei

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


@main.command()
@params.deployment(precompute=True)
@params.output_file
@params.common
def precompute(
    chain_id: Optional[int],
    chain_specific: bool,
    custom_proxy_factory: Optional[str],
    custom_singleton: Optional[str],
    fallback: Optional[str],
    output: typing.TextIO | None,
    owners: list[str],
    salt_nonce: str,
    threshold: int,
    without_events: bool,
):
    """Compute a Safe address offline."""
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
    print_safe_deploy_info(data, address)
    if not output:
        console.line()
    output_console = get_output_console(output)
    output_console.print(address)


@main.command()
@params.rpc(click.option, required=True)
@click.argument("txfile", type=click.File("r"), required=True)
@params.sigfile
@params.common
def preview(
    rpc: str,
    sigfiles: list[str],
    txfile: typing.TextIO,
):
    """Preview a Safe transaction.

    A SIGFILE must be a valid owner signature.
    """
    with status("Loading Safe transaction..."):
        from safe_eth.eth import EthereumClient

        client = EthereumClient(cast("URI", rpc))
        safetxdata = reconstruct_safetx(client, txfile, version=None)

    with status("Retrieving chain data..."):
        chaindata = fetch_chaindata(safetxdata.safetx.chain_id)

    console.line()
    print_safetx(safetxdata, chaindata)

    from safe_eth.safe import Safe

    if sigfiles:
        safe = Safe(safetxdata.safetx.safe_address, safetxdata.safetx.ethereum_client)  # type: ignore[abstract]
        owners = safe.retrieve_owners()
        threshold = safe.retrieve_threshold()
        sigdata = parse_signatures(owners, safetxdata, sigfiles)
        console.line()
        print_signatures(sigdata, threshold)


@main.command()
@optgroup.group("Sign offline")
@params.safe_version
@optgroup.group("Sign online")
@params.rpc(optgroup.option)
@params.authentication
@params.output_file
@params.force
@click.argument("txfile", type=click.File("r"), required=True)
@params.common
def sign(
    force: bool,
    keyfile: str,
    output: typing.TextIO | None,
    rpc: Optional[str],
    safe_version: Optional[str],
    trezor: Optional[str],
    txfile: typing.TextIO,
):
    """Sign a Safe transaction."""
    with status("Loading Safe transaction..."):
        if not rpc and not safe_version:
            raise click.ClickException(
                "Cannot determine Safe version and no RPC URL provided."
            )
        elif safe_version is not None and safe_version not in SAFE_CONTRACT_VERSIONS:
            raise click.ClickException(
                f"Invalid or unsupported Safe version {safe_version}."
            )

        from safe_eth.eth import EthereumClient

        client = EthereumClient(cast("URI", rpc))
        safetxdata = reconstruct_safetx(client, txfile, safe_version)

    with status("Retrieving chain data..."):
        chaindata = fetch_chaindata(safetxdata.safetx.chain_id)

    console.line()
    print_safetx(safetxdata, chaindata)

    console.line()
    if not force and not Confirm.ask("Sign Safe transaction?", default=False):
        raise click.Abort()

    from safe_eth.safe.safe_signature import SafeSignature

    auth = validate_authenticator(keyfile, trezor)
    sigbytes = auth.sign_typed_data(safetxdata.data)
    sigobj = SafeSignature.parse_signature(sigbytes, safetxdata.hash)[0]
    signature = sigobj.export_signature()

    output_console = get_output_console(output)
    output_console.print(signature.to_0x_hex())
