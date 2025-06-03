#!/usr/bin/env -S uv run --script

import json
import random
import shutil
import typing
from decimal import Decimal
from getpass import getpass
from typing import (
    Annotated,
    Optional,
)

import click
import eth_typing
from click_option_group import (
    optgroup,
)
from eth_account import Account
from eth_typing import URI
from eth_utils.address import is_checksum_address, to_checksum_address
from hexbytes import HexBytes
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
)
from rich.console import Console
from safe_eth.eth import EthereumClient
from safe_eth.eth.contracts import (
    get_safe_V1_4_1_contract,
)
from safe_eth.eth.exceptions import EthereumClientException
from safe_eth.safe import ProxyFactory, Safe, SafeOperationEnum, SafeTx
from safe_eth.safe.exceptions import SafeServiceException
from safe_eth.safe.safe_signature import SafeSignature
from safe_eth.safe.signatures import (
    signature_to_bytes,
)
from web3.constants import ADDRESS_ZERO

from . import option
from .util import as_checksum, mktable, serialize

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
# │ Model │
# └───────┘


def validate_checksum_address(address: str) -> str:
    if not is_checksum_address(address):
        raise ValueError("Invalid EIP-55 checksum address.")
    return address


ChecksumAddress = Annotated[
    eth_typing.ChecksumAddress, AfterValidator(validate_checksum_address)
]


class Signature(BaseModel):
    safetx: str
    owner: ChecksumAddress
    signature: str


class SafeTxWrapper(BaseModel):
    account: ChecksumAddress
    version: str
    chain_id: int
    nonce: int
    to: ChecksumAddress
    txvalue: str = Field(alias="value")
    data: str

    model_config = ConfigDict(serialize_by_alias=True)

    def unwrap(
        self,
        client: Optional[EthereumClient] = None,
        signatures: Optional[bytes] = None,
    ) -> SafeTx:
        return SafeTx(
            ethereum_client=client if client else EthereumClient(),
            safe_address=to_checksum_address(self.account),
            to=to_checksum_address(self.to),
            value=int(Decimal(self.txvalue) * 10**18),
            data=HexBytes(self.data),
            operation=SafeOperationEnum.CALL.value,
            safe_tx_gas=0,
            base_gas=0,
            gas_price=0,
            gas_token=None,
            refund_receiver=None,
            signatures=signatures,
            safe_nonce=self.nonce,
            safe_version=self.version,
            chain_id=self.chain_id,
        )


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
    """CLI for Safe Accounts."""
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
@click.option("--version", required=True, help="Safe Account version")
@click.option("--chain", type=int, metavar="ID", required=True, help="ChainID")
@click.option("--nonce", type=int, required=True, help="nonce of the Safe Account")
@click.option(
    "--to", "to_str", metavar="ADDRESS", required=True, help="destination address"
)
@click.option("--value", "value_", default="0.0", help="tx value in decimals")
@click.option("--data", default="0x", help="optional call data payload")
@click.option(
    "--output", "-o", type=click.File(mode="w"), help="write JSON to output FILENAME"
)
def build_tx(
    account: str,
    version: str,
    chain_id: int,
    nonce: int,
    to_str: str,
    value_: str,
    data: str,
    output: typing.TextIO | None,
) -> None:
    """Build a custom SafeTx."""
    safetx = SafeTxWrapper(
        account=to_checksum_address(account),
        version=version,
        chain_id=chain_id,
        nonce=nonce,
        to=to_checksum_address(to_str),
        value=value_,
        data=data,
    )
    if not output:
        output = click.get_text_stream("stdout")
    click.echo(serialize(safetx), file=output)


@main.command()
# pyright: reportUntypedFunctionDecorator=information
# pyright: reportUnknownMemberType=information
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
    "--threshold", type=int, default=1, help="number of required confirmations"
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
    help="make account address repend on ChainID",
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
    --chain-specific option to include the ChainID in the CREATE2 salt derivation.

    The account uses the 'SafeL2.sol' implementation by default, which
    emits events. To use the gas-saving 'Safe.sol' variant instead, pass
    --without-events.
    """
    client = EthereumClient(URI(rpc))

    if salt_nonce == SALT_NONCE_SENTINEL:
        salt_nonce_int = random.randint(0, 2**256 - 1)  # uint256
    else:
        salt_nonce_int = int(salt_nonce)
    owner_addresses = [to_checksum_address(owner) for owner in owners]
    if threshold <= 0:
        raise click.ClickException(f"Invalid threshold '{threshold}'.")
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

    safe_contract = get_safe_V1_4_1_contract(client.w3, singleton_address)
    initializer = HexBytes(
        safe_contract.encode_abi(
            "setup",
            [
                owner_addresses,  # [alice]
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

    proxy_factory = ProxyFactory(
        address=proxy_factory_address,
        ethereum_client=client,
        version=DEPLOY_SAFE_VERSION,
    )  # type: ignore[abstract]

    predicted_address = proxy_factory.calculate_proxy_address(
        master_copy=singleton_address,
        initializer=initializer,
        salt_nonce=salt_nonce_int,
        chain_specific=chain_specific,
    )
    existing_code = client.w3.eth.get_code(predicted_address)
    if existing_code != b"":
        raise click.ClickException(
            f"Safe Account predicted address {predicted_address} already contains code."
        )

    table = mktable()
    table.add_row("Safe Account", f"{predicted_address} (predicted)")
    table.add_row("Version", DEPLOY_SAFE_VERSION)
    table.add_row(f"Owners({len(owner_addresses)})", ", ".join(owner_addresses))
    table.add_row("Threshold", str(threshold))
    table.add_row("Fallback Handler", fallback_address)
    table.add_row("Salt Nonce", str(salt_nonce_int))
    table.add_row("Singleton", singleton_address)
    table.add_row("Proxy Factory", proxy_factory_address)

    console = Console()
    console.print(table)
    click.confirm("Do you want to continue?", abort=True)

    with click.open_file(keyfile) as kf:
        keydata = kf.read()
    password = getpass()
    privkey = Account.decrypt(keydata, password=password)
    account = Account.from_key(privkey)

    tx = proxy_factory.deploy_proxy_contract_with_nonce(
        deployer_account=account,
        master_copy=singleton_address,
        initializer=initializer,
        salt_nonce=salt_nonce_int,
        gas=None,
        gas_price=None,
        nonce=None,
        chain_specific=chain_specific,
    )
    table = mktable()
    table.add_row("Safe Account", tx.contract_address)
    table.add_row("Web3 TxHash", HexBytes(tx.tx_hash).to_0x_hex())
    console.print(table)


@main.command()
@option.authentication
@click.option(
    "--signature",
    "-g",
    "sigfiles",
    type=click.Path(exists=True),
    multiple=True,
    required=True,
    help="owner signature JSON",
)
@option.web3tx
@click.argument("txfile", type=click.File("rb"), required=False)
def exec(
    keyfile: str,
    sigfiles: list[str],
    rpc: str,
    txfile: typing.BinaryIO | None,
):
    """Execute a signed SafeTx.

    The Web3 tx will be signed using the keyfile account and then sent to the
    RPC endpoint.

    Repeat the signature option to include all required signatures.
    """
    # SafeTx
    if not txfile:
        txfile = click.get_binary_stream("stdin")
    json_data = txfile.read()
    client = EthereumClient(URI(rpc))
    safetx = SafeTxWrapper.model_validate_json(json_data)
    safetx_ = safetx.unwrap()
    safetxhash = safetx_.safe_tx_hash

    # Keyfile
    with click.open_file(keyfile) as kf:
        keydata = kf.read()
    password = getpass()
    privkey = Account.decrypt(keydata, password=password)
    account = Account.from_key(privkey)

    # Sigs
    sigobjs: list[SafeSignature] = []
    for sigfile in sigfiles:
        with open(sigfile, "rb") as sf:
            sigjson = json.loads(sf.read())
        sigbytes = HexBytes(sigjson["signature"])
        siglist = SafeSignature.parse_signature(sigbytes, safetxhash)
        for sigobj in siglist:
            sigobjs.append(sigobj)
    signatures = SafeSignature.export_signatures(sigobjs)
    print(signatures.to_0x_hex())

    # Final SafeTx with signers
    safetx_ = safetx.unwrap(client, signatures)
    print(safetx_)

    # Send
    try:
        safetx_.call(
            tx_sender_address=account.address,
            block_identifier="latest",
        )
        w3txhash, _ = safetx_.execute(
            tx_sender_private_key=privkey.to_0x_hex(),
            block_identifier="latest",
        )
    except (EthereumClientException, SafeServiceException) as exc:
        raise click.ClickException(str(exc)) from exc
    table = mktable()
    table.add_row("Web3 TxHash", w3txhash.to_0x_hex())
    console = Console()
    console.print(table)


@main.command()
@click.argument("txfile", type=click.File("rb"), required=False)
def hash(txfile: typing.BinaryIO | None) -> None:
    """Compute SafeTxHash of a SafeTx.

    TXFILE must be a SafeTx in JSON format, which can be created using the
    'build' subcommand.
    """
    if not txfile:
        txfile = click.get_binary_stream("stdin")
    json_data = txfile.read()
    safetx = SafeTxWrapper.model_validate_json(json_data)
    hashstr = safetx.unwrap().safe_tx_hash.to_0x_hex()
    table = mktable()
    table.add_row("SafeTxHash", hashstr)
    console = Console()
    console.print(table)


@main.command()
@click.argument("address")
@option.rpc
def inspect(rpc: str, address: str):
    """Print the state of the Safe Account at ADDRESS."""
    acc_addr = to_checksum_address(address)
    client = EthereumClient(URI(rpc))
    try:
        safeobj = Safe(acc_addr, client)  # type: ignore[abstract]
        info = safeobj.retrieve_all_info()
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    table = mktable()
    table.add_row("Safe Account", info.address)
    table.add_row("Version", info.version)
    table.add_row("Nonce", str(info.nonce))
    table.add_row(f"Owners({len(info.owners)})", ", ".join(info.owners))
    table.add_row("Threshold", str(info.threshold))
    table.add_row("Fallback Handler", info.fallback_handler)
    table.add_row("Singleton", info.master_copy)
    table.add_row("Guard", info.guard)
    table.add_row("Modules", ", ".join(info.modules) if info.modules else "<none>")
    console = Console()
    console.print(table)


@main.command()
@option.authentication
@click.option(
    "--output", "-o", type=click.File(mode="w"), help="write JSON to output FILENAME"
)
@click.argument("txfile", type=click.File("rb"), required=False)
def sign(
    keyfile: str,
    output: typing.TextIO | None,
    txfile: typing.BinaryIO | None,
):
    """Sign a SafeTx.

    TXFILE must be a SafeTx in JSON format, which can be created using the
    'build' subcommand.
    """
    if not txfile:
        txfile = click.get_binary_stream("stdin")
    json_data = txfile.read()
    safetx = SafeTxWrapper.model_validate_json(json_data)
    with click.open_file(keyfile) as kf:
        keydata = kf.read()
    password = getpass()
    privkey = Account.decrypt(keydata, password=password)
    account = Account.from_key(privkey)
    hashbytes = safetx.unwrap().safe_tx_hash
    sigdict = account.unsafe_sign_hash(hashbytes)
    v, r, s = (sigdict[k] for k in ["v", "r", "s"])
    sigbytes = signature_to_bytes(v, r, s)
    sigobj = SafeSignature.parse_signature(sigbytes, hashbytes)[0]
    signature = sigobj.export_signature()
    # print(get_signing_address(sigbytes, v, r, s), account.address)
    signature = Signature(
        safetx=hashbytes.to_0x_hex(),
        owner=account.address,
        signature=signature.to_0x_hex(),
    )
    if not output:
        output = click.get_text_stream("stdout")
    click.echo(serialize(signature), file=output)


if __name__ == "__main__":
    main()
