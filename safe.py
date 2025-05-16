#!/usr/bin/env -S uv run

import typing
from eth_account import Account
from click import echo
from hexbytes import HexBytes
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt


# import rich_click as click
import click
from decimal import Decimal
from getpass import getpass
from eth_typing import URI
from eth_utils.address import to_checksum_address
from click_repl import register_repl
import sys

# from eth_typing import ChecksumAddress
from safe_eth.eth import EthereumClient
from safe_eth.safe import Safe, SafeOperationEnum

from safe_eth.safe import SafeTx as SafeTx_
from typing import (
    Annotated,
    Any,
    TypedDict,
    cast,
)

from eth_utils.address import is_checksum_address
from pydantic import (
    AfterValidator,
    AnyUrl,
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    HttpUrl,
    IPvAnyAddress,
    NonNegativeInt,
    StringConstraints,
    ValidationInfo,
    model_serializer,
    model_validator,
)
from safe_eth.safe.safe_signature import SafeSignatureEOA
from safe_eth.safe.signatures import signature_to_bytes
from typing_extensions import Self


ETHEREUM_NODE_URL = "https://sepolia.drpc.org"

# CLICK_CONTEXT_SETTINGS = {}
CLICK_CONTEXT_SETTINGS = dict(
    show_default=True,
    help_option_names=["-h", "--help"],
)

# ┌───────┐
# │ Model │
# └───────┘


def validate_checksum_address(address: str) -> str:
    if not is_checksum_address(address):
        raise ValueError("Invalid EIP-55 checksum address.")
    return address


import eth_typing

ChecksumAddress = Annotated[
    eth_typing.ChecksumAddress, AfterValidator(validate_checksum_address)
]
# ChecksumAddress = Annotated[str, AfterValidator(validate_checksum_address)]


class Signature(BaseModel):
    safetx: str
    owner: ChecksumAddress
    signature: str


class SafeTx(BaseModel):
    safe: ChecksumAddress
    version: str
    chain_id: int
    nonce: int
    to: ChecksumAddress
    txvalue: str = Field(alias="value")
    data: str

    model_config = ConfigDict(serialize_by_alias=True)

    def transform(self) -> SafeTx_:
        return SafeTx_(
            ethereum_client=EthereumClient(),
            safe_address=self.safe,
            to=self.to,
            value=int(Decimal(self.txvalue) * 10**18),
            data=self.data,
            operation=SafeOperationEnum.CALL.value,
            safe_tx_gas=0,
            base_gas=0,
            gas_price=0,
            gas_token=None,
            refund_receiver=None,
            signatures=None,
            safe_nonce=self.nonce,
            safe_version=self.version,
            chain_id=self.chain_id,
        )


# ┌──────────┐
# │ Commands │
# └──────────┘


@click.group()
def build():
    """Build a SafeTx for signing."""
    pass


@click.command(name="batch")
def build_batch():
    """Build a batch SafeTx.

    This uses the Safe implementation of MultiSend.
    """
    raise NotImplementedError


build.add_command(build_batch)


@click.command(name="call")
@click.option(
    "--abi",
    "abi_path",
    type=click.Path(exists=True),
    help="contract ABI file",
)
@click.option("--method", "-m", help="contract method to call")
@click.argument("parameters", nargs=-1)
def build_call(
    abi_path: str,
    method: str,
    parameters: list[str],
) -> None:
    """Build a smart contract call SafeTx."""
    raise NotImplementedError


build.add_command(build_call)


@click.command(name="erc20")
def build_erc20():
    """Build an ERC-20 transfer SafeTx."""
    raise NotImplementedError


build.add_command(build_erc20)


@click.command(name="tx")
@click.option("--safe", "-s", "safe_str", required=True, help="address of the Safe")
@click.option("--version", "-v", required=True, help="Safe Account version")
@click.option("--chain-id", "-c", type=int, required=True, help="chain ID")
@click.option("--nonce", "-n", type=int, required=True, help="nonce of the Safe")
@click.option("--to", "-t", "to_str", required=True, help="destination address")
@click.option("--value", "-v", "value_", default="0.0", help="tx value in decimals")
@click.option("--data", "-d", help="optional call data payload")
@click.option(
    "--output", "-o", type=click.File(mode="w"), help="write JSON to output FILENAME"
)
def build_tx(
    safe_str: str,
    version: str,
    chain_id: int,
    nonce: int,
    to_str: str,
    value_: str,
    data: str,
    output: typing.TextIO | None,
) -> None:
    """Build a custom SafeTx."""
    safetx = SafeTx(
        safe=to_checksum_address(safe_str),
        version=version,
        chain_id=chain_id,
        nonce=nonce,
        to=to_checksum_address(to_str),
        value=value_,
        data=data if data else "0x",
    )
    if not output:
        output = click.get_text_stream("stdout")
    click.echo(_serialize(safetx), file=output)


build.add_command(build_tx)


@click.command()
def deploy():
    """Deploy a new Safe Account."""
    raise NotImplementedError


@click.command()
def exec():
    """Execute a signed SafeTx."""
    raise NotImplementedError


@click.command()
@click.argument("txfile", type=click.File("rb"), required=False)
def hash(txfile: typing.BinaryIO | None) -> None:
    """Compute SafeTxHash of a SafeTx.

    TXFILE must be a SafeTx in JSON format, which can be created using the 'build' subcommand.
    """
    if not txfile:
        txfile = click.get_binary_stream("stdin")
    json_data = txfile.read()
    safetx = SafeTx.model_validate_json(json_data)
    hashstr = safetx.transform().safe_tx_hash.to_0x_hex()
    table = _mktable()
    table.add_row("SafeTxHash", hashstr)
    console = Console()
    console.print(table)


@click.command()
@click.option("--safe", "-s", "safe_str", required=True, help="address of the Safe")
@click.option("--rpc", "-r", required=True, help="JSON-RPC endpoint URI")
def inspect(safe_str: str, rpc: str):
    """Retrieve Safe info from chain."""
    safe_addr = to_checksum_address(safe_str)
    client = EthereumClient(URI(rpc))
    safe = Safe(safe_addr, client)  # pyright: ignore[reportAbstractUsage, reportArgumentType]
    info = safe.retrieve_all_info()
    table = _mktable()
    table.add_row("Safe Account", info.address)
    table.add_row("Version", info.version)
    table.add_row("Nonce", str(info.nonce))
    table.add_row("Owners", ", ".join(info.owners))
    table.add_row("Threshold", str(info.threshold))
    table.add_row("Master Copy", info.master_copy)
    table.add_row("Fallback Handler", info.fallback_handler)
    table.add_row("Guard", info.guard)
    table.add_row("Modules", ", ".join(info.modules) if info.modules else "(none)")
    console = Console()
    console.print(table)


@click.command()
def manage():
    """Manage Safe Account."""
    raise NotImplementedError


@click.command()
def setup():
    """Manage local accounts."""
    raise NotImplementedError


@click.command()
@click.option(
    "--keyfile",
    "-k",
    type=click.Path(exists=True),
    required=True,
    help="encrypted keyfile of signer",
)
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

    TXFILE must be a SafeTx in JSON format, which can be created using the 'build' subcommand.
    """
    if not txfile:
        txfile = click.get_binary_stream("stdin")
    json_data = txfile.read()
    safetx = SafeTx.model_validate_json(json_data)
    with click.open_file(keyfile) as kf:
        keydata = kf.read()
    password = getpass()
    privkey = Account.decrypt(keydata, password=password)
    account = Account.from_key(privkey)
    hashbytes = safetx.transform().safe_tx_hash
    sigdict = account.unsafe_sign_hash(hashbytes)
    sigbytes = HexBytes(signature_to_bytes(*[sigdict[k] for k in ["v", "r", "s"]]))
    signature = Signature(
        safetx=hashbytes.to_0x_hex(),
        owner=account.address,
        signature=sigbytes.to_0x_hex(),
    )
    if not output:
        output = click.get_text_stream("stdout")
    click.echo(_serialize(signature), file=output)


# ┌─────────┐
# │ Helpers │
# └─────────┘


def _serialize(model: BaseModel):
    return model.model_dump_json(indent=2)


def _mktable():
    table = Table(show_header=False, box=False, pad_edge=False)
    table.add_column("Field", justify="right", style="bold", no_wrap=True)
    table.add_column("Value")
    return table


# ┌──────┐
# │ main │
# └──────┘


@click.group(context_settings=CLICK_CONTEXT_SETTINGS)
def main():
    """An alternative command-line interface for Safe."""
    pass


main.add_command(build)
main.add_command(deploy)
main.add_command(exec)
main.add_command(hash)
main.add_command(inspect)
main.add_command(manage)
main.add_command(setup)
main.add_command(sign)


# register_repl(main)

if __name__ == "__main__":
    main()
