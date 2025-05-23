#!/usr/bin/env -S uv run --script

import json
import typing
from decimal import Decimal
from getpass import getpass
from typing import (
    Annotated,
    Optional,
)

import click
import eth_typing
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
from rich.table import Table
from safe_eth.eth import EthereumClient
from safe_eth.eth.exceptions import EthereumClientException
from safe_eth.safe import Safe, SafeOperationEnum, SafeTx
from safe_eth.safe.exceptions import SafeServiceException
from safe_eth.safe.safe_signature import SafeSignature
from safe_eth.safe.signatures import (
    signature_to_bytes,
)

from . import option

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


# ┌──────────┐
# │ Commands │
# └──────────┘


@click.group(context_settings=CLICK_CONTEXT_SETTINGS)
def main():
    """CLI for Safe Smart Accounts."""
    pass


@main.group()
def build():
    """Build a SafeTx for signing."""
    pass


@build.command(name="tx")
@option.safe
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
    safe: str,
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
        account=to_checksum_address(safe),
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


@main.command()
def deploy():
    """Deploy a new Safe Account."""
    raise NotImplementedError


@main.command()
@option.keyfile
@click.option(
    "--signature",
    "-g",
    "sigfiles",
    type=click.Path(exists=True),
    multiple=True,
    required=True,
    help="owner signature JSON",
)
@option.rpc
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
    # safetx
    if not txfile:
        txfile = click.get_binary_stream("stdin")
    json_data = txfile.read()
    client = EthereumClient(URI(rpc))
    safetx = SafeTxWrapper.model_validate_json(json_data)
    safetx_ = safetx.unwrap()
    safetxhash = safetx_.safe_tx_hash

    # keyfile
    with click.open_file(keyfile) as kf:
        keydata = kf.read()
    password = getpass()
    privkey = Account.decrypt(keydata, password=password)
    account = Account.from_key(privkey)

    # sigs
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

    # final safetx with signers
    safetx_ = safetx.unwrap(client, signatures)
    print(safetx_)

    # send
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
    table = _mktable()
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
    table = _mktable()
    table.add_row("SafeTxHash", hashstr)
    console = Console()
    console.print(table)


@main.command()
@option.safe
@option.rpc
def inspect(safe: str, rpc: str):
    """Retrieve Safe info from chain."""
    acc_addr = to_checksum_address(safe)
    client = EthereumClient(URI(rpc))
    try:
        safeobj = Safe(acc_addr, client)  # pyright: ignore[reportAbstractUsage, reportArgumentType]
        info = safeobj.retrieve_all_info()
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
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


@main.command()
@option.keyfile
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
    click.echo(_serialize(signature), file=output)


# ┌─────────┐
# │ Helpers │
# └─────────┘


def _serialize(model: BaseModel):
    return model.model_dump_json(indent=2)


def _mktable():
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column("Field", justify="right", style="bold", no_wrap=True)
    table.add_column("Value")
    return table


if __name__ == "__main__":
    main()
