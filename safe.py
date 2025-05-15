#!/usr/bin/env -S uv run

import click
from decimal import Decimal
from eth_typing import URI
from eth_utils.address import to_checksum_address
from click_repl import register_repl

# from eth_typing import ChecksumAddress
from safe_eth.eth import EthereumClient
from safe_eth.safe import Safe, SafeOperationEnum

from safe_eth import safe
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
    StringConstraints,
    ValidationInfo,
    model_validator,
)
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


ChecksumAddress = Annotated[str, AfterValidator(validate_checksum_address)]
ChecksumAddress


class SafeTx(BaseModel):
    safe: ChecksumAddress
    chain_id: int
    nonce: int
    to: ChecksumAddress
    txvalue: str = Field(alias="value")
    data: str


# ┌──────────┐
# │ Commands │
# └──────────┘


@click.group()
def build():
    """Build a SafeTx for signing."""
    pass


@click.command(name="batch")
def build_batch():
    """Build a batch SafeTx to execute.

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
    """Build an ERC20 token transfer SafeTx."""
    raise NotImplementedError


build.add_command(build_erc20)


@click.command(name="tx")
@click.option("--safe", "-s", "safe_str", required=True, help="address of the Safe")
@click.option("--chain-id", type=int, required=True, help="chain ID")
@click.option("--nonce", "-n", type=int, required=True, help="nonce of the Safe")
@click.option("--to", "-t", "to_str", required=True, help="destination address")
@click.option("--value", "-v", "txvalue", default="0.0", help="tx value in decimals")
@click.option("--data", "-d", help="optional call data payload")
def build_tx(
    safe_str: str,
    nonce: int,
    to_str: str,
    chain_id: int,
    data: str,
    txvalue: str,
) -> None:
    """
    Build a SafeTx from scratch."""
    safe_addr = to_checksum_address(safe_str)
    to_addr = to_checksum_address(to_str)

    safetx = safe.SafeTx(
        ethereum_client=EthereumClient(),
        safe_address=safe_addr,
        to=to_addr,
        value=int(Decimal(txvalue) * 10**18),
        data=data,
        operation=SafeOperationEnum.CALL.value,
        safe_tx_gas=0,
        base_gas=0,
        gas_price=0,
        gas_token=None,
        refund_receiver=None,
        signatures=None,
        safe_nonce=nonce,
        safe_version=None,
        chain_id=chain_id,
    )
    print(safetx)


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
@click.option("--safe", "-s", "safe_str", required=True, help="address of the Safe")
@click.option("--rpc", "-r", required=True, help="JSON-RPC endpoint URI")
def inspect(safe_str: str, rpc: str):
    """Retrieve Safe info from chain."""
    safe_addr = to_checksum_address(safe_str)
    client = EthereumClient(URI(rpc))
    safe = Safe(safe_addr, client)  # pyright: ignore[reportAbstractUsage, reportArgumentType]
    print(safe.retrieve_all_info())


@click.command()
def manage():
    """Manage Safe Account."""
    raise NotImplementedError


@click.command()
def setup():
    """Manage local accounts."""
    raise NotImplementedError


@click.command()
def sign():
    """Sign a SafeTx."""
    raise NotImplementedError


# ┌──────┐
# │ main │
# └──────┘


@click.group(context_settings=CLICK_CONTEXT_SETTINGS)
def main():
    pass


main.add_command(build)
main.add_command(deploy)
main.add_command(exec)
main.add_command(inspect)
main.add_command(manage)
main.add_command(setup)
main.add_command(sign)


register_repl(main)

if __name__ == "__main__":
    main()


# ┌─────────┐
# │ Helpers │
# └─────────┘
