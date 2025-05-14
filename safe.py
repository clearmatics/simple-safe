#!/usr/bin/env -S uv run

import click

from eth_typing import ChecksumAddress
from safe_eth.eth import EthereumClient
from safe_eth.safe import Safe
# from safe_eth.safe import SafeTx

ETHEREUM_NODE_URL = "https://sepolia.drpc.org"


def get_safe():
    safe_address = "0xb6e46b8Ad163C68d736Ec4199F43033B43379c70"
    ethereum_client = EthereumClient(ETHEREUM_NODE_URL)  # pyright: ignore[reportArgumentType]
    return Safe(safe_address, ethereum_client)  # pyright: ignore[reportAbstractUsage, reportArgumentType]


@click.group()
def main():
    print("hello")
    return
    # safe = get_safe()
    # safe_info = safe.retrieve_all_info()
    # print(safe_info)


@click.command()
@click.option("--safe", "-s", required=True, help="address of the Safe")
@click.option("--nonce", "-n", type=int, required=True, help="nonce of the Safe")
@click.option("--to", "-t", help="destination address")
@click.option(
    "--abi",
    "contract_abi_path",
    type=click.Path(exists=True),
    help="contract ABI file (for a contract tx)",
)
@click.option("--method", "-m", help="contract method to call (for a contract tx)")
@click.option("--value", "-v", help="value in ETH", default="0")
@click.argument("parameters", nargs=-1)
def create(safe: str, none: int):
    """
    Create a SafeTx from the options and parameters passed in.

    For a smart contract transaction, set the destination address to the contract address.
    """
    pass


main.add_command(create)


if __name__ == "__main__":
    main()
