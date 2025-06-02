import functools
from typing import Any, Callable, TypeVar, cast

import click
from click import Command

FC = TypeVar("FC", bound=Callable[..., Any] | Command)

keyfile = click.option(
    "--keyfile",
    "-k",
    type=click.Path(exists=True),
    required=True,
    help="encrypted keyfile",
)

rpc = click.option(
    "--rpc",
    "-r",
    required=True,
    help="HTTP JSON-RPC endpoint URI",
)

safe = click.option(
    "--safe",
    "-s",
    "safe",
    required=True,
    help="Safe Account address",
)


def web3tx(f: FC) -> FC:
    @rpc
    @functools.wraps(f)
    def wrapper(*args: object, **kwargs: object) -> object:
        f(*args, **kwargs)

    return cast(FC, wrapper)
