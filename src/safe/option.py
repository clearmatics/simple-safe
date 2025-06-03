import functools
from typing import Any, Callable, TypeVar, cast

import click
from click import Command
from click_option_group import (
    optgroup,
)

FC = TypeVar("FC", bound=Callable[..., Any] | Command)

account = click.option(
    "--account",
    "account",
    metavar="ADDRESS",
    required=True,
    help="Safe Account address",
)


# pyright: reportUntypedFunctionDecorator=information
# pyright: reportUnknownMemberType=information
def authentication(f: FC) -> FC:
    @optgroup.group(
        "Authentication",
    )
    @optgroup.option(
        "--keyfile",
        "-k",
        type=click.Path(exists=True),
        required=True,
        help="Ethereum Keyfile",
    )
    @functools.wraps(f)
    def wrapper(*args: object, **kwargs: object) -> object:
        f(*args, **kwargs)

    return cast(FC, wrapper)


rpc = click.option(
    "--rpc",
    "-r",
    required=True,
    help="HTTP JSON-RPC endpoint URI",
)


def web3tx(f: FC) -> FC:
    @rpc
    @functools.wraps(f)
    def wrapper(*args: object, **kwargs: object) -> object:
        f(*args, **kwargs)

    return cast(FC, wrapper)
