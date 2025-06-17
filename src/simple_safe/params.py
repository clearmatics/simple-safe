import functools
from typing import Any, Callable, TypeVar, cast

import click
from click import Command
from click_option_group import (
    RequiredAnyOptionGroup,
    optgroup,
)

from .validation import help_callback, verbose_callback

FC = TypeVar("FC", bound=Callable[..., Any] | Command)


# pyright: reportUntypedFunctionDecorator=false
# pyright: reportUnknownMemberType=false
def authentication(f: FC) -> FC:
    @optgroup.group(
        "Authentication",
        cls=RequiredAnyOptionGroup,
    )
    @optgroup.option(
        "--keyfile",
        "-k",
        type=click.Path(exists=True),
        help="local Ethereum keyfile",
    )
    @functools.wraps(f)
    def wrapper(*args: object, **kwargs: object) -> object:
        f(*args, **kwargs)

    return cast(FC, wrapper)


def build_safetx(f: FC) -> FC:
    @click.option("--value", "value_", default="0.0", help="tx value in decimals")
    @optgroup.group("Build offline")
    @optgroup.option("--chain-id", "chain_id", type=int, metavar="ID", help="chain ID")
    @safe_version
    @optgroup.option("--safe-nonce", type=int, help="Safe nonce")
    @optgroup.group("Build online")
    @rpc(optgroup.option)
    @functools.wraps(f)
    def wrapper(*args: object, **kwargs: object) -> object:
        f(*args, **kwargs)

    return cast(FC, wrapper)


def common(f: FC) -> FC:
    @help
    @click.option(
        "--verbose",
        "-v",
        is_flag=True,
        expose_value=False,
        is_eager=True,
        help="print debug log messages",
        callback=verbose_callback,
    )
    @functools.wraps(f)
    def wrapper(*args: object, **kwargs: object) -> object:
        f(*args, **kwargs)

    return cast(FC, wrapper)


force = click.option(
    "--force",
    "-f",
    is_flag=True,
    default=False,
    help="skip confirmation prompts",
)

help = click.option(
    "--help",
    "-h",
    is_flag=True,
    expose_value=False,
    is_eager=True,  # ensures it's handled early
    help="show this message and exit",
    callback=help_callback,
)


output_file = click.option(
    "--output", "-o", type=click.File(mode="w"), help="write output to FILENAME"
)


def rpc(decorator: Any, required: bool = False) -> Callable[[FC], FC]:
    return decorator(
        "--rpc",
        "-r",
        required=required,
        envvar="SAFE_RPC",
        metavar="URI",
        show_envvar=True,
        help="HTTP JSON-RPC endpoint",
    )


safe = click.option(
    "--safe",
    "safe",
    metavar="ADDRESS",
    required=True,
    help="Safe account address",
)


# click_option_group is not well-typed
safe_version: Any = optgroup.option("--safe-version", help="Safe version")


sigfile = click.argument(
    "sigfiles",
    metavar="[SIGFILE]...",
    type=click.Path(exists=True),
    nargs=-1,
)


def web3tx(f: FC) -> FC:
    @functools.wraps(f)
    def wrapper(*args: object, **kwargs: object) -> object:
        f(*args, **kwargs)

    return cast(FC, wrapper)
