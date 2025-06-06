import functools
from typing import Any, Callable, TypeVar, cast

import click
from click import Command
from click_option_group import (
    RequiredAnyOptionGroup,
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
        help="local Ethereum Keyfile",
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
    help="execute without confirmation prompts",
)

output_file = click.option(
    "--output", "-o", type=click.File(mode="w"), help="write output to FILENAME"
)


rpc = click.option(
    "--rpc",
    "-r",
    envvar="SAFE_RPC",
    metavar="URI",
    show_envvar=True,
    required=True,
    prompt="RPC",
    prompt_required=False,
    help="HTTP JSON-RPC endpoint",
)


def web3tx(f: FC) -> FC:
    @rpc
    @functools.wraps(f)
    def wrapper(*args: object, **kwargs: object) -> object:
        f(*args, **kwargs)

    return cast(FC, wrapper)
