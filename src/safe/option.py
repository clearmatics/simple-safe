import functools
from typing import Any, Callable, TypeVar, cast

import click
from click import Command
from click_option_group import (
    RequiredAnyOptionGroup,
    optgroup,
)

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


safe = click.option(
    "--safe",
    "safe",
    metavar="ADDRESS",
    required=True,
    help="Safe Account address",
)


rpc = click.option(
    "--rpc",
    "-r",
    envvar="SAFE_RPC",
    metavar="URI",
    show_envvar=True,
    required=True,
    prompt="RPC URI",
    prompt_required=False,
    help="HTTP JSON-RPC endpoint",
)


def safetx(f: FC) -> FC:
    @click.option("--version", help="Safe Account version")
    @click.option("--chain", "chain_id", type=int, metavar="ID", help="Chain ID")
    @click.option("--safe-nonce", type=int, help="Safe nonce")
    @click.option(
        "--to", "to_str", metavar="ADDRESS", required=True, help="destination address"
    )
    @click.option("--value", "value_", default="0.0", help="tx value in decimals")
    @functools.wraps(f)
    def wrapper(*args: object, **kwargs: object) -> object:
        f(*args, **kwargs)

    return cast(FC, wrapper)


def safetx_custom(f: FC) -> FC:
    @safetx
    @click.option("--data", default="0x", help="call data payload")
    @functools.wraps(f)
    def wrapper(*args: object, **kwargs: object) -> object:
        f(*args, **kwargs)

    return cast(FC, wrapper)


def web3tx(f: FC) -> FC:
    @rpc
    @functools.wraps(f)
    def wrapper(*args: object, **kwargs: object) -> object:
        f(*args, **kwargs)

    return cast(FC, wrapper)
