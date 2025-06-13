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


def build_safetx(f: FC) -> FC:
    @click.option("--value", "value_", default="0.0", help="tx value in decimals")
    @optgroup.group("Build offline")
    @optgroup.option("--chain", "chain_id", type=int, metavar="ID", help="chain ID")
    @optgroup.option("--version", help="Safe version")
    @optgroup.option("--safe-nonce", type=int, help="Safe nonce")
    @optgroup.group("Build online")
    @rpc(optgroup.option)
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
    help="Safe Account address",
)


signature = click.option(
    "--sigfile",
    "-g",
    "sigfiles",
    type=click.Path(exists=True),
    multiple=True,
    help="owner signature file",
)


def web3tx(f: FC) -> FC:
    @functools.wraps(f)
    def wrapper(*args: object, **kwargs: object) -> object:
        f(*args, **kwargs)

    return cast(FC, wrapper)
