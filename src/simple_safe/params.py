import functools
from typing import Any, Callable, TypeVar

import click
from click import Command
from click_option_group import (
    RequiredAnyOptionGroup,
    optgroup,
)

from .constants import DEPLOY_SAFE_VERSION, SALT_NONCE_SENTINEL
from .validation import help_callback, verbose_callback

FC = TypeVar("FC", bound=Callable[..., Any] | Command)
Decorator = Callable[[FC], Any]


# pyright: reportUntypedFunctionDecorator=false
# pyright: reportUnknownMemberType=false
def authentication(f: FC) -> Decorator[FC]:
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
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        f(*args, **kwargs)

    return wrapper


def build_safetx(f: FC) -> Decorator[FC]:
    @click.option("--value", default="0.0", help="tx value in decimals")
    @optgroup.group("Build offline")
    @optgroup.option("--chain-id", "chain_id", type=int, metavar="ID", help="chain ID")
    @safe_version
    @optgroup.option("--safe-nonce", type=int, help="Safe nonce")
    @optgroup.group("Build online")
    @rpc(optgroup.option)
    @functools.wraps(f)
    def wrapper(*args: object, **kwargs: object) -> object:
        f(*args, **kwargs)

    return wrapper


def common(f: FC) -> Decorator[FC]:
    @help
    @click.option(
        "--verbose",
        "-v",
        is_flag=True,
        expose_value=False,
        is_eager=True,
        help="print informational messages",
        callback=verbose_callback,
    )
    @functools.wraps(f)
    def wrapper(*args: object, **kwargs: object) -> object:
        f(*args, **kwargs)

    return wrapper


def deployment(offline: bool) -> Callable[[FC], Decorator[FC]]:
    def outer(f: FC) -> Decorator[FC]:
        @optgroup.group(
            "Deployment settings",
        )
        @optgroup.option(
            "--chain-specific",
            is_flag=True,
            default=False,
            hidden=offline,
            help="account address based on RPC node Chain ID",
        )
        @optgroup.option(
            "--chain-id",
            type=int,
            hidden=not offline,
            help="Chain ID (required for chain-specific address)",
        )
        @optgroup.option(
            "--salt-nonce",
            type=str,
            metavar="BYTES32",
            default=SALT_NONCE_SENTINEL,
            help="nonce used to generate CREATE2 salt",
        )
        @optgroup.option(
            "--without-events",
            is_flag=True,
            default=False,
            help="use implementation that does not emit events",
        )
        @optgroup.option(
            "--custom-singleton",
            metavar="ADDRESS",
            help=f"use a non-canonical Singleton {DEPLOY_SAFE_VERSION}",
        )
        @optgroup.option(
            "--custom-proxy-factory",
            metavar="ADDRESS",
            help=f"use a non-canonical SafeProxyFactory {DEPLOY_SAFE_VERSION}",
        )
        @optgroup.group(
            "Initialization settings",
        )
        @optgroup.option(
            "--owner",
            "owners",
            required=True,
            multiple=True,
            metavar="ADDRESS",
            type=str,
            help="add an owner (repeat option to add more)",
        )
        @optgroup.option(
            "--threshold",
            type=int,
            default=1,
            help="number of required confirmations",
        )
        @optgroup.option(
            "--fallback",
            metavar="ADDRESS",
            help="custom Fallback Handler address",
        )
        @functools.wraps(f)
        def wrapper(*args: object, **kwargs: object) -> object:
            f(*args, **kwargs)

        return wrapper

    return outer


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
safe_version: Any = optgroup.option("--safe-version", help="Safe version")  # pyright: ignore[reportUnknownVariableType]


sigfile = click.argument(
    "sigfiles",
    metavar="[SIGFILE]...",
    type=click.Path(exists=True),
    nargs=-1,
)


def web3tx(f: FC) -> Decorator[FC]:
    @functools.wraps(f)
    def wrapper(*args: object, **kwargs: object) -> object:
        f(*args, **kwargs)

    return wrapper
