import dataclasses
from typing import Any, Callable, Iterable, Optional, TypeVar, Union

import click
from click import Command
from click_option_group import RequiredMutuallyExclusiveOptionGroup
from click_option_group._decorators import (
    _OptGroup,  # pyright: ignore[reportPrivateUsage]
)

from .constants import DEPLOY_SAFE_VERSION, SALT_NONCE_SENTINEL
from .validation import help_callback, verbose_callback

FC = TypeVar("FC", bound=Callable[..., Any] | Command)

Decorator = Callable[[FC], FC]

optgroup = _OptGroup()

# ┌─────────────┐
# │ Option Info │
# └─────────────┘


@dataclasses.dataclass(kw_only=True)
class OptionInfo:
    args: Iterable[str]
    help: str
    # defaults should match click.Option
    metavar: Optional[str] = None
    type: Optional[Union[click.types.ParamType, Any]] = None


def make_option(
    option: OptionInfo, cls: Decorator[Any] = click.option, **overrides: Any
) -> Decorator[FC]:
    info = dataclasses.asdict(option)
    info.update(**overrides)
    args = info.pop("args")
    return cls(*args, **info)


chain_id_option_info = OptionInfo(
    args=["--chain-id"],
    help="the chain ID to use",
    type=int,
    metavar="ID",
)

safe_version_option_info = OptionInfo(
    args=["--safe-version"],
    help="Safe version",
)


# ┌─────────┐
# │ Options │
# └─────────┘


def authentication(f: FC) -> FC:
    for option in reversed(
        [
            optgroup.group(
                "Authentication",
                cls=RequiredMutuallyExclusiveOptionGroup,
            ),
            optgroup.option(
                "--keyfile",
                "-k",
                type=click.Path(exists=True),
                help="local Ethereum keyfile",
            ),
            optgroup.option(
                "--trezor",
                metavar="ACCOUNT",
                help="Trezor BIP32 derivation path or account index",
            ),
        ]
    ):
        f = option(f)
    return f


def build_safetx(f: FC) -> FC:
    for option in reversed(
        [
            click.option("--value", default="0.0", help="tx value in decimals"),
            optgroup.group("Build offline"),
            make_option(chain_id_option_info, cls=optgroup.option),
            safe_version,
            optgroup.option("--safe-nonce", type=int, help="Safe nonce"),
            optgroup.group("Build online"),
            rpc(optgroup.option),
        ]
    ):
        f = option(f)
    return f


def common(f: FC) -> FC:
    for option in reversed(
        [
            click.option(
                "--verbose",
                "-v",
                is_flag=True,
                expose_value=False,
                is_eager=True,
                help="print informational messages",
                callback=verbose_callback,
            ),
        ]
    ):
        f = option(f)
    return f


# Reuse the same decorator for `safe deploy` and `safe precompute`.
def deployment(precompute: bool) -> Callable[[FC], FC]:
    def decorator(f: FC) -> FC:
        for option in reversed(
            [
                optgroup.group(
                    "Deployment settings",
                ),
                optgroup.option(
                    "--chain-specific",
                    is_flag=True,
                    default=False,
                    help="account address will depend on "
                    + ("Web3 chain ID" if not precompute else "--chain-id"),
                ),
                # In `safe deploy`, the `--chain-id` option is in the Web3
                # section, not here, so don't duplicate it here.
                make_option(
                    chain_id_option_info,
                    cls=optgroup.option,
                    help=chain_id_option_info.help + " (required for --chain-specific)",
                )
                if precompute
                else None,
                optgroup.option(
                    "--salt-nonce",
                    type=str,
                    metavar="BYTES32",
                    default=SALT_NONCE_SENTINEL,
                    help="nonce used to generate CREATE2 salt",
                ),
                optgroup.option(
                    "--without-events",
                    is_flag=True,
                    default=False,
                    help="use implementation that does not emit events",
                ),
                optgroup.option(
                    "--custom-singleton",
                    metavar="ADDRESS",
                    help=f"use a non-canonical Singleton {DEPLOY_SAFE_VERSION}",
                ),
                optgroup.option(
                    "--custom-proxy-factory",
                    metavar="ADDRESS",
                    help=f"use a non-canonical SafeProxyFactory {DEPLOY_SAFE_VERSION}",
                ),
                optgroup.group(
                    "Initialization settings",
                ),
                optgroup.option(
                    "--owner",
                    "owners",
                    required=True,
                    multiple=True,
                    metavar="ADDRESS",
                    type=str,
                    help="add an owner (repeat option to add more)",
                ),
                optgroup.option(
                    "--threshold",
                    type=int,
                    default=1,
                    help="number of required confirmations",
                ),
                optgroup.option(
                    "--fallback",
                    metavar="ADDRESS",
                    help="custom Fallback Handler address",
                ),
            ]
        ):
            if option is not None:
                f = option(f)
        return f

    return decorator


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


def rpc(
    decorator: Callable[..., Callable[[FC], FC]], required: bool = False
) -> Callable[[FC], FC]:
    return decorator(
        "--rpc",
        "-r",
        required=required,
        envvar="SAFE_RPC",
        metavar="URL",
        show_envvar=True,
        help="HTTP JSON-RPC endpoint",
    )


safe_address = click.option(
    "--safe",
    "safe_address",
    metavar="ADDRESS",
    required=True,
    help="Safe account address",
)

safe_version = make_option(safe_version_option_info, cls=optgroup.option)

sigfile = click.argument(
    "sigfiles",
    metavar="[SIGFILE]...",
    type=click.Path(exists=True),
    nargs=-1,
)


def web3tx(f: FC) -> FC:
    for option in reversed(
        [
            optgroup.group(
                "Web3 Transaction",
            ),
            optgroup.option(
                "--sign-only",
                is_flag=True,
                help="sign but do not broadcast transaction to the network",
            ),
        ]
    ):
        f = option(f)
    return f
