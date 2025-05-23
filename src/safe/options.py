import click

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

# import functools
# from typing import Any, Callable, TypeVar, cast
# from click import Command
# FC = TypeVar("FC", bound=Callable[..., Any] | Command)
# def rpc(f: FC) -> FC:
#     @click.option("--rpc", "-r", required=True, help="HTTP JSON-RPC endpoint URI")
#     @functools.wraps(f)
#     def wrapper(*args: object, **kwargs: object) -> object:
#         f(*args, **kwargs)
#     return cast(FC, wrapper)
