from typing import Any, Optional

from .console import activate_logging

import click


def help_callback(
    ctx: click.Context, _: click.Option, value: Optional[bool]
) -> Optional[Any]:
    if value:
        click.echo(ctx.get_help())
        ctx.exit()
    return None


def verbose_callback(
    ctx: click.Context, opt: click.Option, value: Optional[bool]
) -> Optional[Any]:
    if value:
        activate_logging()
    return None
