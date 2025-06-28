from typing import Any, Optional

import click

from .console import SAFE_DEBUG, activate_logging


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
    if value and not SAFE_DEBUG:
        activate_logging()
    return None
