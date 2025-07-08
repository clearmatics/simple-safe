"""Custom Click command Command and Group with properly-formatted help text."""

from typing import Any, Callable, cast
import click
from click.decorators import FC


def help_option(*param_decls: str, **kwargs: Any) -> Callable[[FC], FC]:
    def show_help(ctx: click.Context, param: click.Parameter, value: bool) -> None:
        """Callback that print the help page on ``<stdout>`` and exits."""
        if value and not ctx.resilient_parsing:
            click.echo(ctx.get_help(), color=ctx.color)
            ctx.exit()

    if not param_decls:
        param_decls = ("--help",)

    kwargs.setdefault("is_flag", True)
    kwargs.setdefault("expose_value", False)
    kwargs.setdefault("is_eager", True)
    kwargs.setdefault("help", "show this message and exit")
    kwargs.setdefault("callback", show_help)

    return click.option(*param_decls, **kwargs)


class Command(click.Command):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    def get_help_option(self, ctx: click.Context) -> click.Option | None:
        help_option_names = self.get_help_option_names(ctx)

        if self._help_option is None:  # pyright: ignore[reportUnnecessaryComparison]
            # Apply help_option decorator and pop resulting option
            help_option(*help_option_names)(self)
            self._help_option = self.params.pop()
        return self._help_option  # pyright: ignore[reportReturnType]


class Group(click.Group):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    def group(self, *args: Any, **kwargs: Any) -> click.Group:
        kwargs.setdefault("cls", Group)
        return cast(click.Group, super().group(*args, **kwargs))

    def command(self, *args: Any, **kwargs: Any) -> click.Command:
        kwargs.setdefault("cls", Command)
        return cast(click.Command, super().command(*args, **kwargs))

    def get_help_option(self, ctx: click.Context) -> click.Option | None:
        help_option_names = self.get_help_option_names(ctx)

        if self._help_option is None:  # pyright: ignore[reportUnnecessaryComparison]
            # Apply help_option decorator and pop resulting option
            help_option(*help_option_names)(self)
            self._help_option = self.params.pop()
        return self._help_option  # pyright: ignore[reportReturnType]
