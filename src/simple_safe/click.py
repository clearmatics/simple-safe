"""Custom Click command Command and Group with properly-formatted help text."""

from typing import Any, cast

import click
from click.decorators import HelpOption


# Match Click 8.1.8 implementation. Revise when Click is upgraded.
class CustomHelpOption(HelpOption):
    def __init__(
        self,
        **kwargs: Any,
    ) -> None:
        param_decls = (
            "-h",
            "--help",
        )

        kwargs.setdefault("is_flag", True)
        kwargs.setdefault("expose_value", False)
        kwargs.setdefault("is_eager", True)
        kwargs.setdefault("help", "show this message and exit")
        kwargs.setdefault("callback", self.show_help)

        return super().__init__(param_decls, **kwargs)

    @staticmethod
    def show_help(ctx: click.Context, param: click.Parameter, value: bool) -> None:
        """Callback that print the help page on ``<stdout>`` and exits."""
        if value and not ctx.resilient_parsing:
            click.echo(ctx.get_help(), color=ctx.color)
            ctx.exit()


class Command(click.Command):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    # Match Click 8.1.8 implementation. Revise when Click is upgraded.
    def get_help_option(self, ctx: click.Context) -> click.Option | None:
        if self._help_option is None:
            self._help_option = CustomHelpOption()
        return self._help_option


class Group(click.Group):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    def group(self, *args: Any, **kwargs: Any) -> click.Group:
        kwargs.setdefault("cls", Group)
        return cast(click.Group, super().group(*args, **kwargs))

    def command(self, *args: Any, **kwargs: Any) -> click.Command:
        kwargs.setdefault("cls", Command)
        return cast(click.Command, super().command(*args, **kwargs))

    # Match Click 8.1.8 implementation. Revise when Click is upgraded.
    def get_help_option(self, ctx: click.Context) -> click.Option | None:
        if self._help_option is None:
            self._help_option = CustomHelpOption()
        return self._help_option
