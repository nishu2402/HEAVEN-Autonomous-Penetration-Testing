"""HEAVEN — `heaven info` command."""

from __future__ import annotations

import click

from heaven.utils.logger import print_banner


@click.command()
def info() -> None:
    """Display platform information and available tools."""
    print_banner()
    from heaven.utils.platform_detect import detect_platform, print_platform_info
    platform_info = detect_platform()
    print_platform_info(platform_info)


def register(cli: click.Group) -> None:
    cli.add_command(info)
