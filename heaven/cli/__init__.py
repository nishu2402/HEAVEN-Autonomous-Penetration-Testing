"""
HEAVEN — CLI subpackage
Defines the root `cli` Click group and wires all subcommand modules.

The previous monolithic `heaven/main.py` (1380 lines) is now a thin shim
that re-exports `cli` from this package. Each subcommand lives in its own
module here, registered via a `register(cli)` function.

If click is not installed, `cli` becomes a minimal fallback that points
the user at the install command — same behaviour as the old main.py.
"""

from __future__ import annotations

from typing import Optional

from heaven import __banner__, __version__
from heaven.config import get_config, reload_config
from heaven.utils.logger import get_logger, setup_logging

logger = get_logger("cli")


try:
    import click
    HAS_CLICK = True
except ImportError:
    HAS_CLICK = False


if HAS_CLICK:

    @click.group(invoke_without_command=True)
    @click.version_option(version=__version__, prog_name="HEAVEN")
    @click.option("--debug", is_flag=True, help="Enable debug logging")
    @click.option("--config-file", type=click.Path(), help="Path to .env config file")
    @click.pass_context
    def cli(ctx: click.Context, debug: bool, config_file: Optional[str]) -> None:
        """HEAVEN — Automated Vulnerability Scanner & Risk Triage Platform"""
        if config_file:
            try:
                from dotenv import load_dotenv
                load_dotenv(config_file)
            except ImportError:
                logger.warning("python-dotenv not installed — .env file ignored")
            reload_config()

        cfg = get_config()
        if debug:
            cfg.debug = True
            cfg.log_level = "DEBUG"

        setup_logging(level=cfg.log_level)

        from heaven.utils.platform_detect import configure_event_loop
        configure_event_loop()

        if ctx.invoked_subcommand is None:
            from heaven.cli._dashboard import show_dashboard
            show_dashboard()

    # Wire up every subcommand module
    from heaven.cli import (
        audit, autonomous, coverage, db, diff, engage, exploitdb, findings,
        info, knowledge, lateral, methodology, mitre, replay, sast, scan,
        server, tickets, train, watch,
    )
    audit.register(cli)
    autonomous.register(cli)
    coverage.register(cli)
    db.register(cli)
    diff.register(cli)
    engage.register(cli)
    exploitdb.register(cli)
    findings.register(cli)
    info.register(cli)
    knowledge.register(cli)
    lateral.register(cli)
    methodology.register(cli)
    mitre.register(cli)
    replay.register(cli)
    sast.register(cli)
    scan.register(cli)
    server.register(cli)
    tickets.register(cli)
    train.register(cli)
    watch.register(cli)

else:
    def cli() -> None:  # type: ignore[misc]
        """Minimal CLI fallback when click is not installed."""
        print(__banner__)
        print(f"HEAVEN v{__version__}")
        print("\nUsage: pip install click rich aiohttp && python -m heaven.main scan --help")
        print("\nAvailable commands: scan, info, serve, init-db, self-audit, mitre-report")
        print("Install click for full CLI: pip install click")


__all__ = ["cli", "HAS_CLICK"]
