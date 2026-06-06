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
from heaven.cli._richconfig import apply_rich_click
from heaven.config import get_config, reload_config
from heaven.utils.logger import get_logger, setup_logging

logger = get_logger("cli")


# rich-click presentation layer (optional). apply_rich_click() must run BEFORE
# `import click` and before the subcommand modules are imported, so the patched
# — and far prettier — Command/Group/Option classes get picked up by every
# decorator. No-op + graceful fallback to plain Click when rich-click is absent.
# (The import itself lives in the top import block to satisfy E402.)
HAS_RICH_CLICK = apply_rich_click()

try:
    import click
    HAS_CLICK = True
except ImportError:
    HAS_CLICK = False


if HAS_CLICK:

    class HeavenGroup(click.Group):
        """Root command group that suggests close matches on a mistyped command.

        `heaven scna` → "Did you mean: heaven scan". Pure UX sugar; the
        command resolution itself is unchanged.
        """

        def resolve_command(self, ctx, args):  # type: ignore[override]
            try:
                return super().resolve_command(ctx, args)
            except click.exceptions.UsageError as exc:
                # rich-click ships its own "Did you mean?" suggestion, so only
                # add ours on the plain-Click fallback path (no duplication).
                if HAS_RICH_CLICK:
                    raise
                import difflib

                typed = args[0] if args else ""
                candidates = sorted(self.list_commands(ctx))
                matches = difflib.get_close_matches(typed, candidates, n=3, cutoff=0.45)
                if matches:
                    exc.message = (exc.message or "") + (
                        "\n\nDid you mean:\n"
                        + "\n".join(f"    heaven {m}" for m in matches)
                    )
                raise

    @click.group(cls=HeavenGroup, invoke_without_command=True)
    @click.version_option(version=__version__, prog_name="HEAVEN")
    @click.option("--debug", is_flag=True, help="Enable debug logging")
    @click.option("--config-file", type=click.Path(), help="Path to .env config file")
    @click.pass_context
    def cli(ctx: click.Context, debug: bool, config_file: Optional[str]) -> None:
        """HEAVEN — Automated Vulnerability Scanner & Risk Triage Platform"""
        # Always load environment from a .env file, so the flow
        #   heaven init  →  writes .env  →  heaven serve / heaven autonomous
        # "just works" without having to remember `--config-file` or `source .env`.
        # This is the wiring that connects the CLI to the rest of the stack:
        # the Web-UI admin password (HEAVEN_ADMIN_PASSWORD / HEAVEN_ADMIN_USERNAME),
        # the LLM keys (GEMINI/ANTHROPIC/OPENAI — without which `heaven autonomous`
        # silently falls back to the rule-based planner), and the NVD / Shodan /
        # SIEM / ticketing settings all live in .env.
        #
        # `.env` is the single source of truth and is loaded with override=True,
        # so it wins over any stale shell exports — editing `.env` (or the Web-UI
        # password change that writes back to it) always takes effect on the next
        # run, with no "I changed it but a leftover `export` shadowed it" gotcha.
        # To intentionally override a value for one run, edit `.env` or point at a
        # different file with `--config-file`.
        try:
            from dotenv import find_dotenv, load_dotenv
            target = config_file or find_dotenv(usecwd=True)
            if target:
                load_dotenv(target, override=True)
        except ImportError:
            if config_file:
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
        audit, autonomous, completion, coverage, db, diff, engage, exploitdb,
        findings, info, init as init_module, knowledge, lateral, methodology,
        mitre, replay, sast, scan, server, status as status_module, tickets,
        train, update as update_module, use as use_module, watch,
    )
    audit.register(cli)
    autonomous.register(cli)
    completion.register(cli)
    coverage.register(cli)
    db.register(cli)
    diff.register(cli)
    engage.register(cli)
    exploitdb.register(cli)
    findings.register(cli)
    info.register(cli)
    init_module.register(cli)
    knowledge.register(cli)
    lateral.register(cli)
    methodology.register(cli)
    mitre.register(cli)
    replay.register(cli)
    sast.register(cli)
    scan.register(cli)
    server.register(cli)
    status_module.register(cli)
    tickets.register(cli)
    train.register(cli)
    update_module.register(cli)
    use_module.register(cli)
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
