"""
HEAVEN — CLI dashboard
Renders the branded landing screen shown when `heaven` is invoked with no
subcommand. Uses Rich if available, falls back to plain text.
"""

from __future__ import annotations

from heaven import __version__
from heaven.cli._helpers import check_module_health
from heaven.utils.logger import HAS_RICH

_BANNER = r"""
  ██╗  ██╗███████╗ █████╗ ██╗   ██╗███████╗███╗   ██╗
  ██║  ██║██╔════╝██╔══██╗██║   ██║██╔════╝████╗  ██║
  ███████║█████╗  ███████║██║   ██║█████╗  ██╔██╗ ██║
  ██╔══██║██╔══╝  ██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║
  ██║  ██║███████╗██║  ██║ ╚████╔╝ ███████╗██║ ╚████║
  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝
"""

_CMDS: list[tuple[str, str, str]] = [
    ("heaven scan -t <ip>",        "Network & service scan",         "--i-have-authorization"),
    ("heaven scan -u <url>",        "Web application scan",           "--api-scan --i-have-authorization"),
    ("heaven scan -m web",          "Web-only mode",                  "-u https://target.com -m web"),
    ("heaven schedule <mins>",      "Continuous monitoring",          "60 -t 10.0.0.1 --i-have-authorization"),
    ("heaven engage init <name>",   "Create pentest engagement",      "--client 'Acme Corp'"),
    ("heaven scope add <target>",   "Add target to scope",            "10.0.0.0/24 --kind cidr"),
    ("heaven findings",             "List findings",                  "--severity high"),
    ("heaven export -o report.md",  "Export findings report",         "--format markdown"),
    ("heaven kill-chain",           "Cyber Kill Chain coverage",      "--engagement <name>"),
    ("heaven report -o out.html",   "Compliance HTML report",         "--framework OWASP_TOP10"),
    ("heaven serve",                "Start API + Command Centre UI",  "--host 127.0.0.1 --port 8443"),
    ("heaven self-audit",           "Security self-audit",            "--output audit.json"),
    ("heaven info",                 "Platform & tool status",         ""),
]


def show_dashboard() -> None:
    """Print branded HEAVEN dashboard when invoked without a subcommand."""
    if HAS_RICH:
        from heaven.utils.logger import console
        if console:
            from rich.panel import Panel
            from rich.table import Table
            from rich import box as rich_box

            console.print(f"[bold cyan]{_BANNER}[/bold cyan]")
            console.print(
                f"  [bold white]v{__version__}[/bold white]  "
                "[dim]Autonomous Penetration Testing Platform[/dim]\n"
            )

            health = check_module_health()
            htable = Table(box=rich_box.SIMPLE, show_header=False, padding=(0, 2))
            htable.add_column(width=24)
            htable.add_column(width=50)
            for name, status in health.items():
                ok = status == "OK"
                icon = "[bold green]✓[/bold green]" if ok else "[yellow]⚠[/yellow]"
                sdisplay = "[green]ready[/green]" if ok else f"[yellow]{status[:46]}[/yellow]"
                htable.add_row(f"{icon}  {name}", sdisplay)
            console.print(Panel(htable,
                                title="[bold cyan] Module Status [/bold cyan]",
                                border_style="cyan", padding=(0, 1)))

            ctable = Table(box=rich_box.SIMPLE, show_header=True,
                           header_style="bold cyan", padding=(0, 2))
            ctable.add_column("Command",      width=30, style="bold cyan", no_wrap=True)
            ctable.add_column("Description",  width=32)
            ctable.add_column("Example Flags", width=42, style="dim")
            for cmd, desc, ex in _CMDS:
                ctable.add_row(cmd, desc, ex)
            console.print(Panel(ctable,
                                title="[bold cyan] Available Commands [/bold cyan]",
                                border_style="cyan", padding=(0, 1)))

            console.print(
                "  [dim]Run [/dim][cyan]heaven <command> --help[/cyan]"
                "[dim] for full options.  "
                "Always add [/dim][cyan]--i-have-authorization[/cyan]"
                "[dim] to confirm written permission before scanning.[/dim]\n"
            )
            return

    # Plain fallback when Rich is not installed
    print(_BANNER)
    print(f"  HEAVEN v{__version__} — Autonomous Penetration Testing Platform\n")
    health = check_module_health()
    print("  Module Status:")
    for name, status in health.items():
        icon = "OK" if status == "OK" else "!!"
        print(f"    [{icon}] {name}")
    print("\n  Commands:")
    for cmd, desc, _ in _CMDS[:8]:
        print(f"    {cmd:<34}  {desc}")
    print("\n  Run 'heaven <command> --help' for options.\n")
