"""HEAVEN — `egress` command: route scanning traffic through TOR / VPN / WireGuard.

The dashboard and API stay local; only the outbound *scanning* traffic is pushed
through the configured anonymity path. Legitimate OPSEC for an **authorized**
engagement — every scan still requires explicit authorization.

    heaven egress status      # show the configured mode + tool availability
    heaven egress confirm     # leak check: what IP does the target actually see?
    heaven egress up          # raise the WireGuard tunnel
    heaven egress down        # drop the WireGuard tunnel
    heaven egress set --mode tor
    heaven egress set --mode wireguard --wg-config /etc/wireguard/wg0.conf

Config is stored in the shared ``.env`` (same source the web Settings page and
``heaven config`` use), so a value set here is live everywhere.
"""

from __future__ import annotations

import asyncio

import click

from heaven.cli._helpers import _print, emit_json, json_output


def _fmt_bool(v: bool) -> str:
    return "[green]yes[/green]" if v else "[dim]no[/dim]"


def _render_status(snap: dict) -> None:
    mode = snap.get("mode", "off")
    armed = snap.get("armed")
    _print("\n[bold]Egress[/bold]  [dim] · the dashboard stays local; only scan "
           "traffic is routed[/dim]")
    colour = "green" if armed else "dim"
    _print(f"  Mode        [{colour}]{mode}[/{colour}]"
           + ("" if armed else "  [dim](traffic exits directly)[/dim]"))
    if snap.get("proxy_url"):
        _print(f"  Proxy       {snap['proxy_url']}")
    if snap.get("wg_config"):
        _print(f"  WG config   {snap['wg_config']}")
    if snap.get("wg_interface"):
        _print(f"  WG iface    {snap['wg_interface']}")
    ks = snap.get("killswitch")
    _print(f"  Kill-switch {'[green]on[/green]' if ks else '[yellow]off[/yellow]'}"
           + ("  [dim](scan aborts if the egress isn't carrying traffic)[/dim]" if ks
              else "  [dim](direct fallback allowed)[/dim]"))
    if snap.get("error"):
        _print(f"  [yellow]⚠ {snap['error']}[/yellow]")
    if snap.get("mode") in ("socks5", "tor"):
        _print("  [dim]Note: SOCKS/Tor routes nuclei, nmap (via proxychains) and "
               "in-process HTTP checks (built-in SOCKS5 — no extra install). Raw "
               "SYN/UDP scans and authenticated SOCKS proxies need WireGuard.[/dim]")
    tools = snap.get("tools", {})
    _print("\n  [bold]Tools[/bold]")
    for name in ("wg", "wg-quick", "proxychains", "curl", "tor"):
        _print(f"    {name:<12} {_fmt_bool(bool(tools.get(name)))}")
    tun = snap.get("tunnel")
    if tun:
        up = tun.get("up")
        _print(f"\n  [bold]Tunnel[/bold]   {'[green]up[/green]' if up else '[dim]down[/dim]'}"
               + (f"  iface={tun.get('interface')}  peers={tun.get('peers')}"
                  f"  endpoint={tun.get('endpoint') or '?'}" if up else ""))


def _render_confirm(res: dict) -> None:
    ok = res.get("ok")
    icon = "[green]✓[/green]" if ok else "[red]✗[/red]"
    _print(f"\n{icon} Egress [bold]{res.get('mode')}[/bold] · {res.get('detail')}")
    _print(f"  Apparent public IP : {res.get('public_ip') or '[dim]unknown[/dim]'}")
    _print(f"  Direct baseline IP : {res.get('baseline_ip') or '[dim]unknown[/dim]'}")
    _print(f"  Routed via         : {res.get('via')}")
    if res.get("mode") not in ("off", None) and not res.get("changed"):
        _print("  [yellow]⚠ exit IP did not change vs the direct baseline ·  "
               "traffic may NOT be anonymised.[/yellow]")


def register(cli: click.Group) -> None:
    @cli.group()
    def egress() -> None:
        """Route scan traffic through TOR / VPN / WireGuard (dashboard stays local)."""

    @egress.command("status")
    def status_cmd() -> None:
        """Show the configured egress mode and tool availability."""
        from heaven.net import egress as eg
        snap = eg.status()
        if json_output():
            emit_json(snap)
            return
        _render_status(snap)

    @egress.command("confirm")
    def confirm_cmd() -> None:
        """Leak check: what public IP does the target actually see?"""
        from heaven.net import egress as eg
        res = asyncio.run(eg.confirm_egress(timeout=12.0))
        if json_output():
            emit_json(res)
            return
        _render_confirm(res)

    @egress.command("up")
    def up_cmd() -> None:
        """Raise the WireGuard tunnel (needs HEAVEN_WG_CONFIG + root)."""
        from heaven.net import egress as eg
        res = eg.tunnel_up()
        if json_output():
            emit_json(res)
            return
        if res.get("ok"):
            _print("[green]✓[/green] tunnel up"
                   + (f" ({res.get('interface')})" if res.get("interface") else "")
                   + (" — already up" if res.get("already_up") else ""))
        else:
            _print(f"[red]✗[/red] {res.get('error')}")

    @egress.command("down")
    def down_cmd() -> None:
        """Drop the WireGuard tunnel."""
        from heaven.net import egress as eg
        res = eg.tunnel_down()
        if json_output():
            emit_json(res)
            return
        _print("[green]✓[/green] tunnel down" if res.get("ok")
               else f"[red]✗[/red] {res.get('error')}")

    @egress.command("set")
    @click.option("--mode", type=click.Choice(["off", "http", "socks5", "tor", "wireguard"]),
                  help="Egress mode.")
    @click.option("--proxy", "proxy_url", help="Proxy URL for http/socks5 modes.")
    @click.option("--tor-socks", help="Tor SOCKS address (default socks5://127.0.0.1:9050).")
    @click.option("--wg-config", help="Path to a WireGuard .conf for wireguard mode.")
    @click.option("--wg-interface", help="WireGuard interface name (else derived).")
    @click.option("--killswitch", type=click.Choice(["on", "off"]),
                  help="Abort a scan if the egress isn't carrying traffic (default on).")
    def set_cmd(mode, proxy_url, tor_socks, wg_config, wg_interface, killswitch) -> None:
        """Persist egress settings to .env (shared with the web UI + config)."""
        from heaven.settings_catalog import apply_settings
        updates: dict[str, str] = {}
        if mode is not None:
            updates["HEAVEN_EGRESS_MODE"] = mode
        if proxy_url is not None:
            updates["HEAVEN_EGRESS_PROXY"] = proxy_url
        if tor_socks is not None:
            updates["HEAVEN_TOR_SOCKS"] = tor_socks
        if wg_config is not None:
            updates["HEAVEN_WG_CONFIG"] = wg_config
        if wg_interface is not None:
            updates["HEAVEN_WG_INTERFACE"] = wg_interface
        if killswitch is not None:
            updates["HEAVEN_EGRESS_KILLSWITCH"] = killswitch
        if not updates:
            _print("[yellow]nothing to set · pass --mode / --proxy / --wg-config / …[/yellow]")
            return
        result = apply_settings(updates)
        if json_output():
            emit_json({"changed": result["changed"]})
            return
        _print(f"[green]✓[/green] updated: {', '.join(result['changed']) or '(no change)'}")
        from heaven.net import egress as eg
        _render_status(eg.status())
