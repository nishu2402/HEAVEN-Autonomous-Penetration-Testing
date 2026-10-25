"""HEAVEN `oast` command: run the in-house out-of-band collaborator standalone.

HEAVEN's blind-vulnerability proofs (SSRF, XXE, blind OS command injection,
out-of-band DNS-exfil SQLi) work by having the *target* call back to a
collaborator HEAVEN controls. For a localhost / lab target the collaborator the
scanner starts on 127.0.0.1 is enough. For an internet-facing bug-bounty target
the callback has to reach a box the target can route to, so you run this
collaborator there and point a scan's OAST environment variables at it.

Typical use on a public VPS you are authorised to receive callbacks on::

    # HTTP channel only (SSRF/XXE/cmdi that can open an outbound HTTP connection)
    heaven oast --host 203.0.113.10 --bind 0.0.0.0 --port 80

    # Add the DNS channel (catches blind bugs where only name resolution escapes).
    # Delegate an NS record for the zone to this box first, e.g. in your DNS:
    #   oast.example.com.  IN NS  vps.example.com.
    #   vps.example.com.    IN A   203.0.113.10
    # then run with privileges to bind UDP/53:
    sudo heaven oast --host 203.0.113.10 --bind 0.0.0.0 --port 80 \\
        --dns-zone oast.example.com --public-ip 203.0.113.10

Point a scan at it from another shell::

    export HEAVEN_OAST_HOST=203.0.113.10 HEAVEN_OAST_PORT=80
    export HEAVEN_OAST_DNS_ZONE=oast.example.com HEAVEN_OAST_PUBLIC_IP=203.0.113.10
    heaven scan https://target.example.com --profile bugbounty --engagement acme

Every inbound callback is printed as it arrives, that line *is* the evidence.
The collaborator records only what a target sends it; it initiates nothing.
"""

from __future__ import annotations

import time

import click

from heaven.cli._helpers import _print, emit_json, json_output


def _interaction_row(ix) -> dict:
    return {
        "channel": getattr(ix, "channel", "http"),
        "method": ix.method,
        "path": ix.path,
        "from": ix.client_ip,
        "token": ix.token,
    }


def register(cli) -> None:
    @cli.command()
    @click.option("-H", "--host", "advertised", default="",
                  help="Routable address advertised to targets in callback URLs "
                       "(defaults to the bind address; use a public IP/hostname "
                       "for internet targets).")
    @click.option("--bind", default="", metavar="ADDR",
                  help="Local address to bind the HTTP listener (default: the "
                       "advertised host; 0.0.0.0 to accept callbacks on every "
                       "interface behind NAT/port-forward).")
    @click.option("--port", default=0, type=int,
                  help="HTTP listener port (default: an OS-assigned high port).")
    @click.option("--dns-zone", default="", metavar="ZONE",
                  help="Delegated zone for the DNS channel, e.g. oast.example.com. "
                       "When set, blind probes resolve <token>.<zone> and a "
                       "recorded lookup is proof. Needs the zone's NS delegated "
                       "to this box.")
    @click.option("--dns-bind", default="", metavar="ADDR",
                  help="Local address to bind the UDP DNS listener "
                       "(default: the HTTP bind address).")
    @click.option("--dns-port", default=53, type=int,
                  help="UDP port for the DNS listener (default: 53; real "
                       "resolvers only ever query 53, override only for local "
                       "tests where binding 53 needs privileges).")
    @click.option("--public-ip", default="", metavar="IPV4",
                  help="IPv4 address answered in A records (defaults to the "
                       "advertised host when it is an IPv4 literal).")
    def oast(advertised: str, bind: str, port: int, dns_zone: str,
             dns_bind: str, dns_port: int, public_ip: str) -> None:
        """Run the out-of-band (OAST) collaborator and print callbacks as they arrive."""
        from heaven.vulnscan.oast import OASTListener

        host = bind or advertised or "127.0.0.1"
        listener = OASTListener(
            host=host, port=port, advertised_host=advertised or host,
            dns_zone=dns_zone, dns_bind=dns_bind, dns_port=dns_port,
            public_ip=public_ip,
        )
        try:
            listener.start()
        except OSError as exc:
            _print(f"[red]Could not start the collaborator:[/red] {exc}")
            raise SystemExit(1) from exc

        sample_token = listener.new_token()
        dns_host = listener.hostname_for(sample_token)
        info = {
            "http_callback_base": listener.base_url,
            "http_bind": f"{host}:{listener.port}",
            "dns_enabled": listener.dns_enabled,
            "dns_zone": listener.dns_zone,
            "dns_bind": f"{listener._dns_bind}:{listener.dns_port}" if listener.dns_enabled else "",
            "dns_answer_ip": listener._public_ip if listener.dns_enabled else "",
            "example_dns_hostname": dns_host,
        }

        if json_output():
            emit_json({"status": "listening", **info})
        else:
            _print("\n[bold]HEAVEN OAST collaborator[/bold], listening (Ctrl-C to stop)")
            _print(f"  [cyan]HTTP callback base[/cyan]  {listener.base_url}  "
                   f"[dim](bound {host}:{listener.port})[/dim]")
            if listener.dns_enabled:
                _print(f"  [cyan]DNS channel[/cyan]         zone "
                       f"[green]{listener.dns_zone}[/green] on "
                       f"{listener._dns_bind}:{listener.dns_port}, answering A "
                       f"{listener._public_ip}")
                _print(f"  [dim]probe hostname looks like[/dim] {dns_host}")
            else:
                _print("  [dim]DNS channel off (pass --dns-zone to enable; needs an "
                       "NS delegation and usually UDP/53 privileges).[/dim]")
            _print("\n  Point a scan at this box:")
            _print(f"    [dim]export HEAVEN_OAST_HOST={listener.advertised_host} "
                   f"HEAVEN_OAST_PORT={listener.port}[/dim]")
            if listener.dns_enabled:
                _print(f"    [dim]export HEAVEN_OAST_DNS_ZONE={listener.dns_zone} "
                       f"HEAVEN_OAST_PUBLIC_IP={listener._public_ip}[/dim]")
            _print("\n  [bold]Callbacks[/bold] (each line is proof a target reached us):")

        seen = 0
        try:
            while True:
                with listener._lock:  # noqa: SLF001 - read snapshot of recorded hits
                    current = list(listener._interactions)
                for ix in current[seen:]:
                    row = _interaction_row(ix)
                    if json_output():
                        emit_json({"callback": row})
                    else:
                        _print(f"    [green]<-[/green] [{row['channel']}] "
                               f"{row['method']} {row['path']}  "
                               f"[dim]from {row['from']}  token={row['token']}[/dim]")
                seen = len(current)
                time.sleep(0.3)
        except KeyboardInterrupt:
            if not json_output():
                _print(f"\n[dim]Stopped. {seen} callback(s) recorded.[/dim]")
        finally:
            listener.stop()
