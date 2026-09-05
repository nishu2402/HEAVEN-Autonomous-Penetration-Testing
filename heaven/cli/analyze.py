"""HEAVEN — `heaven analyze` (offline authorized-artifact analysis).

Analyzes a file the operator is authorized to examine — a packet capture,
firmware image, binary, APK, image (steganography), or hash file — and reports
real findings. Closes the sniffing / DDoS-analysis / firmware / mobile /
offline-crypto / binary domains without any live target.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import _print

_KINDS = ["binary", "firmware", "pcap", "stego", "apk", "ipa", "crypto"]


@click.command(name="analyze")
@click.argument("path", required=False, type=click.Path())
@click.option("--kind", type=click.Choice(_KINDS), default=None,
              help="Force the artifact type instead of auto-detecting.")
@click.option("--wordlist", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Wordlist for hash cracking (crypto artifacts).")
@click.option("--decode", default=None,
              help="Decode a base64/hex/base32/rot13 string and exit (no file).")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Write the full JSON result to this path.")
@click.option("--report", "report_fmt", type=click.Choice(["md", "html", "json", "pdf"]),
              default=None, help="Write a formatted report (Markdown/HTML/JSON/PDF).")
def analyze(path: Optional[str], kind: Optional[str], wordlist: Optional[str],
            decode: Optional[str], output: Optional[str],
            report_fmt: Optional[str]) -> None:
    """Analyze an offline artifact PATH and report findings.

    Examples:

        heaven analyze capture.pcap
        heaven analyze firmware.bin
        heaven analyze app.apk
        heaven analyze app.ipa
        heaven analyze secret.png
        heaven analyze hashes.txt --wordlist rockyou.txt
        heaven analyze --decode 'YWRtaW46c2VjcmV0'
    """
    from heaven.forensics.dispatch import analyze_artifact, detect_kind

    if decode is not None:
        from heaven.forensics.crypto import analyze_crypto
        res = analyze_crypto("", decode_text=decode)
        for d in res["report"]["decodings"]:
            _print(f"  [cyan]{d['scheme']:8}[/cyan] {d['decoded']}")
        if not res["report"]["decodings"]:
            _print("  [dim]no valid decoding found[/dim]")
        return

    if not path:
        _print("[red]Missing PATH (or use --decode). See 'heaven analyze --help'.[/red]")
        sys.exit(2)
    if not Path(path).is_file():
        _print(f"[red]Not a file: {path}[/red]")
        sys.exit(2)

    detected = kind or detect_kind(path)
    _print(f"[cyan]Analyzing[/cyan] [bold]{path}[/bold] as [magenta]{detected}[/magenta]")

    kwargs = {}
    if wordlist:
        kwargs["wordlist_path"] = wordlist
    result = analyze_artifact(path, kind=kind or "", **kwargs)

    if "error" in result:
        _print(f"[red]{result['error']}[/red]")
        sys.exit(1)

    if result.get("summary"):
        _print(f"[dim]{result['summary']}[/dim]")

    findings = result.get("findings", [])
    if findings:
        _print(f"\n[bold]{len(findings)} finding(s):[/bold]")
        sev_color = {"critical": "red", "high": "red", "medium": "yellow",
                     "low": "cyan", "info": "dim"}
        for f in findings:
            c = sev_color.get(f.get("severity", "info"), "white")
            _print(f"  [{c}]{f.get('severity', '?'):8}[/{c}] {f.get('title', '')}")
    else:
        _print("\n[green]No findings.[/green]")

    if output:
        Path(output).write_text(json.dumps(result, indent=2, default=str))
        _print(f"\n[green]JSON written:[/green] {output}")

    if report_fmt:
        result.setdefault("kind", detected)
        result.setdefault("filename", Path(path).name)
        out_path = Path(path).with_suffix("").name
        if report_fmt == "pdf":
            from heaven.forensics.report import render_pdf
            report_path = f"heaven-{detected}-{out_path}.pdf"
            Path(report_path).write_bytes(render_pdf(result))
        else:
            from heaven.forensics.report import render_report
            content, _mt, ext = render_report(result, report_fmt)
            report_path = f"heaven-{detected}-{out_path}.{ext}"
            Path(report_path).write_text(content)
        _print(f"[green]Report written:[/green] {report_path}")


@click.command(name="mobile")
@click.argument("app", required=True, type=click.Path())
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Write the full JSON result to this path.")
def mobile(app: str, output: Optional[str]) -> None:
    """Static security analysis of a mobile app (Android .apk or iOS .ipa).

    Scores the app against the OWASP Mobile Top 10 / MASVS: embedded secrets,
    cleartext-traffic posture, permissions, debuggable/backup flags (Android) and
    App Transport Security / URL schemes (iOS).

    Examples:

        heaven mobile app.apk
        heaven mobile app.ipa -o mobile.json
    """
    from heaven.forensics.dispatch import analyze_artifact, detect_kind

    if not Path(app).is_file():
        _print(f"[red]Not a file: {app}[/red]")
        sys.exit(2)
    kind = detect_kind(app)
    if kind not in ("apk", "ipa"):
        _print(f"[red]Not a mobile app (.apk/.ipa): detected '{kind}'.[/red]")
        sys.exit(2)
    _print(f"[cyan]Analyzing[/cyan] [bold]{app}[/bold] as [magenta]{kind.upper()}[/magenta]")
    result = analyze_artifact(app, kind=kind)
    if "error" in result:
        _print(f"[red]{result['error']}[/red]")
        sys.exit(1)
    if result.get("summary"):
        _print(f"[dim]{result['summary']}[/dim]")
    findings = result.get("findings", [])
    if findings:
        _print(f"\n[bold]{len(findings)} finding(s):[/bold]")
        sev_color = {"critical": "red", "high": "red", "medium": "yellow",
                     "low": "cyan", "info": "dim"}
        for f in findings:
            c = sev_color.get(f.get("severity", "info"), "white")
            owasp = f" [dim]({f['owasp_mobile']})[/dim]" if f.get("owasp_mobile") else ""
            _print(f"  [{c}]{f.get('severity', '?'):8}[/{c}] {f.get('title', '')}{owasp}")
    else:
        _print("\n[green]No findings.[/green]")
    if output:
        Path(output).write_text(json.dumps(result, indent=2, default=str))
        _print(f"\n[green]JSON written:[/green] {output}")


def register(cli: click.Group) -> None:
    cli.add_command(analyze)
    cli.add_command(mobile)
