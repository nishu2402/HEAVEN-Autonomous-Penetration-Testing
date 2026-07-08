"""HEAVEN — Training commands: `train-model` (NVD CVSS regressor) and
`train-priors` (Bayesian-smoothed priors from engagement history), plus
`download-model` (fetch the pre-trained NVD model instead of training it)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import click

from heaven.cli._helpers import _print

# ── Pre-trained NVD CVSS model distribution ──────────────────────────────────
# The 48 MB model is intentionally NOT in the wheel or git (gitignored), so pip
# and clone users fetch it once from the GitHub Release. Verified by SHA-256 so
# a corrupted/tampered download is rejected. If the model is retrained, update
# both the release asset and this digest (or pass --sha256 / --no-verify).
_MODEL_REPO = "nishu2402/HEAVEN-Autonomous-Penetration-Testing"
_MODEL_ASSET = "NVD_model.pkl"
_MODEL_DEFAULT_TAG = "v1.0.0"
_MODEL_SHA256 = "ba0167681a6c2ca22f94a3c6d15fb7cc75115992122869421e6399a9a2066845"
_MODEL_SIZE_BYTES = 50238433


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _default_model_url(tag: str) -> str:
    return f"https://github.com/{_MODEL_REPO}/releases/download/{tag}/{_MODEL_ASSET}"


def fetch_model(url: str, dest: Path, expected_sha: str | None) -> Path:
    """Download `url` to `dest`, verify the SHA-256 (if given), atomic-replace.

    Streams to a temp file next to `dest` and only moves it into place after the
    digest checks out, so an interrupted or tampered download never leaves a bad
    model where the loader would pick it up. Raises on any failure.
    """
    import shutil
    import tempfile
    import urllib.request

    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".NVD_model.", suffix=".part", dir=dest.parent)
    tmp = Path(tmp_name)
    try:
        # Only http(s)/file are honoured — never gopher://, data://, etc.
        if not url.startswith(("https://", "http://", "file://")):
            raise click.ClickException(f"refusing to fetch non-web URL: {url[:40]}")
        with urllib.request.urlopen(url, timeout=60) as resp, open(fd, "wb") as out:  # noqa: S310
            shutil.copyfileobj(resp, out, length=1 << 20)
        if expected_sha:
            got = _sha256_file(tmp)
            if got.lower() != expected_sha.lower():
                raise click.ClickException(
                    "checksum mismatch — refusing to install.\n"
                    f"  expected {expected_sha}\n  got      {got}\n"
                    "If you retrained the model, pass --sha256 <digest> or --no-verify."
                )
        tmp.replace(dest)
        return dest
    finally:
        if tmp.exists():
            tmp.unlink()


@click.command(name="download-model")
@click.option("--tag", default=_MODEL_DEFAULT_TAG, show_default=True,
              help="Release tag to fetch the model from.")
@click.option("--url", default=None,
              help="Full model URL (overrides --tag; supports file:// for testing).")
@click.option("--dest", default=None, type=click.Path(),
              help="Where to save the model (default: the user cache dir the loader searches).")
@click.option("--sha256", "sha_override", default=None,
              help="Expected SHA-256 (overrides the built-in digest).")
@click.option("--no-verify", is_flag=True, help="Skip checksum verification (not recommended).")
@click.option("--force", is_flag=True, help="Re-download even if a valid model is already present.")
def download_model_cmd(tag: str, url: str | None, dest: str | None,
                       sha_override: str | None, no_verify: bool, force: bool) -> None:
    """Fetch the pre-trained NVD CVSS model (R²≈0.99) instead of training it.

    The 48 MB model isn't bundled in the wheel or git, so this pulls it once from
    the GitHub Release and stores it where HEAVEN's loader looks. Verified by
    SHA-256. HEAVEN runs without it (CVSS falls back to each finding's base
    score) — this just enables the ML-predicted scores.
    """
    from heaven.ml.risk_model import default_model_dir

    target = Path(dest) if dest else (default_model_dir() / _MODEL_ASSET)
    expected = None if no_verify else (sha_override or _MODEL_SHA256)

    if target.exists() and not force:
        if expected and _sha256_file(target) == expected.lower():
            _print(f"[green]✓ Model already present[/green] and verified → {target}")
            return
        if not expected:
            _print(f"[green]✓ Model already present[/green] → {target} "
                   f"[dim](use --force to re-download)[/dim]")
            return
        _print("[yellow]Existing model failed verification — re-downloading.[/yellow]")

    src = url or _default_model_url(tag)
    _print(f"[cyan]Downloading NVD model[/cyan] (~{_MODEL_SIZE_BYTES // (1 << 20)} MB) "
           f"from {src}")
    try:
        fetch_model(src, target, expected)
    except click.ClickException:
        raise
    except Exception as e:  # noqa: BLE001
        # 404 usually means the maintainer hasn't attached the asset to the
        # release yet — say so instead of a raw traceback.
        raise click.ClickException(
            f"download failed: {e}\n"
            "If this is a 404, the model asset may not be attached to the release "
            f"'{tag}' yet. See docs/BENCHMARK_HOWTO.md, or train locally with "
            "`heaven train-model`."
        ) from e

    _print(f"[green]✓ Model installed[/green] → {target}"
           + ("" if no_verify else "  [dim](SHA-256 verified)[/dim]"))
    _print("[dim]ML CVSS scoring is now active. Restart `heaven serve` if it's running.[/dim]")


def register(cli: click.Group) -> None:
    cli.add_command(train_model_cmd)
    cli.add_command(train_priors_cmd)
    cli.add_command(download_model_cmd)


@click.command(name="train-model")
@click.option("--data-dir", default="nvd_data", type=click.Path())
@click.option("--model-dir", default="models", type=click.Path())
def train_model_cmd(data_dir: str, model_dir: str) -> None:
    """Download NVD data and train the CVSS prediction model."""
    from heaven.ml.train_model import train_cvss_model
    metrics = train_cvss_model(Path(data_dir), Path(model_dir))
    _print(f"[green]Training complete:[/green] R²={metrics['r2']}  RMSE={metrics['rmse']}")
    _print(f"  Trained on {metrics['n_train']:,} CVEs, tested on {metrics['n_test']:,}")


@click.command(name="train-priors")
@click.option(
    "--engagements-dir", "-e", multiple=True, type=click.Path(),
    help="Directories to scan for *.db engagement files. "
         "Default: engagements/ and data/engagements/",
)
@click.option(
    "--bootstrap", default="data/models/priors_bootstrap.json", type=click.Path(),
    help="Bootstrap priors file (used as Bayesian prior when data is sparse)",
)
@click.option(
    "--output", "-o", default="data/models/priors_learned.json", type=click.Path(),
    help="Where to write the learned priors file",
)
@click.option(
    "--prior-strength", default=10.0, type=float,
    help="Pseudo-observation count for the Beta prior. Higher = bootstrap dominates longer.",
)
def train_priors_cmd(engagements_dir: tuple[str, ...], bootstrap: str,
                     output: str, prior_strength: float) -> None:
    """Aggregate engagement findings into empirical Bayesian priors.

    Reads every *.db file in the engagement directories, joins on host+service,
    and produces a service-priors table smoothed against the bootstrap values.
    Output replaces data/models/priors_bootstrap.json as the preferred priors
    file for heaven.ml.ai_brain.
    """
    from heaven.ml.train_priors import discover_engagement_dbs, train_priors

    if engagements_dir:
        dirs = [Path(d) for d in engagements_dir]
    else:
        dirs = [Path("engagements"), Path("data/engagements")]

    dbs = discover_engagement_dbs(*dirs)
    if not dbs:
        _print("[yellow]No engagement *.db files found in:[/yellow]")
        for d in dirs:
            _print(f"  - {d}")
        _print("\nRun some scans first (`heaven engage init <name>` then `heaven scan ...`).")
        raise click.ClickException("nothing to train on")

    _print(f"[cyan]Aggregating findings from {len(dbs)} engagement DB(s)…[/cyan]")
    result = train_priors(
        engagement_paths=dbs,
        bootstrap_path=Path(bootstrap),
        out_path=Path(output),
        prior_strength=prior_strength,
    )
    _print(
        f"[green]Training complete:[/green]\n"
        f"  Engagements with data:    {result.summary['engagements_with_data']}\n"
        f"  Findings ingested:        {result.finding_count}\n"
        f"  Services observed:        {result.services_observed}\n"
        f"  Service priors updated:   {result.service_priors_updated}\n"
        f"  Top services by findings: {result.summary['top_services_by_findings']}\n"
        f"  Output:                   {result.out_path}"
    )
    _print(
        "[dim]heaven.ml.ai_brain will now prefer this file over priors_bootstrap.json.[/dim]"
    )
