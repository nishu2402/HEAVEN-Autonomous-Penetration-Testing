"""HEAVEN — Training commands: `train-model` (NVD CVSS regressor) and
`train-priors` (Bayesian-smoothed priors from engagement history), plus
`download-model` (fetch the pre-trained NVD model instead of training it)."""

from __future__ import annotations

import contextlib
import hashlib
from pathlib import Path

import click

from heaven.cli._helpers import _print

# ── Pre-trained CVSS model distribution ──────────────────────────────────────
# The models are intentionally NOT in the wheel or git (gitignored), so pip and
# clone users fetch them once from the GitHub Release. Verified by SHA-256 so a
# corrupted/tampered download is rejected. If a model is retrained, update both
# the release asset and this digest (or pass --sha256 / --no-verify).
#
# NOTE: the digests below track the retrained models (vector model re-pickled
# under scikit-learn 1.9.0; description model trained on the NVD_Cybersecurity
# dataset). Re-upload data/models/NVD_model.pkl and cvss_text_model.joblib to the
# release so `download-model` matches what `train-model` produces locally.
_MODEL_REPO = "nishu2402/HEAVEN-Autonomous-Penetration-Testing"
_MODEL_ASSET = "NVD_model.pkl"
# Release tags known to carry the SHA-256-matching model asset, newest first.
# With no explicit --tag/--url, `download-model` tries the running version's own
# tag first and then each of these, installing the first asset whose digest
# matches _MODEL_SHA256. The model is identical between releases, so if it hasn't
# been re-attached to the newest release the fetch transparently falls back to a
# release that has it, and the checksum pin guarantees every candidate is the
# exact expected model. Prepend a tag here only after attaching the matching
# NVD_model.pkl to that release.
_MODEL_KNOWN_TAGS = ("v3.1.0",)
_MODEL_SHA256 = "b6dba49ad45e271a609521ae1292b16734e30e0806ad5350c72225b6149bc525"
_MODEL_SIZE_BYTES = 5912225

# The description/type fallback model (heaven.ml.desc_model). Optional: older
# releases won't carry it, so download-model fetches it best-effort and never
# fails the whole command when it is absent.
_DESC_ASSET = "cvss_text_model.joblib"
_DESC_META_ASSET = "cvss_text_model.meta.json"
_DESC_SHA256 = "73e41b525d1078a85cd0a68cad35aac08ad44006edbac142e2df2054b030c01c"
_DESC_SIZE_BYTES = 1024916


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _default_model_url(tag: str) -> str:
    return f"https://github.com/{_MODEL_REPO}/releases/download/{tag}/{_MODEL_ASSET}"


def _candidate_tags() -> list[str]:
    """Ordered, de-duplicated release tags to try for the model asset: the running
    version's own tag first (so a release that re-attaches the model is preferred
    automatically), then the known-good fallbacks in `_MODEL_KNOWN_TAGS`."""
    from heaven import __version__

    seen: set[str] = set()
    out: list[str] = []
    for tag in (f"v{__version__}", *_MODEL_KNOWN_TAGS):
        if tag not in seen:
            seen.add(tag)
            out.append(tag)
    return out


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
        # Scheme allow-listed above (http/https/file only) and the download is
        # SHA-256-verified below before it replaces the model, so a hostile URL
        # can't smuggle an unexpected scheme or a tampered artifact.
        with urllib.request.urlopen(url, timeout=60) as resp, open(fd, "wb") as out:  # noqa: S310  # nosec B310
            shutil.copyfileobj(resp, out, length=1 << 20)
        if expected_sha:
            got = _sha256_file(tmp)
            if got.lower() != expected_sha.lower():
                raise click.ClickException(
                    "checksum mismatch, refusing to install.\n"
                    f"  expected {expected_sha}\n  got      {got}\n"
                    "If you retrained the model, pass --sha256 <digest> or --no-verify."
                )
        tmp.replace(dest)
        return dest
    finally:
        if tmp.exists():
            tmp.unlink()


@click.command(name="download-model")
@click.option("--tag", default=None,
              help="Release tag to fetch the model from. Default: the running "
                   "version's tag, then known-good fallbacks.")
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
    """Fetch the pre-trained CVSS models instead of training them.

    The vector model (ExtraTrees, ~R²=0.91) and the description/type fallback
    model aren't bundled in the wheel or git, so this pulls them once from the
    GitHub Release and stores them where HEAVEN's loader looks. Verified by
    SHA-256. HEAVEN runs without them (CVSS falls back to each finding's base
    score). This just enables the ML-predicted scores.
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
        _print("[yellow]Existing model failed verification · re-downloading.[/yellow]")

    # Build the ordered sources to try. An explicit --url or --tag is a single,
    # authoritative source (fail loudly if it doesn't serve the asset). The
    # default fans out across the candidate tags and installs the first asset
    # that verifies, so bumping the app version never breaks the fetch.
    if url:
        sources: list[tuple[str | None, str]] = [(None, url)]
    elif tag:
        sources = [(tag, _default_model_url(tag))]
    else:
        sources = [(t, _default_model_url(t)) for t in _candidate_tags()]

    _print(f"[cyan]Fetching pre-trained NVD model[/cyan] "
           f"(~{_MODEL_SIZE_BYTES // (1 << 20)} MB)…")
    installed = False
    used_tag: str | None = None
    last_err: Exception | None = None
    for cand_tag, src in sources:
        try:
            fetch_model(src, target, expected)
            installed, used_tag = True, cand_tag
            break
        except click.ClickException:
            # A verification/scheme failure from a single explicit source is
            # authoritative — surface it exactly (preserves --url/--tag behaviour
            # and exit code). In a fallback chain, treat it as a miss and move on.
            if len(sources) == 1:
                raise
            _print(f"[dim]· {cand_tag}: asset did not verify, trying the next release…[/dim]")
        except Exception as e:  # noqa: BLE001 — network/404: try the next source
            if len(sources) == 1:
                where = f"the release '{cand_tag}'" if cand_tag else "that URL"
                raise click.ClickException(
                    f"download failed: {e}\n"
                    f"If this is a 404, the model asset may not be attached to "
                    f"{where} yet. See docs/BENCHMARK_HOWTO.md, or train locally "
                    "with `heaven train-model`."
                ) from e
            last_err = e
            _print(f"[dim]· {cand_tag}: not available here, trying the next release…[/dim]")

    if not installed:
        tried = ", ".join(t or "url" for t, _ in sources)
        raise click.ClickException(
            f"download failed from every candidate release ({tried}).\n"
            f"Last error: {last_err}\n"
            "The model asset isn't attached to any of these releases yet. See "
            "docs/BENCHMARK_HOWTO.md, or train locally with `heaven train-model`."
        )

    where = f" from {used_tag}" if used_tag else ""
    _print(f"[green]✓ Model installed[/green]{where} → {target}"
           + ("" if no_verify else "  [dim](SHA-256 verified)[/dim]"))

    # Best-effort: also fetch the description/type fallback model from the same
    # release the vector model came from. Older releases won't have it, so a 404
    # (or any failure) is a soft skip — the hybrid falls back to the vector model
    # for every finding, which is the pre-hybrid behaviour.
    if not url and used_tag:  # a custom --url is vector-only
        desc_base = _default_model_url(used_tag)
        desc_target = target.parent / _DESC_ASSET
        desc_expected = None if no_verify else _DESC_SHA256
        try:
            fetch_model(desc_base.replace(_MODEL_ASSET, _DESC_ASSET),
                        desc_target, desc_expected)
            with contextlib.suppress(Exception):
                fetch_model(desc_base.replace(_MODEL_ASSET, _DESC_META_ASSET),
                            desc_target.parent / _DESC_META_ASSET, None)
            _print(f"[green]✓ Description model installed[/green] → {desc_target}")
        except Exception:  # noqa: BLE001 — optional asset; hybrid works without it
            _print("[dim]Description model not on this release · the hybrid will use "
                   "the vector model for every finding (train it with "
                   "`heaven train-model --csv <NVD_Cybersecurity_Dataset.csv>`).[/dim]")

    _print("[dim]ML CVSS scoring is now active. Restart `heaven serve` if it's running.[/dim]")


def register(cli: click.Group) -> None:
    cli.add_command(train_model_cmd)
    cli.add_command(train_priors_cmd)
    cli.add_command(download_model_cmd)


@click.command(name="train-model")
@click.option("--data-dir", default="nvd_data", type=click.Path())
@click.option("--model-dir", default="models", type=click.Path())
@click.option("--csv", default=None,
              help="Path to NVD_Cybersecurity_Dataset.csv for the description "
                   "model (or set HEAVEN_NVD_CSV). Skipped if absent.")
def train_model_cmd(data_dir: str, model_dir: str, csv: str | None) -> None:
    """Train HEAVEN's hybrid CVSS model: the vector model (13 CVSS features) and,
    when the description dataset is available, the description/type fallback."""
    from heaven.ml.train_model import train_cvss_model
    metrics = train_cvss_model(Path(data_dir), Path(model_dir))
    _print(f"[green]Vector model:[/green] split R²={metrics['r2']}  "
           f"5-fold CV R²={metrics.get('cv_r2', '?')}  MAE={metrics['mae']}")
    _print(f"  Trained on {metrics['n_train']:,} CVEs, tested on {metrics['n_test']:,}")

    # The description/type model needs the large NVD CSV; train it when present,
    # otherwise the hybrid simply uses the vector model for every finding.
    from heaven.ml.train_desc_model import train_desc_model
    desc = train_desc_model(csv=csv, model_dir=Path("data/models"))
    if desc:
        _print(f"[green]Description model:[/green] trained on {desc['n_samples']:,} real "
               f"(non-zero) findings  [dim](dropped {desc.get('n_dropped_zero', 0):,} "
               f"info-CVEs)[/dim]")
        _print(f"  Deployment (flagged findings): R²={desc.get('deploy_r2')}  "
               f"MAE={desc.get('deploy_mae')}  band exact={desc.get('deploy_band_exact')}  "
               f"within-one-band={desc.get('deploy_band_within1')} "
               f"[dim](the metric that reflects real use)[/dim]")
    else:
        _print("[dim]Description model skipped (no CSV) · hybrid uses the vector "
               "model for every finding.[/dim]")


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
