"""HEAVEN — Training commands: `train-model` (NVD CVSS regressor) and
`train-priors` (Bayesian-smoothed priors from engagement history)."""

from __future__ import annotations

from pathlib import Path

import click

from heaven.cli._helpers import _print


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


def register(cli: click.Group) -> None:
    cli.add_command(train_model_cmd)
    cli.add_command(train_priors_cmd)
