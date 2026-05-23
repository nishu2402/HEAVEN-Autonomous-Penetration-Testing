"""
HEAVEN — Publication-grade benchmark suite

Goal: produce defensible detection-rate / false-positive numbers for HEAVEN
against vulnerable-by-design web apps (DVWA, Juice Shop, etc.). Without this
suite, every "X% accuracy" claim in the README is unverifiable marketing.

How it works
------------
For each target app (DVWA today; Juice Shop / WebGoat planned):
1. A docker-compose fixture brings up the vulnerable app at a known version.
2. A YAML ground-truth file lists every known vulnerability the app exposes
   (endpoint, parameter, vuln category, OWASP/CWE mapping, severity, whether
   detection is *required* to pass the benchmark vs. *nice to have*).
3. The benchmark test runs `heaven scan` against the live app and reads the
   findings out of the engagement DB.
4. The metrics module pairs each finding to a ground-truth entry (when one
   matches) and computes precision, recall, F1 — both overall and per
   vulnerability category.
5. Reporters emit a markdown table (for the paper) and a CSV in the same
   shape as Burp Scanner / OWASP ZAP exports, so head-to-head comparison is
   one diff away.

Ground-truth YAML schema
------------------------
See `tests/benchmarks/ground_truth/dvwa.yaml` for the worked example.
The schema is intentionally scanner-agnostic — anything that produces
findings shaped like {target_url, vuln_type, parameter} can be benchmarked
against the same files.

Required top-level keys:
  target_app   : str         — short identifier ("dvwa", "juiceshop")
  version      : str         — pinned app version
  docker_image : str         — image tag (and ideally @sha256 digest)
  base_url     : str         — where the app listens after `docker compose up`
  auth         : dict | null — login flow if needed
  vulnerabilities: list      — the labeled vulns (see below)

Each vulnerability entry:
  id                : str        — stable identifier for reports
  endpoint          : str        — path (relative to base_url)
  method            : str        — GET / POST
  parameter         : str | null — the vulnerable input
  category          : str        — canonical: sqli, xss, cmdi, lfi, csrf, ...
  subtypes_ok       : list[str]  — optional finer-grained types that count
  owasp             : str        — OWASP Top 10 ID (e.g., A03_2021)
  cwe               : str        — CWE ID (e.g., CWE-89)
  severity          : str        — critical / high / medium / low
  difficulty        : str        — low / medium / high / impossible
  detection_required: bool       — if true, a miss fails the benchmark
  notes             : str        — human description of *why* it's vulnerable

CI behaviour
------------
These benchmarks DO NOT run during normal `pytest`. They require Docker
and take minutes. To run them, set `HEAVEN_RUN_BENCHMARKS=1`:

    HEAVEN_RUN_BENCHMARKS=1 pytest tests/benchmarks/ -v

Only `tests/benchmarks/test_metrics.py` runs in regular CI — it validates
the metrics math with synthetic inputs and needs no Docker.
"""
