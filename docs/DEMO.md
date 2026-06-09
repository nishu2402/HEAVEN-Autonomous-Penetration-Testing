# HEAVEN — Recording a Demo

A 60-second asciinema cast is the single highest-leverage README
addition you can make. Stars/forks correlate way more with "I saw it
in action" than with feature lists.

## What to record

The narrative is **observe → act → reproduce**. ~60 seconds total.

### Scene 1 — Brand the demo (5s)

```bash
heaven --version
clear
```

The banner reads `HEAVEN v1.0.0 — Autonomous Penetration Testing Platform`
and lists 31 commands. This is the "moment of trust" — the viewer knows
they're not watching a toy.

### Scene 2 — One-shot scan (20s)

```bash
# Start a target (do this off-camera, then jump to scan)
docker run --rm -d -p 8080:80 --name dvwa vulnerables/web-dvwa

# On-camera:
heaven scan -u http://localhost:8080 -m web --i-have-authorization
```

Show the live HUD — phase indicators advancing through RECON → VULN_SCAN
→ ML_SCORING → MITRE_MAPPING → REPORTING. Severity counters tick up in
red/yellow as findings appear. This is the visual hook.

### Scene 3 — Triage one finding (15s)

```bash
heaven findings --severity high
heaven show <id>           # full evidence + curl repro
```

The `show` output is the differentiator — request/response excerpts +
the exact curl command to reproduce, formatted as Rich Markdown. Most
scanners show "SQLi at /index.php?id=" and stop there.

### Scene 4 — Differential scan (10s)

```bash
heaven scan -u http://localhost:8080 -m web --engagement demo --i-have-authorization
heaven diff <baseline-id> <current-id> --engagement demo
```

Show the bucketed output — **NEW** in green, **REGRESSED** in red. This
is the watch-mode preview.

### Scene 5 — Web UI walkthrough (10s)

```bash
heaven serve
```

Cut to browser at `http://localhost:8443`. Show:

1. Dashboard — gradient stat cards + live severity-distribution bars
2. Click → KillChain page (Cyber Kill Chain phase coverage)
3. Click → Watch page (continuous-monitoring status)

End on the Watch page. The viewer's last impression is "this runs
continuously without me."

---

## Recording tools

### asciinema (preferred — text-based, embeddable, 5KB)

```bash
brew install asciinema           # macOS
pip install asciinema             # any

asciinema rec heaven-demo.cast \
    --idle-time-limit 1 \
    --command "$SHELL"

# Then run through the scenes above. Ctrl-D when done.

asciinema upload heaven-demo.cast
# → returns a URL like https://asciinema.org/a/xxxxx
```

Embed in README:

```markdown
[![asciicast](https://asciinema.org/a/xxxxx.svg)](https://asciinema.org/a/xxxxx)
```

### Video (heavier — for YouTube / X / LinkedIn posts)

```bash
brew install --cask obs        # macOS — full screen recording
# OR
brew install ffmpeg            # CLI capture
ffmpeg -f avfoundation -i "1:0" -r 30 -t 90 heaven-demo.mp4
```

Post-process to ≤ 1080p, ≤ 30 fps, ≤ 90 seconds. Anything longer than
90 seconds loses the second-half audience on social.

---

## Scripted-mode recording (deterministic, no typos)

For a clean cast with no operator hesitation, use the `--seed` flag so
the scan output is reproducible, and pre-write a tmux script:

```bash
# demo-script.sh
set -e
clear
echo "# HEAVEN — autonomous pen-test framework"
sleep 1

echo "$ heaven --version"
heaven --version
sleep 2

echo
echo "$ heaven scan -u http://localhost:8080 -m web --seed 42 --i-have-authorization"
heaven scan -u http://localhost:8080 -m web --seed 42 --i-have-authorization
sleep 3

echo
echo "$ heaven findings --severity high"
heaven findings --severity high
sleep 5
```

Run with asciinema:

```bash
asciinema rec demo.cast --command "bash demo-script.sh"
```

The `--seed 42` ensures the demo is bit-for-bit reproducible — the same
findings in the same order, every time.

---

## Where to put the demo

| Asset | Location |
|---|---|
| `asciinema` embed badge | README.md top-of-file, just under the typing SVG |
| MP4 / WebM video | GitHub Release assets (do NOT commit to git) |
| Animated GIF (≤ 5 MB) | `docs/screenshots/heaven-demo.gif`, embedded in README |
| YouTube link | README "Documentation & Community" section |

## Pre-recording checklist

- [ ] Terminal is 120×40 with a dark theme + readable font (JetBrains Mono 16pt)
- [ ] Prompt is plain `$ ` — no zsh-syntax-highlighter coloring the demo
- [ ] DVWA container is freshly created (no leftover findings from previous runs)
- [ ] LLM API key is set so the AI layers actually fire (otherwise viewers see "skipped: gateway unavailable")
- [ ] `HEAVEN_ADMIN_PASSWORD` is set so the Web UI doesn't show the auto-generated-password warning
- [ ] You have written authorization for every target shown — yes, even localhost (the flag is mandatory)
