# Local AI & the HEAVEN Assistant

HEAVEN's AI layers (false-positive triage, remediation write-ups, attack-chain
planning, coverage grading, vuln hypotheses) and the built-in **security
assistant (chatbot)** run through one provider-agnostic gateway. You can point
that gateway at a **local model** — private, free, and free of the rate limits
that throttle cloud free tiers — or at a cloud key, or both.

> **Design promise:** the LLM only *assists*. HEAVEN's deterministic detectors
> remain the source of truth; the AI never invents a finding or a confirmation.
> That's what makes a small local model safe to rely on.

---

## Why local?

- **No API key, no rate limits.** A cloud key eventually 429s; a local model
  doesn't.
- **Private.** With Ollama, your findings never leave the machine — important for
  engagements under NDA.
- **Zero extra Python deps.** HEAVEN talks to local servers over `httpx` (already
  bundled). Nothing new to `pip install`.

## Set it up from the web app (no terminal)

Prefer clicking to typing? **Settings → AI / LLM → Local AI** is a full
point-and-click wizard:

1. It checks whether Ollama is installed and running (live status pills, with a
   **Refresh** button).
2. If Ollama isn't installed yet, it shows the exact one-line install command for
   your OS with a **Copy** button (installing system software is the only step a
   browser can't do for you) and a download link.
3. Once the server is up, pick a recommended model and click **Pull** — a live
   progress bar streams the download straight from Ollama.
4. Click **Use** and HEAVEN points itself at that model and runs a live test —
   green "Local AI is live" means every AI feature and the assistant now run
   locally. No `.env` editing, no restart.

There's also an **Other endpoint** tab to connect any OpenAI-compatible server
(LM Studio / llama.cpp / vLLM / LocalAI) by base URL + model.

## Quick start (Ollama — CLI, equivalent to the web wizard)

```bash
heaven ai setup            # detects/installs Ollama, pulls qwen2.5:7b, wires .env, live-tests
heaven ai status           # provider/model + local runtime health
heaven chat                # chat with the engagement-grounded assistant
```

`heaven ai setup` is idempotent and safe to re-run. Under the hood it sets in
your `.env`:

```ini
HEAVEN_LLM_PROVIDER=ollama
HEAVEN_LLM_MODEL=qwen2.5:7b
HEAVEN_OLLAMA_HOST=http://localhost:11434
```

### Choosing a model (by hardware)

| Machine            | Model              | Notes                                   |
|--------------------|--------------------|-----------------------------------------|
| ~8 GB RAM          | `llama3.2:3b`      | Fast, lightweight                       |
| ~16 GB RAM (default) | `qwen2.5:7b`     | Balanced — strong instruction / JSON    |
| ~16 GB RAM         | `llama3.1:8b`      | Great general reasoning                  |
| 32 GB+ / GPU       | `qwen2.5:14b`      | Deeper reasoning, slower on CPU         |

```bash
heaven ai pull llama3.1:8b
heaven ai setup --model llama3.1:8b
```

Keep the temperature low (HEAVEN uses 0.1–0.2 for security tasks) — the local
model reasons over evidence rather than free-associating.

## Any OpenAI-compatible server (LM Studio / llama.cpp / vLLM / LocalAI)

```bash
heaven ai setup --provider local \
  --base-url http://localhost:1234/v1 \
  --model your-served-model
```

Or in `.env`:

```ini
HEAVEN_LLM_PROVIDER=local
HEAVEN_LLM_BASE_URL=http://localhost:1234/v1
HEAVEN_LLM_MODEL=your-served-model
HEAVEN_LLM_API_KEY=            # only if your endpoint requires a bearer token
```

## Hybrid — local first, cloud safety net (or vice-versa)

```ini
HEAVEN_LLM_PROVIDER=ollama
HEAVEN_LLM_FALLBACK_PROVIDER=gemini   # used only when the primary is down/empty
```

If the primary is unavailable or returns nothing, HEAVEN retries **once** on the
fallback. A dead local endpoint fails fast (no retry burn), so a scan never
stalls waiting on a model that isn't running.

## The assistant (chatbot)

- **CLI:** `heaven chat` — streaming REPL. `--once "question"` for one-shot;
  `--engagement NAME` to ground in a specific engagement; `--no-context` to skip
  grounding. `/exit` or `Ctrl-D` quits, `/clear` resets.
- **Web:** the **Assistant** page in the sidebar, plus a floating chat button on
  every page. Toggle "Ground in engagement" to feed it your active findings.
- **API:** `POST /api/chat` (`{messages, engagement?, grounded?}`) and a streaming
  `WS /api/chat/stream`.

"Grounded" means the assistant is given a compact, read-only summary of your
active engagement — top findings, hosts, last scan — so it answers about *your*
results and cites them. With Ollama that context stays entirely local.

## Verify

```bash
heaven ai test        # one tiny real completion against the configured model
heaven doctor         # shows LLM provider + local runtime (installed/reachable/models)
```

## Install Ollama manually

- macOS: `brew install ollama` (or <https://ollama.com/download>)
- Linux: `curl -fsSL https://ollama.com/install.sh | sh`
- Windows: `winget install Ollama.Ollama` (or <https://ollama.com/download>)

During `scripts/install.sh` / `install.ps1` you can set `HEAVEN_WITH_OLLAMA=1` to
install Ollama and pull the default model as part of setup.

## Kill switch / no AI

Everything degrades gracefully: with no model and no key, HEAVEN uses its
deterministic paths. `heaven autonomous … --no-llm` forces that explicitly.
