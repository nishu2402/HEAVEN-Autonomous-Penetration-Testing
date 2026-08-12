"""HEAVEN — `heaven chat`: interactive AI security assistant in the terminal.

Streams replies token-by-token from whatever provider is configured (a local
Ollama/OpenAI-compatible model, or a cloud key). Grounds answers in the active
engagement's findings by default so it talks about YOUR results.

    heaven chat                       # interactive REPL, grounded in active engagement
    heaven chat --once "explain finding 3 and how to fix it"
    heaven chat --engagement acme --no-context
"""

from __future__ import annotations

import sys
from typing import Optional

import click

from heaven.cli._helpers import _print


def _resolve_store(engagement: Optional[str], use_context: bool):
    """Open the engagement store for grounding, or None (no context / not found)."""
    if not use_context:
        return None
    from heaven.cli._helpers import _engagement_db_path, resolve_engagement_name
    name = resolve_engagement_name(engagement)
    if not name:
        return None
    try:
        from heaven.engagement import EngagementStore
        return EngagementStore(_engagement_db_path(name))
    except Exception:  # noqa: BLE001 — grounding is optional, never blocks chat
        return None


@click.command("chat")
@click.option("--engagement", help="Engagement to ground answers in.")
@click.option("--no-context", "no_context", is_flag=True,
              help="Don't feed engagement findings to the assistant.")
@click.option("--once", "one_shot", default=None,
              help="Ask a single question, print the answer, and exit.")
def chat_cmd(engagement: Optional[str], no_context: bool, one_shot: Optional[str]) -> None:
    """Chat with the HEAVEN AI security assistant."""
    from heaven.ai.chat_assistant import ChatAssistant
    assistant = ChatAssistant()
    if not assistant.available:
        gw = assistant.gateway
        _print(f"[yellow]No LLM configured.[/yellow] {gw._init_error or ''}".rstrip())
        _print("  Set up a free local model: [cyan]heaven ai setup[/cyan]")
        _print("  …or add a cloud key: [cyan]heaven config set GEMINI_API_KEY[/cyan]")
        raise SystemExit(1)

    store = _resolve_store(engagement, not no_context)
    gw = assistant.gateway
    grounded = store is not None

    def _answer(messages: list[dict]) -> str:
        """Stream one assistant turn to stdout; return the full text."""
        chunks: list[str] = []
        for piece in assistant.stream(messages, store=store, include_context=grounded):
            chunks.append(piece)
            sys.stdout.write(piece)
            sys.stdout.flush()
        sys.stdout.write("\n")
        sys.stdout.flush()
        text = "".join(chunks)
        if not text:
            _print("[dim](no response — the model returned nothing)[/dim]")
        return text

    if one_shot:
        _answer([{"role": "user", "content": one_shot}])
        return

    _print(f"[bold cyan]HEAVEN assistant[/bold cyan] · {gw.provider} ({gw.model})"
           + (" · grounded in engagement" if grounded else ""))
    _print("[dim]Type your question. /exit to quit, /clear to reset context.[/dim]\n")
    history: list[dict] = []
    while True:
        try:
            user = input("you › ").strip()
        except (EOFError, KeyboardInterrupt):
            _print("\n[dim]bye[/dim]")
            break
        if not user:
            continue
        if user in ("/exit", "/quit", ":q"):
            _print("[dim]bye[/dim]")
            break
        if user == "/clear":
            history = []
            _print("[dim](context cleared)[/dim]")
            continue
        history.append({"role": "user", "content": user})
        sys.stdout.write("ai  › ")
        sys.stdout.flush()
        answer = _answer(history)
        if answer:
            history.append({"role": "assistant", "content": answer})


def register(cli: click.Group) -> None:
    cli.add_command(chat_cmd)
