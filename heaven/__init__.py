# HEAVEN — Autonomous Pen-Testing Framework
# Core package initialisation

__version__ = "1.0.0"
__codename__ = "HEAVEN"
__tagline__ = "Autonomous Penetration-Testing Platform"


def _build_banner() -> str:
    """Assemble the framed CLI banner.

    Built programmatically (every content row is centred to a fixed interior
    width) so the box stays perfectly aligned no matter how the copy changes —
    hand-padded ASCII art drifts the moment a line is edited.
    """
    w = 66  # interior width, in monospace columns

    # HEAVEN — block wordmark (each row is the same column width)
    art = [
        r"██╗  ██╗███████╗ █████╗ ██╗   ██╗███████╗███╗   ██╗",
        r"██║  ██║██╔════╝██╔══██╗██║   ██║██╔════╝████╗  ██║",
        r"███████║█████╗  ███████║██║   ██║█████╗  ██╔██╗ ██║",
        r"██╔══██║██╔══╝  ██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║",
        r"██║  ██║███████╗██║  ██║ ╚████╔╝ ███████╗██║ ╚████║",
        r"╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝",
    ]

    def row(s: str = "") -> str:
        return "║" + s.center(w) + "║"

    lines = ["╔" + "═" * w + "╗", row()]
    lines += [row(a) for a in art]
    lines += [
        row(),
        row("/\\   A S C E N D A N T   A E G I S   /\\"),
        row("A U T O N O M O U S   P E N T E S T"),
        row("─" * 46),
        row("Find It.   Confirm It.   Prove It.   Report It."),
        row(),
        row("AI-Driven · MITRE ATT&CK · ML Risk Triage · Kill-Chain"),
        row(f"v{__version__} · Recon -> Exploit -> Post-Ex -> Report"),
        row(),
        row("Owned & Developed by  Nisarg Chasmawala (Shroff)"),
        "╚" + "═" * w + "╝",
    ]
    return "\n" + "\n".join(lines) + "\n"


__banner__ = _build_banner()
