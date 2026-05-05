"""
HEAVEN — Cross-Platform Compatibility Layer
Handles all OS-specific differences: event loops, paths, permissions, tools.
Supported: Linux (all distros), macOS (Intel/Apple Silicon), Windows 10/11.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from heaven.utils.logger import get_logger

logger = get_logger("platform")


@dataclass
class PlatformInfo:
    """Detected platform capabilities."""
    os_name: str                    # linux, darwin, windows
    os_version: str
    arch: str                       # x86_64, arm64, aarch64
    python_version: str
    is_root: bool
    has_raw_sockets: bool
    has_nmap: bool
    has_git: bool
    has_docker: bool
    has_scapy: bool
    event_loop_policy: str          # uvloop, proactor, default
    data_dir: Path
    temp_dir: Path
    available_tools: dict[str, str] = field(default_factory=dict)


def detect_platform() -> PlatformInfo:
    """Detect the current platform and available tools."""
    os_name = sys.platform
    if os_name.startswith("linux"):
        os_name = "linux"
    elif os_name == "darwin":
        os_name = "darwin"
    elif os_name == "win32":
        os_name = "windows"

    # Check root/admin privileges
    is_root = False
    if os_name in ("linux", "darwin"):
        is_root = os.geteuid() == 0
    elif os_name == "windows":
        try:
            import ctypes
            is_root = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_root = False

    # Check raw socket capability
    has_raw = is_root  # Linux/macOS need root for raw sockets
    if os_name == "windows":
        has_raw = True  # Windows allows raw sockets for admin users

    # Detect tools
    tools = {}
    for tool in ["nmap", "git", "docker", "masscan", "nikto", "sqlmap",
                  "ffuf", "gobuster", "curl", "wget", "tcpdump", "tshark"]:
        path = shutil.which(tool)
        if path:
            tools[tool] = path

    # Check scapy
    has_scapy = False
    try:
        import scapy  # noqa: F401
        has_scapy = True
    except ImportError:
        pass

    # Determine data directory
    if os_name == "windows":
        data_dir = Path(os.environ.get("APPDATA", "C:\\ProgramData")) / "HEAVEN"
        temp_dir = Path(os.environ.get("TEMP", "C:\\Windows\\Temp")) / "heaven"
    elif os_name == "darwin":
        data_dir = Path.home() / "Library" / "Application Support" / "HEAVEN"
        temp_dir = Path("/tmp/heaven")
    else:
        data_dir = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share"))) / "heaven"
        temp_dir = Path("/tmp/heaven")

    # Event loop policy
    loop_policy = "default"
    if os_name in ("linux", "darwin"):
        try:
            import uvloop  # noqa: F401
            loop_policy = "uvloop"
        except ImportError:
            loop_policy = "default"
    elif os_name == "windows":
        loop_policy = "proactor"

    return PlatformInfo(
        os_name=os_name,
        os_version=platform.release(),
        arch=platform.machine(),
        python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        is_root=is_root,
        has_raw_sockets=has_raw,
        has_nmap="nmap" in tools,
        has_git="git" in tools,
        has_docker="docker" in tools,
        has_scapy=has_scapy,
        event_loop_policy=loop_policy,
        data_dir=data_dir,
        temp_dir=temp_dir,
        available_tools=tools,
    )


def configure_event_loop() -> None:
    """Configure the best available event loop for this platform."""
    import asyncio
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        return
    try:
        import uvloop
        uvloop.install()
        logger.info("uvloop installed")
    except ImportError:
        logger.debug("uvloop not available, using default event loop")


def ensure_directories(info: PlatformInfo) -> None:
    """Create required directories for this platform."""
    for d in [info.data_dir, info.temp_dir, info.data_dir / "models",
              info.data_dir / "reports", info.data_dir / "logs"]:
        d.mkdir(parents=True, exist_ok=True)


def get_shell_command(cmd: str) -> list[str]:
    """Wrap a command for the current platform's shell."""
    if sys.platform == "win32":
        return ["cmd", "/c", cmd]
    return ["sh", "-c", cmd]


def print_platform_info(info: PlatformInfo) -> None:
    """Display platform info in the terminal."""
    try:
        from rich.console import Console
        from rich.table import Table

        con = Console()
        table = Table(title="⟐ HEAVEN Platform Info", border_style="cyan")
        table.add_column("Property", style="bold")
        table.add_column("Value", style="green")

        table.add_row("OS", f"{info.os_name} {info.os_version}")
        table.add_row("Architecture", info.arch)
        table.add_row("Python", info.python_version)
        table.add_row("Privileged", "✓ ROOT" if info.is_root else "✗ unprivileged")
        table.add_row("Raw Sockets", "✓" if info.has_raw_sockets else "✗")
        table.add_row("Event Loop", info.event_loop_policy)
        table.add_row("Data Dir", str(info.data_dir))
        table.add_row("Tools", ", ".join(sorted(info.available_tools.keys())) or "none")

        con.print(table)
    except ImportError:
        # Fallback: plain text
        print(f"OS: {info.os_name} {info.os_version} ({info.arch})")
        print(f"Python: {info.python_version}")
        print(f"Privileged: {'yes' if info.is_root else 'no'}")
        print(f"Event Loop: {info.event_loop_policy}")
        print(f"Tools: {', '.join(sorted(info.available_tools.keys())) or 'none'}")

