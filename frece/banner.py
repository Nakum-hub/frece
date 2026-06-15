# Copyright (c) 2025 FRECE Contributors. Licensed under the MIT License.
"""Startup banner system — msfconsole-style random ASCII banners.

When FRECE is launched in an interactive terminal it prints one of 20
randomly-selected ASCII banners (just like the Metasploit Framework
console), followed by a small metadata block summarising the build.

Design notes
------------
- Banners are written to *stderr*, never stdout, so the machine-readable
  JSON emitted by most commands is never polluted.
- Display is gated on an interactive TTY so the test-suite, shell pipes and
  automation stay clean. Force it on with ``FRECE_FORCE_BANNER=1`` or turn
  it off with ``FRECE_NO_BANNER=1`` / the global ``--no-banner`` flag.
- ANSI colour is applied only on a TTY and suppressed when ``NO_COLOR`` is
  set (https://no-color.org). The banner must never crash the program, so
  any rendering/encoding error is swallowed silently.
"""

from __future__ import annotations

import os
import random
import sys
from typing import TextIO

from frece import __version__

__all__ = [
    "BANNERS",
    "random_banner",
    "format_banner",
    "print_banner",
    "banner_enabled",
]


# Each entry is one complete ASCII banner. Every banner is branded with the
# application name (FRECE) and/or "FILE RECOVERY". Keep this list at 20+; the
# picker simply chooses one uniformly at random on each launch.
BANNERS: list[str] = [
    # 1 — ANSI shadow block: FRECE
    r"""
███████╗██████╗ ███████╗ ██████╗███████╗
██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
█████╗  ██████╔╝█████╗  ██║     █████╗
██╔══╝  ██╔══██╗██╔══╝  ██║     ██╔══╝
██║     ██║  ██║███████╗╚██████╗███████╗
╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝╚══════╝
          F O R E N S I C   R E C O V E R Y
""",
    # 2 — standard figlet: FRECE
    r"""
 _____ ____  _____ ____ _____
|  ___|  _ \| ____/ ___| ____|
| |_  | |_) |  _|| |   |  _|
|  _| |  _ <| |__| |___| |___
|_|   |_| \_\_____\____|_____|
     file recovery & carving engine
""",
    # 3 — slant: FRECE
    r"""
   __________  ___________________
  / ____/ __ \/ ____/ ____/ ____/ /
 / /_  / /_/ / __/ / /   / __/ / /
/ __/ / _, _/ /___/ /___/ /___/_/
/_/   /_/ |_/_____/\____/_____(_)
     :: FRECE · recover · carve · prove ::
""",
    # 4 — big: FRECE
    r"""
 ______ _____  ______ _____ ______
|  ____|  __ \|  ____/ ____|  ____|
| |__  | |__) | |__ | |    | |__
|  __| |  _  /|  __|| |    |  __|
| |    | | \ \| |___| |____| |____
|_|    |_|  \_\______\_____|______|
        forensic recovery engine
""",
    # 5 — doom: FRECE
    r"""
______ ______ _____ _____ _____
|  ___|| ___ \  ___/  __ \  ___|
| |_   | |_/ / |__ | /  \/ |__
|  _|  |    /|  __|| |   |  __|
| |    | |\ \| |___| \__/\ |___
\_|    \_| \_\____/ \____/\____/
     >> FRECE · digital evidence carver <<
""",
    # 6 — banner3 hash: FRECE
    r"""
######  #####  ####### #####  #######
#       #    # #      #     # #
#####   #####  #####  #       #####
#       #   #  #      #       #
#       #    # ####### #####  #######
        F R E C E   t o o l k i t
""",
    # 7 — standard figlet: FILE RECOVERY
    r"""
 _____ _ _        ____
|  ___(_) | ___  |  _ \ ___  ___ _____   _____ _ __ _   _
| |_  | | |/ _ \ | |_) / _ \/ __/ _ \ \ / / _ \ '__| | | |
|  _| | | |  __/ |  _ <  __/ (_| (_) \ V /  __/ |  | |_| |
|_|   |_|_|\___| |_| \_\___|\___\___/ \_/ \___|_|   \__, |
              :: the FRECE engine ::                |___/
""",
    # 8 — calvin-ish box font: FILE RECOVERY
    r"""
╔═╗╦╦  ╔═╗  ╦═╗╔═╗╔═╗╔═╗╦  ╦╔═╗╦═╗╦ ╦
╠╣ ║║  ║╣   ╠╦╝╠╣ ║  ║ ║╚╗╔╝║╣ ╠╦╝╚╦╝
╚  ╩╩═╝╚═╝  ╩╚═╚═╝╚═╝╚═╝ ╚╝ ╚═╝╩╚═ ╩
      FRECE — carve · recover · verify
""",
    # 9 — small block: FILE RECOVERY
    r"""
 ___  _  _    ___  ___  ___  __   _  _  ___  ___ _   _
| __|| || |  | __|| _ \| __|/ _| | || || __|| _ \ | | |
| _| | || |_ | _| |   /| _|| (_  | __ || _| |   / |_| |
|_|  |_||___||___||_|_\|___|\__| |_||_||___||_|_\\___/
          file recovery & evidence engine
""",
    # 10 — clean rule box
    r"""
+================================================+
|   F R E C E   ::   F I L E   R E C O V E R Y   |
|        forensic recovery & carving engine      |
+================================================+
""",
    # 11 — magnifying-glass motif
    r"""
        .-------.
       /  .-.    \         F R E C E
      |  /   \    |     -----------------
      |  \   /    |      file recovery &
       \  '-'    /        evidence carver
        '---.___/_
             \  \ '.
              '--'--'
""",
    # 12 — hard-disk motif
    r"""
   ____________________________
  |  ________________________  |      F R E C E
  | |                        | |    forensic file
  | |   F R E C E   DISK     | |    recovery and
  | |   recovery engine      | |    carving engine
  | |________________________| |
  |____________________________|   recover · carve
     O   recover · carve · score   O   · score
""",
    # 13 — shield motif
    r"""
        ____________
       /            \        F R E C E
      |   F R E C E  |    ------------------
      |     [::]      |     chain-of-custody
      |    carve &    |     forensic engine
       \   recover   /
        \__________ /        recover · prove
         '--------'
""",
    # 14 — forensic mask motif
    r"""
        _.-'''''-._
      .'  _     _  '.        F R E C E
     /   (o)   (o)   \     forensic file
    |        ^        |    recovery engine
    |    \  '-'  /    |    carve · recover
     \    '._.'     /      · score · verify
      '._       _.'
         '-----'
""",
    # 15 — outline font: FRECE FREE (recover what was lost)
    r"""
╦═╗╔═╗╔═╗╔═╗╦  ╦╔═╗╦═╗╦ ╦  ╔═╗╦═╗╔═╗╔═╗╔═╗
╠╦╝╠╣ ║  ║ ║╚╗╔╝║╣ ╠╦╝╚╦╝  ╠╣ ╠╦╝║╣ ║  ║╣
╩╚═╚═╝╚═╝╚═╝ ╚╝ ╚═╝╩╚═ ╩   ╚  ╩╚═╚═╝╚═╝╚═╝
        :: FRECE · recover what was lost ::
""",
    # 16 — dotted matrix: FRECE
    r"""
.########.########..########..######..########
.##.......##.....##.##.......##....##.##......
.##.......##.....##.##.......##.......##......
.######...########..######...##.......######..
.##.......##...##...##.......##.......##......
.##.......##....##..##.......##....##.##......
.##.......##.....##.########..######..########
.......file recovery & carving engine
""",
    # 17 — rectangle font: FRECE
    r"""
  _____  _____  _____  _____  _____
 |   __||  _  ||   __||     ||   __|
 |   __||     ||   __||   --||   __|
 |__|   |__|__||_____||_____||_____|
  FRECE — F O R E N S I C   C A R V E R
""",
    # 18 — wave rule
    r"""
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ≈  FRECE  ≈  file recovery engine  ≈
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   recover · carve · classify · prove
""",
    # 19 — bracket tiles
    r"""
   [ F ][ R ][ E ][ C ][ E ]
  :::  F I L E   R E C O V E R Y  :::
  :::   forensic carving engine   :::
""",
    # 20 — slant: FILE RECOVERY (compact)
    r"""
   ___________  ____________________
  / __/ _ \ __/ / ___/ __/ ___/ __/ /
 / _// , _/ _/  / /__/ _// /__/ _//_/
/_/ /_/|_/___/  \___/___/\___/___(_)
    FRECE · forensic file recovery
""",
]


_COLORS = (
    "\033[36m", "\033[1;36m", "\033[32m", "\033[1;32m", "\033[31m",
    "\033[1;31m", "\033[35m", "\033[1;35m", "\033[34m", "\033[1;34m",
    "\033[33m", "\033[1;33m",
)
_RESET = "\033[0m"


def random_banner() -> str:
    """Return one banner chosen uniformly at random."""
    return random.choice(BANNERS)


def _metadata_block() -> str:
    """Return the msfconsole-style metadata footer printed under the art."""
    return (
        f"       =[ FRECE v{__version__} — Forensic Recovery & Evidence Carving Engine ]\n"
        f"+ -- --=[ 88 carving signatures · 46 structural validators · 12 metadata extractors ]\n"
        f"+ -- --=[ 17 commands · YARA scanning · DFXML · HMAC chain-of-custody ]\n"
    )


def format_banner(art: str | None = None, *, color: bool = False) -> str:
    """Render a full banner (art + metadata block) ready for printing.

    Args:
        art: A specific banner to render. Defaults to a random one.
        color: When True, wrap the art in a random ANSI colour.
    """
    chosen = art if art is not None else random_banner()
    chosen = chosen.strip("\n")
    if color:
        chosen = f"{random.choice(_COLORS)}{chosen}{_RESET}"
    return f"\n{chosen}\n\n{_metadata_block()}"


def banner_enabled(stream: TextIO | None = None, *, force: bool = False) -> bool:
    """Decide whether the banner should be shown for this run.

    Precedence: explicit force / FRECE_FORCE_BANNER > FRECE_NO_BANNER >
    interactive-TTY detection. Non-interactive runs (tests, pipes, CI) stay
    silent so machine output is never disturbed.
    """
    if force or os.environ.get("FRECE_FORCE_BANNER"):
        return True
    if os.environ.get("FRECE_NO_BANNER"):
        return False
    stream = stream if stream is not None else sys.stderr
    isatty = getattr(stream, "isatty", None)
    if not callable(isatty):
        return False
    try:
        return bool(isatty())
    except (ValueError, OSError):
        return False


def print_banner(stream: TextIO | None = None, *, force: bool = False) -> bool:
    """Print a random banner to *stream* (stderr by default).

    Returns True if a banner was actually printed. A decorative banner must
    never break the application, so all rendering/encoding/IO errors are
    swallowed.
    """
    stream = stream if stream is not None else sys.stderr
    if not banner_enabled(stream, force=force):
        return False
    isatty = getattr(stream, "isatty", None)
    on_tty = bool(isatty()) if callable(isatty) else False
    use_color = on_tty and not os.environ.get("NO_COLOR")
    try:
        print(format_banner(color=use_color), file=stream)
        stream.flush()
    except (OSError, ValueError, UnicodeError):
        return False
    return True
