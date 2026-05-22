"""Shared logging utility for all Batch KG scripts.

Usage in any top-level script (run directly with ``python <script>.py``):

    from classes.log_utils import setup_logging
    logger = setup_logging(__file__)

    The script then creates  log/<script_stem>_<ddMMM_HHMM>.log  automatically.
    No PowerShell redirection (> or 2>&1) is needed.

Usage in library/module files (only ever imported, never run directly):

    import logging
    logger = logging.getLogger(__name__)

    Do NOT call basicConfig or setup_logging inside library modules.
    The top-level calling script is responsible for configuring logging.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path

# Parent directory of the repo root (d:\Iris\practice\GenAI\code\)
# log_utils.py lives at  <repo>/classes/log_utils.py
# so  .parent.parent        = <repo>  (Batch_KG)
#     .parent.parent.parent  = <repo parent>  (code)
_REPO_PARENT = Path(__file__).resolve().parent.parent.parent


class _RepoRelativeFormatter(logging.Formatter):
    """Custom formatter that shortens %(pathname)s to  <repo>\\<relative_path>.

    Example output:  Batch_KG\\neo4j_direct_instance_loader_v3.py
    instead of:      D:\\Iris\\practice\\GenAI\\code\\Batch_KG\\...
    """

    def format(self, record: logging.LogRecord) -> str:
        # Work on a shallow copy so the original record is never mutated.
        r = logging.makeLogRecord(record.__dict__)
        try:
            r.pathname = str(
                Path(record.pathname).resolve().relative_to(_REPO_PARENT)
            )
        except (ValueError, TypeError):
            pass  # Keep original path if relative_to fails (e.g. stdlib files).
        return super().format(r)


def setup_logging(calling_file: str) -> logging.Logger:
    """Configure the root logger with a FileHandler and a console StreamHandler.

    * Log file path: ``log/<script_stem>_<ddMMM_HHMM>.log``
      relative to the current working directory (the repo root when scripts
      are launched from ``D:\\Iris\\practice\\GenAI\\code\\Batch_KG``).

    * Calling this function when the root logger already has handlers is a
      no-op, so modules that also call ``setup_logging`` will not override
      the configuration already set by the top-level script.

    Args:
        calling_file: Pass ``__file__`` from the calling script.

    Returns:
        Logger named after the calling script's stem.
    """
    root = logging.getLogger()

    if root.handlers:
        # Already configured by a parent/top-level script — do nothing.
        return logging.getLogger(Path(calling_file).stem)

    script_stem = Path(calling_file).stem
    log_dir = Path("log")
    log_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%d%b_%H%M")   # e.g. 22May_0814
    log_path = log_dir / f"{script_stem}_{timestamp}.log"

    fmt = (
        "%(asctime)s - %(levelname)s - "
        "[%(pathname)s:%(lineno)d %(funcName)s] - %(message)s"
    )
    formatter = _RepoRelativeFormatter(fmt)

    # FileHandler: Python manages the file directly — no PowerShell CRLF issue.
    fh = logging.FileHandler(str(log_path), encoding="utf-8")
    fh.setFormatter(formatter)

    # StreamHandler: console output (stdout).
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(formatter)

    root.setLevel(logging.INFO)
    root.addHandler(fh)
    root.addHandler(sh)

    root.info("Log file: %s", log_path)
    return logging.getLogger(script_stem)
