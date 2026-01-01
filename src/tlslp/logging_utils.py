"""Logging helpers used by both the TLS client and server.

This module configures the **root** logger so application code can simply call
``logging.getLogger(__name__)`` and emit messages.

Behavior:
- A file handler is attached at the requested level (default: ``INFO``) and
  writes to an OS-appropriate directory (``XDG_STATE_HOME`` on Linux/WSL or
  ``LOCALAPPDATA`` on Windows).
- A stderr handler is attached at ``WARNING`` and above.
- Python warnings are routed through logging (via ``logging.captureWarnings``).

In tutorial mode (``tutorial=True``), log timestamps are made deterministic so
test outputs and tutorial logs are reproducible.
"""

import logging
import os
import pathlib
import sys
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler


@dataclass(frozen=True)
class LogRecordPayload:
    """Structured payload for JSON logs."""

    ts: str
    level: str
    logger: str
    msg: str

    # helpful context:
    module: str
    func: str
    line: int
    pid: int | None

    # optional extras:
    exc_type: str | None = None
    exc: str | None = None


def _set_formatter(tutorial: bool, handler: logging.Handler) -> None:
    date = "2000-01-01T00:00:00+0100" if tutorial else "{asctime}"
    handler.setFormatter(
        logging.Formatter(
            fmt=date + " {levelname} {name}: {message}",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
            style="{",
        )
    )


def _default_log_dir() -> pathlib.Path:
    """Return an OS-appropriate log directory."""
    if os.name == "nt":
        base = pathlib.Path(
            os.getenv("LOCALAPPDATA", pathlib.Path.home() / "AppData" / "Local")
        )
    else:
        # Linux / WSL: prefer XDG state dir
        base = pathlib.Path(
            os.getenv("XDG_STATE_HOME", pathlib.Path.home() / ".local" / "state")
        )

    log_dir = base / "tlslp" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    return log_dir


def configure_logging(
    *, level: str = "INFO", node: str = "server", tutorial: bool = False
) -> None:
    """Configure root logging for the application.

    This attaches two handlers to the **root** logger:

    1) A file handler at ``level`` writing to ``<state-dir>/tlslp/logs/<node>.log``.
       - On Linux/WSL: ``$XDG_STATE_HOME`` (fallback: ``~/.local/state``)
       - On Windows: ``%LOCALAPPDATA%`` (fallback: ``~/AppData/Local``)

    2) A stderr handler at ``WARNING`` and above.

    Calling this function multiple times is safe: existing root handlers are
    removed and closed before new handlers are installed.

    Args:
        level (str): Logging level name (e.g., ``"DEBUG"``, ``"INFO"``).
        node (str): Logical node name used for the log filename (e.g., ``"server"`` or
            ``"client"``).
        tutorial (bool): If True, use deterministic timestamps and overwrite the log
            file each run.

    Raises:
        ValueError: If ``level`` is not a valid logging level name.

    Examples:
        >>> import logging
        >>> from tlslp.logging_utils import configure_logging
        >>> configure_logging(level="INFO", node="demo", tutorial=True)
        >>> logging.getLogger("demo").info("hello")
    """
    # route Python warnings through logging.
    logging.captureWarnings(True)
    warn_logger = logging.getLogger("py.warnings")

    # normalize and validate level
    level_upper = level.upper()
    numeric_level = getattr(logging, level_upper, None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {level!r}")

    root = logging.getLogger()
    root.setLevel(numeric_level)

    # avoid duplicated logs if configure_logging is called more than once
    for h in list(root.handlers):
        root.removeHandler(h)
        try:
            h.close()
        finally:
            pass

    # base class for StreamHandler and RotatingFileHandler allowing both to type check out
    handler: logging.Handler

    # let warnings flow to root handlers (avoid duplicates)
    warn_logger.handlers.clear()
    warn_logger.propagate = True

    # create err handler (WARNING and above)
    err_handler = logging.StreamHandler(stream=sys.stderr)
    err_handler.setLevel("WARNING")
    _set_formatter(tutorial, err_handler)
    root.addHandler(err_handler)

    # define and create folder for saving log
    log_file = pathlib.Path(node).with_suffix(".log")
    fn = _default_log_dir() / log_file

    # for tutorial we don't want setup tests to be written to the log file, so we
    # use write mode and only keep the last written log
    if tutorial:
        handler = logging.FileHandler(filename=fn, mode="w")
    else:
        handler = RotatingFileHandler(
            filename=fn, mode="a", maxBytes=50 * 1024 * 1024, backupCount=2
        )

    # create debug handler (all messages)
    _set_formatter(tutorial, handler)
    root.addHandler(handler)
    handler.setLevel(numeric_level)
