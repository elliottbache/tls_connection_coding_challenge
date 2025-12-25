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
    """
    Configure root logging for the application.

    Creates 2 handlers:
    1. Takes ```level``` (default ```INFO```) and sends to a log file in the
    XDG_STATE_HOME/tlslp/ (~/.local/state/tlslp in Linux)
    2. Takes "WARNING" and above and sends to stderr

    Args:
        level (str): Logging level name (e.g., "DEBUG", "INFO").
        node (str): Client or server
        tutorial (bool): If True, we are in tutorial mode and want to reproduce exactly
            the same logs.
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
