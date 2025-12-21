import datetime
import json
import logging
import os
import pathlib
import sys
from dataclasses import asdict, dataclass
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


class JsonFormatter(logging.Formatter):
    """Format logs as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        # use UTC timestamp
        ts = datetime.datetime.fromtimestamp(
            record.created, tz=datetime.UTC
        ).isoformat()

        exc_type = None
        exc_text = None
        if record.exc_info:
            exc_type = record.exc_info[0].__name__ if record.exc_info[0] else None
            exc_text = self.formatException(record.exc_info)

        payload = LogRecordPayload(
            ts=ts,
            level=record.levelname,
            logger=record.name,
            msg=record.getMessage(),
            module=record.module,
            func=record.funcName,
            line=record.lineno,
            pid=record.process,
            exc_type=exc_type,
            exc=exc_text,
        )
        return json.dumps(asdict(payload), ensure_ascii=False)


def _set_formatter(json_logs: bool, handler: logging.Handler) -> None:
    if json_logs:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                fmt="{asctime} {levelname} {name}: {message}",
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
    *, level: str = "INFO", json_logs: bool = False, node: str = "server"
) -> None:
    """
    Configure root logging for the application.

    Creates 2 handlers:
    1. Takes ```level``` (default ```INFO```) and sends to a log file in the
    XDG_STATE_HOME/tlslp/ (~/.local/state/tlslp in Linux)
    2. Takes "WARNING" and above and sends to stderr

    Args:
        level (str): Logging level name (e.g., "DEBUG", "INFO").
        json_logs (bool): If True, emit JSON lines, otherwise emit human-readable logs.
        node (str): Client or server
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

    # base class for StreamHandler and RotatingFileHandler allowing both to type check out
    handler: logging.Handler

    # create err handler (WARNING and above)
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setLevel("WARNING")
    _set_formatter(json_logs, handler)
    root.addHandler(handler)
    warn_logger.addHandler(handler)

    # we want to disable file logs for tests during installation.
    # this option is selected in the Makefile
    if os.getenv("TLSCC_DISABLE_FILE_LOGS", "").lower() in {"1", "true", "yes", "on"}:
        return None

    # define and create folder for saving log
    log_file = pathlib.Path(node).with_suffix(".log")
    fn = _default_log_dir() / log_file

    # create debug handler (all)
    handler = RotatingFileHandler(
        filename=fn, mode="a", maxBytes=50 * 1024 * 1024, backupCount=2
    )
    _set_formatter(json_logs, handler)
    root.addHandler(handler)
    handler.setLevel(numeric_level)
    _set_formatter(json_logs, handler)
    root.addHandler(handler)
    warn_logger.addHandler(handler)
