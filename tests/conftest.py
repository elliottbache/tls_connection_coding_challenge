import hashlib
import os
import socket
from collections.abc import Callable
from typing import Any

import pytest


@pytest.fixture
def readout(capsys) -> Callable[[], Any]:
    def _():
        return capsys.readouterr().out.replace("\r\n", "\n").rstrip("\n")

    return _


@pytest.fixture
def path_to_pow_challenge():
    return "path/to/pow_challenge"


@pytest.fixture
def valid_messages():
    return {"MAILNUM", "HELLO", "WORK", "ERROR"}


@pytest.fixture
def token():
    return "gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzuWROTeTaSmqFCAzuwkwLCRgIIq"


@pytest.fixture
def suffix():
    return "2biu"


@pytest.fixture
def pow_hash(token, suffix):
    return hashlib.sha256((token + suffix).encode()).hexdigest()  # noqa: S324


@pytest.fixture
def random_string():
    return "LGTk"


@pytest.fixture
def difficulty():
    return "6"


@pytest.fixture
def timeout():
    return 7200


@pytest.fixture
def threads():
    return "2"


@pytest.fixture(scope="function")
def socket_pair():
    s1, s2 = socket.socketpair()
    s1.settimeout(1.0)
    s2.settimeout(1.0)
    try:
        yield s1, s2
    finally:
        try:
            s1.close()
        except OSError as e:
            print(f"OSError: {e}")
        try:
            s2.close()
        except OSError as e:
            print(f"OSError: {e}")


# create a non-persistent flag to not save log files for tests,
# especially during installation
def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--no-persistent-logs",
        action="store_true",
        default=False,
        help="Disable persistent file logging during tests.",
    )


@pytest.fixture(autouse=True)
def _disable_persistent_logs_if_requested(request: pytest.FixtureRequest) -> None:
    """
    If --no-persistent-logs is passed, tell the application code to not attach
    FileHandlers (so tests don't pollute persistent logs).
    """
    if request.config.getoption("--no-persistent-logs"):
        os.environ["TLSCC_DISABLE_FILE_LOGS"] = "1"
