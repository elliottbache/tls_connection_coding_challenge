import hashlib
import socket
from collections.abc import Callable
from typing import Any

import pytest

from tlslp.server import DEFAULT_DIFFICULTY


@pytest.fixture
def readout(capsys) -> Callable[[], Any]:
    def _():
        return capsys.readouterr().out.replace("\r\n", "\n").rstrip("\n")

    return _


@pytest.fixture
def readerr(capsys) -> Callable[[], Any]:
    def _():
        return capsys.readouterr().err.replace("\r\n", "\n").rstrip("\n")

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
    return "bgwrg"


@pytest.fixture
def pow_hash(token, suffix):
    return hashlib.sha256((token + suffix).encode()).hexdigest()  # noqa: S324


@pytest.fixture
def random_string():
    return "LGTk"


@pytest.fixture
def difficulty():
    return str(DEFAULT_DIFFICULTY)


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
