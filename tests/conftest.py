import hashlib
import socket
from collections.abc import Callable
from typing import Any

import pytest

from tlslp.server import DEFAULT_N_BITS


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
def path_to_work_challenge():
    return "path/to/work_challenge"


@pytest.fixture
def valid_messages():
    return {"EMAIL1", "HELLO", "WORK", "FAIL"}


@pytest.fixture
def token():
    return "gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzuWROTeTaSmqFCAzuwkwLCRgIIq"


@pytest.fixture
def suffix():
    return "TlVR_"


@pytest.fixture
def work_hash(token, suffix):
    return hashlib.sha256((token + suffix).encode()).hexdigest()


@pytest.fixture
def random_string():
    return "LGTk"


@pytest.fixture
def n_bits():
    return str(DEFAULT_N_BITS)


@pytest.fixture
def timeout():
    return 1800


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
