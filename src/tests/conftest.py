import socket

import pytest


@pytest.fixture
def readout(capsys) -> str:
    def _():
        return capsys.readouterr().out.replace("\r\n", "\n").rstrip("\n")
    return _

@pytest.fixture
def path_to_pow_benchmark():
    return "path/to/pow_benchmark"

@pytest.fixture
def valid_messages():
    return {'MAILNUM', 'HELLO', 'WORK', 'ERROR'}

@pytest.fixture
def token():
    return 'gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzu' \
            + 'WROTeTaSmqFCAzuwkwLCRgIIq'

@pytest.fixture
def suffix():
    return '2biu'

@pytest.fixture
def random_string():
    return 'LGTk'

@pytest.fixture
def difficulty():
    return '6'

@pytest.fixture
def threads():
    return '2'

@pytest.fixture
def socket_pair():
    s1, s2 = socket.socketpair()
    s1.settimeout(1.0)
    s2.settimeout(1.0)
    try:
        yield s1, s2
    finally:
        for s in (s1, s2):
            try:
                s.close()
            except OSError:
                pass
