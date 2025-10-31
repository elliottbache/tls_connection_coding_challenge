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
