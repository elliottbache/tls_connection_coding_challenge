import pytest
import ssl, socket, errno
import hashlib, subprocess, queue
from src import client
from types import SimpleNamespace
import os, stat, textwrap
import time

# fixtures & helpers

@pytest.fixture
def path_to_pow_benchmark():
    return "path/to/pow_benchmark"

@pytest.fixture
def valid_messages():
    return {'MAILNUM', 'HELO', 'POW', 'ERROR'}

@pytest.fixture
def authdata():
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
def pow_hash():
    return '000000dbb98b6c3a3bdc5a9ab0346633247d0ab9'

@pytest.fixture
def server_port():
    return 3481

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

def norm(s: str) -> str:
    return s.replace("\r\n", "\n").rstrip("\n")

class FakeWrappedSock:
    pass

class FakeContext:
    def __init__(self):
        self.purpose = None
        self.check_hostname = False
        self.verify_mode = None
        self._loaded = []
        self.wrap_calls = []

    def load_cert_chain(self, certfile=None, keyfile=None):
        self._loaded.append(("chain", certfile, keyfile))

    def wrap_socket(self, sock, server_side=False, do_handshake_on_connect=True,
                    suppress_ragged_eofs=True, server_hostname=None, session=None):
        self.wrap_calls.append({
            "sock": sock,
            "server_side": server_side,
            "server_hostname": server_hostname,
        })
        return FakeWrappedSock()

## unit tests
# tls_connect

def test_tls_connect(capsys, monkeypatch):
    fake_context = FakeContext()

    def fake_create_default_context():
        return fake_context

    monkeypatch.setattr(client.ssl, "create_default_context", fake_create_default_context)

    # make os.path.exists deterministic for prints
    monkeypatch.setattr(client.os.path, "exists", lambda p: True)

    wrapped_sock = client.tls_connect("cert.pem", "key.pem", "localhost")

    # client_sock was created and is valid types
    assert isinstance(wrapped_sock, FakeWrappedSock)

    # certificate and key are succesfully loaded
    assert ("chain", "cert.pem", "key.pem") in fake_context._loaded

    # check context parameters
    assert not fake_context.check_hostname
    assert fake_context.verify_mode == ssl.CERT_NONE

    # check wrapped calls
    assert len(fake_context.wrap_calls) == 1
    call = fake_context.wrap_calls[0]
    assert isinstance(call["sock"], socket.socket)
    assert call["server_hostname"] == "localhost"
    assert call["server_side"] is False

    out = capsys.readouterr().out
    assert "Client cert exists: True" in out
    assert "Private key exists: True" in out

def test_hasher(authdata, random_string):
    assert (hashlib.sha1((authdata + random_string).encode()).hexdigest()
            == client.hasher(authdata, random_string))

def test_decipher_message_success(random_string, valid_messages, capsys):
    command = 'MAILNUM'
    err, message = client.decipher_message((command + " " + random_string + "\n").encode(), valid_messages)
    assert err == 0
    assert message == [command, random_string]

    captured = capsys.readouterr().out
    assert norm(captured).startswith("Received " + command)

def test_decipher_message_non_bytes(random_string, valid_messages, capsys):
    command = 'MAILNUM'
    err, message = client.decipher_message((command + " " + random_string + "\n"), valid_messages)
    assert err == 1
    assert message == [""]

    captured = capsys.readouterr().out
    assert norm(captured).startswith("string is not valid: ")
    assert "string is probably not UTF-8" in norm(captured)

def test_decipher_message_empty(random_string, valid_messages, capsys):
    command = b''
    err, message = client.decipher_message(command, valid_messages)
    assert err == 2
    assert message == [""]

    captured = capsys.readouterr().out
    assert "No args in the response" in norm(captured)

def test_decipher_message_invalid(random_string, valid_messages, capsys):
    command = 'INCORRECT_COMMAND'
    err, message = client.decipher_message((command + " " + random_string + "\n").encode(), valid_messages)
    assert err == 2
    assert message == [""]

    captured = capsys.readouterr().out
    assert "This response is not valid: " in norm(captured)

def test_decipher_message_one_arg(valid_messages, capsys):
    command = 'MAILNUM'
    err, message = client.decipher_message((command + "\n").encode(), valid_messages)
    assert err == 0
    assert message == [command, ""]

    captured = capsys.readouterr().out
    assert norm(captured).startswith("Received " + command)

def test_handle_pow_cpp_success(authdata, difficulty, threads, suffix, pow_hash, path_to_pow_benchmark, monkeypatch, capsys):
    def fake_subprocess_run(*a, **k):
        return SimpleNamespace(stdout="RESULT:" + suffix + "\n", stderr="", returncode=0)

    monkeypatch.setattr(client.subprocess, "run", fake_subprocess_run)

    assert client.handle_pow_cpp(authdata, difficulty, path_to_pow_benchmark, threads) == (0, (suffix + '\n').encode())

    captured = capsys.readouterr().out
    assert f"Authdata: {authdata}\nValid POW Suffix: {suffix}\n" \
           f"Hash: {pow_hash}" in captured

def test_handle_pow_cpp_non_str_authdata(authdata, difficulty, threads, path_to_pow_benchmark, capsys):
    wrong_authdata = 5.3

    assert client.handle_pow_cpp(wrong_authdata, difficulty, path_to_pow_benchmark, threads) == (4, '\n'.encode())

    captured = capsys.readouterr().out
    assert "authdata is not a string.  Exiting since hashing function " \
              "will not work correctly" in captured

def test_handle_pow_cpp_non_int_difficulty(authdata, difficulty, threads, path_to_pow_benchmark, capsys):
    wrong_difficulty = 'five'

    assert client.handle_pow_cpp(authdata, wrong_difficulty, path_to_pow_benchmark, threads) == (4, '\n'.encode())

    captured = capsys.readouterr().out
    assert "POW difficulty is not an integer" in captured

def test_handle_pow_cpp_no_executable(authdata, difficulty, threads, path_to_pow_benchmark, capsys):

    assert client.handle_pow_cpp(authdata, difficulty, path_to_pow_benchmark, threads) == (4, '\n'.encode())

    captured = capsys.readouterr().out
    assert "POW benchmark executable not found." in captured

def test_handle_pow_cpp_error(authdata, difficulty, threads, suffix, pow_hash, path_to_pow_benchmark, monkeypatch, capsys):
    def fake_subprocess_run(*a, **k):
        raise subprocess.CalledProcessError(returncode=1, cmd=a[0], output="RESULT:" + suffix + "\n", stderr="")

    monkeypatch.setattr(client.subprocess, "run", fake_subprocess_run)

    assert client.handle_pow_cpp(authdata, difficulty, path_to_pow_benchmark, threads) == (4, '\n'.encode())

    captured = capsys.readouterr().out
    assert "Error running executable:" in captured

def test_handle_pow_cpp_no_result(authdata, difficulty, threads, suffix, pow_hash, path_to_pow_benchmark, monkeypatch, capsys):
    def fake_subprocess_run(*a, **k):
        return SimpleNamespace(stdout="RESULT:\n", stderr="", returncode=0)

    monkeypatch.setattr(client.subprocess, "run", fake_subprocess_run)

    assert client.handle_pow_cpp(authdata, difficulty, path_to_pow_benchmark, threads) == (4, '\n'.encode())

    captured = capsys.readouterr().out
    assert "No RESULT found in output." in captured

def test_define_response_success_helo(authdata, valid_messages, path_to_pow_benchmark, threads, capsys):


    q = queue.Queue()
    responses = {}
    client.define_response(["HELO"], authdata, valid_messages, q, responses, path_to_pow_benchmark, threads)
    assert q.get() == [0, "EHLO\n".encode()]

    captured = capsys.readouterr().out
    assert norm(captured) == ""

def test_define_response_success_end(authdata, valid_messages, path_to_pow_benchmark, threads, capsys):
    import queue

    q = queue.Queue()
    responses = {}
    client.define_response(["END"], authdata, valid_messages, q, responses, path_to_pow_benchmark, threads)
    assert q.get() == [1, "OK\n".encode()]

    captured = capsys.readouterr().out
    assert norm(captured) == ""

def test_define_response_success_error(authdata, valid_messages, path_to_pow_benchmark, threads, capsys):
    import queue

    q = queue.Queue()
    responses = {}
    client.define_response(["ERROR", "test", "args"], authdata, valid_messages, q, responses, path_to_pow_benchmark, threads)
    assert q.get() == [2, "\n".encode()]

    captured = capsys.readouterr().out
    assert norm(captured) == "Server error: test args"

def test_define_response_success(authdata, random_string, valid_messages, path_to_pow_benchmark, threads, capsys):
    import queue
    q = queue.Queue()
    responses = {"MAILNUM": "2"}
    args = ["MAILNUM", random_string]

    client.define_response(args, authdata, valid_messages, q, responses, path_to_pow_benchmark, threads)
    out_string = hashlib.sha1((authdata + args[1]).encode()).hexdigest() + " " + responses[args[0]] + "\n"
    assert q.get() == [0, out_string.encode()]

    captured = capsys.readouterr().out
    assert "Extra arguments = " + args[1] + "\nAuthentification data = " +  authdata in norm(captured)

def test_define_response_success_pow(authdata, difficulty, random_string, suffix, valid_messages, path_to_pow_benchmark, threads, capsys, monkeypatch):
    import queue
    q = queue.Queue()
    responses = {"MAILNUM": "2"}
    args = ["POW", authdata, difficulty]

    def fake_handle_pow_cpp(*args, **kwargs):
        return [0, (suffix + "\n").encode()]

    monkeypatch.setattr(client, "handle_pow_cpp", fake_handle_pow_cpp)

    client.define_response(args, authdata, valid_messages, q, responses, path_to_pow_benchmark, threads)
    assert q.get() == [0, (suffix + "\n").encode()]

    captured = capsys.readouterr().out
    assert "The time of execution of POW challenge is :" in norm(captured)

def test_define_response_success_invalid(authdata, valid_messages, path_to_pow_benchmark, threads, capsys):
    import queue

    q = queue.Queue()
    responses = {}
    client.define_response(["HELOP"], authdata, valid_messages, q, responses, path_to_pow_benchmark, threads)
    assert q.get() == [4, "\n".encode()]

    captured = capsys.readouterr().out
    assert norm(captured) == ""

def test_define_response_result_no_newline(authdata, difficulty, random_string, suffix, valid_messages, path_to_pow_benchmark, threads, capsys, monkeypatch):
    import queue
    q = queue.Queue()
    responses = {"MAILNUM": "2"}
    args = ["POW", authdata, difficulty]

    def fake_handle_pow_cpp(*args, **kwargs):
        return [0, suffix.encode()]

    monkeypatch.setattr(client, "handle_pow_cpp", fake_handle_pow_cpp)

    client.define_response(args, authdata, valid_messages, q, responses, path_to_pow_benchmark, threads)
    assert q.get() == [0, (suffix + "\n").encode()]

    captured = capsys.readouterr().out
    assert "string does not end with new line" in norm(captured)

def test_connect_to_server_success(capsys):
    calls = {}
    # create socket-like object
    class FakeSocket():
        def connect(self, addr):
            calls["addr"] = addr
            return None

    # call connect_to_server(sock: socket.socket, hostname: str, port: int)
    assert client.connect_to_server(FakeSocket(), 'localhost', 3481)
    assert calls["addr"] == ("localhost", 3481)

    # check that "Connected to {port}\n" was printed
    captured = capsys.readouterr().out
    assert "Connected to 3481" in norm(captured)

@pytest.mark.parametrize("exc, expected", [
    (lambda: socket.timeout(), "Connect timeout to localhost:3481"),
    (lambda: ConnectionRefusedError(), "Connection refused by localhost:3481"),
    (lambda: socket.gaierror(8, "hostname not found"),
     "DNS/addr error for localhost:3481"),
    (lambda: ssl.SSLCertVerificationError("bad cert"),
     "Certificate verification failed for localhost:3481"),
    (lambda: ssl.SSLError("proto"),
     "TLS error during connect to localhost:3481"),
    (lambda: OSError(errno.EHOSTUNREACH, "no route"),
     "Host unreachable: localhost:3481"),
    (lambda: OSError(errno.ENETUNREACH, "net down"),
     "Network unreachable when connecting to localhost:3481"),
    (lambda: OSError(123, "weird"),
     "OS error connecting to localhost:3481:")
])

def test_connect_to_server_exception(capsys, monkeypatch, exc, expected):
    # create socket-like object
    class FakeSocket():
        def connect(self, addr):
            return None

    def fake_connect(*a, **k):
        raise exc()

    sock = FakeSocket()
    monkeypatch.setattr(sock, "connect", fake_connect)

    assert not client.connect_to_server(sock, 'localhost', 3481)

    captured = capsys.readouterr().out
    assert expected in norm(captured)