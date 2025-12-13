import errno
import hashlib
import queue
import socket
import ssl
import subprocess

import pytest

from src import client


# helpers
class FakeCompleted:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


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

    def wrap_socket(self, sock, **kwargs):
        self.wrap_calls.append({
            "sock": sock,
            **kwargs
        })
        return FakeWrappedSock()


# unit tests
class TestTlsConnect:

    def test_tls_connect(self, readout, monkeypatch):
        fake_context = FakeContext()

        def fake_create_default_context():
            return fake_context

        monkeypatch.setattr(client.ssl, "create_default_context",
                            fake_create_default_context)

        # make os.path.exists deterministic for prints
        monkeypatch.setattr(client.os.path, "exists", lambda p: True)

        wrapped_sock = client.tls_connect("cert.pem", "key.pem", "localhost")

        # client_sock was created and is valid types
        assert isinstance(wrapped_sock, FakeWrappedSock)

        # certificate and key are successfully loaded
        assert ("chain", "cert.pem", "key.pem") in fake_context._loaded

        # check context parameters
        assert not fake_context.check_hostname
        assert fake_context.verify_mode == ssl.CERT_NONE

        # check wrapped calls
        assert len(fake_context.wrap_calls) == 1
        call = fake_context.wrap_calls[0]
        assert isinstance(call["sock"], socket.socket)
        assert call["server_hostname"] == "localhost"

        out = readout()
        assert "Client cert exists: True" in out
        assert "Private key exists: True" in out


class TestHasher:
    def test_hasher(self, authdata, random_string):
        assert (hashlib.sha1((authdata + random_string).encode()).hexdigest()
                == client.hasher(authdata, random_string))


class TestDecipherMessage:
    @pytest.mark.parametrize("message, err, expected", [
        (b"MAILNUM LGTk\n", 0, "Received MAILNUM LGTk"),
        ("MAILNUM LGTk\n", 1, "string is not valid:"),
        (b"", 2, "No args in the response"),
        (b"INCORRECT LGTk\n", 2, "This response is not valid:"),
        (b"MAILNUM\n", 0, "Received MAILNUM")
    ])
    def test_decipher_message_cases(self, valid_messages, message, err,
                                    expected, readout):
        e, args = client.decipher_message(message, valid_messages)
        assert e == err
        out = readout()
        assert expected in out


@pytest.fixture(scope="class", autouse=True)
def pow_hash():
    return '000000dbb98b6c3a3bdc5a9ab0346633247d0ab9'


class TestHandlePowCpp:
    def test_handle_pow_cpp_success(self, authdata, difficulty,
                                    suffix, pow_hash, path_to_pow_benchmark,
                                    monkeypatch, readout):
        def fake_subprocess_run(*a, **k):
            return FakeCompleted(stdout="RESULT:" + suffix + "\n", stderr="",
                                 returncode=0)

        monkeypatch.setattr(client.subprocess, "run", fake_subprocess_run)

        assert (client.handle_pow_cpp(authdata, difficulty,
                                      path_to_pow_benchmark)
                == (0, (suffix + '\n').encode()))

        out = readout()
        assert f"Authdata: {authdata}\nValid POW Suffix: {suffix}\n" \
               f"Hash: {pow_hash}" in out

    def test_handle_pow_cpp_non_str_authdata(self, authdata, difficulty,
                                             path_to_pow_benchmark,
                                             readout):
        wrong_authdata = 5.3

        assert (client.handle_pow_cpp(wrong_authdata, difficulty,
                                      path_to_pow_benchmark)
                == (4, b'\n'))

        out = readout()
        assert "authdata is not a string.  Exiting since hashing function " \
               "will not work correctly" in out

    def test_handle_pow_cpp_non_int_difficulty(self, authdata, difficulty,
                                               path_to_pow_benchmark,
                                               readout):
        wrong_difficulty = 'five'

        assert (client.handle_pow_cpp(authdata, wrong_difficulty,
                                      path_to_pow_benchmark)
                == (4, b'\n'))

        out = readout()
        assert "POW difficulty is not an integer" in out

    def test_handle_pow_cpp_no_executable(self, authdata, difficulty,
                                          path_to_pow_benchmark, readout):

        assert (client.handle_pow_cpp(authdata, difficulty,
                                      path_to_pow_benchmark)
                == (4, b'\n'))

        out = readout()
        assert "POW benchmark executable not found." in out

    def test_handle_pow_cpp_error(self, authdata, difficulty, suffix,
                                  pow_hash, path_to_pow_benchmark, monkeypatch,
                                  readout):
        def fake_subprocess_run(*a, **k):
            raise subprocess.CalledProcessError(returncode=1, cmd=a[0],
                                                output="RESULT:" + suffix
                                                       + "\n", stderr="")

        monkeypatch.setattr(client.subprocess, "run", fake_subprocess_run)

        assert (client.handle_pow_cpp(authdata, difficulty,
                                      path_to_pow_benchmark)
                == (4, b'\n'))

        out = readout()
        assert "Error running executable:" in out

    def test_handle_pow_cpp_no_result(self, authdata, difficulty,
                                      suffix, pow_hash, path_to_pow_benchmark,
                                      monkeypatch, readout):
        def fake_subprocess_run(*a, **k):
            return FakeCompleted(stdout="RESULT:\n", stderr="", returncode=0)

        monkeypatch.setattr(client.subprocess, "run", fake_subprocess_run)

        assert (client.handle_pow_cpp(authdata, difficulty,
                                      path_to_pow_benchmark)
                == (4, b'\n'))

        out = readout()
        assert "No RESULT found in output." in out


class TestDefineResponse:
    def test_define_response_success_helo(self, authdata, valid_messages,
                                          path_to_pow_benchmark,
                                          readout):
        q = queue.Queue()
        responses = {}
        client.define_response(["HELO"], authdata, valid_messages, q,
                               responses, path_to_pow_benchmark)
        assert q.get() == [0, b'EHLO\n']

        out = readout()
        assert out == ""

    def test_define_response_success_end(self, authdata, valid_messages,
                                         path_to_pow_benchmark,
                                         readout):
        import queue

        q = queue.Queue()
        responses = {}
        client.define_response(["END"], authdata, valid_messages, q, responses,
                               path_to_pow_benchmark)
        assert q.get() == [1, b'OK\n']

        out = readout()
        assert out == ""

    def test_define_response_success_error(self, authdata, valid_messages,
                                           path_to_pow_benchmark,
                                           readout):
        import queue

        q = queue.Queue()
        responses = {}
        client.define_response(["ERROR", "test", "args"], authdata,
                               valid_messages, q, responses,
                               path_to_pow_benchmark)
        assert q.get() == [2, b'\n']

        out = readout()
        assert out == "Server error: test args"

    def test_define_response_success(self, authdata, random_string,
                                     valid_messages, path_to_pow_benchmark,
                                     readout):
        import queue
        q = queue.Queue()
        responses = {"MAILNUM": "2"}
        args = ["MAILNUM", random_string]

        client.define_response(args, authdata, valid_messages, q, responses,
                               path_to_pow_benchmark)
        out_string = (hashlib.sha1((authdata + args[1]).encode()).hexdigest()
                      + " " + responses[args[0]] + "\n")
        assert q.get() == [0, out_string.encode()]

        out = readout()
        assert ("Extra arguments = " + args[1] + "\nAuthentication data = "
                + authdata in out)

    def test_define_response_success_pow(self, authdata, difficulty,
                                         random_string, suffix, valid_messages,
                                         path_to_pow_benchmark,
                                         readout, monkeypatch):
        import queue
        q = queue.Queue()
        responses = {"MAILNUM": "2"}
        args = ["POW", authdata, difficulty]

        def fake_handle_pow_cpp(*args, **kwargs):
            return [0, (suffix + "\n").encode()]

        monkeypatch.setattr(client, "handle_pow_cpp", fake_handle_pow_cpp)

        client.define_response(args, authdata, valid_messages, q, responses,
                               path_to_pow_benchmark)
        assert q.get() == [0, (suffix + "\n").encode()]

        out = readout()
        assert "The time of execution of POW challenge is :" in out

    def test_define_response_success_invalid(self, authdata, valid_messages,
                                             path_to_pow_benchmark):
        import queue

        q = queue.Queue()
        responses = {}
        client.define_response(["HELOP"], authdata, valid_messages, q,
                               responses, path_to_pow_benchmark)
        assert q.get() == [4, b'\n']

    def test_define_response_result_no_newline(self, authdata, difficulty,
                                               random_string, suffix,
                                               valid_messages,
                                               path_to_pow_benchmark,
                                               readout, monkeypatch):
        import queue
        q = queue.Queue()
        responses = {"MAILNUM": "2"}
        args = ["POW", authdata, difficulty]

        def fake_handle_pow_cpp(*args, **kwargs):
            return [0, suffix.encode()]

        monkeypatch.setattr(client, "handle_pow_cpp", fake_handle_pow_cpp)

        client.define_response(args, authdata, valid_messages, q, responses,
                               path_to_pow_benchmark)
        assert q.get() == [0, (suffix + "\n").encode()]

        out = readout()
        assert "string does not end with new line" in out


class TestConnectToServer:
    def test_connect_to_server_success(self, readout):
        calls = {}

        # create socket-like object
        class FakeSocket:
            def connect(self, addr):
                calls["addr"] = addr
                return None

        # call connect_to_server(sock: socket.socket, hostname: str, port: int)
        assert client.connect_to_server(FakeSocket(), 'localhost', 3481)
        assert calls["addr"] == ("localhost", 3481)

        # check that "Connected to {port}\n" was printed
        out = readout()
        assert "Connected to 3481" in out

    @pytest.mark.parametrize("exc, expected", [
        (lambda: TimeoutError(), "Connect timeout to localhost:3481"),
        (lambda: ConnectionRefusedError(),
         "Connection refused by localhost:3481"),
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
    def test_connect_to_server_exception(self, readout, monkeypatch, exc,
                                         expected):
        # create socket-like object
        class FakeSocket:
            def connect(self, addr):
                return None

        def fake_connect(*a, **k):
            raise exc()

        sock = FakeSocket()
        monkeypatch.setattr(sock, "connect", fake_connect)

        assert not client.connect_to_server(sock, 'localhost', 3481)

        out = readout()
        assert expected in out
