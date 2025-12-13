import errno
import hashlib
import os
import queue
import socket
import ssl
import stat
import subprocess
import sys

import pytest

from src import client


# helpers
class FakeCompleted:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class FakeParent:
    def __init__(self, st_mode=16804):
        self.st_mode = st_mode

    def stat(self):
        return self

class FakeFile:
    def __init__(self, file_type='file', content="", st_mode=4516):
        self.file_type = file_type
        self.content = content
        self.st_mode = st_mode
        self.parent = FakeParent()

    def is_file(self):
        return self.file_type == 'file'

    def is_symlink(self):
        return self.file_type == 'symlink'

    def stat(self):
        return self

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


@pytest.fixture(scope="function")
def fake_bin(tmp_path):
    new_path = tmp_path
    new_path.chmod(new_path.stat().st_mode & ~stat.S_IWOTH)
    new_bin = new_path / "pow_benchmark"
    new_bin.touch()
    new_bin.chmod(new_bin.stat().st_mode & ~stat.S_IWOTH)
    return new_bin


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

    def test_tls_connect_non_local_host(self, monkeypatch):

        fake_context = FakeContext()

        def fake_create_default_context():
            return fake_context

        monkeypatch.setattr(client.ssl, "create_default_context",
                            fake_create_default_context)

        # make os.path.exists deterministic for prints
        monkeypatch.setattr(client.os.path, "exists", lambda p: True)

        with pytest.raises(ValueError, match="Refusing insecure TLS to"):
            client.tls_connect("cert.pem", "key.pem", "example.com")


class TestHasher:
    def test_hasher(self, authdata, random_string):
        assert (
            hashlib.sha1((authdata + random_string).encode()).hexdigest()  # noqa: S324
            == client.hasher(authdata, random_string)
        )


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
        e, _ = client.decipher_message(message, valid_messages)
        assert e == err
        out = readout()
        assert expected in out


@pytest.fixture(scope="class", autouse=True)
def pow_hash():
    return '000000dbb98b6c3a3bdc5a9ab0346633247d0ab9'


class TestRunPowBinary:
    def test_run_pow_binary_success(self, fake_bin, authdata, difficulty,
                                    suffix, pow_hash, path_to_pow_benchmark,
                                    monkeypatch, readout):

        calls = {}
        def fake_subprocess_run(args, *, text, capture_output, check, timeout, cwd, env):
            calls["args"] = args
            calls["text"] = text
            calls["capture_output"] = capture_output
            calls["check"] = check
            calls["timeout"] = timeout
            calls["cwd"] = cwd
            calls["env"] = env
            return FakeCompleted(stdout="RESULT:" + suffix + "\n", stderr="",
                                 returncode=0)
        monkeypatch.setattr(client.subprocess, "run", fake_subprocess_run)

        result = client.run_pow_binary(str(fake_bin), authdata, difficulty)

        assert isinstance(result, FakeCompleted)
        assert result.returncode == 0
        assert result.stdout == "RESULT:" + suffix + "\n"
        assert result.stderr == ""

        assert calls["args"] == [
            os.fspath(fake_bin),
            "gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzuWROTeTaSmqFCAzuwkwLCRgIIq",
            "6"
        ]
        assert calls["text"] is True
        assert calls["capture_output"] is True
        assert calls["check"] is True
        assert calls["timeout"] == 7200
        assert calls["cwd"] == os.fspath(fake_bin.parent)
        assert calls["env"] == {"LC_ALL": "C"}

    def test_run_pow_binary_non_str_authdata(self, fake_bin, difficulty,
                                             path_to_pow_benchmark):
        wrong_authdata = 5.3

        with pytest.raises(ValueError, match=r"authdata is not a string."):
            client.run_pow_binary(fake_bin, wrong_authdata, difficulty)

    def test_run_pow_binary_invalid_authdata(self, difficulty,
                                             fake_bin):
        wrong_authdata = 'poiasfdlkas+/'
        with pytest.raises(ValueError, match="authdata contains disallowed characters or length"):
            client.run_pow_binary(fake_bin, wrong_authdata, difficulty)

        wrong_authdata = 'poiasfdlkaspppppppppppppppppppppppppppppppppppppppppppppppp'\
            + 'asdfdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' \
            + 'asdfdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'
        with pytest.raises(ValueError, match="authdata contains disallowed characters or length"):
            client.run_pow_binary(fake_bin, wrong_authdata, difficulty)

    def test_run_pow_binary_non_int_difficulty(self, authdata,
                                               fake_bin):
        wrong_difficulty = 'five'
        with pytest.raises(TypeError, match="POW difficulty is not an integer"):
            client.run_pow_binary(fake_bin, authdata, wrong_difficulty)

    def test_run_pow_binary_invalid_difficulty(self, authdata,
                                               fake_bin):
        wrong_difficulty = 65
        with pytest.raises(ValueError, match="POW difficulty is out of range"):
            client.run_pow_binary(fake_bin, authdata, wrong_difficulty)

    def test_run_pow_binary_no_executable(self, authdata, difficulty,
                                          fake_bin):

        with pytest.raises(FileNotFoundError, match="POW binary not a regular file"):
            client.run_pow_binary(fake_bin.parent, authdata, difficulty)

    @pytest.mark.skipif(sys.platform.startswith("win"),
                        reason="POSIX chmod not supported on Windows")
    def test_run_pow_binary_writable_linux_executable(self, authdata, difficulty,
                                          fake_bin):

        fake_bin.chmod(0o777)
        with pytest.raises(PermissionError, match="Insecure permissions on"):
            client.run_pow_binary(fake_bin, authdata, difficulty)

    def test_run_pow_binary_error(self, authdata, difficulty, suffix,
                                  fake_bin, monkeypatch):
        def fake_subprocess_run(*a, **k):
            raise subprocess.CalledProcessError(
                returncode=1, stderr="Big, bad error",
                cmd="pow_benchmark gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzuWROTeTaSmqFC"\
                    +"AzuwkwLCRgIIq 6"
            )

        monkeypatch.setattr(client.subprocess, "run", fake_subprocess_run)
        with pytest.raises(subprocess.CalledProcessError):
            client.run_pow_binary(fake_bin, authdata, difficulty)


class TestHandlePowCpp:
    def test_handle_pow_cpp_success(self, fake_bin, authdata, difficulty, timeout,
                                    suffix, pow_hash, path_to_pow_benchmark,
                                    monkeypatch, readout):

        def fake_subprocess_run(*a, **k):
            return FakeCompleted(stdout="RESULT:" + suffix + "\n", stderr="",
                                 returncode=0)
        monkeypatch.setattr(client.subprocess, "run", fake_subprocess_run)

        err, suffix_output = client.handle_pow_cpp(authdata, difficulty,
                                      str(fake_bin))

        assert (err, suffix_output) == (0, (suffix + '\n').encode())

        out = readout()
        assert f"Authdata: {authdata}\nValid POW Suffix: {suffix}\n" \
               f"Hash: {pow_hash}" in out

    def test_handle_pow_cpp_no_executable(self, authdata, difficulty, timeout,
                                          path_to_pow_benchmark):

        with pytest.raises(FileNotFoundError, match="POW binary not a regular file"):
            client.handle_pow_cpp(authdata, difficulty, path_to_pow_benchmark, timeout)

    def test_handle_pow_cpp_no_result(self, authdata, difficulty, timeout,
                                      fake_bin, monkeypatch):

        def fake_subprocess_run(*a, **k):
            return FakeCompleted(stdout="RESULT:\n", stderr="", returncode=0)

        monkeypatch.setattr(client.subprocess, "run", fake_subprocess_run)

        with pytest.raises(ValueError, match=r"No RESULT found in POW output."):
            client.handle_pow_cpp(authdata, difficulty, fake_bin, timeout)


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
        out_string = (
            hashlib.sha1((authdata + args[1]).encode()).hexdigest()  # noqa: S324
            + " " + responses[args[0]] + "\n"
        )
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
            def close(self):
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
            def close(self):
                return None

        def fake_connect(*a, **k):
            raise exc()

        sock = FakeSocket()
        monkeypatch.setattr(sock, "connect", fake_connect)

        assert not client.connect_to_server(sock, 'localhost', 3481)

        out = readout()
        assert expected in out
