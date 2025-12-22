import hashlib
import os
import queue
import socket
import ssl
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from helpers import FakeContext, FakeSocket, FakeWrappedSock

from tlslp import client, protocol


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
    def __init__(self, file_type="file", content="", st_mode=4516):
        self.file_type = file_type
        self.content = content
        self.st_mode = st_mode
        self.parent = FakeParent()

    def is_file(self):
        return self.file_type == "file"

    def is_symlink(self):
        return self.file_type == "symlink"

    def stat(self):
        return self


class FakeMPQueue:
    def __init__(self):
        self._items = []
        self.created = {}
        self.block = True
        self.timeout = None

    def put(self, x):
        self._items.append(x)

    def get(self, block=True, timeout=None):
        if not self._items:
            raise RuntimeError("FakeMPQueue.get() called with no items")
        return self._items.pop(0)


class FakeProcess:
    def __init__(self, target=None, args=(), *, run_target=True, alive=False):
        self._target = target
        self._args = args
        self._run_target = run_target
        self._alive = alive
        self.terminated = False
        self.join_timeouts = []

    def start(self):
        if self._run_target and self._target is not None:
            self._target(*self._args)

    def join(self, timeout=None):
        self.join_timeouts.append(timeout)

    def is_alive(self):
        return self._alive

    def terminate(self):
        self.terminated = True


@pytest.fixture(scope="function")
def fake_bin(tmp_path):
    new_path = tmp_path
    # switch off others write access
    new_path.chmod(new_path.stat().st_mode & ~stat.S_IWOTH)
    new_bin = new_path / "pow_challenge"
    new_bin.touch()
    # switch off others write access
    new_bin.chmod(new_bin.stat().st_mode & ~stat.S_IWOTH)
    # switch on user, group, and others execute access
    new_bin.chmod(new_bin.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return new_bin


# unit tests
class TestTlsConnect:

    def test_prepare_client_socket_secure(self, monkeypatch):
        fake_context = FakeContext()

        def fake_create_default_context(*args, **kwargs):
            return fake_context

        monkeypatch.setattr(
            client.ssl, "create_default_context", fake_create_default_context
        )

        # make os.path.exists deterministic for prints
        monkeypatch.setattr(client.os.path, "exists", lambda p: True)

        wrapped_sock = client.prepare_client_socket(
            "ca.pem", "cert.pem", "key.pem", "localhost", True
        )

        # client_sock was created and is valid types
        assert isinstance(wrapped_sock, FakeWrappedSock)

        # certificate and key are successfully loaded
        assert ("chain", "cert.pem", "key.pem") in fake_context._loaded

        # check context parameters
        assert fake_context.check_hostname
        assert fake_context.verify_mode == ssl.CERT_REQUIRED

        # check wrapped calls
        assert len(fake_context.wrap_calls) == 1
        call = fake_context.wrap_calls[0]
        assert isinstance(call["sock"], socket.socket)
        assert call["server_hostname"] == "localhost"

    def test_prepare_client_socket_insecure(self, monkeypatch):
        fake_context = FakeContext()

        def fake_create_default_context():
            return fake_context

        monkeypatch.setattr(
            client.ssl, "create_default_context", fake_create_default_context
        )

        # make os.path.exists deterministic for prints
        monkeypatch.setattr(client.os.path, "exists", lambda p: True)

        wrapped_sock = client.prepare_client_socket(
            "ca.pem", "cert.pem", "key.pem", "localhost", False
        )

        # client_sock was created and is valid types
        assert isinstance(wrapped_sock, FakeWrappedSock)

        # certificate and key are successfully loaded
        assert len(fake_context._loaded) == 0

        # check context parameters
        assert not fake_context.check_hostname
        assert fake_context.verify_mode == ssl.CERT_NONE

        # check wrapped calls
        assert len(fake_context.wrap_calls) == 1
        call = fake_context.wrap_calls[0]
        assert isinstance(call["sock"], socket.socket)
        assert call["server_hostname"] == "localhost"

    def test_prepare_client_socket_non_local_host_insecure(self, monkeypatch):

        fake_context = FakeContext()

        def fake_create_default_context():
            return fake_context

        monkeypatch.setattr(
            client.ssl, "create_default_context", fake_create_default_context
        )

        # make os.path.exists deterministic for prints
        monkeypatch.setattr(client.os.path, "exists", lambda p: True)

        with pytest.raises(ValueError, match="Refusing insecure TLS to"):
            client.prepare_client_socket(
                "ca.pem", "cert.pem", "key.pem", "example.com", False
            )


class TestHasher:
    def test_hasher(self, token, random_string):
        assert hashlib.sha256(  # noqa: S324
            (token + random_string).encode()
        ).hexdigest() == client.hasher(token, random_string)


class TestDecipherMessage:
    @pytest.mark.parametrize(
        "message, is_err, expected, err_type, err_message",
        [
            ("MAILNUM LGTk\n", False, ["MAILNUM", "LGTk"], None, ""),
            ("", True, [], ValueError, "No args in the response"),
            ("INCORRECT LGTk\n", True, [], ValueError, "This response is not valid:"),
            ("MAILNUM\n", False, ["MAILNUM", ""], None, ""),
        ],
    )
    def test_decipher_message_cases(
        self, valid_messages, message, is_err, expected, err_type, err_message
    ):
        if is_err:
            with pytest.raises(err_type, match=err_message):
                client.decipher_message(message, valid_messages)
        else:
            args = client.decipher_message(message, valid_messages)
            assert len(args) > 1
            for arg, expect in zip(args, expected, strict=True):
                assert arg == expect


class TestRunPowBinary:
    def test_run_pow_binary_success(
        self,
        fake_bin,
        token,
        difficulty,
        suffix,
        pow_hash,
        path_to_pow_challenge,
        monkeypatch,
        readout,
    ):

        calls = {}

        def fake_subprocess_run(
            args, *, text, capture_output, check, timeout, cwd, env
        ):
            calls["args"] = args
            calls["text"] = text
            calls["capture_output"] = capture_output
            calls["check"] = check
            calls["timeout"] = timeout
            calls["cwd"] = cwd
            calls["env"] = env
            return FakeCompleted(
                stdout="RESULT:" + suffix + "\n", stderr="", returncode=0
            )

        monkeypatch.setattr(client.subprocess, "run", fake_subprocess_run)
        monkeypatch.setattr(client, "DEFAULT_ALLOWED_ROOT", fake_bin.parent)

        result = client.run_pow_binary(fake_bin, token, difficulty)

        assert isinstance(result, FakeCompleted)
        assert result.returncode == 0
        assert result.stdout == "RESULT:" + suffix + "\n"
        assert result.stderr == ""

        assert calls["args"] == [
            os.fspath(fake_bin),
            token,
            difficulty,
        ]
        assert calls["text"] is True
        assert calls["capture_output"] is True
        assert calls["check"] is True
        assert calls["timeout"] == 7200
        assert calls["cwd"] == os.fspath(fake_bin.parent)
        assert calls["env"] == {"LC_ALL": "C"}

    def test_run_pow_binary_non_str_token(
        self, fake_bin, difficulty, path_to_pow_challenge, monkeypatch
    ):
        wrong_token = 5.3

        monkeypatch.setattr(client, "DEFAULT_ALLOWED_ROOT", fake_bin.parent)
        with pytest.raises(TypeError, match=r"Tested variable is not a string."):
            client.run_pow_binary(fake_bin, wrong_token, difficulty)

    def test_run_pow_binary_invalid_token(self, difficulty, fake_bin, monkeypatch):
        wrong_token = "poiasfdlkas+/"

        monkeypatch.setattr(client, "DEFAULT_ALLOWED_ROOT", fake_bin.parent)
        with pytest.raises(
            ValueError, match="String contains disallowed characters or length"
        ):
            client.run_pow_binary(fake_bin, wrong_token, difficulty)

        wrong_token = (
            "poiasfdlkaspppppppppppppppppppppppppppppppppppppppppppppppp"
            + "asdfdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            + "asdfdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        )
        with pytest.raises(
            ValueError, match="String contains disallowed characters or length"
        ):
            client.run_pow_binary(fake_bin, wrong_token, difficulty)

    def test_run_pow_binary_non_int_difficulty(self, token, fake_bin, monkeypatch):
        wrong_difficulty = "five"
        monkeypatch.setattr(client, "DEFAULT_ALLOWED_ROOT", fake_bin.parent)

        with pytest.raises(TypeError, match="WORK difficulty is not an integer"):
            client.run_pow_binary(fake_bin, token, wrong_difficulty)

    def test_run_pow_binary_invalid_difficulty(self, token, fake_bin, monkeypatch):
        wrong_difficulty = 65
        monkeypatch.setattr(client, "DEFAULT_ALLOWED_ROOT", fake_bin.parent)

        with pytest.raises(ValueError, match="WORK difficulty is out of range"):
            client.run_pow_binary(fake_bin, token, wrong_difficulty)

    def test_run_pow_binary_error(
        self, token, difficulty, suffix, fake_bin, monkeypatch
    ):
        def fake_subprocess_run(*a, **k):
            raise subprocess.CalledProcessError(
                returncode=1,
                stderr="Big, bad error",
                cmd="pow_challenge gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzuWROTeTaSmqFC"
                + "AzuwkwLCRgIIq 6",
            )

        monkeypatch.setattr(client.subprocess, "run", fake_subprocess_run)
        monkeypatch.setattr(client, "DEFAULT_ALLOWED_ROOT", fake_bin.parent)
        with pytest.raises(subprocess.CalledProcessError):
            client.run_pow_binary(fake_bin, token, difficulty)

    def test_run_pow_binary_timeout(
        self, token, difficulty, suffix, fake_bin, monkeypatch
    ):
        timeout = 1

        def fake_subprocess_run(*a, **k):
            raise subprocess.TimeoutExpired(
                timeout=timeout,
                output="",
                stderr="",
                cmd="pow_challenge gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzuWROTeTaSmqFC"
                + "AzuwkwLCRgIIq 6",
            )

        monkeypatch.setattr(client.subprocess, "run", fake_subprocess_run)
        monkeypatch.setattr(client, "DEFAULT_ALLOWED_ROOT", fake_bin.parent)
        with pytest.raises(subprocess.TimeoutExpired):
            client.run_pow_binary(fake_bin, token, difficulty)


class TestHandlePowCpp:
    def test_handle_pow_cpp_success(
        self,
        fake_bin,
        token,
        difficulty,
        timeout,
        suffix,
        pow_hash,
        path_to_pow_challenge,
        monkeypatch,
        readout,
    ):

        def fake_subprocess_run(*a, **k):
            return FakeCompleted(
                stdout="RESULT:" + suffix + "\n", stderr="", returncode=0
            )

        monkeypatch.setattr(client.subprocess, "run", fake_subprocess_run)
        monkeypatch.setattr(client, "DEFAULT_ALLOWED_ROOT", fake_bin.parent)

        suffix_output = client.handle_pow_cpp(token, difficulty, fake_bin)

        assert suffix_output == suffix + "\n"

    def test_handle_pow_cpp_no_result(
        self, token, difficulty, timeout, fake_bin, monkeypatch
    ):

        def fake_subprocess_run(*a, **k):
            return FakeCompleted(stdout="RESULT:\n", stderr="", returncode=0)

        monkeypatch.setattr(client.subprocess, "run", fake_subprocess_run)
        monkeypatch.setattr(client, "DEFAULT_ALLOWED_ROOT", fake_bin.parent)

        with pytest.raises(ValueError, match=r"No RESULT found in WORK output."):
            client.handle_pow_cpp(token, difficulty, fake_bin, timeout)


class TestDefineResponse:
    def test_define_response_success_helo(
        self, token, valid_messages, path_to_pow_challenge, readout
    ):
        q = queue.Queue()
        responses = {}
        client.define_response(
            ["HELLO"], token, valid_messages, q, responses, path_to_pow_challenge
        )
        assert q.get() == (False, "HELLOBACK\n")

        out = readout()
        assert out == ""

    def test_define_response_success_end(
        self, token, valid_messages, path_to_pow_challenge, readout
    ):
        q = queue.Queue()
        responses = {}
        client.define_response(
            ["DONE"], token, valid_messages, q, responses, path_to_pow_challenge
        )
        assert q.get() == (False, "OK\n")

    def test_define_response_success_error(
        self, token, valid_messages, path_to_pow_challenge
    ):
        q = queue.Queue()
        responses = {}
        client.define_response(
            ["ERROR", "test", "args"],
            token,
            valid_messages,
            q,
            responses,
            path_to_pow_challenge,
        )
        assert q.get() == (False, "\n")

    def test_define_response_success(
        self, token, random_string, valid_messages, path_to_pow_challenge
    ):
        q = queue.Queue()
        responses = {"MAILNUM": "2"}
        args = ["MAILNUM", random_string]

        client.define_response(
            args, token, valid_messages, q, responses, path_to_pow_challenge
        )
        out_string = (
            hashlib.sha256((token + args[1]).encode()).hexdigest()  # noqa: S324
            + " "
            + responses[args[0]]
            + "\n"
        )
        assert q.get() == (False, out_string)

    def test_define_response_success_pow(
        self,
        token,
        difficulty,
        random_string,
        suffix,
        valid_messages,
        path_to_pow_challenge,
        monkeypatch,
    ):
        q = queue.Queue()
        responses = {"MAILNUM": "2"}
        args = ["WORK", token, difficulty]

        def fake_handle_pow_cpp(*args, **kwargs):
            return suffix + "\n"

        monkeypatch.setattr(client, "handle_pow_cpp", fake_handle_pow_cpp)

        client.define_response(
            args, token, valid_messages, q, responses, path_to_pow_challenge
        )
        assert q.get() == (False, suffix + "\n")

    def test_define_response_success_invalid(
        self, token, valid_messages, path_to_pow_challenge
    ):
        q = queue.Queue()
        responses = {}
        client.define_response(
            ["HELLOP"], token, valid_messages, q, responses, path_to_pow_challenge
        )
        assert q.get() == (True, "\n")

    def test_define_response_result_no_newline(
        self,
        token,
        difficulty,
        random_string,
        suffix,
        valid_messages,
        path_to_pow_challenge,
        monkeypatch,
    ):
        q = queue.Queue()
        responses = {"MAILNUM": "2"}
        args = ["WORK", token, difficulty]

        def fake_handle_pow_cpp(*args, **kwargs):
            return suffix

        monkeypatch.setattr(client, "handle_pow_cpp", fake_handle_pow_cpp)

        client.define_response(
            args, token, valid_messages, q, responses, path_to_pow_challenge
        )
        assert q.get() == (False, suffix)


class TestConnectToServer:
    def test_connect_to_server_success(self):

        sock = FakeSocket()
        # call connect_to_server(sock: socket.socket, server_host: str, port: int)
        assert client.connect_to_server(sock, "localhost", 1234)
        assert sock.calls["addr"] == ("localhost", 1234)

    @pytest.mark.parametrize(
        "exc, expected_err, err_msg",
        [
            (TimeoutError, protocol.TransportError, "Failed to connect to"),
            (ConnectionRefusedError, protocol.TransportError, "Failed to connect to"),
            (
                socket.gaierror,
                protocol.TransportError,
                "Failed to connect to",
            ),
            (
                ssl.SSLCertVerificationError,
                protocol.TransportError,
                "Failed to connect to",
            ),
            (
                ssl.SSLError,
                protocol.TransportError,
                "Failed to connect to",
            ),
            (
                OSError,
                OSError,
                "OSError",
            ),
        ],
    )
    def test_connect_to_server_exception(self, monkeypatch, exc, expected_err, err_msg):

        def fake_connect(*a, **k):
            raise exc

        sock = FakeSocket()
        monkeypatch.setattr(sock, "connect", fake_connect)

        with pytest.raises(expected_err, match=err_msg):
            client.connect_to_server(sock, "localhost", 1234)


class TestReceiveAndDecipherMessage:
    def test_receive_and_decipher_message_success(self, monkeypatch, valid_messages):
        fake_sock = FakeSocket()

        def fake_receive_message(sock, *args):
            fake_sock.calls["sock"] = sock
            return "MAILNUM LGTk"

        def fake_decipher_message(message, vm):
            fake_sock.calls["message"] = message
            fake_sock.calls["valid_messages"] = vm
            return ["MAILNUM", "LGTk"]

        monkeypatch.setattr(client, "receive_message", fake_receive_message)
        monkeypatch.setattr(client, "decipher_message", fake_decipher_message)

        args = client._receive_and_decipher_message(fake_sock, valid_messages)

        assert args == ["MAILNUM", "LGTk"]
        assert fake_sock.calls["sock"] is fake_sock
        assert fake_sock.calls["message"] == "MAILNUM LGTk"
        assert fake_sock.calls["valid_messages"] is valid_messages

    def test_receive_and_decipher_message_decipher_error(
        self, monkeypatch, valid_messages
    ):
        fake_sock = FakeSocket()

        def fake_receive_message(sock, *args):
            fake_sock.calls["sock"] = sock
            return "BADMSG"

        monkeypatch.setattr(client, "receive_message", fake_receive_message)

        def problem(*args, **kwargs):
            raise ValueError("Error!")

        monkeypatch.setattr(client, "decipher_message", problem)

        with pytest.raises(Exception) as e:
            client._receive_and_decipher_message(fake_sock, valid_messages)
        assert "Error!" in str(e)


class TestProcessMessageWithTimeout:
    def test_process_message_with_timeout_success_uses_timeout(
        self, monkeypatch, token, valid_messages
    ):
        q = FakeMPQueue()

        def fake_queue_ctor():
            return q

        def fake_process_ctor(target, args):
            p = FakeProcess(target=target, args=args, run_target=True, alive=False)
            q.created["p"] = p
            return p

        monkeypatch.setattr(client.multiprocessing, "Queue", fake_queue_ctor)
        monkeypatch.setattr(client.multiprocessing, "Process", fake_process_ctor)

        # if args[0] != "WORK" -> other_timeout
        response = client._process_message_with_timeout(
            args=["HELLO"],
            token=token,
            valid_messages=valid_messages,
            responses={},
            bin_path=Path("/path/to/challenge"),
            pow_timeout=999,
            other_timeout=123,
        )

        assert response == "HELLOBACK\n"
        assert q.created["p"].join_timeouts[0] == 123

    def test_process_message_with_timeout_success_uses_pow_timeout(
        self, monkeypatch, token, valid_messages, suffix
    ):
        q = FakeMPQueue()

        def fake_queue_ctor():
            return q

        def fake_process_ctor(target, args):
            # run target immediately; it will call handle_pow_cpp, so patch that
            p = FakeProcess(target=target, args=args, run_target=True, alive=False)
            q.created["p"] = p
            return p

        monkeypatch.setattr(client, "handle_pow_cpp", lambda *a, **k: suffix + "\n")
        monkeypatch.setattr(client.multiprocessing, "Queue", fake_queue_ctor)
        monkeypatch.setattr(client.multiprocessing, "Process", fake_process_ctor)

        response = client._process_message_with_timeout(
            args=["WORK", token, "6"],
            token=token,
            valid_messages=valid_messages,
            responses=client.DEFAULT_RESPONSES,
            bin_path=Path("/path/to/challenge"),
            pow_timeout=777,
            other_timeout=1,
        )

        assert response == suffix + "\n"
        assert q.created["p"].join_timeouts[0] == 777

    def test_process_message_with_timeout_times_out(
        self, monkeypatch, token, valid_messages
    ):
        q = FakeMPQueue()

        def fake_queue_ctor():
            return q

        def fake_process_ctor(target, args):
            p = FakeProcess(target=target, args=args, run_target=False, alive=True)
            q.created["p"] = p
            return p

        monkeypatch.setattr(client.multiprocessing, "Queue", fake_queue_ctor)
        monkeypatch.setattr(client.multiprocessing, "Process", fake_process_ctor)

        with pytest.raises(TimeoutError, match=r"MAILNUM function timed out\."):
            client._process_message_with_timeout(
                args=["MAILNUM", "LGTk"],
                token=token,
                valid_messages=valid_messages,
                responses=client.DEFAULT_RESPONSES,
                bin_path=Path("/path/to/challenge"),
                pow_timeout=1,
                other_timeout=1,
            )

        assert q.created["p"].terminated

    def test_process_message_with_timeout_command_failed(
        self, monkeypatch, token, valid_messages
    ):
        q = FakeMPQueue()
        q.put((True, "bad\n"))

        monkeypatch.setattr(client.multiprocessing, "Queue", lambda: q)
        monkeypatch.setattr(
            client.multiprocessing,
            "Process",
            lambda target, args: FakeProcess(
                target=target, args=args, run_target=False, alive=False
            ),
        )

        with pytest.raises(Exception, match=r"MAILNUM failed: bad"):
            client._process_message_with_timeout(
                args=["MAILNUM", "LGTk"],
                token=token,
                valid_messages=valid_messages,
                responses=client.DEFAULT_RESPONSES,
                bin_path=Path("/path/to/challenge"),
                pow_timeout=1,
                other_timeout=1,
            )


class TestMain:
    def test_main_success(self, monkeypatch, valid_messages, fake_bin):

        monkeypatch.setattr(client.os.path, "exists", lambda p: True)

        # force single port
        monkeypatch.setattr(client, "DEFAULT_PORTS", [1234])
        monkeypatch.setattr(client, "DEFAULT_SERVER_HOST", "localhost")

        fake_sock = FakeSocket()

        # fake TLS socket creation + connect
        monkeypatch.setattr(client, "prepare_client_socket", lambda *a, **k: fake_sock)
        monkeypatch.setattr(client, "connect_to_server", lambda sock, host, port: True)

        # drive the main loop with 2 messages then DONE
        seq = iter([["HELLO", ""], ["DONE", ""]])
        monkeypatch.setattr(
            client, "_receive_and_decipher_message", lambda *a, **k: next(seq)
        )

        def fake_process(args, *a, **k):
            return "HELLOBACK\n" if args[0] == "HELLO" else "OK\n"

        monkeypatch.setattr(client, "_process_message_with_timeout", fake_process)

        sent = []

        def fake_send_message(msg, sock, logger):
            sent.append((msg, sock))

        monkeypatch.setattr(client, "send_message", fake_send_message)
        monkeypatch.setattr(client, "DEFAULT_CPP_BINARY_PATH", str(fake_bin))
        monkeypatch.setattr(client, "DEFAULT_ALLOWED_ROOT", str(fake_bin.parent))

        client.main([])

        assert sent == [("HELLOBACK\n", fake_sock), ("OK\n", fake_sock)]
        assert fake_sock.closed

    def test_main_no_pow_binary(self, monkeypatch, valid_messages, readerr, tmp_path):

        bin_path = tmp_path / "non_existent_file.txt"
        monkeypatch.setattr(client, "DEFAULT_CPP_BINARY_PATH", str(bin_path))

        with pytest.raises(FileNotFoundError) as e:
            client.main([])

        assert "make build-cpp" in str(e.value)

    @pytest.mark.skipif(
        sys.platform.startswith("win"), reason="POSIX chmod not supported on Windows"
    )
    def test_main_pow_binary_not_executable(
        self, monkeypatch, valid_messages, readerr, fake_bin
    ):

        bin_path = fake_bin
        bin_path.chmod(bin_path.stat().st_mode & ~stat.S_IXUSR)
        monkeypatch.setattr(client, "DEFAULT_CPP_BINARY_PATH", str(bin_path))

        with pytest.raises(PermissionError) as e:
            client.main([])

        assert "is not executable" in str(e.value)

    @pytest.mark.skipif(
        sys.platform.startswith("win"), reason="POSIX chmod not supported on Windows"
    )
    def test_main_pow_binary_writable_linux_executable(
        self, monkeypatch, valid_messages, readerr, fake_bin
    ):
        bin_path = fake_bin
        bin_path.chmod(bin_path.stat().st_mode | stat.S_IWOTH)
        monkeypatch.setattr(client, "DEFAULT_CPP_BINARY_PATH", bin_path)

        with pytest.raises(PermissionError) as e:
            client.main([])

        assert "Insecure permissions" in str(e.value)

    def test_main_server_error(self, monkeypatch, valid_messages, fake_bin):

        monkeypatch.setattr(client.os.path, "exists", lambda p: True)

        # force single port
        monkeypatch.setattr(client, "DEFAULT_PORTS", [1234])
        monkeypatch.setattr(client, "DEFAULT_SERVER_HOST", "localhost")

        fake_sock = FakeSocket()

        # fake TLS socket creation + connect
        monkeypatch.setattr(client, "prepare_client_socket", lambda *a, **k: fake_sock)
        monkeypatch.setattr(client, "connect_to_server", lambda sock, host, port: True)

        # drive the main loop with 2 messages then DONE
        seq = iter([["HELLO", ""], ["ERROR", ""]])
        monkeypatch.setattr(
            client, "_receive_and_decipher_message", lambda *a, **k: next(seq)
        )

        def fake_process(args, *a, **k):
            if args[0] == "HELLO":
                return "HELLOBACK\n"
            return None

        monkeypatch.setattr(client, "_process_message_with_timeout", fake_process)
        monkeypatch.setattr(client, "DEFAULT_CPP_BINARY_PATH", str(fake_bin))
        monkeypatch.setattr(client, "DEFAULT_ALLOWED_ROOT", str(fake_bin.parent))

        sent = []

        def fake_send_message(msg, sock, logger):
            sent.append((msg, sock))

        monkeypatch.setattr(client, "send_message", fake_send_message)

        client.main([])

        assert sent == [("HELLOBACK\n", fake_sock)]
        assert fake_sock.closed

    def test_main_connect_fail(self, monkeypatch, fake_bin):
        monkeypatch.setattr(client.os.path, "exists", lambda p: True)
        monkeypatch.setattr(client, "DEFAULT_PORTS", [1234])
        monkeypatch.setattr(client, "DEFAULT_SERVER_HOST", "localhost")

        fake_sock = FakeSocket()
        monkeypatch.setattr(client, "prepare_client_socket", lambda *a, **k: fake_sock)

        def fake_connect(*a, **k):
            raise ConnectionRefusedError("nope")

        monkeypatch.setattr(client, "connect_to_server", fake_connect)

        # make sys.exit testable
        def fake_exit(code):
            raise SystemExit(code)

        monkeypatch.setattr(client.sys, "exit", fake_exit)
        monkeypatch.setattr(client, "DEFAULT_CPP_BINARY_PATH", str(fake_bin))
        monkeypatch.setattr(client, "DEFAULT_ALLOWED_ROOT", str(fake_bin.parent))

        with pytest.raises(SystemExit) as e:
            client.main([])
        assert e.value.code == 1


class TestBuildClientParser:
    def test_build_client_parser_defaults(self):
        p = client.build_client_parser()
        ns = p.parse_args([])
        assert ns.host == "localhost"
        assert isinstance(ns.ports, list)

    def test_build_client_parser_custom_ports(self):
        p = client.build_client_parser()
        ns = p.parse_args(["--ports", "1234,7883,8235"])
        assert ns.ports == [1234, 7883, 8235]
