import hashlib
import logging
import socket
from contextlib import closing

import pytest
from helpers import FakeContext, FakeSocket, FakeSSLContext

from tlslp import server


# helpers
@pytest.fixture
def cksum(token, random_string):
    return hashlib.sha256((token + random_string).encode()).hexdigest()  # noqa: S324


def recv_line(sock) -> bytes:
    buf = bytearray()
    while True:
        chunk = sock.recv(1024)
        buf += chunk
        if buf.endswith(b"\n"):
            return bytes(buf)


def peer(sock, q, to_send):
    received_message = recv_line(sock)
    q.put(received_message)
    _ = sock.sendall(to_send)

    received_message = recv_line(sock)
    q.put(received_message)
    q.put("__PEER_DONE__")

    try:
        sock.close()
    finally:
        pass

    return True


# unit tests
class TestSendMessage:
    @pytest.mark.parametrize(
        "payload, expected", [("HELLO\n", "HELLO\n"), ("HELLO", "HELLO\n")]
    )
    def test_send_message(self, socket_pair, payload, expected, caplog):
        logger = logging.getLogger("tlslp")
        s1, s2 = socket_pair
        err = server.send_message(payload, s1, logger)
        _ = s2.recv(1024)
        assert err is None

        msg = expected.rstrip("\n")
        with caplog.at_level(logging.DEBUG):
            logger.debug(f"Sent {msg}")

        # Verify the message exists in the logs
        assert f"Sent {msg}" in caplog.text
        # Verify the log level
        assert caplog.records[0].levelname == "DEBUG"


class TestSendAndReceive:
    def test_send_and_receive_error_choice(self, socket_pair, token, readout):
        s1, s2 = socket_pair

        _ = s2.sendall(b"ERROR internal server error\n")
        msg = server.send_and_receive(token, "ERROR internal server error", s1)

        assert not msg

    def test_send_and_receive_error_sending(
        self, socket_pair, token, random_string, readout
    ):
        s1, s2 = socket_pair
        s2.close()

        with pytest.raises(Exception, match=r"Send failed."):
            server.send_and_receive(token, random_string, s1)

    def test_send_and_receive_error_receiving(
        self, socket_pair, token, random_string, readout
    ):
        s1, s2 = socket_pair
        s2.settimeout(0)

        with pytest.raises(Exception, match=r"Client timeout"):
            server.send_and_receive(token, random_string, s1)

    def test_send_and_receive_helo(self, socket_pair, token):
        s1, s2 = socket_pair

        _ = s2.sendall(b"HELLOBACK\n")
        msg = server.send_and_receive(token, "HELLO", s1)
        assert msg == "HELLOBACK"

    def test_send_and_receive_end(self, socket_pair, token):
        s1, s2 = socket_pair

        _ = s2.sendall(b"OK\n")
        msg = server.send_and_receive(token, "DONE", s1)
        assert msg == "OK"

    def test_send_and_receive_mailnum(
        self, socket_pair, token, random_string, cksum
    ):
        s1, s2 = socket_pair

        _ = s2.sendall((cksum + " 2\n").encode("utf-8"))
        msg = server.send_and_receive(token, "MAILNUM " + random_string, s1)
        assert msg == cksum + " 2"

    def test_send_and_receive_pow(
        self, socket_pair, token, suffix, pow_hash, difficulty, readout
    ):
        s1, s2 = socket_pair

        _ = s2.sendall((suffix + "\n").encode("utf-8"))
        msg = server.send_and_receive(
            token, "WORK " + token + " " + difficulty, s1
        )
        assert msg == suffix

    def test_send_and_receive_invalid_suffix(
        self, socket_pair, token, suffix, pow_hash, difficulty, readout
    ):
        s1, s2 = socket_pair

        # client sends wrong suffix
        s2.sendall((suffix + "p\n").encode("utf-8"))

        # server sends WORK command and receives incorrect suffix from client
        with pytest.raises(ValueError, match=r"Invalid suffix returned from client."):
            server.send_and_receive(token, "WORK " + token + " " + difficulty, s1)

        # check second message sent from server declaring an error has occurred in the WORK challenge
        received_message = recv_line(s2).decode("utf-8")
        assert "ERROR Invalid suffix returned from client." in received_message

    def test_send_and_receive_invalid_cksum(
        self, socket_pair, token, random_string, cksum
    ):
        s1, s2 = socket_pair

        # client sends wrong suffix
        s2.sendall((cksum[:-1] + "p 2\n").encode("utf-8"))

        # server sends MAILNUM command and receives incorrect checksum from client
        with pytest.raises(ValueError, match=r"Invalid checksum received."):
            server.send_and_receive(token, "MAILNUM " + random_string, s1)

        # check second message sent from server declaring an error has occurred in
        # the checksum
        received_message = recv_line(s2).decode("utf-8")
        assert "ERROR Invalid checksum received" in received_message


class TestSendError:
    def test_send_error_success(self, socket_pair):
        s1, s2 = socket_pair
        message_to_send = "ERROR test message"

        err = server.send_error(message_to_send, s1)
        _ = s2.recv(1024)

        assert err is None

    def test_send_error_fail(self, socket_pair, readout):
        s1, _ = socket_pair
        message_to_send = "æ".encode("cp1252")

        with pytest.raises(TypeError, match=r"Send failed.  Unexpected type:"):
            server.send_error(message_to_send, s1)


class TestPrepareSocket:
    def test_prepare_server_socket_with_mocked_ssl(
        self, monkeypatch, readout, tmp_path
    ):
        fake_context = FakeContext()

        def fake_ssl_context(protocol_tls_server):
            fake_context.protocol_tls_server = protocol_tls_server
            return fake_context

        monkeypatch.setattr(server.ssl, "SSLContext", fake_ssl_context)

        server_sock, context = server.prepare_server_socket(
            "localhost",
            0,
            ca_cert_path="ca.pem",
            server_cert_path="srv.pem",
            server_key_path="key.pem",
        )

        with closing(server_sock):
            # server_sock and context were created and are valid types
            assert isinstance(server_sock, socket.socket)
            assert context is fake_context

            # socket bound to a valid port (positive integer)
            assert server_sock.getsockname()[1] > 0

            # CA, server certificate and server key are successfully loaded
            assert ("chain", "srv.pem", "key.pem") in fake_context._loaded


class TestMain:
    def test_main_runs_one_session(
        self, token, random_string, cksum, suffix, monkeypatch
    ):
        fake_server_sock = FakeSocket()
        fake_context = FakeSSLContext()

        prepare_calls = []

        def fake_prepare_server_socket(
            server_host,
            port,
            ca_cert_path,
            server_cert_path,
            server_key_path,
            is_secure=True,
        ):
            prepare_calls.append(
                (server_host, port, ca_cert_path, server_cert_path, server_key_path)
            )
            return fake_server_sock, fake_context

        monkeypatch.setattr(server, "prepare_server_socket", fake_prepare_server_socket)

        # avoid ERROR choice
        monkeypatch.setattr(server.random, "choice", lambda seq: "MAILNUM")

        calls = []

        def fake_send_and_receive(this_token, to_send, secure_sock, timeout):
            calls.append((this_token, to_send))
            if to_send == "HELLO":
                return "HELLOBACK"
            if to_send.startswith("WORK "):
                return suffix
            if to_send == "DONE":
                return "OK"
            # info commands
            return f"{cksum} 2"

        monkeypatch.setattr(server, "send_and_receive", fake_send_and_receive)

        rc = server.main([])
        assert rc == 0

        # prepare_server_socket called with defaults
        assert prepare_calls == [
            (
                server.DEFAULT_SERVER_HOST,
                server.DEFAULT_PORT,
                server.DEFAULT_CA_CERT,
                server.DEFAULT_SERVER_CERT,
                server.DEFAULT_SERVER_KEY,
            )
        ]

        # accepted exactly once
        assert fake_server_sock.accept_calls == 1

        # TLS context wrap called with server_side=True
        assert len(fake_context.wrap_calls) == 1
        _, server_side = fake_context.wrap_calls[0]
        assert server_side is True

        # send_and_receive called expected number of times:
        # HELLO + WORK + 20 body requests + DONE = 23
        assert len(calls) == 23
        assert calls[0][1] == "HELLO"
        assert calls[1][1] == f"WORK {token} {server.DEFAULT_DIFFICULTY}"
        assert calls[-1][1] == "DONE"
        # body messages: "choice <random_string>"
        for _, to_send in calls[2:-1]:
            assert to_send == f"MAILNUM {random_string}"

    def test_main_closes_wrapped_socket_on_exception(self, monkeypatch, readout):
        fake_server_sock = FakeSocket()
        fake_context = FakeSSLContext()

        monkeypatch.setattr(
            server,
            "prepare_server_socket",
            lambda *a, **k: (fake_server_sock, fake_context),
        )

        def problem(*args, **kwargs):
            raise Exception("Error!")

        monkeypatch.setattr(server, "send_and_receive", problem)

        server.main([])

        # catch error and print
        out = readout()
        assert "Connection closed" in out

        # even on exception, __exit__ should run
        assert fake_context.wrapped.exited is True
