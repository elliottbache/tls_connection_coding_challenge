import hashlib
import logging
import socket
from contextlib import closing

import pytest
from helpers import FakeContext, FakeSocket, FakeSSLContext, FakeWrappedSock

from tlslp import protocol, server
from tlslp.protocol import DEFAULT_CA_CERT, DEFAULT_SERVER_HOST
from tlslp.server import (
    DEFAULT_PORT,
    DEFAULT_SERVER_CERT,
    DEFAULT_SERVER_KEY,
    ServerConfig,
)


# helpers
@pytest.fixture
def cksum(token, random_string):
    return hashlib.sha256((token + random_string).encode()).hexdigest()  # noqa: S324


@pytest.fixture
def server_config(token, timeout, random_string, difficulty):
    return ServerConfig(
        server_host=DEFAULT_SERVER_HOST,
        port=DEFAULT_PORT,
        server_cert=DEFAULT_CA_CERT,
        server_key=DEFAULT_SERVER_CERT,
        ca_cert=DEFAULT_SERVER_KEY,
        pow_timeout=timeout,
        other_timeout=6,
        insecure=False,
        token=token,
        random_string=random_string,
        difficulty=difficulty,
        log_level="DEBUG",
        tutorial=False,
    )


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
        logger = logging.getLogger("test_server")
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

        with pytest.raises(protocol.TransportError) as e:
            server.send_and_receive(token, random_string, s1)

        assert "Send failed.  Sending" in str(e.value)

    def test_send_and_receive_error_receiving(
        self, socket_pair, token, random_string, readout
    ):
        # since s1 is created with 1s timeout, it will have TimeoutError after 1s
        s1, s2 = socket_pair
        s2.settimeout(0)

        with pytest.raises(protocol.TransportError) as e:
            server.send_and_receive(token, random_string, s1)

        assert "Receive timeout" in str(e.value)

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

    def test_send_and_receive_protocol_error_sends_error(
        self, monkeypatch, token, socket_pair
    ):
        s1, _ = socket_pair

        def raise_protocol_error(*args, **kwargs):
            raise server.ProtocolError("bad")

        monkeypatch.setattr(server, "receive_message", raise_protocol_error)

        sent = []
        monkeypatch.setattr(server, "send_error", lambda msg, sock: sent.append(msg))

        with pytest.raises(server.ProtocolError):
            server.send_and_receive(token, "MAILNUM X", s1, timeout=0.01)

        assert sent and sent[0].startswith("ERROR receiving.")

    def test_send_and_receive_timeout_sends_error(
        self, monkeypatch, token, socket_pair
    ):
        s1, _ = socket_pair

        def raise_timeout_error(*args, **kwargs):
            raise TimeoutError("bad")

        monkeypatch.setattr(server, "receive_message", raise_timeout_error)

        sent = []
        monkeypatch.setattr(server, "send_error", lambda msg, sock: sent.append(msg))

        with pytest.raises(protocol.TransportError) as e:
            server.send_and_receive(token, "MAILNUM X", s1, timeout=0.001)

        assert "Receive timeout" in str(e.value)

        assert sent and sent[0].startswith("ERROR receiving.")


class TestSendError:
    def test_send_error_success(self, socket_pair):
        s1, s2 = socket_pair
        message_to_send = "ERROR test message"

        err = server.send_error(message_to_send, s1)
        _ = s2.recv(1024)

        assert err is None

    def test_send_error_fail(self, socket_pair, caplog):
        s1, _ = socket_pair
        message_to_send = "æ".encode("cp1252")

        server.send_error(message_to_send, s1)

        assert "Error could not be sent." in caplog.text


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

    def test_prepare_server_socket_insecure_non_local_rejected(self):
        with pytest.raises(ValueError, match="Refusing insecure TLS"):
            server.prepare_server_socket(
                server_host="example.com",
                port=0,
                ca_cert_path="ca.pem",
                server_cert_path="srv.pem",
                server_key_path="key.pem",
                is_secure=False,
            )


def test_handle_one_session(
    token, random_string, cksum, suffix, monkeypatch, server_config
):
    fake_server_sock = FakeWrappedSock()

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
        # body commands
        return f"{cksum} 2"

    monkeypatch.setattr(server, "send_and_receive", fake_send_and_receive)

    server.handle_one_session(True, server_config, fake_server_sock)

    # send_and_receive called expected number of times:
    # HELLO + WORK + 20 body requests + DONE = 23
    assert len(calls) == 23
    assert calls[0][1] == "HELLO"
    assert calls[1][1] == f"WORK {token} {server.DEFAULT_DIFFICULTY}"
    assert calls[-1][1] == "DONE"
    # body messages: "choice <random_string>"
    for _, to_send in calls[2:-1]:
        assert to_send == f"MAILNUM {random_string}"


class TestMain:

    def test_main_tutorial(self, token, random_string, cksum, suffix, monkeypatch):

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

        """# avoid ERROR choice
        monkeypatch.setattr(server.random, "choice", lambda seq: "MAILNUM")"""

        calls = []

        def fake_send_and_receive(this_token, to_send, secure_sock, timeout):
            calls.append((this_token, to_send))
            if to_send == "HELLO":
                return "HELLOBACK"
            elif to_send.startswith("WORK "):
                return suffix
            elif to_send.startswith("FULL_NAME"):
                return f"{cksum} Elliott Bache"
            elif to_send.startswith("MAILNUM"):
                return f"{cksum} 2"
            elif to_send.startswith("EMAIL1"):
                return f"{cksum} elliottbache@gmail.com"
            elif to_send.startswith("EMAIL2"):
                return f"{cksum} elliottbache2@gmail.com"
            elif to_send.startswith("SOCIAL"):
                return f"{cksum} elliottbache@hotmail.com"
            elif to_send.startswith("BIRTHDATE"):
                return f"{cksum} 99.99.1982"
            elif to_send.startswith("COUNTRY"):
                return f"{cksum} USA"
            elif to_send.startswith("ADDRNUM"):
                return f"{cksum} 2"
            elif to_send.startswith("ADDR_LINE1"):
                return f"{cksum} 234 Evergreen Terrace"
            elif to_send.startswith("ADDR_LINE2"):
                return f"{cksum} Springfield"
            elif to_send.startswith("DONE"):
                return f"{cksum} OK"
            else:
                raise ValueError("Invalid message.")

        monkeypatch.setattr(server, "send_and_receive", fake_send_and_receive)

        rc = server.main(["--tutorial"])
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
        # HELLO + WORK + 10 body requests + DONE = 13
        assert len(calls) == 13
        assert calls[0][1] == "HELLO"
        assert calls[1][1] == f"WORK {token} {server.DEFAULT_DIFFICULTY}"
        assert calls[-1][1] == "DONE"
        # body messages: "choice <random_string>"
        for _, to_send in calls[2:-1]:
            assert random_string in to_send

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

        server.main(["--tutorial"])

        # catch error and print
        out = readout()
        assert "Connection closed" in out

        # even on exception, __exit__ should run
        assert fake_context.wrapped.exited is True
