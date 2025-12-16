import hashlib
import socket
from contextlib import closing

import pytest

from src import server


# helpers
class FakeContext:
    def __init__(self):
        self.purpose = None
        self.verify_mode = None
        self._loaded = []

    def load_verify_locations(self, cafile=None, capath=None, cadata=None):
        # record parameters for assertion if desired
        self._loaded.append(("ca", cafile, capath, bool(cadata)))

    def load_cert_chain(self, certfile=None, keyfile=None):
        self._loaded.append(("chain", certfile, keyfile))


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
    def test_send_message(self, socket_pair, payload, expected):
        s1, s2 = socket_pair
        err = server.send_message(payload, s1)
        _ = s2.recv(1024)
        assert err is None


@pytest.fixture
def cksum(token, random_string):
    return hashlib.sha256((token + random_string).encode()).hexdigest()  # noqa: S324


class TestSendAndReceive:
    def test_send_and_receive_error_choice(self, socket_pair, token):
        s1, s2 = socket_pair

        _ = s2.sendall(b"ERROR internal server error\n")
        with pytest.raises(Exception, match=r"ERROR internal server error"):
            server.send_and_receive(token, "ERROR internal server error", s1)

    def test_send_and_receive_error_sending(
        self, socket_pair, token, random_string, readout
    ):
        s1, s2 = socket_pair
        s1.close()
        s2.close()

        with pytest.raises(Exception, match=r"Send failed."):
            server.send_and_receive(token, random_string, s1)

    def test_send_and_receive_error_receiving(
        self, socket_pair, token, random_string, readout
    ):
        s1, s2 = socket_pair
        s2.settimeout(0)

        with pytest.raises(Exception, match=r"Receive failed."):
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
        with pytest.raises(Exception, match=r"Invalid suffix returned from client."):
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
        with pytest.raises(Exception, match=r"Invalid checksum received."):
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
    def test_prepare_socket_with_mocked_ssl(self, monkeypatch, readout, tmp_path):
        fake_context = FakeContext()

        """def fake_create_default_context(purpose):
            fake_context.purpose = purpose
            return fake_context"""

        def fake_ssl_context(protocol_tls_server):
            fake_context.protocol_tls_server = protocol_tls_server
            return fake_context

        """monkeypatch.setattr(
            server.ssl, "create_default_context", fake_create_default_context
        )"""
        monkeypatch.setattr(server.ssl, "SSLContext", fake_ssl_context)

        """ca_cert_path = tmp_path / "ca.pem"
        server_cert_path = tmp_path / "srv.pem"
        server_key_path = tmp_path / "key.pem"
        server_sock, context = server.prepare_socket(
            "localhost",
            0,
            ca_cert_path=ca_cert_path,
            server_cert_path=server_cert_path,
            server_key_path=server_key_path,
        )"""
        server_sock, context = server.prepare_socket(
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
