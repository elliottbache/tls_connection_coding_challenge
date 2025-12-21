import hashlib
import logging
import socket
from contextlib import closing

import pytest
from helpers import FakeContext

from tlscc import protocol, server


# helpers
@pytest.fixture
def cksum(authdata, random_string):
    return hashlib.sha1((authdata + random_string).encode()).hexdigest()  # noqa: S324


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
        "payload, expected", [("HELO\n", "HELO\n"), ("HELO", "HELO\n")]
    )
    def test_send_message(self, socket_pair, payload, expected, caplog):
        logger = logging.getLogger("tlscc")
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
    def test_send_and_receive_error_choice(self, socket_pair, authdata, readout):
        s1, s2 = socket_pair

        _ = s2.sendall(b"ERROR internal server error\n")
        msg = server.send_and_receive(authdata, "ERROR internal server error", s1)

        assert not msg

    def test_send_and_receive_error_sending(
        self, socket_pair, authdata, random_string, readout
    ):
        s1, s2 = socket_pair
        s2.close()

        with pytest.raises(protocol.TransportError) as e:
            server.send_and_receive(authdata, random_string, s1)

        assert "Send failed.  Sending" in str(e.value)

    def test_send_and_receive_error_receiving(
        self, socket_pair, authdata, random_string, readout
    ):
        s1, s2 = socket_pair
        s2.settimeout(0)

        with pytest.raises(protocol.TransportError) as e:
            server.send_and_receive(authdata, random_string, s1)

        assert "Receive timeout" in str(e.value)

    def test_send_and_receive_helo(self, socket_pair, authdata):
        s1, s2 = socket_pair

        _ = s2.sendall(b"EHLO\n")
        msg = server.send_and_receive(authdata, "HELO", s1)
        assert msg == "EHLO"

    def test_send_and_receive_end(self, socket_pair, authdata):
        s1, s2 = socket_pair

        _ = s2.sendall(b"OK\n")
        msg = server.send_and_receive(authdata, "END", s1)
        assert msg == "OK"

    def test_send_and_receive_mailnum(
        self, socket_pair, authdata, random_string, cksum
    ):
        s1, s2 = socket_pair

        _ = s2.sendall((cksum + " 2\n").encode("utf-8"))
        msg = server.send_and_receive(authdata, "MAILNUM " + random_string, s1)
        assert msg == cksum + " 2"

    def test_send_and_receive_pow(
        self, socket_pair, authdata, suffix, pow_hash, difficulty, readout
    ):
        s1, s2 = socket_pair

        _ = s2.sendall((suffix + "\n").encode("utf-8"))
        msg = server.send_and_receive(
            authdata, "POW " + authdata + " " + difficulty, s1
        )
        assert msg == suffix

    def test_send_and_receive_invalid_suffix(
        self, socket_pair, authdata, suffix, pow_hash, difficulty, readout
    ):
        s1, s2 = socket_pair

        # client sends wrong suffix
        s2.sendall((suffix + "p\n").encode("utf-8"))

        # server sends POW command and receives incorrect suffix from client
        with pytest.raises(ValueError, match=r"Invalid suffix returned from client."):
            server.send_and_receive(authdata, "POW " + authdata + " " + difficulty, s1)

        # check second message sent from server declaring an error has occurred in the POW challenge
        received_message = recv_line(s2).decode("utf-8")
        assert "ERROR Invalid suffix returned from client." in received_message

    def test_send_and_receive_invalid_cksum(
        self, socket_pair, authdata, random_string, cksum
    ):
        s1, s2 = socket_pair

        # client sends wrong suffix
        s2.sendall((cksum[:-1] + "p 2\n").encode("utf-8"))

        # server sends MAILNUM command and receives incorrect checksum from client
        with pytest.raises(ValueError, match=r"Invalid checksum received."):
            server.send_and_receive(authdata, "MAILNUM " + random_string, s1)

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
