import queue
import socket
import ssl
import threading

import pytest
import trustme

from src import server


# helpers
class FakeSock:
    def recv(self, n):
        return "hello\n"   # <-- str, not bytes


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


def peer(sock, q, to_send):
    received_message = sock.recv(1024)
    q.put(received_message)
    _ = sock.sendall(to_send)

    received_message = sock.recv(1024)
    q.put(received_message)
    q.put("__PEER_DONE__")

    try:
        sock.close()
    except OSError:
        pass

    return True


# unit tests
class TestSendMessage:
    @pytest.mark.parametrize(
        "payload, expected",
        [("HELO\n", "HELO\n"), ("HELO", "HELO\n")]
    )
    def test_send_message(self, socket_pair, readout, payload, expected):
        s1, s2 = socket_pair
        err = server.send_message(payload, s1)
        out = s2.recv(1024)
        assert err == 0
        assert out == expected.encode()
        assert readout() == "\nSending " + expected.rstrip("\n")


class TestReceiveMessage:
    def test_receive_message(self, socket_pair, readout):
        s1, s2 = socket_pair
        message_to_receive = b"EHLO\n"

        _ = s1.send(message_to_receive)
        received_message = server.receive_message(s2)

        assert received_message == "EHLO\n"

        out = readout()
        assert out == "Received " + message_to_receive.decode().rstrip("\n")

    def test_receive_message_non_utf(self, socket_pair, readout):
        s1, s2 = socket_pair
        message_to_receive = 'æ'.encode('cp1252')

        _ = s1.sendall(message_to_receive)
        err = server.receive_message(s2)
        assert err == -1

        out = readout()
        assert out.startswith("string is not valid: ")

    def test_receive_message_no_newline(self, socket_pair, readout):
        s1, s2 = socket_pair
        message_to_receive = b"EHLO"

        _ = s1.sendall(message_to_receive)
        err = server.receive_message(s2)
        assert err == -1

        out = readout()
        assert out == "string does not end with new line"

    def test_receive_empty_message(self, socket_pair, readout):
        s1, s2 = socket_pair
        s1.close()

        err = server.receive_message(s2)
        assert err == -1

        out = readout()
        assert out == "empty string"

    def test_receive_non_bytes(self, socket_pair, readout):
        sock = FakeSock()
        err = server.receive_message(sock)
        assert err == -1

        out = readout()
        assert out.startswith("unexpected type: ")


@pytest.fixture(scope="class")
def cksum():
    return 'bd8de303197ac9997d5a721a11c46d9ed0450798'


@pytest.fixture(scope="class")
def pow_hash():
    return '000000dbb98b6c3a3bdc5a9ab0346633247d0ab9'


class TestIsSucceedSendAndReceive:
    def test_is_succeed_send_and_receive_error_sending(
            self, socket_pair, authdata, random_string, readout
    ):
        s1, s2 = socket_pair
        s1.close()
        s2.close()

        err = server.is_succeed_send_and_receive(authdata, random_string, s1)
        assert not err

        out = readout()
        assert out.startswith("\nSending " + random_string
                              + "\nSend failed:")

    def test_is_succeed_send_and_receive_error_receiving(
            self, socket_pair, authdata, random_string, readout
    ):
        s1, s2 = socket_pair
        s2.close()

        err = server.is_succeed_send_and_receive(authdata, random_string, s1)
        assert not err

        out = readout()
        assert out.startswith("\nSending " + random_string
                              + "\nReceive failed:")

    def test_is_succeed_send_and_receive_helo(
            self, socket_pair, authdata, readout
    ):
        s1, s2 = socket_pair

        _ = s2.sendall(b'EHLO\n')
        err = server.is_succeed_send_and_receive(authdata, 'HELO', s1)
        assert err

        out = readout()
        assert out.startswith("\nSending HELO\nReceived EHLO")

    def test_is_succeed_send_and_receive_end(
            self, socket_pair, authdata, readout
    ):
        s1, s2 = socket_pair

        _ = s2.sendall(b'OK\n')
        err = server.is_succeed_send_and_receive(authdata, 'END', s1)
        assert err

        out = readout()
        assert out.startswith("\nSending END\nReceived OK")

    def test_is_succeed_send_and_receive_mailnum(
            self, socket_pair, authdata, random_string, cksum, readout
    ):
        s1, s2 = socket_pair

        _ = s2.sendall((cksum + ' 2\n').encode("utf-8"))
        err = server.is_succeed_send_and_receive(
            authdata, 'MAILNUM ' + random_string, s1
        )
        assert err

        out = readout()
        assert out.startswith("\nSending MAILNUM " + random_string
                              + "\nReceived " + cksum
                              + " 2\nChecksum received: " + cksum
                              + "\nChecksum calculated: " + cksum
                              + "\nValid checksum received."
                              )

    def test_is_succeed_send_and_receive_pow(
            self, socket_pair, authdata, suffix, pow_hash, difficulty, readout
    ):
        s1, s2 = socket_pair

        _ = s2.sendall((suffix + '\n').encode("utf-8"))
        err = server.is_succeed_send_and_receive(
            authdata, 'POW ' + authdata + ' ' + difficulty, s1
        )
        assert err

        out = readout()
        assert out.startswith(
            "\nSending POW " + authdata + " " + difficulty + "\nReceived "
            + suffix + "\n" + "POW suffix from client: " + suffix
            + "\nAuthentication data: " + authdata + "\n" + "Hash: "
            + pow_hash + "\n" + "Valid suffix returned from client."
        )

    def test_is_succeed_send_and_receive_invalid_suffix(
            self, socket_pair, authdata, suffix, pow_hash, difficulty, readout
    ):

        s1, s2 = socket_pair

        q = queue.Queue()

        # create thread for client actions
        t = threading.Thread(
            target=peer,
            args=(s2, q, (suffix + 'p\n').encode("utf-8"),),
            daemon=True
        )
        t.start()

        err = server.is_succeed_send_and_receive(authdata,
                                                 'POW ' + authdata + ' '
                                                 + difficulty, s1)
        assert not err

        t.join(timeout=2)
        assert not t.is_alive(), "peer did not finish"

        # check first message sent from server requesting POW challenge
        received_message = q.get(timeout=1)
        assert received_message == ("POW " + authdata + " " + difficulty
                                    + "\n").encode("utf-8")

        # check second message sent from server declaring an error has
        # occurred in the POW challenge
        received_message = q.get(timeout=1)
        assert received_message.decode().startswith(
            "ERROR from invalid POW challenge hash."
        )

        # check that stdout error is correctly printed
        out = readout()
        assert "Invalid suffix returned from client." in out

    def test_is_succeed_send_and_receive_invalid_cksum(
            self, socket_pair, authdata, random_string, cksum, readout
    ):

        s1, s2 = socket_pair

        q = queue.Queue()

        # create thread for client actions
        t = threading.Thread(
            target=peer, args=(s2, q, (cksum[:-1] + 'p 2\n').encode("utf-8"),),
            daemon=True
        )
        t.start()

        err = server.is_succeed_send_and_receive(
            authdata, 'MAILNUM ' + random_string, s1
        )
        assert not err

        t.join(timeout=2)

        # check first message sent from server requesting MAILNUM
        received_message = q.get(timeout=1)
        assert received_message == ("MAILNUM " +
                                    random_string + "\n").encode("utf-8")

        # check second message sent from server declaring an error has
        # occurred in the checksum
        received_message = q.get(timeout=1)
        assert received_message.decode().startswith(
            "ERROR from invalid checksum.")

        # check that stdout error is correctly printed
        out = readout()
        assert out.startswith("\nSending MAILNUM " + random_string
                              + "\nReceived " + cksum[:-1] + 'p'
                              + " 2\nChecksum received: " + cksum[:-1] + 'p'
                              + "\nChecksum calculated: " + cksum
                              + "\nInvalid checksum received."
                              )


class TestSendError:
    def test_send_error(self, socket_pair, readout):
        s1, s2 = socket_pair
        message_to_send = "ERROR test message"

        err = server.send_error(message_to_send, s1)
        _ = s2.recv(1024)

        assert not err

        out = readout()
        assert "Sending ERROR test message" in out
        assert "closing connection" in out


class TestPrepareSocket:
    def test_prepare_socket_with_mocked_ssl(self, monkeypatch, readout):
        fake_context = FakeContext()

        def fake_create_default_context(purpose):
            fake_context.purpose = purpose
            return fake_context

        monkeypatch.setattr(server.ssl, "create_default_context",
                            fake_create_default_context)

        server_sock, context = server.prepare_socket(
            "localhost", 0, ca_cert_path="ca.pem", server_cert_path="srv.pem",
            server_key_path="key.pem"
        )

        # server_sock and context were created and are valid types
        assert isinstance(server_sock, socket.socket)
        assert context is fake_context

        # socket bound to a valid port (positive integer)
        assert server_sock.getsockname()[1] > 0

        # CA, server certificate and server key are successfully loaded
        assert ("chain", "srv.pem", "key.pem") in fake_context._loaded
        assert ("ca", "ca.pem", None, False) in fake_context._loaded

        out = readout()
        assert out.startswith("Server listening on https://localhost:")


# integration tests
def test_tls_handshake_connect():

    # generate throwaway certificates
    ca = trustme.CA()
    server_cert = ca.issue_cert("localhost")

    # build server context
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_cert.configure_cert(server_ctx)

    # start a TLS server
    lsock = socket.socket()
    lsock.bind(("localhost", 0))
    lsock.listen(1)
    host, port = lsock.getsockname()

    def srv():
        csock, _ = lsock.accept()
        with server_ctx.wrap_socket(csock, server_side=True) as ssock:
            ssock.sendall(b"hello\n")

    t = threading.Thread(target=srv, daemon=True)
    t.start()

    # 4) Build client context that trusts the CA
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ca.configure_trust(client_ctx)
    client_ctx.check_hostname = False  # we're connecting by IP

    # 5) Connect and read
    with socket.create_connection((host, port), timeout=3) as s:
        with client_ctx.wrap_socket(s, server_hostname=None) as c:
            assert c.recv(1024) == b"hello\n"

    lsock.close()
    t.join(timeout=1)
