import socket
import pytest

from src import server


# fixtures

@pytest.fixture
def random_string():
    return 'LGTk'

@pytest.fixture
def token():
    return 'gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzuWROTeTaSmqFCAzuwkwLCRgIIq'

@pytest.fixture
def cksum():
    return 'bd8de303197ac9997d5a721a11c46d9ed0450798'

@pytest.fixture
def suffix():
    return '2biu'

@pytest.fixture
def pow_hash():
    return '000000dbb98b6c3a3bdc5a9ab0346633247d0ab9'

@pytest.fixture
def difficulty():
    return '6'

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
        self._loaded.append(("ca", cafile))

    def load_cert_chain(self, certfile=None, keyfile=None):
        self._loaded.append(("chain", certfile, keyfile))

def peer(sock, q, to_send):
    received_message = sock.recv(1024)
    q.put(received_message)
    _ = sock.sendall(to_send)

    received_message = sock.recv(1024)
    q.put(received_message)

    try:
        sock.close()
    except OSError:
        pass

    return True

def norm(s: str) -> str:
    return s.replace("\r\n", "\n").rstrip("\n")

## unit tests
# send_message

def test_send_message(socket_pair, capsys):
    s1, s2 = socket_pair
    message_to_send = "HELLO\n"

    err = server.send_message(message_to_send, s1)
    out = s2.recv(1024)

    assert err == 0
    assert out.decode().endswith("\n")
    assert out == (message_to_send).encode()

    captured = capsys.readouterr()
    assert norm(captured.out) == "\nSending " + message_to_send.rstrip("\n")

def test_send_message_no_newline(socket_pair, capsys):
    s1, s2 = socket_pair
    message_to_send = "HELLO"

    err = server.send_message(message_to_send, s1)
    out = s2.recv(1024)

    assert err == 0
    assert out.decode().endswith("\n")
    assert out == (message_to_send + "\n").encode()

    captured = capsys.readouterr()
    assert norm(captured.out) == "\nSending " + message_to_send

# receive_message

def test_receive_message(socket_pair, capsys):
    s1, s2 = socket_pair
    message_to_receive = b"HELLOBACK\n"

    _ = s1.send(message_to_receive)
    received_message = server.receive_message(s2)

    assert received_message == "HELLOBACK\n"

    captured = capsys.readouterr()
    assert (norm(captured.out) == "Received "
            + message_to_receive.decode().rstrip("\n"))

def test_receive_message_non_utf(socket_pair, capsys):
    s1, s2 = socket_pair
    message_to_receive = u'æ'.encode('cp1252')

    _ = s1.send(message_to_receive)
    err = server.receive_message(s2)
    assert err == -1

    captured = capsys.readouterr()
    assert captured.out.startswith("string is not valid: ")

def test_receive_message_no_newline(socket_pair, capsys):
    s1, s2 = socket_pair
    message_to_receive = b"HELLOBACK"

    _ = s1.send(message_to_receive)
    err = server.receive_message(s2)
    assert err == -1

    captured = capsys.readouterr()
    assert norm(captured.out) == "string does not end with new line"

def test_receive_empty_message(socket_pair, capsys):
    s1, s2 = socket_pair
    s1.close()

    err = server.receive_message(s2)
    assert err == -1

    captured = capsys.readouterr()
    assert norm(captured.out) == "empty string"

def test_receive_non_bytes(socket_pair, capsys):
    sock = FakeSock()
    err = server.receive_message(sock)
    assert err == -1

    captured = capsys.readouterr()
    assert captured.out.startswith("unexpected type: ")

# is_succeed_send_and_receive

def test_is_succeed_send_and_receive_error_sending(socket_pair, token,
                                                   random_string, capsys):
    s1, s2 = socket_pair
    s1.close()
    s2.close()

    err = server.is_succeed_send_and_receive(token, random_string, s1)
    assert not err

    captured = capsys.readouterr()
    assert norm(captured.out).startswith("\nSending " + random_string
                                   + "\nSend failed:")

def test_is_succeed_send_and_receive_error_receiving(socket_pair, token,
                                                     random_string, capsys):
    s1, s2 = socket_pair
    s2.close()

    err = server.is_succeed_send_and_receive(token, random_string, s1)
    assert not err

    captured = capsys.readouterr()
    assert norm(captured.out).startswith("\nSending " + random_string
                                   + "\nReceive failed:")

def test_is_succeed_send_and_receive_helo(socket_pair, token, capsys):
    s1, s2 = socket_pair

    _ = s2.send(b'HELLOBACK\n')
    err = server.is_succeed_send_and_receive(token, 'HELLO',s1)
    assert err

    captured = capsys.readouterr()
    assert norm(captured.out).startswith("\nSending HELLO\nReceived HELLOBACK")

def test_is_succeed_send_and_receive_end(socket_pair, token, capsys):
    s1, s2 = socket_pair

    _ = s2.send(b'OK\n')
    err = server.is_succeed_send_and_receive(token, 'DONE',s1)
    assert err

    captured = capsys.readouterr()
    assert norm(captured.out).startswith("\nSending DONE\nReceived OK")

def test_is_succeed_send_and_receive_mailnum(socket_pair, token,
                                             random_string, cksum, capsys):
    s1, s2 = socket_pair

    _ = s2.send((cksum + ' 2\n').encode("utf-8"))
    err = server.is_succeed_send_and_receive(token,
                                             'MAILNUM ' + random_string, s1)
    assert err

    captured = capsys.readouterr()
    assert norm(captured.out).startswith("\nSending MAILNUM " + random_string
                                   + "\nReceived " + cksum
                                   + " 2\nChecksum received: "
                                   + cksum
                                   + "\nChecksum calculated: "
                                   + cksum
                                   + "\nValid checksum received.")

def test_is_succeed_send_and_receive_pow(socket_pair, token, suffix, pow_hash,
                                         difficulty, capsys):
    s1, s2 = socket_pair

    _ = s2.send((suffix + '\n').encode("utf-8"))
    err = server.is_succeed_send_and_receive(token,
                                             'WORK ' + token + ' ' + difficulty, s1)
    assert err

    captured = capsys.readouterr()
    assert norm(captured.out).startswith("\nSending WORK " + token + " " + difficulty
            + "\nReceived " + suffix + "\n"
            + "WORK suffix from client: "
            + suffix + "\nAuthentification data: "
            + token + "\n"
            + "Hash: " + pow_hash + "\n"
            + "Valid suffix returned from client.")

def test_is_succeed_send_and_receive_invalid_suffix(socket_pair, token,
                                                    suffix, pow_hash, difficulty, capsys):
    import threading
    import queue

    s1, s2 = socket_pair

    q = queue.Queue()

    # create thread for client actions
    t = threading.Thread(target=peer, args=(s2, q, (suffix + 'p\n').encode("utf-8"),), daemon=True)
    t.start()

    err = server.is_succeed_send_and_receive(token,
                                             'WORK ' + token + ' ' + difficulty, s1)
    assert not err

    t.join(timeout=2)
    assert not t.is_alive(), "peer did not finish"

    # check first messasge sent from server requesting WORK challenge
    received_message = q.get(timeout=1)
    assert received_message == ("WORK " + token + " " + difficulty + "\n").encode("utf-8")

    # check second message sent from server declaring an error has occurred in
    # the WORK challenge
    received_message = q.get(timeout=1)
    assert received_message.decode().startswith("ERROR from invalid WORK challenge hash.")

    # check that stdout error is correctly printed
    captured = capsys.readouterr()
    assert "Invalid suffix returned from client." in captured.out

def test_is_succeed_send_and_receive_invalid_cksum(socket_pair, token,
            random_string, cksum, capsys):
    import threading
    import queue

    s1, s2 = socket_pair

    q = queue.Queue()

    # create thread for client actions
    t = threading.Thread(target=peer, args=(s2, q, (cksum[:-1] + 'p 2\n').encode("utf-8"),), daemon=True)
    t.start()

    err = server.is_succeed_send_and_receive(token,
                                             'MAILNUM ' + random_string, s1)
    assert not err

    t.join(timeout=2)

    # check first messasge sent from server requesting MAILNUM
    received_message = q.get(timeout=1)
    assert received_message == ("MAILNUM " + random_string + "\n").encode("utf-8")

    # check second message sent from server declaring an error has occurred in
    # the checksum
    received_message = q.get(timeout=1)
    assert received_message.decode().startswith("ERROR from invalid checksum.")

    # check that stdout error is correctly printed
    captured = capsys.readouterr()
    assert norm(captured.out).startswith("\nSending MAILNUM " + random_string
                                   + "\nReceived " + cksum[:-1] + 'p'
                                   + " 2\nChecksum received: "
                                   + cksum[:-1] + 'p'
                                   + "\nChecksum calculated: "
                                   + cksum
                                   + "\nInvalid checksum received.")

# send_error

def test_send_error(socket_pair, capsys):
    s1, s2 = socket_pair
    message_to_send = "ERROR test message"

    err = server.send_error(message_to_send, s1)
    out = s2.recv(1024)

    assert not err

    captured = capsys.readouterr()
    assert norm(captured.out) == "\nSending ERROR test message\nclosing connection"

# prepare_socket

def test_prepare_socket_with_mocked_ssl(monkeypatch, capsys):
    fake_context = FakeContext()

    def fake_create_default_context(purpose):
        fake_context.purpose = purpose
        return fake_context

    monkeypatch.setattr(server.ssl, "create_default_context", fake_create_default_context)

    server_sock, context = server.prepare_socket("localhost", 0,
                                          ca_cert_path="ca.pem",
                                          server_cert_path="srv.pem",
                                          server_key_path="key.pem")

    # server_sock and context were created and are valid types
    assert isinstance(server_sock, socket.socket)
    assert context is fake_context

    # socket bound to a valid port (positive integer)
    assert server_sock.getsockname()[1] > 0

    # CA, server certificate and server key are succesfully loaded
    assert ("chain", "srv.pem", "key.pem") in fake_context._loaded
    assert ("ca", "ca.pem") in fake_context._loaded

    captured = capsys.readouterr()
    assert norm(captured.out).startswith("Server listening on https://localhost:")

## integration tests

def test_tls_handshake_connect(capsys):
    import ssl, trustme
    import threading

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