import socket
import ssl
import threading
from typing import Any

import pytest
import trustme


def _start_mtls_server(
    server_context: ssl.SSLContext,
) -> tuple[str, int, dict[str, Any], threading.Thread]:
    """
    Start a one-shot TLS server in a background thread.

    Returns:
        host, port, result_dict, thread
    """
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)

    host, port = lsock.getsockname()
    result = dict()
    ready = threading.Event()

    def srv() -> None:
        csock = None
        try:
            ready.set()
            csock, _ = lsock.accept()
            with server_context.wrap_socket(csock, server_side=True) as ssock:
                # If mTLS worked, the server will see a client cert here.
                result["peer_cert"] = ssock.getpeercert()
                ssock.sendall(b"hello\n")
                # Optional: read one line from client to ensure full duplex.
                _ = ssock.recv(1024)
        except Exception as e:
            result["error"] = e
        finally:
            lsock.close()
            if csock is not None:
                csock.close()

    t = threading.Thread(target=srv, daemon=True)
    t.start()
    ready.wait(timeout=2)
    return host, port, result, t


# integration tests
def test_tls_handshake_connect_insecure():

    # generate throwaway certificates
    ca = trustme.CA()
    server_cert = ca.issue_cert("localhost")

    # build server context
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_cert.configure_cert(server_context)

    # start a TLS server
    # start a TLS server
    host, port, _, t = _start_mtls_server(server_context)

    # build client context that trusts the CA
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.minimum_version = ssl.TLSVersion.TLSv1_2
    ca.configure_trust(client_context)
    client_context.check_hostname = False  # we're connecting by IP

    # connect and read
    with client_context.wrap_socket(
        socket.create_connection((host, port), timeout=3), server_hostname=None
    ) as c:
        assert c.recv(1024) == b"hello\n"

    t.join(timeout=1)


def test_tls_handshake_connect_secure():

    # generate throwaway certificates
    ca = trustme.CA()
    server_cert = ca.issue_cert("localhost")
    client_cert = ca.issue_cert("client")

    # build server context
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_cert.configure_cert(server_context)
    ca.configure_trust(server_context)
    server_context.verify_mode = ssl.CERT_REQUIRED

    # start a TLS server
    host, port, result, t = _start_mtls_server(server_context)

    # build client context that trusts the CA
    client_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ca.configure_trust(client_context)
    client_cert.configure_cert(client_context)  # <-- client presents cert to server
    client_context.check_hostname = True  # we're connecting by IP
    client_context.verify_mode = ssl.CERT_REQUIRED
    client_context.minimum_version = ssl.TLSVersion.TLSv1_2

    # connect and read
    with client_context.wrap_socket(
        socket.create_connection((host, port), timeout=2), server_hostname="localhost"
    ) as c:
        assert c.recv(1024) == b"hello\n"
        c.sendall(b"ok\n")

    t.join(timeout=1)

    assert not t.is_alive(), "Server thread did not finish."
    assert "error" not in result, f"Server error: {result.get('error')}."

    peer = result.get("peer_cert")
    assert peer, "server did not receive a client certificate (mTLS not active)"


def test_tls_handshake_connect_secure_no_cert():
    # generate throwaway certificates
    ca = trustme.CA()
    server_cert = ca.issue_cert("localhost")

    # build server context
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_cert.configure_cert(server_context)
    ca.configure_trust(server_context)
    server_context.verify_mode = ssl.CERT_REQUIRED

    # start a TLS server
    host, port, result, t = _start_mtls_server(server_context)

    # build client context that trusts the CA
    client_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ca.configure_trust(client_context)
    client_context.check_hostname = True  # we're connecting by IP
    client_context.verify_mode = ssl.CERT_REQUIRED
    client_context.minimum_version = ssl.TLSVersion.TLSv1_2

    # connect and read
    with (
        pytest.raises(ssl.SSLError),
        client_context.wrap_socket(
            socket.create_connection((host, port), timeout=2),
            server_hostname="localhost",
        ) as c,
    ):
        assert c.recv(1024) == b"hello\n"
        c.sendall(b"ok\n")

    t.join(timeout=1)

    assert not t.is_alive(), "Server thread did not finish."

    peer = result.get("peer_cert")
    assert not peer, "server received a client certificate (mTLS active)"
