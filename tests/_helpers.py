"""Test helpers used by the unit tests.

These classes provide lightweight stand-ins for ``ssl.SSLContext``,
``ssl.SSLSocket``, and a basic socket object so tests can exercise the client
and server logic without opening real network connections or loading real PEM
files.

Classes:
    FakeContext:
        Minimal context used in tests that patch ``ssl.SSLContext`` or
        ``ssl.create_default_context``. Records certificate-loading calls and
        wrap parameters.

    FakeSSLContext:
        Minimal server-side SSL context used by ``server.main()`` tests. Returns
        a context-manager compatible ``FakeWrappedSock`` from ``wrap_socket``.

    FakeWrappedSock:
        Context-manager socket-like object with ``getpeername()``,
        ``getpeercert()``, and ``settimeout()`` used by server/client session
        handlers.

    FakeSocket:
        Socket-like object used to emulate connect/accept/recv behavior in tests.
        Note: ``recv()`` intentionally returns ``str`` (not ``bytes``) to validate
        protocol error handling paths.
"""


class FakeContext:
    """Test double for both client and server SSL contexts.

    - Client tests expect wrap_calls entries as dicts (server_hostname, etc.).
    - Server tests expect wrap_calls entries as tuples: (client_socket, server_side).
    """

    def __init__(self) -> None:
        self.purpose = None
        self.check_hostname = False
        self.verify_mode = None
        self._loaded: list[tuple] = []
        self.wrap_calls: list[object] = []  # dict (client) OR tuple (server)
        self.wrapped = FakeWrappedSock()

    def load_cert_chain(self, certfile=None, keyfile=None) -> None:
        self._loaded.append(("chain", certfile, keyfile))

    def load_verify_locations(self, cafile=None, capath=None, cadata=None) -> None:
        # record parameters for assertion if desired
        self._loaded.append(("ca", cafile, capath, bool(cadata)))

    def wrap_socket(self, sock, server_side: bool = False, **kwargs):
        # Server path: server_side is meaningful and no extra kwargs
        if server_side and not kwargs:
            self.wrap_calls.append((sock, server_side))
        else:
            # Client path: kwargs like server_hostname=...
            self.wrap_calls.append({"sock": sock, "server_side": server_side, **kwargs})

        return self.wrapped


class FakeWrappedSock:
    """Context-manager object returned by FakeSSLContext.wrap_socket()."""

    def __init__(self) -> None:
        self.exited = False
        self.timeout = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.exited = True
        return False

    def getpeername(self):
        return ("127.0.0.1", 12345)

    def getpeercert(self):
        return {
            "issuer": (("country", "US"), ("organization", "EB LLC")),
            "notAfter": "Nov 22 08:15:19 2056 GMT",
        }

    def settimeout(self, timeout):
        self.timeout = timeout


# create socket-like object
class FakeSocket:
    def __init__(self) -> None:
        self.accept_calls = 0
        self.calls = {}

    def connect(self, addr):
        self.calls["addr"] = addr
        return None

    def close(self):
        self.closed = True
        return None

    def accept(self):
        self.accept_calls += 1
        return object(), ("127.0.0.1", 54321)

    def recv(self, n):
        return "hello\n"  # <-- str, not bytes

    def settimeout(self, t):
        self.timeout = t

    def getpeercert(self):
        return {
            "issuer": (("country", "US"), ("organization", "EB LLC")),
            "notAfter": "Nov 22 08:15:19 2056 GMT",
        }
