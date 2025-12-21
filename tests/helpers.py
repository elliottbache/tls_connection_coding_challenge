class FakeContext:
    def __init__(self):
        self.purpose = None
        self.check_hostname = False
        self.verify_mode = None
        self._loaded = []
        self.wrap_calls = []
        self.wrapped = FakeWrappedSock()

    def load_cert_chain(self, certfile=None, keyfile=None):
        self._loaded.append(("chain", certfile, keyfile))

    def wrap_socket(self, sock, **kwargs):
        self.wrap_calls.append({"sock": sock, **kwargs})
        return FakeWrappedSock()

    def load_verify_locations(self, cafile=None, capath=None, cadata=None):
        # record parameters for assertion if desired
        self._loaded.append(("ca", cafile, capath, bool(cadata)))


class FakeSSLContext:
    """Enough of ssl.SSLContext for server.main() to run."""

    def __init__(self) -> None:
        self.wrap_calls = []
        self.wrapped = FakeWrappedSock()

    def wrap_socket(self, client_socket, server_side: bool = False):
        self.wrap_calls.append((client_socket, server_side))
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
        return "Awesome socket"

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
