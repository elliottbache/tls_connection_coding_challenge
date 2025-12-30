"""Open a TLS client that responds to server messages as per the coding-challenge rules.

This follows a set of rules defined in the toy protocol demo. The specific rules and
the external IP address are not quoted here for confidentiality reasons.

The client connects to a server, receives newline-delimited commands, and responds
one-by-one. The handshake consists of ``HELLO`` followed by a ``WORK`` challenge. The
WORK challenge must be resolved within 2 hours; it is solved by invoking a compiled
C++ helper (``work_challenge``).

Main functions:
    prepare_client_socket:
        Create a TLS-wrapped socket (secure or insecure).

    hasher:
        Compute SHA256(token + payload) as a hex string.

    decipher_message:
        Parse and validate a received command line.

    handle_work_cpp:
        Run the WORK helper and parse its ``RESULT:<suffix>`` output line.

    define_response:
        Create the protocol response for a single server command.

    main:
        CLI entry point.
"""

import argparse
import errno
import hashlib
import logging
import math
import multiprocessing
import os
import re
import socket
import ssl
import stat
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from queue import Empty

from tlslp.logging_utils import configure_logging
from tlslp.protocol import (
    DEFAULT_BODY_MESSAGES,
    DEFAULT_CA_CERT,
    DEFAULT_OTHER_TIMEOUT,
    DEFAULT_SERVER_HOST,
    DEFAULT_WORK_TIMEOUT,
    MAX_LINE_LENGTH,
    TransportError,
    _parse_positive_int,
    receive_message,
    send_message,
)

DEFAULT_CPP_BINARY_PATH = str(
    Path(__file__).parent / "_bin/work_challenge"
)  # path to C++ executable
DEFAULT_ALLOWED_ROOT = str(Path(__file__).parent / "_bin")
DEFAULT_RESPONSES = {
    "FULL_FULL_NAME": "Elliott Bache",
    "EEMAIL1": "elliottbache@gmail.com",
    "EEMAIL2": "elliottbache2@gmail.com",
    "SOCIAL": "elliottbache@hotmail.com",
    "BIRTHDATE": "99.99.1982",
    "COUNTRY": "USA",
    "ADDR_LINE1": "234 Evergreen Terrace",
    "ADDR_LINE2": "Springfield",
}
DEFAULT_VALID_MESSAGES = set(DEFAULT_BODY_MESSAGES)
DEFAULT_VALID_MESSAGES.add("HELLO")
DEFAULT_VALID_MESSAGES.add("WORK")
DEFAULT_VALID_MESSAGES.add("DONE")
DEFAULT_VALID_MESSAGES.add("FAIL")
DEFAULT_PORTS = [3115, 7883, 8235, 38154, 1234, 55532]
DEFAULT_PRIVATE_KEY_PATH = "certificates/ec_private_key.pem"
DEFAULT_CLIENT_CERT_PATH = "certificates/client_cert.pem"

logger = logging.getLogger(__name__)


@dataclass
class ClientConfig:
    """Configuration for the TLS client CLI.

    This is built from CLI arguments and passed through to connection and message
    handling helpers.
    """

    server_host: str
    ports: list[int]
    client_cert: str
    private_key: str
    ca_cert: str
    work_binary: str
    work_timeout: int
    other_timeout: int
    insecure: bool
    log_level: str
    tutorial: bool


def _parse_port(s: str) -> int:
    try:
        p = int(s)
    except ValueError as e:
        raise argparse.ArgumentTypeError("port must be an integer") from e
    if not (0 < p < 65536):
        raise argparse.ArgumentTypeError("port out of range (1..65535)")
    return p


def build_client_parser() -> argparse.ArgumentParser:
    """Build the argparse parser for the ``tlslp-client`` CLI.

    Returns:
        argparse.ArgumentParser: Configured parser.
    """
    parser = argparse.ArgumentParser(
        prog="tlslp-client", description="TLS client for the toy protocol demo."
    )

    parser.add_argument(
        "--host",
        default=DEFAULT_SERVER_HOST,
        help=f"server hostname (default: {DEFAULT_SERVER_HOST})",
    )

    parser.add_argument(
        "--ports",
        default=DEFAULT_PORTS,
        type=lambda s: [_parse_port(x) for x in s.split(",")],
        help="comma-separated list of ports (e.g. 1234,8235)",
    )

    parser.add_argument(
        "--client-cert",
        default=DEFAULT_CLIENT_CERT_PATH,
        type=str,
        help="path to client certificate (PEM)",
    )
    parser.add_argument(
        "--private-key",
        default=DEFAULT_PRIVATE_KEY_PATH,
        type=str,
        help="path to client private key (PEM)",
    )
    parser.add_argument(
        "--ca-cert",
        default=DEFAULT_CA_CERT,
        type=str,
        help="path to client CA certificate (PEM)",
    )

    parser.add_argument(
        "--work-binary",
        default=DEFAULT_CPP_BINARY_PATH,
        type=str,
        help="path to work_binary executable",
    )

    parser.add_argument(
        "--work-timeout",
        default=DEFAULT_WORK_TIMEOUT,
        type=_parse_positive_int,
        help=f"timeout (s) for WORK (default: {DEFAULT_WORK_TIMEOUT})",
    )
    parser.add_argument(
        "--other-timeout",
        default=DEFAULT_OTHER_TIMEOUT,
        type=_parse_positive_int,
        help=f"timeout (s) for non-WORK steps (default: {DEFAULT_OTHER_TIMEOUT})",
    )

    parser.add_argument(
        "--insecure",
        action="store_true",
        help="skip server cert verification (ONLY for localhost dev)",
    )

    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )

    parser.add_argument(
        "--tutorial",
        action="store_true",
        help="Handle one connection then exit (useful for tests).",
    )

    return parser


def _merge_ports(ns: argparse.Namespace) -> list[int]:
    """Return the effective list of ports to try.

    Args:
        ns (argparse.Namespace): Parsed CLI args.

    Returns:
        list[int]: Ports to try in order.
    """
    if ns.ports:
        return ns.ports
    else:
        return DEFAULT_PORTS


def args_to_client_config(ns: argparse.Namespace) -> ClientConfig:
    """Convert parsed CLI args into a :class:`ClientConfig`.

    Args:
        ns (argparse.Namespace): Parsed CLI args.

    Returns:
        ClientConfig: Normalized configuration.
    """
    return ClientConfig(
        server_host=ns.host,
        ports=_merge_ports(ns),
        client_cert=ns.client_cert,
        private_key=ns.private_key,
        ca_cert=ns.ca_cert,
        work_binary=ns.work_binary,
        work_timeout=ns.work_timeout,
        other_timeout=ns.other_timeout,
        insecure=ns.insecure,
        log_level=ns.log_level,
        tutorial=ns.tutorial,
    )


def prepare_client_socket(
    ca_cert_path: str,
    client_cert_path: str,
    private_key_path: str,
    server_host: str,
    is_secure: bool = False,
) -> socket.socket:
    """Create a TLS-wrapped client socket.

    In secure mode (``is_secure=True``), the client verifies the server certificate
    against ``ca_cert_path`` and enables hostname verification.

    In insecure mode (``is_secure=False``), certificate verification is disabled and
    hostname checks are disabled; to avoid accidental misuse, insecure mode is only
    allowed for ``localhost``.

    The returned socket has a default timeout of
    ``min(DEFAULT_OTHER_TIMEOUT, DEFAULT_WORK_TIMEOUT)``; callers may override this via
    ``settimeout(...)``.

    Args:
        ca_cert_path (str): Path to CA certificate (PEM).
        client_cert_path (str): Path to client certificate (PEM).
        private_key_path (str): Path to client private key (PEM).
        server_host (str): Server hostname.
        is_secure (bool, optional): If True, verify the server certificate and hostname.

    Returns:
        socket.socket: A TLS-wrapped socket ready to ``connect(...)``.

    Raises:
        ValueError: If insecure mode is requested for a non-local host.
    """
    # check that server_host is local if insecure mode, otherwise raise error so
    # that insecure connection isn't mistakenly used
    if not is_secure and server_host != "localhost":
        raise ValueError(
            f"Refusing insecure TLS to {server_host}. For "
            f"non-local hosts, enable certificate verification."
        )

    # create the client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(min(DEFAULT_OTHER_TIMEOUT, DEFAULT_WORK_TIMEOUT))

    if is_secure:
        # create an SSL context, loading CA certificate
        context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH, cafile=ca_cert_path
        )

        # load the client's private key and certificate
        context.load_cert_chain(certfile=client_cert_path, keyfile=private_key_path)

        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

    else:
        # create an SSL context
        context = ssl.create_default_context()

        # disable server certificate verification (not recommended for production)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    context.minimum_version = ssl.TLSVersion.TLSv1_2
    wrapped = context.wrap_socket(client_socket, server_hostname=server_host)
    wrapped.settimeout(min(DEFAULT_OTHER_TIMEOUT, DEFAULT_WORK_TIMEOUT))

    return wrapped


def hasher(token: str, input_string: str) -> str:
    """Hash a string using SHA256.

    Concatenates ``token`` and ``input_string`` and returns the SHA256 digest in
    lowercase hex.

    Args:
        token (str): Authentication data provided by the server.
        input_string (str): ASCII payload provided by the server.

    Returns:
        str: SHA256(token + input_string) as lowercase hex.

    Examples:
        >>> from tlslp.client import hasher
        >>> auth = "AUTH"
        >>> hasher(auth, "LGTk")
        '189af41571a36ba3655451530a84e33f018bdca2'
    """
    to_be_hashed = token + input_string
    cksum_in_hex = hashlib.sha256(to_be_hashed.encode()).hexdigest()  # noqa: S324

    return cksum_in_hex


def decipher_message(message: str, valid_messages: set[str]) -> list[str]:
    """Parse and validate a server message.

    Splits the message into whitespace-delimited tokens and validates that the first
    token is a known command. If the server sends only a command (no argument), an
    empty second token is appended so callers can uniformly access ``args[1]``.

    Args:
        message (str): The received message line (with or without trailing newline).
        valid_messages (set[str]): Allowed command names.

    Returns:
        list[str]: Parsed tokens, with at least two elements.

    Raises:
        ValueError: If the message is empty or the command is not in ``valid_messages``.

    Examples:
        >>> from tlslp.client import decipher_message
        >>> vm = {"EEMAIL1", "HELLO", "WORK", "DONE", "FAIL"}
        >>> decipher_message("EEMAIL1 LGTk\\n", vm)
        ['EEMAIL1', 'LGTk']
    """
    args = message.split()

    # check that the message has arguments
    if not args:
        raise ValueError(f"No args in the response: {message}")

    # check that message belongs to list of possible messages
    if args[0] not in valid_messages:
        raise ValueError(
            f"This response is not valid: {message}. "
            f"Valid messages: {valid_messages}"
        )

    # if only 1 argument is received add another empty string argument
    # to avoid errors since server is supposed to send 2 args.
    if len(args) == 1:
        args.append("")

    return args


def _is_world_writable(path: Path) -> bool:
    """Check if path is world writable.

    A world writable path is one where anyone can write to this path,
    not only the owner.

    Args:
          path (Path): The path to be checked.

    Returns:
          bool: Whether the path is world writable.  Returns False for
          0 and True for all other ints

    Notes:
        - mode is an int representing info for file system object "path"
          converting to octal gives the more typical representation
        - e.g. 100644 is for a regular file where the owner has
          read/write permissions, and the group and others have
          read-only access (rw-r--r--).
        - r=4, w=2, x=1: e.g. u+rwx, g+rw, a+r -> 0o764
        - stat.S_IWOTH = 0o002 (corresponds to a+w)
        - since 4 = 0b100, 2 = 0b010, 1 = 0b001: 4 & 2 = 0, 6 & 2 = 2
    """
    try:
        mode = path.stat().st_mode
        if os.name == "posix":
            return bool(mode & stat.S_IWOTH)
        else:
            return False  # Windows is assumed to be OK
    except OSError:
        return True


def _validate_path(bin_path: Path, allowed_root: Path | None = None) -> bool:
    """Validate that a binary path is safe to execute.

    Checks:
    - not a symlink
    - executable bit set (POSIX)
    - not world-writable (file or parent directory)
    - (optional) located under ``allowed_root``

    Args:
        bin_path (Path): Path to the binary.
        allowed_root (Path | None): If provided, require ``bin_path`` to be under this root.

    Returns:
        bool: True if all checks pass.

    Raises:
        PermissionError: If a safety check fails.
    """

    # check if it's a symbolic link
    if bin_path.is_symlink():
        raise PermissionError(f"Refusing to execute symlink: {bin_path}")
    # check if it's executable
    if os.name == "posix" and not os.access(bin_path, os.X_OK):
        raise PermissionError(f"WORK binary at {bin_path} is not executable.")
    # check if it's world writable
    if _is_world_writable(bin_path) or _is_world_writable(bin_path.parent):
        raise PermissionError(f"Insecure permissions on {bin_path} or its directory")
    # check if it's in an allowed folder
    if allowed_root is not None:
        root = allowed_root.resolve(strict=True)
        if not bin_path.is_relative_to(root):
            raise PermissionError(
                f"Insecure directory location {bin_path.parent} for {bin_path}"
            )

    return True


def _validate_string(s: str) -> None:
    """Validate a protocol string for charset and length.

    Args:
        s (str): String to validate.

    Raises:
        TypeError: If ``s`` is not a str.
        ValueError: If the string contains disallowed characters or exceeds limits.
    """
    if not isinstance(s, str):
        raise TypeError(
            "Tested variable is not a string.  Exiting since hashing function "
            "will not work correctly"
        )

    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", s):
        raise ValueError("String contains disallowed characters or length")

    if len(s) > MAX_LINE_LENGTH:
        raise ValueError("String too long")


def _validate_difficulty(difficulty: str) -> None:
    """Validate WORK difficulty.

    Args:
        difficulty (str): Difficulty string received from the server.

    Raises:
        TypeError: If difficulty cannot be converted to an int.
        ValueError: If difficulty is outside the allowed range.
    """
    try:
        idifficulty = int(difficulty)
    except (ValueError, TypeError) as e:
        raise TypeError("WORK difficulty is not an integer") from e

    if idifficulty < 0 or idifficulty > 64:
        raise ValueError("WORK difficulty is out of range")


def _check_inputs(token: str, difficulty: str) -> None:
    """Validate WORK inputs before invoking the external solver.

    Args:
        token (str): Authentication data.
        difficulty (str): WORK difficulty.

    Raises:
        TypeError: If types are invalid.
        ValueError: If values are outside the accepted charset/range.
    """
    # validate token
    _validate_string(token)

    # validate difficulty as an int
    _validate_difficulty(difficulty)


def run_work_binary(
    bin_path: Path, token: str, difficulty: str, timeout: int = 7200
) -> subprocess.CompletedProcess:
    """Run the WORK challenge C++ binary.

    Args:
        bin_path (Path): The path of the C++ binary.
        token (str): The token to use.
        difficulty (str): The difficulty to use.
        timeout (int, optional): The timeout to use.

    Returns:
        subprocess.CompletedProcess: The completed process.

    Notes:
        In subprocess.run,
            - the environment variables are scrubbed, leaving only the
              simplest (env={"LC_ALL": "C"})
            - the stdout and stderr are returned as text and not bytes
              (text=True, capture_output=True)
            - the exit status is returned and a CalledProcessError
              exception is raised if non-zero (check=True)
            - the timeout is set at 2 hours (timeout=timeout)
            - the current working directory is set as the binary's
              directory to avoid flakiness in tests
              (cwd=str(cpp_binary_path.parent))

    """
    _check_inputs(token, difficulty)
    return subprocess.run(
        args=[os.fspath(bin_path), token, difficulty],
        text=True,
        capture_output=True,
        check=True,
        timeout=timeout,
        cwd=os.fspath(bin_path.parent),
        env={"LC_ALL": "C"},
    )


def handle_work_cpp(
    token: str,
    difficulty: str,
    bin_path: Path = Path(DEFAULT_CPP_BINARY_PATH),
    timeout: int = 7200,
) -> str:
    """Solve the WORK challenge using the external C++ helper.

    Runs the WORK binary and parses the first stdout line starting with ``RESULT:``.
    The returned suffix includes a trailing newline to match the wire protocol.

    Args:
        token (str): Authentication data from the server.
        difficulty (str): Required number of leading hex zeros.
        bin_path (Path, optional): Path to the WORK solver binary.
        timeout (int, optional): Subprocess timeout in seconds.

    Returns:
        str: The suffix followed by ``"\\n"``.

    Raises:
        ValueError: If no ``RESULT:`` line is found or the suffix is empty.
        subprocess.CalledProcessError: If the solver exits non-zero.

    Examples:
        >>> from pathlib import Path
        >>> import tlslp.client as c
        >>> class R:  # fake CompletedProcess
        ...     stdout = "RESULT:abcd\\n"
        >>> c.run_work_binary = lambda *a, **k: R()
        >>> c.handle_work_cpp("AUTH", "4", bin_path=Path("work_challenge"))
        'abcd\\n'
    """
    # run pre-compiled c++ code for finding suffix
    try:
        result = run_work_binary(bin_path, token, difficulty, timeout)

        # Extract the single result line
        suffix = None
        for line in result.stdout.splitlines():
            if line.startswith("RESULT:"):
                suffix = line[len("RESULT:") :]
                break

        if suffix:
            return suffix + "\n"
        else:
            raise ValueError("No RESULT found in WORK output.")

    except subprocess.CalledProcessError as e:
        raise subprocess.CalledProcessError(
            returncode=1, output="Error running executable", cmd=str(bin_path)
        ) from e


def define_response(
    args: list[str],
    token: str,
    valid_messages: set[str],
    queue: multiprocessing.Queue,
    responses: dict[str, str] = DEFAULT_RESPONSES,
    bin_path: Path = Path(DEFAULT_CPP_BINARY_PATH),
) -> None:
    """Create a response for a single server command and enqueue it.

    This computes the appropriate response for a parsed server message and places
    a tuple ``(is_err, result)`` into ``queue``.

    Args:
        args (list[str]): Parsed server tokens (command is ``args[0]``).
        token (str): Current authentication data (set after receiving ``WORK``).
        valid_messages (set[str]): Allowed command names.
        queue (multiprocessing.Queue): Queue-like object that supports ``put(...)``.
        responses (dict[str, str], optional): Static responses for body commands.
        bin_path (Path, optional): Path to the WORK solver binary.

    Returns:
        None

    Examples:
        >>> import tlslp.client as c
        >>> class Q:
        ...     def __init__(self): self.items = []
        ...     def put(self, x): self.items.append(x)
        >>> q = Q()
        >>> c.define_response(["HELLO"], token="", valid_messages={"HELLO"}, queue=q, responses={})
        >>> q.items
        [(False, 'HELLOBACK\\n')]
    """
    if args[0] == "HELLO":
        is_err, result = False, "HELLOBACK\n"
    elif args[0] == "DONE":
        is_err, result = False, "OK\n"
    elif args[0] == "FAIL":
        is_err, result = False, "\n"
    elif args[0] == "WORK":
        difficulty = args[2]

        result = handle_work_cpp(token, difficulty, bin_path)
        _validate_string(result.rstrip("\n"))
        is_err = False

    elif args[0] in valid_messages:
        _validate_string(token)
        is_err, result = (
            False,
            hasher(token, args[1]) + " " + responses[args[0]] + "\n",
        )

    else:
        is_err, result = True, "\n"

    results = (is_err, result)
    queue.put(results)


def connect_to_server(sock: socket.socket, server_host: str, port: int) -> bool:
    """Connect to server and return True if connection was successful.

    Args:
        sock (socket.socket): The socket to connect to.
        server_host (str): The server_host to connect to.
        port (int): The port to connect to.

    Returns:
        bool: True if connection was successful, False otherwise.
    """
    exc: Exception | None = None
    try:
        sock.connect((server_host, int(port)))
        return True
    except (
        TimeoutError,
        ConnectionRefusedError,
        socket.gaierror,
        ssl.SSLCertVerificationError,
        ssl.SSLError,
    ) as e:
        exc = e
        raise TransportError(f"Failed to connect to {server_host}:{port}") from e
    except OSError as e:
        exc = e
        # catch-all for OS-level socket errors
        if e.errno == errno.EHOSTUNREACH:
            raise OSError(f"OSError. Host unreachable: {server_host}:{port}") from e
        elif e.errno == errno.ENETUNREACH:
            raise OSError(
                f"OSError. Network unreachable when "
                f"connecting to {server_host}:{port}"
            ) from e
        else:
            raise OSError(f"OSError connecting to {server_host}:{port}") from e
    finally:
        if exc is not None:
            sock.close()


def _receive_and_decipher_message(
    secure_sock: socket.socket,
    valid_messages: set[str],
) -> list[str]:
    """Receive one message from the server and return parsed tokens.

    Args:
        secure_sock (socket.socket): Connected TLS socket.
        valid_messages (set[str]): Allowed command names.

    Returns:
        list[str]: Parsed tokens as returned by :func:`decipher_message`.

    Raises:
        TransportError: If receiving fails at the transport layer.
        ValueError: If the decoded message is invalid for this protocol.
    """
    while True:
        message = receive_message(secure_sock)
        logger.info(f"Received {message!r}")

        # Error check message and create list from message
        return decipher_message(message, valid_messages)


def _process_message_with_timeout(
    args: list[str],
    token: str,
    valid_messages: set[str],
    responses: dict[str, str] = DEFAULT_RESPONSES,
    bin_path: Path = Path(DEFAULT_CPP_BINARY_PATH),
    work_timeout: float = DEFAULT_WORK_TIMEOUT,
    other_timeout: float = DEFAULT_OTHER_TIMEOUT,
) -> str:
    """Process a single server command with a hard timeout.

    This runs :func:`define_response` in a separate process to enforce timeouts:
    - WORK commands use ``work_timeout``
    - all other commands use ``other_timeout``

    Args:
        args (list[str]): Parsed server tokens.
        token (str): Current authentication data.
        valid_messages (set[str]): Allowed command names.
        responses (dict[str, str], optional): Static responses for body commands.
        bin_path (Path, optional): Path to the WORK solver binary.
        work_timeout (float, optional): Timeout (seconds) for WORK handling.
        other_timeout (float, optional): Timeout (seconds) for non-WORK handling.

    Returns:
        str: Response line to send (includes trailing newline).

    Raises:
        TimeoutError: If processing exceeds the command timeout or queue is empty.
        Exception: If the worker reported an error.
    """
    # Define timeouts and extract token
    this_timeout = (
        work_timeout if args and args[0] and args[0] == "WORK" else other_timeout
    )

    # use multiprocessing for setting timeout.  Only 1 process is used
    queue: multiprocessing.Queue = multiprocessing.Queue()
    p = multiprocessing.Process(
        target=define_response,
        args=(
            args,
            token,
            valid_messages,
            queue,
            responses,
            bin_path,
        ),
    )
    p.start()
    p.join(timeout=this_timeout)  # wait up to 6 or 7200 seconds
    if p.is_alive():
        p.terminate()  # forcefully stop the process
        p.join()
        raise TimeoutError(f"{args[0]} function timed out.")
    else:
        try:
            is_err, msg = queue.get(block=True, timeout=other_timeout)
        except Empty as e:
            raise TimeoutError(f"Queue is empty: {e}") from e

        if is_err:
            to_send = msg.rstrip("\n")
            raise Exception(f"{args[0]} failed: {to_send}.")
        else:
            return msg


def _resolved_bin_path(cpp_binary_path: str) -> Path:
    """Resolve and validate the configured WORK binary path.

    On Windows, if the provided path has no suffix, ``.exe`` is appended before
    resolving.

    Args:
        cpp_binary_path (str): User-supplied path to the WORK binary.

    Returns:
        Path: Resolved path to an existing file.

    Raises:
        FileNotFoundError: If the binary cannot be resolved to an existing path.
    """

    bin_path = Path(cpp_binary_path)
    if sys.platform.startswith("win") and bin_path.suffix == "":
        bin_path = bin_path.with_suffix(".exe")

    try:
        bin_path = bin_path.resolve(strict=True)
    except (FileNotFoundError, OSError) as e:
        raise FileNotFoundError(
            f"WORK binary not a regular file: {cpp_binary_path!r}.\nIf it is "
            f"elsewhere, use --work-binary flag to define its path.  If "
            f"not yet installed, try installing"
            f" it with 'make build-cpp' from the root directory.\n"
            f"Otherwise, g++ -O3 -std=c++17 work_challenge.cpp work_core.cpp"
            f" -o ../build/work_challenge -lssl -lcrypto -pthread from"
            f" cpp/; cp ../build/work_challenge ../src/tlslp/_bin/"
        ) from e

    return bin_path


def main(argv: Sequence[str] | None = None) -> int:
    """
    Entry point for the CLI.

    Args:
        argv: sys.argv[1:] is used.

    Returns:
        Process exit code: 0 on success; nonzero on error.

    Side effects:
        Opens network connections, prints to stdout/stderr.
    """
    parser = build_client_parser()
    ns = parser.parse_args(argv)
    cfg = args_to_client_config(ns)

    configure_logging(level=cfg.log_level, node="client", tutorial=cfg.tutorial)
    if os.name == "nt":
        logger.warning("Windows ACLs not checked.  Skipping world-writable test.")

    is_secure = not cfg.insecure

    responses = DEFAULT_RESPONSES
    valid_messages = DEFAULT_VALID_MESSAGES  # valid messages from the server
    token = ""  # this will be set with WORK message from server

    # check paths
    logger.debug(f"Client cert exists: {os.path.exists(cfg.client_cert)!r}")
    logger.debug(f"Private key exists: {os.path.exists(cfg.private_key)!r}")
    try:
        bin_path = _resolved_bin_path(cfg.work_binary)
        logger.info(
            f"WORK binary exists: {_validate_path(bin_path, Path(DEFAULT_ALLOWED_ROOT))!r}"
        )
    except FileNotFoundError:
        logger.critical("Client fails.")
        raise
    except PermissionError:
        logger.critical("Client fails.")
        raise

    # Connect to the server using TLS
    # Cycle through possible ports, trying to connect to each until success
    is_connected = False
    for port in cfg.ports:
        if not is_connected:
            try:
                secure_sock = prepare_client_socket(
                    cfg.ca_cert,
                    cfg.client_cert,
                    cfg.private_key,
                    cfg.server_host,
                    is_secure,
                )
                is_connected = connect_to_server(secure_sock, cfg.server_host, port)
                break
            except Exception as e:
                logger.warning(f"Can't connect to {cfg.server_host!r}:{port!r}: {e}")

    if not is_connected:
        logger.critical("Not able to connect to any port.  Exiting")
        sys.exit(1)

    logger.info(f"Connected to {port!r}")
    print(f"Connected to {port}")

    # listen to connection until broken
    try:
        while True:

            args = _receive_and_decipher_message(secure_sock, valid_messages)

            # If no args are received, continue
            if not args or not args[0]:
                logger.warning("Problem deciphering message. Continuing.")
                continue

            if args[0] == "FAIL":
                break

            if args[0] == "WORK":
                token = args[1]

            start = time.time()
            response = _process_message_with_timeout(
                args,
                token,
                valid_messages,
                responses,
                bin_path,
                cfg.work_timeout,
                cfg.other_timeout,
            )
            end = time.time()
            logger.debug(f"The time of execution is : {(end - start)!r}s")

            if args[0] == "WORK":
                this_hash = hashlib.sha256(  # noqa: S324
                    (args[1] + response.rstrip("\n")).encode()
                ).hexdigest()

                # only log first part of token
                half_len_token = math.ceil(len(args[1]) / 2)
                logger.debug(
                    f"Authentication data: {args[1][:half_len_token]!r}..., Difficulty: {args[2]!r}"
                )
                logger.debug(f"Valid suffix: {response!r}")
                logger.debug(f"Hash: {this_hash!r}")

            split_msg = response.split(" ", maxsplit=1)
            cksum = split_msg[0]
            body = split_msg[1] if len(split_msg) > 1 else ""
            logger.info(f"Sending to server: {body!r}")
            logger.debug(f"Checksum sent: {cksum!r}")
            send_message(response, secure_sock)

            if args[0] == "DONE":
                break

    except Exception:
        logger.exception("Client failed")

    finally:
        secure_sock.close()
        logger.info("Connection closed.")
        print("Connection closed.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
