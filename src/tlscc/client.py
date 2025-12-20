"""Opens a client node that will interact with a defined server.

This follows a set of rules defined in the toy protocol demo. The
specific rules and the external IP address are not quoted here for
confidentiality reasons.  The client connects to the server and then
listens for a list of commands that are answered one by one.  The
first two commands are the handshake and contain 'HELLO' and 'WORK'.
The WORK challenge must be resolved in 2 hours.  This challenge is
resolved by a C++ code called pow_challenge.cpp.  Multithreading is
used when calling this C++ code.

Functions:
    prepare_client_socket:
        Create a connection to the remote server.

    hasher:
        Hash a string using SHA256.

    decipher_message:
        Read message and do error checking.

    handle_pow_cpp:
        Takes the token and difficulty and finds a suffix that will
        reproduce a hash with the given number of leading zeros.

    define_response:
        Create response to message depending on received message.

    main:
        Main function.

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

from tlslp.logging_utils import configure_logging
from tlslp.protocol import (
    DEFAULT_CA_CERT,
    DEFAULT_LONG_TIMEOUT,
    DEFAULT_OTHER_TIMEOUT,
    DEFAULT_WORK_TIMEOUT,
    DEFAULT_SERVER_HOST,
    MAX_LINE_LENGTH,
    _parse_positive_int,
    receive_message,
    send_message,
)

DEFAULT_CPP_BINARY_PATH = "src/tlslp/_bin/pow_challenge"  # path to c++ executable
DEFAULT_ALLOWED_ROOT = "src/tlslp/_bin"
DEFAULT_RESPONSES = {
    "FULL_NAME": "Elliott Bache",
    "MAILNUM": "2",
    "EMAIL1": "elliottbache@gmail.com",
    "EMAIL2": "elliottbache2@gmail.com",
    "SOCIAL": "elliottbache@hotmail.com",
    "BIRTHDATE": "99.99.1982",
    "COUNTRY": "USA",
    "ADDRNUM": "2",
    "ADDR_LINE1": "234 Evergreen Terrace",
    "ADDR_LINE2": "Springfield",
}
DEFAULT_VALID_MESSAGES = {
    "HELLO",
    "WORK",
    "ERROR",
    "DONE",
    "FULL_NAME",
    "MAILNUM",
    "EMAIL1",
    "EMAIL2",
    "SOCIAL",
    "BIRTHDATE",
    "COUNTRY",
    "ADDRNUM",
    "ADDR_LINE1",
    "ADDR_LINE2",
}
DEFAULT_PORTS = [3115, 7883, 8235, 38154, 1234, 55532]
DEFAULT_PRIVATE_KEY_PATH = "certificates/ec_private_key.pem"
DEFAULT_CLIENT_CERT_PATH = "certificates/client_cert.pem"

logger = logging.getLogger(__name__)


@dataclass
class ClientConfig:
    server_host: str
    ports: list[int]
    client_cert: str
    private_key: str
    ca_cert: str
    pow_binary: str
    pow_timeout: int
    other_timeout: int
    insecure: bool
    log_level: str
    json_logs: bool


def _parse_port(s: str) -> int:
    try:
        p = int(s)
    except ValueError as e:
        logger.exception(f"port must be an integer: {e}")
        raise argparse.ArgumentTypeError("port must be an integer") from e
    if not (0 < p < 65536):
        logger.exception("port out of range (1..65535)")
        raise argparse.ArgumentTypeError("port out of range (1..65535)")
    return p


def build_client_parser() -> argparse.ArgumentParser:
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
        "--pow-binary",
        default=DEFAULT_CPP_BINARY_PATH,
        type=str,
        help="path to pow_prepare_server_socket executable",
    )

    parser.add_argument(
        "--pow-timeout",
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
        "--json-logs",
        action="store_true",
        help="Emit logs as JSON (one object per line).",
    )

    return parser


def _merge_ports(ns: argparse.Namespace) -> list[int]:
    """Take both flags (ports and port) and combine."""
    if ns.ports:
        return ns.ports
    else:
        return DEFAULT_PORTS


def args_to_client_config(ns: argparse.Namespace) -> ClientConfig:
    return ClientConfig(
        server_host=ns.host,
        ports=_merge_ports(ns),
        client_cert=ns.client_cert,
        private_key=ns.private_key,
        ca_cert=ns.ca_cert,
        pow_binary=ns.pow_binary,
        pow_timeout=ns.pow_timeout,
        other_timeout=ns.other_timeout,
        insecure=ns.insecure,
        log_level=ns.log_level,
        json_logs=ns.json_logs,
    )


def prepare_client_socket(
    ca_cert_path: str,
    client_cert_path: str,
    private_key_path: str,
    server_host: str,
    is_secure: bool = False,
    timeout: int = 6,
) -> socket.socket:
    """
    Prepare a socket for connecting to the server.

    Args:
        ca_cert_path (str): The path to the CA certificate.
        client_cert_path (str): The path to the client certificate.
        private_key_path (str): The path to the private key file.
        server_host (str): The server_host to connect to.
        is_secure (bool, optional): Whether the server is secure or not.

    Returns:
        socket.socket: The socket object.
    """
    # Check that server_host is local, otherwise raise error so that insecure
    # connection isn't mistakenly used
    if server_host != "localhost":
        logger.exception(
            f"Refusing insecure TLS to {server_host!r}. For "
            f"non-local hosts, enable certificate verification."
        )
        raise ValueError(
            f"Refusing insecure TLS to {server_host}. For "
            f"non-local hosts, enable certificate verification."
        )

    # create the client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(DEFAULT_LONG_TIMEOUT)

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

    return context.wrap_socket(client_socket, server_hostname=server_host)


def hasher(token: str, input_string: str) -> str:
    """Hash a string using SHA256.

    Concatenates token and input_string and then hashes.

    Args:
        token (str): The token from the server.
        input_string (str): An ASCII string.

    Returns:
        str: The hashed string.

    Examples:
        >>> token = 'gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzu' \
            + 'WROTeTaSmqFCAzuwkwLCRgIIq'
        >>> input_string = 'LGTk'
        >>> from src import hasher
        >>> hasher(token, input_string)
        'bd8de303197ac9997d5a721a11c46d9ed0450798'
    """
    to_be_hashed = token + input_string
    cksum_in_hex = hashlib.sha256(to_be_hashed.encode()).hexdigest()  # noqa: S324

    return cksum_in_hex


def decipher_message(message: str, valid_messages: set[str]) -> list[str]:
    """Read message and do error checking.

    Args:
        message (str): The message to read.
        valid_messages (set[str]): A set of valid messages that can
                                    be received from server.

    Returns:
        Union[int, list[str]]: An error code 0 if no error, 1 if
                               decoding error, and 2 if message is not
                               valid the decoded message
                               split into list.

    Examples:
        >>> message = b'MAILNUM LGTk\\n'
        >>> valid_messages = {'HELLO', 'DONE', 'EMAIL2', 'BIRTHDATE', \
         'MAILNUM', 'ADDRNUM', 'EMAIL1', 'ADDR_LINE2', 'WORK', 'ERROR', \
         'SOCIAL', 'COUNTRY', 'ADDR_LINE1', 'FULL_NAME'}
        >>> from src import decipher_message
        >>> decipher_message(message, valid_messages)
        Received MAILNUM LGTk
        (0, ['MAILNUM', 'LGTk'])
    """
    args = message.split()

    # check that the message has arguments
    if not args:
        logger.exception(f"No args in the response: {message!r}")
        raise ValueError(f"No args in the response: {message}")

    # check that message belongs to list of possible messages
    if args[0] not in valid_messages:
        logger.exception(
            f"This response is not valid: {message!r}. "
            f"Valid messages: {valid_messages!r}"
        )
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


def _validate_path(bin_path: Path, allowed_root: Path | None = None) -> None:
    """Resolve and vet path."""
    # check if file exists
    if not bin_path.is_file():
        logger.exception(f"WORK binary not a regular file: {bin_path!r}")
        raise FileNotFoundError(f"WORK binary not a regular file: {bin_path}")
    # check if it's a symbolic link
    if bin_path.is_symlink():
        logger.exception(f"Refusing to execute symlink: {bin_path!r}")
        raise PermissionError(f"Refusing to execute symlink: {bin_path}")
    # check if it's executable
    if os.name == "posix" and not os.access(bin_path, os.X_OK):
        logger.exception(f"WORK binary at {bin_path!r} is not executable.")
        raise PermissionError(f"WORK binary at {bin_path} is not executable.")
    # check if it's world writable
    if _is_world_writable(bin_path) or _is_world_writable(bin_path.parent):
        logger.exception(f"Insecure permissions on {bin_path!r} or its directory")
        raise PermissionError(f"Insecure permissions on {bin_path} or its directory")
    # check if it's in an allowed folder
    if allowed_root is not None:
        root = allowed_root.resolve(strict=True)
        if not bin_path.is_relative_to(root):
            logger.exception(
                f"Insecure directory location {bin_path.parent!r} for {bin_path!r}"
            )
            raise PermissionError(
                f"Insecure directory location {bin_path.parent} for {bin_path}"
            )


def _validate_string(s: str) -> None:
    """Validate string."""
    if not isinstance(s, str):
        logger.exception(
            "Tested variable is not a string.  Exiting since hashing function "
            "will not work correctly"
        )
        raise TypeError(
            "Tested variable is not a string.  Exiting since hashing function "
            "will not work correctly"
        )

    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", s):
        logger.exception("String contains disallowed characters or length")
        raise ValueError("String contains disallowed characters or length")

    if len(s) > MAX_LINE_LENGTH:
        logger.exception("String too long")
        raise ValueError("String too long")


def _validate_difficulty(difficulty: str) -> None:
    """Cast difficulty to int and error check."""
    try:
        idifficulty = int(difficulty)
    except (ValueError, TypeError) as e:
        logger.exception(f"WORK difficulty is not an integer: {e}")
        raise TypeError("WORK difficulty is not an integer") from e

    if idifficulty < 0 or idifficulty > 64:
        logger.exception("WORK difficulty is out of range")
        raise ValueError("WORK difficulty is out of range")


def _check_inputs(bin_path: Path, token: str, difficulty: str) -> None:

    # resolve and vet the executable path
    _validate_path(bin_path, Path(DEFAULT_ALLOWED_ROOT))

    # validate token
    _validate_string(token)

    # validate difficulty as an int
    _validate_difficulty(difficulty)


def run_pow_binary(
    cpp_binary_path: str, token: str, difficulty: str, timeout: int = 7200
) -> subprocess.CompletedProcess:
    """Run the WORK challenge C++ binary.

    Args:
        cpp_binary_path (Path): The path of the C++ binary.
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
    bin_path = Path(cpp_binary_path).resolve(strict=True)
    # on Windows, allow implicit .exe
    if (
        sys.platform.startswith("win")
        and bin_path.suffix == ""
        and not bin_path.exists()
    ):
        bin_path = bin_path.with_suffix(".exe")

    _check_inputs(bin_path, token, difficulty)

    return subprocess.run(
        args=[os.fspath(bin_path), token, difficulty],
        text=True,
        capture_output=True,
        check=True,
        timeout=timeout,
        cwd=os.fspath(bin_path.parent),
        env={"LC_ALL": "C"},
    )


def handle_pow_cpp(
    token: str,
    difficulty: str,
    cpp_binary_path: str = DEFAULT_CPP_BINARY_PATH,
    timeout: int = 7200,
) -> str:
    """Find a hash with the given number of leading zeros.

    Takes the token and difficulty and find a suffix that will
    reproduce a hash with the given number of leading zeros.

    Args:
        token (str): The token from the server.
        difficulty (str): The number of leading zeroes required.
        cpp_binary_path (str): The path to the C++ program that solves
            the WORK challenge.

    Returns:
        str: the suffix that solves the WORK challenge.

    Examples:
        >>> import subprocess
        >>> token = 'gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzu' \
            + 'WROTeTaSmqFCAzuwkwLCRgIIq'
        >>> difficulty = "6"
        >>> cpp_binary_path = "build/pow_prepare_server_socket"
        >>> from src import handle_pow_cpp
        >>> handle_pow_cpp(token, difficulty, cpp_binary_path) \
            # doctest: +ELLIPSIS
        WORK difficulty: ...
        WORK prepare_server_socket executable not found.
        (4, b'\\n')
    """
    # run pre-compiled c++ code for finding suffix
    try:
        result = run_pow_binary(cpp_binary_path, token, difficulty, timeout)

        # Extract the single result line
        suffix = None
        for line in result.stdout.splitlines():
            if line.startswith("RESULT:"):
                suffix = line[len("RESULT:") :]
                break

        if suffix:
            return suffix + "\n"
        else:
            logger.exception("No RESULT found in WORK output.")
            raise ValueError("No RESULT found in WORK output.")

    except FileNotFoundError as e:
        logger.exception(f"WORK binary not a regular file {cpp_binary_path!r}: {e}")
        raise FileNotFoundError(
            f"WORK binary not a regular file: {cpp_binary_path}"
        ) from e

    except subprocess.CalledProcessError as e:
        _validate_string(token)
        _validate_difficulty(difficulty)
        logger.exception(f"Error running executable: {e}")
        raise subprocess.CalledProcessError(
            1,
            cmd="pow_prepare_server_socket" + token + difficulty,
            stderr=f"Error running executable: {e}",
        ) from e


def define_response(
    args: list[str],
    token: str,
    valid_messages: set[str],
    queue: multiprocessing.Queue,
    responses: dict[str, str] = DEFAULT_RESPONSES,
    cpp_binary_path: str = DEFAULT_CPP_BINARY_PATH,
) -> None:
    """
    Create response to message depending on received message.

    is_err and result are added to results,
    which are then queued for output in multiprocessing.

    Args:
        args (list[str]): The list of arguments to pass to the client.
        token (str): The token from the server.
        valid_messages (set[str]): The list of valid messages that
            the server can send.
        responses (dict[str, str]): The list of responses to send.
        cpp_binary_path (str): The path to the C++ program that solves
            the WORK challenge.

    Returns:
        None: results are added to "results" list where results[0]
            = is_err and result (str) is the message to
            send to the server.

        Examples:
            >>> args = ["HELLO"]
            >>> token = 'gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzu' \
            + 'WROTeTaSmqFCAzuwkwLCRgIIq'
            >>> valid_messages = {'HELLO', 'DONE', 'EMAIL2', 'BIRTHDATE', \
            'MAILNUM', 'ADDRNUM', 'EMAIL1', 'ADDR_LINE2', 'WORK', 'ERROR', \
            'SOCIAL', 'COUNTRY', 'ADDR_LINE1', 'FULL_NAME'}
            >>> cpp_binary_path = "build/pow_prepare_server_socket"
            >>> responses = {}
            >>> from src import define_response
            >>> # a tiny queue we can inspect
            >>> class Q:
            ...     def __init__(self): self.items = []
            ...     def put(self, x): self.items.append(x)
            >>> queue = Q()
            >>> define_response(args, token, valid_messages,
            ...     queue, responses, cpp_binary_path)
            >>> queue.items
            [[0, b'HELLOBACK\\n']]
    """
    if args[0] == "HELLO":
        is_err, result = False, "HELLOBACK\n"
    elif args[0] == "DONE":
        is_err, result = False, "OK\n"
    elif args[0] == "ERROR":
        is_err, result = False, "\n"
    elif args[0] == "WORK":
        difficulty = args[2]

        result = handle_pow_cpp(token, difficulty, cpp_binary_path)
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
    except TimeoutError as e:
        exc = e
        logger.exception(f"Connect timeout to {server_host!r}:{port!r}: {e}")
        raise TimeoutError(f"Connect timeout to {server_host}:{port}") from e
    except ConnectionRefusedError as e:
        exc = e
        raise ConnectionRefusedError(
            f"Connection refused by {server_host}:{port}"
        ) from e
    except socket.gaierror as e:
        exc = e
        logger.exception(f"DNS/addr error for {server_host!r}:{port!r}: {e}")
        raise socket.gaierror(
            f"DNS/addr error for {server_host}:{port}: {e}"
        ) from e  # bad host / not resolvable
    except ssl.SSLCertVerificationError as e:
        exc = e
        # server_host mismatch, expired, unknown CA, etc.
        logger.exception(
            f"Certificate verification failed for {server_host!r}:{port!r}: {e}"
        )
        raise ssl.SSLCertVerificationError(
            f"Certificate verification failed for {server_host}:{port}: {e}"
        ) from e
    except ssl.SSLError as e:
        exc = e
        # other TLS/handshake issues (protocol mismatch, bad
        # record, etc.)
        logger.exception(f"TLS error during connect to {server_host!r}:{port!r}: {e}")
        raise ssl.SSLError(
            f"TLS error during connect to {server_host}:{port}: {e}"
        ) from e
    except OSError as e:
        exc = e
        # catch-all for OS-level socket errors
        if e.errno == errno.EHOSTUNREACH:
            logger.exception(
                f"OSError. Host unreachable: {server_host!r}:{port!r}: {e}"
            )
            raise OSError(f"OSError. Host unreachable: {server_host}:{port}") from e
        elif e.errno == errno.ENETUNREACH:
            logger.exception(
                f"OSError. Network unreachable when connecting to {server_host!r}:{port!r}: {e}"
            )
            raise OSError(
                f"OSError. Network unreachable when "
                f"connecting to {server_host}:{port}"
            ) from e
        else:
            logger.exception(f"OSError connecting to {server_host!r}:{port!r}: {e}")
            raise OSError(f"OSError connecting to {server_host}:{port}: {e}") from e
    finally:
        if exc is not None:
            sock.close()


def _receive_and_decipher_message(
    secure_sock: socket.socket,
    valid_messages: set[str],
) -> list[str]:
    """Receive and decode message from server and return containing message."""
    while True:
        message = receive_message(secure_sock, logger)
        logger.debug(f"Received {message!r}")

        # Error check message and create list from message
        try:
            return decipher_message(message, valid_messages)
        except Exception as e:
            logger.exception(f"Error deciphering message: {e}")
            raise Exception(f"Error deciphering message: {e}") from e


def _process_message_with_timeout(
    args: list[str],
    token: str,
    valid_messages: set[str],
    responses: dict[str, str] = DEFAULT_RESPONSES,
    cpp_binary_path: str = DEFAULT_CPP_BINARY_PATH,
    pow_timeout: float = DEFAULT_WORK_TIMEOUT,
    other_timeout: float = DEFAULT_OTHER_TIMEOUT,
) -> str:
    """Process message received from server and return response, respecting timeout"""
    # Define timeouts and extract token
    this_timeout = (
        pow_timeout if args and args[0] and args[0] == "WORK" else other_timeout
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
            cpp_binary_path,
        ),
    )
    p.start()
    p.join(timeout=this_timeout)  # wait up to 6 or 7200 seconds
    if p.is_alive():
        p.terminate()  # forcefully stop the process
        p.join()
        logger.exception(f"{args[0]!r} function timed out.")
        raise TimeoutError(f"{args[0]} function timed out.")
    else:
        is_err, msg = queue.get()
        if is_err:
            to_send = msg.rstrip("\n")
            logger.exception(f"{args[0]!r} failed: {to_send!r}.")
            raise Exception(f"{args[0]} failed: {to_send}.")
        else:
            return msg


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

    configure_logging(level=cfg.log_level, json_logs=cfg.json_logs, node="client")
    logger.warning("Windows ACLs not checked.  Skipping world-writable test.")

    is_secure = not cfg.insecure

    responses = DEFAULT_RESPONSES
    valid_messages = DEFAULT_VALID_MESSAGES  # valid messages from the server
    token = ""  # this will be set with WORK message from server

    # Create and wrap socket
    logger.info(f"Client cert exists: {os.path.exists(cfg.client_cert)!r}")
    logger.info(f"Private key exists: {os.path.exists(cfg.private_key)!r}")

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
                    cfg.other_timeout,
                )
                is_connected = connect_to_server(secure_sock, cfg.server_host, port)
                break
            except Exception as e:
                logger.warning(f"when connecting to {cfg.server_host!r}:{port!r}: {e}")

    if not is_connected:
        logger.exception("Not able to connect to any port.  Exiting")
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

            if args[0] == "ERROR":
                break

            if args[0] == "WORK":
                token = args[1]

            start = time.time()
            response = _process_message_with_timeout(
                args,
                token,
                valid_messages,
                responses,
                cfg.pow_binary,
                cfg.pow_timeout,
                cfg.other_timeout,
            )
            end = time.time()
            logger.debug(f"The time of execution is : {(end - start)!r})s")

            if args[0] == "WORK":
                this_hash = hashlib.sha256(  # noqa: S324
                    (args[1] + response.rstrip("\n")).encode()
                ).hexdigest()

                # only log first part of token
                half_len_token = math.ceil(len(args[1]) / 2)
                logger.debug(
                    f"Authentication data: {half_len_token!r}..., Difficulty: {args[2]!r}"
                )
                logger.info(f"Valid suffix returned from client: {response!r}")
                logger.info(f"Hash: {this_hash!r}")

            logger.debug(f"Sending to server = {response!r}")
            send_message(response, secure_sock, logger)

            if args[0] == "DONE":
                break

    except TimeoutError as e:
        logger.exception(f"TimeoutError: {e}")

    except Exception as e:
        logger.exception(f"Exception: {e}")

    finally:
        secure_sock.close()
        logger.info("Connection closed.")
        print("Connection closed.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
