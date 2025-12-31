"""TLS server for querying a client's information.

This CLI starts a TCP listener and sends a simple newline-delimited UTF-8
command protocol over TLS. The server:

1) Accepts a TLS connection (optionally requiring a client certificate for mTLS).
2) Performs a small handshake:
   - Sends ``HELLO`` and expects ``HELLOBACK``.
   - Sends ``WORK <token> <n_bits>`` and expects a suffix that yields a SHA256
   hash with the required number of trailing zero bits.
3) Sends a sequence of body requests (e.g., ``FULL_FULL_NAME``, ``EEMAIL1``, ...). The client
   responds with ``<cksum> <value>`` where ``cksum = SHA256(token + random_string)``.
4) Finishes with ``DONE`` and expects ``OK``.

Timeouts:
- WORK has a long timeout (default: 30 minutes).
- Other steps use a shorter timeout (default: 10 seconds).

The server is primarily intended for localhost/dev usage and a deterministic
``--tutorial`` mode that sends each body message once and then exits.

Raises:
    ProtocolError: For protocol violations (framing/encoding errors).
    TransportError: For network/TLS errors (disconnects, timeouts, etc.).
"""

import argparse
import copy
import hashlib
import logging
import math
import os
import random
import socket
import ssl
from collections.abc import Sequence
from dataclasses import dataclass

from tlslp.logging_utils import configure_logging
from tlslp.protocol import (
    DEFAULT_BODY_MESSAGES,
    DEFAULT_CA_CERT,
    DEFAULT_OTHER_TIMEOUT,
    DEFAULT_SERVER_HOST,
    DEFAULT_WORK_TIMEOUT,
    ProtocolError,
    TransportError,
    _parse_positive_int,
    receive_message,
    send_message,
)

# module-level defaults (safe to import, optional)
DEFAULT_PORT = 1234
DEFAULT_SERVER_CERT = "certificates/server-cert.pem"
DEFAULT_SERVER_KEY = "certificates/server-key.pem"
DEFAULT_TOKEN = (
    "gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzuWROTeTaSmqFCAzuwkwLCRgIIq"  # noqa: S105
)
DEFAULT_RANDOM_STRING = "LGTk"
DEFAULT_N_BITS = 28

logger = logging.getLogger(__name__)


@dataclass
class ServerConfig:
    server_host: str
    port: int
    server_cert: str
    server_key: str
    ca_cert: str
    work_timeout: int
    other_timeout: int
    insecure: bool
    token: str
    random_string: str
    n_bits: int
    log_level: str
    tutorial: bool


def build_server_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser for ``tlslp-server``.

    Returns:
        (argparse.ArgumentParser) configured with server options.

    Examples:
        >>> p = build_server_parser()
        >>> ns = p.parse_args(["--port", "1234", "--tutorial"])
        >>> ns.port
        1234
    """
    parser = argparse.ArgumentParser(
        prog="tlslp-server", description="TLS server for the toy protocol demo."
    )

    parser.add_argument(
        "--host",
        default=DEFAULT_SERVER_HOST,
        help=f"server hostname (default: {DEFAULT_SERVER_HOST})",
    )

    parser.add_argument(
        "--port",
        default=DEFAULT_PORT,
        type=int,
        help="port to listen on",
    )

    parser.add_argument(
        "--server-cert",
        default=DEFAULT_SERVER_CERT,
        type=str,
        help="path to server certificate (PEM)",
    )
    parser.add_argument(
        "--server-key",
        default=DEFAULT_SERVER_KEY,
        type=str,
        help="path to server private key (PEM)",
    )
    parser.add_argument(
        "--ca-cert",
        default=DEFAULT_CA_CERT,
        type=str,
        help="path to client CA certificate (PEM)",
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
        "--token",
        default=DEFAULT_TOKEN,
        type=str,
        help="authentication data for hashing",
    )

    parser.add_argument(
        "--random-string",
        default=DEFAULT_RANDOM_STRING,
        type=str,
        help="random string for body messages checksums",
    )

    parser.add_argument(
        "--n_bits",
        default=DEFAULT_N_BITS,
        type=int,
        help="WORK challenge n_bits",
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


def args_to_server_config(ns: argparse.Namespace) -> ServerConfig:
    """Convert parsed CLI args into a ``ServerConfig``.

    Args:
        ns (argparse.Namespace): Returned by ``ArgumentParser.parse_args``.

    Returns:
        (ServerConfig): The flags/parameters.
    """
    return ServerConfig(
        server_host=ns.host,
        port=ns.port,
        server_cert=ns.server_cert,
        server_key=ns.server_key,
        ca_cert=ns.ca_cert,
        work_timeout=ns.work_timeout,
        other_timeout=ns.other_timeout,
        insecure=ns.insecure,
        token=ns.token,
        random_string=ns.random_string,
        n_bits=ns.n_bits,
        log_level=ns.log_level,
        tutorial=ns.tutorial,
    )


def _check_suffix(to_send: str, token: str, received_message: str) -> bool:
    """Validate a WORK suffix against the requested n_bits.

    Args:
        to_send (str): The original WORK command string (``"WORK <token> <n_bits>"``).
        token (str): Authentication data used as the hash prefix.
        received_message (str): Suffix returned by the client.

    Returns:
        (bool): True if ``sha256(token + suffix)`` ends with ``n_bits`` trailing ``"0"`` bits.
    """
    """Check if suffix has enough leading zeros."""
    n_bits = to_send.split(" ", maxsplit=2)[2]
    last_zeros = "0" * int(n_bits)
    this_hash = hashlib.sha256((token + received_message).encode()).hexdigest()

    # convert to a 256-bit binary string
    binary_digest = format(int(this_hash, 16), "256b")
    return binary_digest.endswith(last_zeros)


def _check_cksum(to_send: str, token: str, received_message: str) -> bool:
    """Validate a body-response checksum.

    The server sends ``"<COMMAND> <random_string>"`` and expects
    ``"<cksum> <value>"`` where ``cksum = SHA256(token + random_string)``.

    Args:
        to_send (str): The original command string sent to the client.
        token (str): Authentication data used as the hash prefix.
        received_message (str): Client response string (``"<cksum> <value>"``).

    Returns:
        (bool): True if the returned checksum matches the expected value.
    """

    cksum = str(received_message).split(" ", maxsplit=1)[0]
    random_string = to_send.split(" ", maxsplit=1)[1]
    cksum_calc = hashlib.sha256((token + random_string).encode()).hexdigest()
    return cksum == cksum_calc


def send_and_receive(
    token: str, to_send: str, secure_sock: socket.socket, timeout: float = 6.0
) -> str:
    """Send one command and receive the client's reply, with protocol validation.

    - Sends ``to_send`` using ``tlslp.protocol.send_message``.
    - Receives a single-line reply using ``tlslp.protocol.receive_message``.
    - For ``WORK`` commands, validates the suffix n_bits requirement.
    - For body commands, validates the checksum.
    - For ``FAIL`` commands, no reply is expected (returns ``""``).

    Args:
        token (str): Authentication data used for checksum/suffix validation.
        to_send (str): Command to send (newline will be ensured by ``send_message``).
        secure_sock (socket.socket): Connected socket.
        timeout (float): Receive timeout in seconds for this step.

    Returns:
        (str): The received message (without trailing newline), or ``""`` for ``FAIL`` sends.

    Raises:
        ProtocolError: If the peer violates protocol framing/encoding.
        TransportError: On network/TLS failures (timeouts, disconnects, etc.).
        ValueError: If WORK suffix or checksum validation fails.

    Examples:
        >>> import socket
        >>> from tlslp.server import send_and_receive
        >>> a, b = socket.socketpair()
        >>> try:
        ...     # peer responds to HELLO with HELLOBACK
        ...     _ = b.recv(1024)  # consume HELLO (sent by send_and_receive)
        ... except Exception:
        ...     pass
        ... finally:
        ...     a.close(); b.close()
        ... # doctest: +SKIP
    """

    secure_sock.settimeout(timeout)
    try:
        send_message(to_send, secure_sock)
    except Exception:
        send_fail("FAIL sending.", secure_sock)
        raise

    # no waiting to receive a message from client
    if to_send.startswith("FAIL"):
        return ""

    try:
        received_message = receive_message(secure_sock)
    except TransportError as e:
        raise TransportError(f"ERROR receiving. {e}") from e
    except ProtocolError as e:
        send_fail("FAIL receiving.", secure_sock)
        raise ProtocolError(f"ERROR receiving. {e}") from e

    # check WORK suffix
    if to_send.startswith("WORK") and not _check_suffix(
        to_send, token, received_message
    ):
        print(f"\ncheck_suffix: {_check_suffix(to_send, token, received_message)}")
        send_fail("FAIL Invalid suffix returned from client.", secure_sock)
        raise ValueError(r"Invalid suffix returned from client.")
    # check checksum for rest of possible messages
    elif not (
        to_send.startswith("WORK")
        or to_send.startswith("HELLO")
        or to_send.startswith("FAIL")
        or to_send.startswith("DONE")
    ) and not _check_cksum(to_send, token, received_message):
        send_fail("FAIL Invalid checksum received.", secure_sock)
        raise ValueError(r"Invalid checksum received.")

    return received_message


def send_fail(to_send: str, secure_sock: socket.socket) -> None:
    """Best-effort send of an ``FAIL ...`` message.

    This is used to notify the client after a failure (e.g., bad checksum).
    Any exception while sending is caught and logged.

    Args:
        to_send (str): Error message to send (typically starts with ``"FAIL"``).
        secure_sock (socket.socket): Connected socket to send on.
    """
    try:
        send_message(to_send, secure_sock)
    except Exception:
        logger.exception("FAIL could not be sent.")
    finally:
        pass


def prepare_server_socket(
    server_host: str,
    port: int,
    ca_cert_path: str,
    server_cert_path: str,
    server_key_path: str,
    is_secure: bool = False,
) -> tuple[socket.socket, ssl.SSLContext]:
    """Create a listening TCP socket and an SSL context for server-side TLS.

    Args:
        server_host (str): Host interface to bind to (e.g., ``"localhost"``).
        port (int): TCP port to bind to.
        ca_cert_path (str): CA certificate used to verify client certificates (mTLS).
        server_cert_path (str): Server certificate (PEM).
        server_key_path (str): Server private key (PEM).
        is_secure (bool): If True, require and verify a client certificate (mTLS). If False,
            the server does not request/verify a client certificate.

    Returns:
        (socket.socket, ssl.SSLContext): (server_socket, ssl_context) where ``server_socket`` is bound and listening.

    Raises:
        ValueError: If insecure mode is requested for a non-localhost bind.

    Examples:
    Insecure TLS is refused for non-local hosts:
    >>> prepare_server_socket("example.com", 0, "ca.pem", "srv.pem", "key.pem", is_secure=False)
    Traceback (most recent call last):
    ...
    ValueError: Refusing insecure TLS to example.com. For non-local hosts, enable certificate verification.
    """
    # Check that server_host is local for basic TLS, otherwise raise error so
    # that insecure connection isn't mistakenly used
    if not is_secure and server_host != "localhost":
        raise ValueError(
            f"Refusing insecure TLS to {server_host}. For "
            f"non-local hosts, enable certificate verification."
        )

    # Define the server address and port
    server_address = (server_host, port)

    # Create the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(server_address)
    server_socket.listen(1)

    if is_secure:
        # wrap the socket with SSL
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # load the CA certificate (for client certificate verification)
        context.load_verify_locations(cafile=ca_cert_path)
        context.verify_mode = ssl.CERT_REQUIRED

    else:
        # wrap the socket with SSL
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # don't load CA certificate
        context.verify_mode = ssl.CERT_NONE

    context.minimum_version = ssl.TLSVersion.TLSv1_2

    # load server certificate and key
    context.load_cert_chain(certfile=server_cert_path, keyfile=server_key_path)

    return server_socket, context


def handle_one_session(
    is_secure: bool, cfg: ServerConfig, secure_sock: ssl.SSLSocket
) -> None:
    """Handle a single connected client session.

    Runs the handshake (HELLO + WORK), then sends a series of body requests, and
    finishes with ``DONE`` unless a ``FAIL`` condition is triggered.

    Args:
        is_secure (bool): True if mTLS is expected (client cert required).
        cfg (ServerConfig): Parsed and normalized server configuration.
        secure_sock (ssl.SSLSocket): TLS-wrapped client socket.

    Raises:
        RuntimeError: If mTLS is enabled and the client presents no certificate.
        ProtocolError/TransportError/ValueError: Propagated from the underlying
            send/receive and validation logic.
    """

    secure_sock.settimeout(min(DEFAULT_OTHER_TIMEOUT, DEFAULT_WORK_TIMEOUT))
    if is_secure and not secure_sock.getpeercert():
        raise RuntimeError("No client certificate presented.")

    client_address = secure_sock.getpeername()
    logger.info(f"Connection from address: {client_address[0]!r}")
    logger.debug(f"Connection from port: {client_address[1]!r}")
    print(f"Connection from {client_address}")

    # handshake
    logger.info("Step: handshake")
    logger.debug("Sending HELLO")
    msg = send_and_receive(cfg.token, "HELLO", secure_sock, cfg.other_timeout)
    logger.debug(f"Received {msg!r}")

    # only log first part of token
    half_len_token = math.ceil(len(cfg.token) / 2)
    logger.debug(
        f"Authentication data: {cfg.token[:half_len_token]!r}..., n_bits: {cfg.n_bits!r}"
    )

    msg = send_and_receive(
        cfg.token,
        "WORK " + str(cfg.token) + " " + str(cfg.n_bits),
        secure_sock,
        cfg.work_timeout,
    )
    logger.debug(f"Valid suffix returned from client: {msg!r}")
    this_hash = hashlib.sha256((cfg.token + msg).encode()).hexdigest()
    logger.debug(f"Hash: {this_hash!r}")

    # body
    choice = None
    body_messages = copy.deepcopy(DEFAULT_BODY_MESSAGES)
    if cfg.tutorial:
        n_body_messages = len(body_messages)
    else:
        n_body_messages = 20
        body_messages.append("FAIL")

    for idx in range(n_body_messages):
        # in tutorial mode, send each message once, else in normal mode, randomly select requests
        choice = (
            body_messages[idx]
            if cfg.tutorial
            else random.choice(body_messages)  # noqa: S311
        )

        logger.info(f"Step: {choice.lower().split(' ', maxsplit=1)[0]!r}")
        logger.debug(f"Sending {choice!r} {cfg.random_string!r}")

        msg = send_and_receive(
            cfg.token,
            f"{choice} " f"{cfg.random_string}",
            secure_sock,
            cfg.other_timeout,
        )

        # if internal server error, break and close connection
        if choice.startswith("FAIL"):
            break

        split_msg = msg.split(" ", maxsplit=1)
        cksum = split_msg[0]
        body = split_msg[1] if len(split_msg) > 1 else ""
        logger.info(f"Received {body!r}")
        logger.debug(f"Checksum received: {cksum!r}")

    # end message
    if choice is not None and not choice.startswith("FAIL"):
        logger.info("Step: done")
        logger.debug("Sending DONE")
        msg = send_and_receive(cfg.token, "DONE", secure_sock, cfg.other_timeout)
        logger.info(f"Received {msg!r}")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the ``tlslp-server`` CLI.

    Args:
        argv (Sequence[str] | None): Optional argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        (int): Exit code (0 on success).

    Side effects:
        Binds a TCP port, accepts connections, writes logs, prints status lines.
    """

    parser = build_server_parser()
    ns = parser.parse_args(argv)
    cfg = args_to_server_config(ns)

    configure_logging(level=cfg.log_level, node="server", tutorial=cfg.tutorial)

    logger.info("Server starting")

    is_secure = not cfg.insecure

    logger.debug(f"CA cert exists: {os.path.exists(cfg.ca_cert)!r}")
    logger.debug(f"Server cert exists: {os.path.exists(cfg.server_cert)!r}")
    logger.debug(f"Server key exists: {os.path.exists(cfg.server_key)!r}")

    server_socket, context = prepare_server_socket(
        cfg.server_host,
        cfg.port,
        cfg.ca_cert,
        cfg.server_cert,
        cfg.server_key,
        is_secure,
    )
    print(f"Server listening on https://{cfg.server_host}:{cfg.port}")
    logger.info(f"Server listening on https://{cfg.server_host!r}:{cfg.port!r}")

    # Wait for a client to connect
    while True:
        client_socket, _ = server_socket.accept()
        with context.wrap_socket(client_socket, server_side=True) as secure_sock:
            try:
                handle_one_session(is_secure, cfg, secure_sock)
            except Exception:
                logger.exception("Unhandled exception in session")

        logger.info("Connection closed")
        print("Connection closed")

        if cfg.tutorial:
            break

    return 0


if __name__ == "__main__":
    main()
