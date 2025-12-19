"""Creates a local server that will listen on a specified port for TLS
connections.

Requires a handshake and then requests randomly
selected defined information from the client.  The WORK challenge in the
handshake has a timeout of 2 hours.

Functions:
    send_message:
        send the supplied string to the client, validating
        the format of the string.

    receive_message:
        receive the supplied string from the client,
        validating the format of the string.

    is_succeed_send_and_receive:
        send message and receive the string from the client.

    prepare_server_socket:
        prepare a socket to be used for sending and receiving.
"""

import argparse
import hashlib
import logging
import math
import random
import socket
import ssl
from collections.abc import Sequence
from dataclasses import dataclass

from tlslp.logging_utils import configure_logging
from tlslp.protocol import (
    DEFAULT_CA_CERT,
    DEFAULT_LONG_TIMEOUT,
    DEFAULT_OTHER_TIMEOUT,
    DEFAULT_WORK_TIMEOUT,
    DEFAULT_SERVER_HOST,
    receive_message,
    send_message,
)

# module-level defaults (safe to import, optional)
DEFAULT_PORT = 1234
DEFAULT_SERVER_CERT = "certificates/server-cert.pem"
DEFAULT_SERVER_KEY = "certificates/server-key.pem"
DEFAULT_AUTHDATA = "gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzuWROTeTaSmqFCAzuwkwLCRgIIq"
DEFAULT_RANDOM_STRING = "LGTk"
DEFAULT_DIFFICULTY = 4

logger = logging.getLogger(__name__)


@dataclass
class ServerConfig:
    server_host: str
    port: int
    server_cert: str
    server_key: str
    ca_cert: str
    pow_timeout: int
    other_timeout: int
    insecure: bool
    token: str
    random_string: str
    difficulty: int
    log_level: str
    json_logs: bool


def port(s: str) -> int:
    try:
        p = int(s)
    except ValueError as e:
        logger.exception(f"port must be an integer: {e}")
        raise argparse.ArgumentTypeError("port must be an integer") from e
    if not (0 < p < 65536):
        logger.exception("port out of range (1..65535)")
        raise argparse.ArgumentTypeError("port out of range (1..65535)")
    return p


def positive_int(s: str) -> int:
    try:
        n = int(s)
    except ValueError as e:
        logger.exception(f"must be an integer: {e}")
        raise argparse.ArgumentTypeError("must be an integer") from e
    if n <= 0:
        logger.exception("must be > 0")
        raise argparse.ArgumentTypeError("must be > 0")
    return n


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
        "--port",
        default=DEFAULT_PORT,
        type=int,
        help="comma-separated list of ports (e.g. 1234,8235)",
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
        "--pow-timeout",
        default=DEFAULT_WORK_TIMEOUT,
        type=positive_int,
        help=f"timeout (s) for WORK (default: {DEFAULT_WORK_TIMEOUT})",
    )
    parser.add_argument(
        "--other-timeout",
        default=DEFAULT_OTHER_TIMEOUT,
        type=positive_int,
        help=f"timeout (s) for non-WORK steps (default: {DEFAULT_OTHER_TIMEOUT})",
    )

    parser.add_argument(
        "--insecure",
        action="store_true",
        help="skip server cert verification (ONLY for localhost dev)",
    )

    parser.add_argument(
        "--token",
        default=DEFAULT_AUTHDATA,
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
        "--difficulty",
        default=DEFAULT_DIFFICULTY,
        type=int,
        help="WORK challenge difficulty",
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


def args_to_server_config(ns: argparse.Namespace) -> ServerConfig:
    return ServerConfig(
        server_host=ns.host,
        port=ns.port,
        server_cert=ns.server_cert,
        server_key=ns.server_key,
        ca_cert=ns.ca_cert,
        pow_timeout=ns.pow_timeout,
        other_timeout=ns.other_timeout,
        insecure=ns.insecure,
        token=ns.token,
        random_string=ns.random_string,
        difficulty=ns.difficulty,
        log_level=ns.log_level,
        json_logs=ns.json_logs,
    )


def _check_suffix(to_send: str, token: str, received_message: str) -> bool:
    """Check if suffix has enough leading zeros."""
    difficulty = to_send.split(" ", maxsplit=2)[2]
    first_zeros = "0" * int(difficulty)
    this_hash = hashlib.sha256(  # noqa: S324
        (token + received_message).encode()
    ).hexdigest()
    return this_hash.startswith(first_zeros)


def _check_cksum(to_send: str, token: str, received_message: str) -> bool:
    """Check if checksum is correct."""
    cksum = str(received_message).split(" ", maxsplit=1)[0]
    random_string = to_send.split(" ", maxsplit=1)[1]
    cksum_calc = hashlib.sha256(  # noqa: S324
        (token + random_string).encode()
    ).hexdigest()
    return cksum == cksum_calc


def send_and_receive(
    token: str, to_send: str, secure_sock: socket.socket, timeout: float = 6.0
) -> str:
    """Send message and receive the string from the client.

    The sent and received messages are checked for format validity and the received
    messages that contain checksums or a WORK suffix are checked.

    Args:
        token (str): the authorization data.
        to_send (str): the string to send (with or without newline character).
        secure_sock (socket.socket): the secure socket to receive from.
        timeout (float): the timeout for receiving.

    Returns:
        str: the string received.
    """
    received_message = ""
    secure_sock.settimeout(timeout)
    if to_send.startswith("ERROR"):
        raise Exception(to_send.split(" ", maxsplit=1)[1])  # internal server ERROR

    try:
        send_message(to_send, secure_sock)
    except Exception as e:
        logger.exception(f"Send error: {e}")
        send_error("ERROR sending.", secure_sock)
        raise ValueError(r"ERROR sending.") from e

    try:
        received_message = receive_message(secure_sock)
    except TimeoutError as e:
        logger.exception(f"Client timeout: {e}")
        raise TimeoutError("Client timeout") from e
    except Exception as e:
        logger.exception(f"Receive error {e}.")
        send_error("ERROR receiving.", secure_sock)
        raise ValueError(r"ERROR receiving.") from e

    # check WORK suffix
    if to_send.startswith("WORK") and not _check_suffix(
        to_send, token, received_message
    ):
        logger.exception("Invalid suffix returned from client.")
        send_error("ERROR Invalid suffix returned from client.", secure_sock)
        raise ValueError(r"Invalid suffix returned from client.")
    # check checksum for rest of possible messages
    elif not (
        to_send.startswith("WORK")
        or to_send.startswith("HELLO")
        or to_send.startswith("ERROR")
        or to_send.startswith("DONE")
    ) and not _check_cksum(to_send, token, received_message):
        logger.exception("Invalid checksum received.")
        send_error("ERROR Invalid checksum received.", secure_sock)
        raise ValueError(r"Invalid checksum received.")

    return received_message


def send_error(to_send: str, secure_sock: socket.socket) -> None:
    """Send an error message to the client.

    Args:
        to_send (str): the string to send.
        secure_sock (socket.socket): the secure socket to receive from.
        is_succeed (bool): True if the string is correctly send.

    Returns:
        None
    """

    try:
        send_message(to_send, secure_sock)
    finally:
        pass


def prepare_server_socket(
    server_host: str,
    port: int,
    ca_cert_path: str,
    server_cert_path: str,
    server_key_path: str,
    is_secure: bool = False,
    timeout: int = 6,
) -> tuple[socket.socket, ssl.SSLContext]:
    """Prepare a socket to be used for sending and receiving.

    Args:
        server_host (str): the server_host to connect to.
        port (int): the port to connect to.
        ca_cert_path (str): path to the CA certificate file.
        server_cert_path (str): path to the server certificate file.
        server_key_path (str): path to the server key file.
        is_secure (bool): True if the socket is secure.

    Returns:
        socket.socket: the socket to be used for sending and receiving.
        ssl.SSLContext: the ssl context to be used for sending and receiving.
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

    # Define the server address and port
    server_address = (server_host, port)

    # Create the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(server_address)
    server_socket.listen(1)
    server_socket.settimeout(DEFAULT_LONG_TIMEOUT)

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


def main(argv: Sequence[str] | None = None) -> int:

    parser = build_client_parser()
    ns = parser.parse_args(argv)
    cfg = args_to_server_config(ns)

    configure_logging(level=cfg.log_level, json_logs=cfg.json_logs, node="server")

    logger.info("Server starting")

    is_secure = not cfg.insecure

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
        client_socket, client_address = server_socket.accept()
        with context.wrap_socket(client_socket, server_side=True) as secure_sock:
            if not secure_sock.getpeername():
                logger.exception("No client certificate presented.")
                raise RuntimeError("No client certificate presented.")
            logger.info(f"Connection from {client_address!r}")

            try:
                # handshake
                logger.info("Step: handshake")
                logger.debug("Sending HELLO")
                msg = send_and_receive(
                    cfg.token, "HELLO", secure_sock, cfg.other_timeout
                )
                logger.debug(f"Received {msg!r}")

                # only log first part of token
                half_len_token = math.ceil(len(cfg.token) / 2)
                logger.debug(
                    f"Authentication data: {cfg.token[:half_len_token]!r}..., Difficulty: {cfg.difficulty!r}"
                )

                msg = send_and_receive(
                    cfg.token,
                    "WORK " + str(cfg.token) + " " + str(cfg.difficulty),
                    secure_sock,
                    cfg.pow_timeout,
                )
                logger.info(f"Valid suffix returned from client: {msg!r}")
                this_hash = hashlib.sha256(  # noqa: S324
                    (cfg.token + msg).encode()
                ).hexdigest()
                logger.info(f"Hash: {this_hash!r}")

                # body
                choice = None
                for _ in range(20):
                    # This randomly sends requests to the client.
                    choice = random.choice(  # noqa: S311
                        [
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
                            "ERROR internal server error",
                        ]
                    )
                    logger.info(f"Step: {choice.lower().split(' ', maxsplit=1)[0]!r}")
                    logger.debug(f"Sending {choice!r} {cfg.random_string!r}")

                    # if internal server error, break and close connection
                    if choice.startswith("ERROR"):
                        break

                    msg = send_and_receive(
                        cfg.token,
                        f"{choice} " f"{cfg.random_string}",
                        secure_sock,
                        cfg.other_timeout,
                    )
                    logger.debug(f"Received {msg!r}")
                    logger.info(
                        f"Valid checksum received: {msg.split(' ', maxsplit=1)[0]!r}"
                    )

                # if internal server error, break and close connection
                if choice is not None and choice.startswith("ERROR"):
                    break

                # end message
                logger.info("Step: end")
                logger.debug("Sending DONE")
                msg = send_and_receive(
                    cfg.token, "DONE", secure_sock, cfg.other_timeout
                )
                logger.debug(f"Received {msg!r}")

            except Exception as e:
                logger.exception(f"Exception: {e}")

            break

    logger.info("Connection closed")
    print("Connection closed")

    return 0


if __name__ == "__main__":
    main()
