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
import random
import socket
import ssl
from collections.abc import Sequence
from dataclasses import dataclass

from src.protocol import (
    DEFAULT_CA_CERT,
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


def port(s: str) -> int:
    try:
        p = int(s)
    except ValueError as e:
        raise argparse.ArgumentTypeError("port must be an integer") from e
    if not (0 < p < 65536):
        raise argparse.ArgumentTypeError("port out of range (1..65535)")
    return p


def positive_int(s: str) -> int:
    try:
        n = int(s)
    except ValueError as e:
        raise argparse.ArgumentTypeError("must be an integer") from e
    if n <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return n


def build_client_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tls-client", description="TLS client for the toy protocol demo."
    )

    p.add_argument(
        "--host",
        default=DEFAULT_SERVER_HOST,
        help=f"server hostname (default: {DEFAULT_SERVER_HOST})",
    )

    p.add_argument(
        "--port",
        default=DEFAULT_PORT,
        type=int,
        help="comma-separated list of ports (e.g. 1234,8235)",
    )

    p.add_argument(
        "--server-cert",
        default=DEFAULT_SERVER_CERT,
        type=str,
        help="path to server certificate (PEM)",
    )
    p.add_argument(
        "--server-key",
        default=DEFAULT_SERVER_KEY,
        type=str,
        help="path to server private key (PEM)",
    )
    p.add_argument(
        "--ca-cert",
        default=DEFAULT_CA_CERT,
        type=str,
        help="path to client CA certificate (PEM)",
    )

    p.add_argument(
        "--pow-timeout",
        default=DEFAULT_WORK_TIMEOUT,
        type=positive_int,
        help=f"timeout (s) for WORK (default: {DEFAULT_WORK_TIMEOUT})",
    )
    p.add_argument(
        "--other-timeout",
        default=DEFAULT_OTHER_TIMEOUT,
        type=positive_int,
        help=f"timeout (s) for non-WORK steps (default: {DEFAULT_OTHER_TIMEOUT})",
    )

    p.add_argument(
        "--insecure",
        action="store_true",
        help="skip server cert verification (ONLY for localhost dev)",
    )

    p.add_argument(
        "--token",
        default=DEFAULT_AUTHDATA,
        type=str,
        help="authentication data for hashing",
    )

    p.add_argument(
        "--random-string",
        default=DEFAULT_RANDOM_STRING,
        type=str,
        help="random string for body messages checksums",
    )

    p.add_argument(
        "--difficulty",
        default=DEFAULT_DIFFICULTY,
        type=int,
        help="WORK challenge difficulty",
    )
    return p


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
    try:
        if to_send.startswith("ERROR"):
            raise Exception(to_send.split(" ", maxsplit=1)[1])  # internal server ERROR

        send_message(to_send, secure_sock)

        try:
            received_message = receive_message(secure_sock)
        except TimeoutError as e:
            raise TimeoutError("Client timeout") from e

        # check WORK suffix
        if to_send.startswith("WORK") and not _check_suffix(
            to_send, token, received_message
        ):
            raise Exception(r"Invalid suffix returned from client.")
        # check checksum for rest of possible messages
        elif not (
            to_send.startswith("WORK")
            or to_send.startswith("HELLO")
            or to_send.startswith("ERROR")
            or to_send.startswith("DONE")
        ) and not _check_cksum(to_send, token, received_message):
            raise Exception(r"Invalid checksum received.")

        return received_message

    except TimeoutError as e:
        send_error("ERROR Client timeout.", secure_sock)
        raise TimeoutError("Client timed out") from e

    except Exception as e:
        try:
            err_msg = str("ERROR " + e.args[0])
        except Exception:
            err_msg = "ERROR"
        send_error(err_msg, secure_sock)
        raise Exception(err_msg) from e


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
    server_socket.settimeout(timeout)

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

    # Wait for a client to connect
    while True:
        client_socket, client_address = server_socket.accept()
        with context.wrap_socket(client_socket, server_side=True) as secure_sock:
            if not secure_sock.getpeername():
                raise RuntimeError("No client certificate presented.")
            print(f"Connection from {client_address}")

            try:
                # handshake
                print("\nSending HELLO")
                msg = send_and_receive(
                    cfg.token, "HELLO", secure_sock, cfg.other_timeout
                )
                print(f"Received {msg}")

                print(
                    f"\nAuthentication data: {cfg.token}\nDifficulty: "
                    f"{cfg.difficulty}"
                )
                print(f"Sending WORK {cfg.token} {cfg.difficulty}")
                msg = send_and_receive(
                    cfg.token,
                    "WORK " + str(cfg.token) + " " + str(cfg.difficulty),
                    secure_sock,
                    cfg.pow_timeout,
                )
                print(f"Received suffix: {msg}")
                this_hash = hashlib.sha256(  # noqa: S324
                    (cfg.token + msg).encode()
                ).hexdigest()
                print(f"Hash: {this_hash}")
                print("Valid suffix returned from client.")

                # body
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
                    print(f"\nSending {choice} {cfg.random_string}")
                    msg = send_and_receive(
                        cfg.token,
                        f"{choice} " f"{cfg.random_string}",
                        secure_sock,
                        cfg.other_timeout,
                    )
                    print(f"Received {msg}")
                    print(f"Checksum received: {msg.split(' ', maxsplit=1)[0]}")
                    print("Valid checksum received.")

                # end message
                print("\nSending DONE")
                msg = send_and_receive(
                    cfg.token, "DONE", secure_sock, cfg.other_timeout
                )
                print(f"Received {msg}")

            except Exception as e:
                print(f"Exception: {e}")

            break

    print("\nConnection closed")

    return 0


if __name__ == "__main__":
    main()
