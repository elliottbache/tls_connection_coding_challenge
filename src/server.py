"""Creates a local server that will listen on a specified port for TLS
connections.

Requires a handshake and then requests randomly
selected defined information from the client.  The POW challenge in the
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

import hashlib
import random
import socket
import ssl

from src.protocol import (
    DEFAULT_CA_CERT,
    DEFAULT_IS_SECURE,
    DEFAULT_OTHER_TIMEOUT,
    DEFAULT_POW_TIMEOUT,
    DEFAULT_SERVER_HOST,
    receive_message,
    send_message,
)

# module-level defaults (safe to import, optional)
DEFAULT_PORT = 3481
DEFAULT_SERVER_CERT = "certificates/server-cert.pem"
DEFAULT_SERVER_KEY = "certificates/server-key.pem"
DEFAULT_AUTHDATA = "gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzuWROTeTaSmqFCAzuwkwLCRgIIq"
DEFAULT_RANDOM_STRING = "LGTk"
DEFAULT_DIFFICULTY = 4


def _check_suffix(to_send: str, authdata: str, received_message: str) -> bool:
    """Check if suffix has enough leading zeros."""
    difficulty = to_send.split(" ", maxsplit=2)[2]
    first_zeros = "0" * int(difficulty)
    this_hash = hashlib.sha1(  # noqa: S324
        (authdata + received_message).encode()
    ).hexdigest()
    return this_hash.startswith(first_zeros)


def _check_cksum(to_send: str, authdata: str, received_message: str) -> bool:
    """Check if checksum is correct."""
    cksum = str(received_message).split(" ", maxsplit=1)[0]
    random_string = to_send.split(" ", maxsplit=1)[1]
    cksum_calc = hashlib.sha1(  # noqa: S324
        (authdata + random_string).encode()
    ).hexdigest()
    return cksum == cksum_calc


def send_and_receive(
    authdata: str, to_send: str, secure_sock: socket.socket, timeout: float = 6.0
) -> str:
    """Send message and receive the string from the client.

    The sent and received messages are checked for format validity and the received
    messages that contain checksums or a POW suffix are checked.

    Args:
        authdata (str): the authorization data.
        to_send (str): the string to send (with or without newline character).
        secure_sock (socket.socket): the secure socket to receive from.
        timeout (float): the timeout for receiving.

    Returns:
        str: the string received.
    """
    received_message = ""
    try:
        if to_send.startswith("ERROR"):
            raise Exception(to_send.split(" ", maxsplit=1)[1])  # internal server ERROR

        send_message(to_send, secure_sock)

        secure_sock.settimeout(timeout)
        try:
            received_message = receive_message(secure_sock)
        except TimeoutError as e:
            raise TimeoutError("Client timeout") from e
        secure_sock.settimeout(None)

        # check POW suffix
        if to_send.startswith("POW") and not _check_suffix(
            to_send, authdata, received_message
        ):
            raise Exception(r"Invalid suffix returned from client.")
        # check checksum for rest of possible messages
        elif not (
            to_send.startswith("POW")
            or to_send.startswith("HELO")
            or to_send.startswith("ERROR")
            or to_send.startswith("END")
        ) and not _check_cksum(to_send, authdata, received_message):
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


def main() -> int:

    authdata = DEFAULT_AUTHDATA
    random_string = DEFAULT_RANDOM_STRING
    difficulty = DEFAULT_DIFFICULTY
    ca_cert_path = DEFAULT_CA_CERT
    server_cert_path = DEFAULT_SERVER_CERT
    server_key_path = DEFAULT_SERVER_KEY
    server_host = DEFAULT_SERVER_HOST
    port = DEFAULT_PORT
    is_secure = DEFAULT_IS_SECURE
    pow_timeout = DEFAULT_POW_TIMEOUT
    other_timeout = DEFAULT_OTHER_TIMEOUT

    server_socket, context = prepare_server_socket(
        server_host, port, ca_cert_path, server_cert_path, server_key_path, is_secure
    )
    print(f"Server listening on https://{server_host}:{port}")

    # Wait for a client to connect
    while True:
        client_socket, client_address = server_socket.accept()
        with context.wrap_socket(client_socket, server_side=True) as secure_sock:
            if not secure_sock.getpeername():
                raise RuntimeError("No client certificate presented.")
            print(f"Connection from {client_address}")

            try:
                # handshake
                print("\nSending HELO")
                msg = send_and_receive(authdata, "HELO", secure_sock, other_timeout)
                print(f"Received {msg}")

                print(
                    f"\nAuthentication data: {authdata}\nDifficulty: " f"{difficulty}"
                )
                print(f"Sending POW {authdata} {difficulty}")
                msg = send_and_receive(
                    authdata,
                    "POW " + str(authdata) + " " + str(difficulty),
                    secure_sock,
                    pow_timeout,
                )
                print(f"Received suffix: {msg}")
                this_hash = hashlib.sha1(  # noqa: S324
                    (authdata + msg).encode()
                ).hexdigest()
                print(f"Hash: {this_hash}")
                print("Valid suffix returned from client.")

                # body
                for _ in range(20):
                    # This randomly sends requests to the client.
                    choice = random.choice(  # noqa: S311
                        [
                            "NAME",
                            "MAILNUM",
                            "MAIL1",
                            "MAIL2",
                            "SKYPE",
                            "BIRTHDATE",
                            "COUNTRY",
                            "ADDRNUM",
                            "ADDRLINE1",
                            "ADDRLINE2",
                            "ERROR internal server error",
                        ]
                    )
                    print(f"\nSending {choice} {random_string}")
                    msg = send_and_receive(
                        authdata,
                        f"{choice} " f"{random_string}",
                        secure_sock,
                        other_timeout,
                    )
                    print(f"Received {msg}")
                    print(f"Checksum received: {msg.split(' ', maxsplit=1)[0]}")
                    print("Valid checksum received.")

                # end message
                print("\nSending END")
                msg = send_and_receive(authdata, "END", secure_sock, other_timeout)
                print(f"Received {msg}")

            except Exception as e:
                print(f"Exception: {e}")

            break

    print("\nConnection closed")

    return 0


if __name__ == "__main__":
    main()
