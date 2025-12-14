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

    prepare_socket:
        prepare a socket to be used for sending and receiving.
"""

import hashlib
import random
import socket
import ssl

# module-level defaults (safe to import, optional)
DEFAULT_HOSTFULL_NAME = "localhost"
DEFAULT_PORT = 1234
DEFAULT_CA_CERT = "certificates/ca_cert.pem"
DEFAULT_SERVER_CERT = "certificates/server-cert.pem"
DEFAULT_SERVER_KEY = "certificates/server-key.pem"


def send_message(string_to_send: str, secure_sock: socket.socket) -> None:
    """Send string to the client.

    This ensures that the string is UTF-8 and ends with a newline
    character.

    Args:
        string_to_send (str): the string to send.
        secure_sock (socket.socket): the secure socket to send to.

    Returns:
        None

    Raises:
        Exception if error in sending.

    Examples:
        Basic usage with an in-process socketpair (no network):
        >>> from src.server import send_message
        >>> s1, s2 = socket.socketpair()
        >>> try:
        ...     _ = send_message("hello\\n", s1)   # returns 0 on success
        ...     s2.recv(1024)
        ... finally:
        ...     s1.close(); s2.close()
        <BLANKLINE>
        Sending hello
        b'hello\\n'

        Newline is added if missing:
        >>> a, b = socket.socketpair()
        >>> try:
        ...     _ = send_message("OK", a)
        ...     b.recv(3)
        ... finally:
        ...     a.close(); b.close()
        <BLANKLINE>
        Sending OK
        b'OK\\n'
    """
    # ensure it's a string object
    if not isinstance(string_to_send, str):
        raise TypeError(f"Send failed.  Unexpected type: " f"{type(string_to_send)}")

    # ensure that the string ends with endline
    if not string_to_send.endswith("\n"):
        string_to_send += "\n"

    # encode string
    bstring_to_send = string_to_send.encode("utf-8")

    # send message
    try:
        secure_sock.send(bstring_to_send)
    except (TimeoutError, ssl.SSLEOFError, ssl.SSLError, OSError, BrokenPipeError) as e:
        string_to_send_no_newline = string_to_send.rstrip("\n")
        raise Exception(
            f"Send failed.  Sending {string_to_send_no_newline}." f"  {type(e)} {e}"
        ) from e


def receive_message(secure_sock: socket.socket) -> str:
    """Receive string from the client.

    This ensures that the string is UTF-8 and ends with a newline
    character.

    Args:
        secure_sock (socket.socket): the secure socket to receive from.

    Returns:
        str: the string without newline if reception is successful.

    Raises:
        Exception if error in receiving.

    Examples:
        Basic usage with an in-process socketpair (no network):
        >>> from src.server import receive_message
        >>> s1, s2 = socket.socketpair()
        >>> try:
        ...     _ = s1.send(b"hello\\n")
        ...     _ = receive_message(s2)
        ... finally:
        ...     s1.close(); s2.close()
        Received hello
    """

    # receive data
    try:
        string_to_receive = secure_sock.recv(1024)
    except (TimeoutError, ssl.SSLError, OSError) as e:
        raise Exception(f"Receive failed: {e}") from e

    # test for empty string
    if not string_to_receive:
        raise ValueError("Receive failed.  Received empty string.")

    # ensure it's a bytes-like object
    if not isinstance(string_to_receive, bytes):
        raise TypeError(
            f"Receive failed.  Unexpected type: " f"{type(string_to_receive)}"
        )

    # test received data to make sure it is UTF-8
    try:
        decoded_string = string_to_receive.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"Receive failed.  Invalid UTF-8: {e}") from e

    # test received data to make sure it ends in newline
    if not decoded_string.endswith("\n"):
        raise ValueError("Receive failed. String does not end with new line.")

    return decoded_string.replace("\n", "")


def send_and_receive(token: str, to_send: str, secure_sock: socket.socket) -> str:
    """Send message and receive the string from the client.

    The messages are checked for validity.  Closes the socket if an error
    occurs.

    Args:
        token (str): the authorization data.
        to_send (str): the string to send.
        secure_sock (socket.socket): the secure socket to receive from.

    Returns:
        str: the string received.
    """
    received_message = ""
    try:
        if to_send.startswith("ERROR"):
            raise Exception(f"ERROR {to_send}")

        send_message(to_send, secure_sock)

        received_message = receive_message(secure_sock)

        if to_send.startswith("WORK"):
            difficulty = to_send.split(" ")[2]
            first_zeros = "0" * int(difficulty)
            hash = hashlib.sha256(  # noqa: S324
                (token + received_message).encode()
            ).hexdigest()
            if not hash.startswith(first_zeros):
                raise Exception(r"Invalid suffix returned from client.")

        elif not (
            to_send.startswith("HELLO")
            or to_send.startswith("ERROR")
            or to_send.startswith("DONE")
        ):
            cksum = str(received_message).split(" ")[0]
            random_string = to_send.split(" ")[1]
            cksum_calc = hashlib.sha256(  # noqa: S324
                (token + random_string).encode()
            ).hexdigest()
            if cksum != cksum_calc:
                raise Exception(r"Invalid checksum received.")

    except Exception as e:
        #        print(f"Exception: {e.args[0]}")
        #        print(f"ERROR {e.args[0]}")
        send_error("ERROR " + e.args[0], secure_sock)
        raise Exception(str(e.args)) from e

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
        secure_sock.close()


def prepare_socket(
    hostname: str,
    port: int,
    ca_cert_path: str,
    server_cert_path: str,
    server_key_path: str,
) -> tuple[socket.socket, ssl.SSLContext]:
    """Prepare a socket to be used for sending and receiving.

    Args:
        hostname (str): the hostname to connect to.
        port (int): the port to connect to.
        ca_cert_path (str): path to the CA certificate file.
        server_cert_path (str): path to the server certificate file.
        server_key_path (str): path to the server key file.

    Returns:
        socket.socket: the socket to be used for sending and receiving.
        ssl.SSLContext: the ssl context to be used for sending and receiving.
    """
    # Check that hostname is local, otherwise raise error so that insecure
    # connection isn't mistakenly used
    if hostname != "localhost":
        raise ValueError(
            f"Refusing insecure TLS to {hostname}. For "
            f"non-local hosts, enable certificate verification."
        )

    # Define the server address and port
    server_address = (hostname, port)

    # Create the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(server_address)
    server_socket.listen(1)

    # Wrap the socket with SSL
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    # Load the CA certificate (for client certificate verification)
    context.load_verify_locations(cafile=ca_cert_path)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=server_cert_path, keyfile=server_key_path)

    return server_socket, context


def main() -> int:

    token = "gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzu" + "WROTeTaSmqFCAzuwkwLCRgIIq"
    random_string = "LGTk"
    difficulty = 6
    ca_cert_path = DEFAULT_CA_CERT
    server_cert_path = DEFAULT_SERVER_CERT
    server_key_path = DEFAULT_SERVER_KEY
    hostname = DEFAULT_HOSTFULL_NAME
    port = DEFAULT_PORT

    server_socket, context = prepare_socket(
        hostname, port, ca_cert_path, server_cert_path, server_key_path
    )
    print(f"Server listening on https://{hostname}:{port}")

    # Wait for a client to connect
    while True:
        client_socket, client_address = server_socket.accept()
        with context.wrap_socket(client_socket, server_side=True) as secure_sock:
            print(f"Connection from {client_address}")

            # handshake
            print("Sending HELLO")
            msg = send_and_receive(token, "HELLO", secure_sock)
            print(f"Received {msg}")

            print(f"Authentication data: {token}\nDifficulty: " f"{difficulty}")
            print(f"Sending WORK {token} {difficulty}")
            msg = send_and_receive(
                token, "WORK " + str(token) + " " + str(difficulty), secure_sock
            )
            print(f"Received suffix: {msg}")
            hash = hashlib.sha256((token + msg).encode()).hexdigest()  # noqa: S324
            print(f"Hash: {hash}")
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
                print(f"Sending {choice} {random_string}")
                msg = send_and_receive(
                    token, f"{choice} " f"{random_string}", secure_sock
                )
                print(f"Received {msg}")
                print(f"Checksum received: {msg.split(' ')[0]}")
                print("Valid checksum received.")

            # end message
            print("Sending DONE")
            msg = send_and_receive(token, "DONE", secure_sock)
            print(f"Received {msg}")
            print("\nConnection closed")
            break

    return 0


if __name__ == "__main__":
    main()
