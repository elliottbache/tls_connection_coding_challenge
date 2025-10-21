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

import ssl
import socket
import random
from typing import Union
import hashlib

# module-level defaults (safe to import, optional)
DEFAULT_HOSTFULL_NAME = "localhost"
DEFAULT_PORT = 1234
DEFAULT_CA_CERT = "../certificates/ca_cert.pem"
DEFAULT_SERVER_CERT = "../certificates/server-cert.pem"
DEFAULT_SERVER_KEY = "../certificates/server-key.pem"


def send_message(string_to_send: str, secure_sock: socket.socket) -> int:
    """Send string to the client.

    This ensures that the string is UTF-8 and ends with a newline
    character.

    Args:
        string_to_send (str): the string to send.
        secure_sock (socket.socket): the secure socket to send to.

    Returns:
        int: 0 if no exception is raised, 1 if the string is invalid.

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

    # ensure that the string ends with endline
    if not string_to_send.endswith("\n"):
        string_to_send += "\n"

    # encode string
    bstring_to_send = string_to_send.encode('utf-8')

    # test received data to make sure it is UTF-8
    try:
        bstring_to_send.decode('utf-8')
    except Exception as e:
        print("string is not valid: ", e)
        return 1

    # send message
    print("\nSending " + string_to_send.rstrip('\n'))
    secure_sock.send(bstring_to_send)

    return 0


def receive_message(secure_sock: socket.socket) -> Union[int, str]:
    """Receive string from the client.

    This ensures that the string is UTF-8 and ends with a newline
    character.

    Args:
        secure_sock (socket.socket): the secure socket to receive from.

    Returns:
        int, str: the string if reception is successful.  Otherwise, -1.

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
    string_to_receive = secure_sock.recv(1024)

    # test for empty string
    if not string_to_receive:
        print("empty string")
        return -1

    # test received data to make sure it is UTF-8
    try:
        to_return = string_to_receive.decode('utf-8')
    except Exception as e:
        print("string is not valid: ", e)
        return -1

    # test received data to make sure it ends in newline
    if not string_to_receive.decode('utf-8').endswith("\n"):
        print("string does not end with new line")
        return -1

    string_received = string_to_receive.decode().replace("\n", "")
    print(f"Received {string_received}")

    return to_return


def is_succeed_send_and_receive(token: str, to_send: str,
                                secure_sock: socket.socket) \
        -> bool:
    """Send message and receive the string from the client.

    Closes the socket if an error occurs.

    Args:
        token (str): the authorization data.
        to_send (str): the string to send.
        secure_sock (socket.socket): the secure socket to receive from.

    Returns:
        bool: True if the string is correctly sent and its response is
            correctly received, False otherwise.
    """

    is_succeed = False
    try:
        if send_message(to_send, secure_sock):
            send_message("ERROR sending " + to_send, secure_sock)
            secure_sock.close()

        if to_send.startswith("ERROR"):
            return is_succeed

        received_message = receive_message(secure_sock)
        if received_message == -1:
            send_message("ERROR receiving " + to_send, secure_sock)
            secure_sock.close()

        is_succeed = True

        if to_send.startswith("WORK"):
            suffix = received_message.replace("\n", "")
            hash = hashlib.sha256((token + suffix).encode()).hexdigest()
            print(f"Valid WORK Suffix: {suffix}\n"
                  f"Authentification data: {token}\n"
                  f"Hash: {hash}")
        elif not (to_send.startswith("HELLO") or to_send.startswith("ERROR")
                  or to_send.startswith("DONE")):
            cksum = received_message.split(" ")[0]
            random_string = to_send.split(" ")[1]
            cksum_calc = hashlib.sha256((token
                                       + random_string).encode()).hexdigest()
            print(f"Checksum received: {cksum}\n"
                  f"Checksum calculated: {cksum_calc}")
            if cksum == cksum_calc:
                print("Valid checksum received.")
            else:
                print("Invalid checksum received.")
                is_succeed = False

    finally:
        if not is_succeed:
            secure_sock.close()
            print("closing connection\n")

    return is_succeed


def prepare_socket(hostname: str, port: int, ca_cert_path: str,
                   server_cert_path: str, server_key_path: str) \
            -> tuple[socket.socket, ssl.SSLContext]:
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

    print(f"Server listening on https://localhost:{port}")

    return server_socket, context


def main() -> int:
    token = 'gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzu' \
               + 'WROTeTaSmqFCAzuwkwLCRgIIq'
    random_string = 'LGTk'
    difficulty = 6
    ca_cert_path = DEFAULT_CA_CERT
    server_cert_path = DEFAULT_SERVER_CERT
    server_key_path = DEFAULT_SERVER_KEY
    hostname = DEFAULT_HOSTFULL_NAME
    port = DEFAULT_PORT

    server_socket, context = prepare_socket(hostname, port, ca_cert_path,
                                            server_cert_path, server_key_path)

    # Wait for a client to connect
    is_error = False
    while True:
        client_socket, client_address = server_socket.accept()
        with context.wrap_socket(client_socket, server_side=True) \
                as secure_sock:
            print(f"Connection from {client_address}")

            # handshake
            if not is_succeed_send_and_receive(token, "HELLO", secure_sock):
                break
            print(f"Authentification data: {token}\nDifficulty: "
                  f"{difficulty}")
            if not is_succeed_send_and_receive(token, "WORK "
                                               + str(token) + " "
                                               + str(difficulty), secure_sock):
                break

            # body
            for i in range(20):
                # This randomly sends requests to the client.
                choice = random.choice([
                                        "FULL_NAME", "MAILNUM", "EMAIL1", "EMAIL2",
                                        "SOCIAL", "BIRTHDATE", "COUNTRY",
                                        "ADDRNUM", "ADDR_LINE1", "ADDR_LINE2",
                                        "ERROR internal server error"
                ])
                if not is_succeed_send_and_receive(token, f"{choice} "
                                                   f"{random_string}",
                                                   secure_sock):
                    is_error = True
                    break
                if choice == "ERROR internal server error":
                    secure_sock.close()
                    is_error = True
                    break
            if is_error:
                break

            # end message
            if not is_succeed_send_and_receive(token, "DONE", secure_sock):
                break

    return 0


if __name__ == '__main__':
    main()
