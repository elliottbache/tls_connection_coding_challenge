"""This contains tools that can be used by both server and client.

Notes:
    - Multiline messages are not supported since this was not part of the coding
    challenge.  Each command sent by the server was meant to be answered with
    a single-line.  Any more lines would fall outside the scope of the proper
    functioning of this program and should thus be treated as an exception.
"""

import socket
import ssl


class ProtocolError(ValueError):
    """Peer violated the newline-delimited UTF-8 protocol."""


class TransportError(RuntimeError):
    """Network/TLS error while sending/receiving."""


MAX_LINE_LENGTH = 1000
DEFAULT_IS_SECURE = True  # if we connect from localhost to localhost, this is False
DEFAULT_CA_CERT = "certificates/ca_cert.pem"
DEFAULT_OTHER_TIMEOUT = 6
DEFAULT_POW_TIMEOUT = 7200
DEFAULT_LONG_TIMEOUT = 24 * 3600
DEFAULT_SERVER_HOST = "localhost"


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
        >>> from src import send_message
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
        secure_sock.sendall(bstring_to_send)
    except (TimeoutError, ssl.SSLEOFError, ssl.SSLError, OSError, BrokenPipeError) as e:
        string_to_send_no_newline = string_to_send.rstrip("\n")
        raise TransportError(
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
        >>> from src import receive_message
        >>> s1, s2 = socket.socketpair()
        >>> try:
        ...     _ = s1.send(b"hello\\n")
        ...     _ = receive_message(s2)
        ... finally:
        ...     s1.close(); s2.close()
        Received hello
    """
    buf = bytearray()
    try:
        while True:
            chunk = secure_sock.recv(1024)

            # test for empty string
            if not chunk or chunk == b"":
                raise TransportError(
                    "Receive failed.  Received empty string. " "Peer probably closed."
                )

            # ensure it's a bytes-like object
            if not isinstance(chunk, bytes):
                raise TypeError(f"Receive failed.  Unexpected type: " f"{type(chunk)}")

            # test received data to make sure it is UTF-8
            try:
                chunk.decode("utf-8")
            except UnicodeDecodeError as e:
                raise ProtocolError(f"Receive failed.  Invalid UTF-8: {e}") from e

            buf += chunk
            if len(buf) > MAX_LINE_LENGTH:
                raise ProtocolError("Line too long")

            # read until newline
            if buf.endswith(b"\n"):
                break

        return buf.decode().rstrip("\n")

    except TimeoutError as e:
        raise TimeoutError("Receive timeout") from e

    except (ssl.SSLError, OSError) as e:
        raise TransportError(f"Receive failed: {e}") from e
