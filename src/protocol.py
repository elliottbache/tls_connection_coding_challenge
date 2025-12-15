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
    buf = ""
    try:
        while True:
            chunk = secure_sock.recv(1024)

            # test for empty string
            if not chunk:
                raise ValueError("Receive failed.  Received empty string.")

            # ensure it's a bytes-like object
            if not isinstance(chunk, bytes):
                raise TypeError(f"Receive failed.  Unexpected type: " f"{type(chunk)}")

            # test received data to make sure it is UTF-8
            try:
                decoded_string = chunk.decode("utf-8")
            except UnicodeDecodeError as e:
                raise ValueError(f"Receive failed.  Invalid UTF-8: {e}") from e

            buf += decoded_string
            if len(buf) > MAX_LINE_LENGTH:
                raise ValueError("Line too long")

            # read until newline
            if buf.endswith("\n"):
                break

        return buf.rstrip("\n")

    except (TimeoutError, ssl.SSLError, OSError) as e:
        raise Exception(f"Receive failed: {e}") from e
