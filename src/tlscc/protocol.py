"""Shared protocol helpers for the TLS client and server.

The challenge protocol is **newline-delimited UTF-8**:

- Every outbound message is a ``str`` that is UTF-8 encoded and ends with ``"\\n"``.
- Every inbound message is read until a trailing newline is seen, then decoded
  as UTF-8 and returned **without** the newline.
- Multiline payloads are intentionally unsupported: a peer must send exactly one
  logical command per line.

This module raises:
- ``ProtocolError`` when the peer violates message framing/encoding rules
  (non-bytes from socket, invalid UTF-8, line too long, etc.).
- ``TransportError`` for network/TLS failures (timeouts, disconnects, OS errors).
"""

import argparse
import logging
import socket
import ssl


class ProtocolError(ValueError):
    """Peer violated the newline-delimited UTF-8 protocol."""


class TransportError(RuntimeError):
    """Network/TLS error while sending/receiving."""


MAX_LINE_LENGTH = 1000
DEFAULT_CA_CERT = "certificates/ca_cert.pem"
DEFAULT_OTHER_TIMEOUT = 6
DEFAULT_WORK_TIMEOUT = 7200
DEFAULT_LONG_TIMEOUT = 24 * 3600
DEFAULT_SERVER_HOST = "localhost"
DEFAULT_BODY_MESSAGES = [
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
]

logger = logging.getLogger(__name__)


def _parse_positive_int(s: str) -> int:
    """Parse a CLI argument as a positive integer (> 0).

    Intended for use as an ``argparse`` ``type=...`` function.

    Args:
        s (str): Flag from the command line.

    Returns:
        (int): Parsed positive integer.

    Raises:
        argparse.ArgumentTypeError: If ``s`` is not an integer or is <= 0.

    Examples:
        >>> _parse_positive_int("6")
        6
    """
    # no logging since errors here would be user input errors and probably shouldn't
    # congest persistent logs
    try:
        n = int(s)
    except ValueError as e:
        raise argparse.ArgumentTypeError("must be an integer") from e
    if n <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return n


def send_message(string_to_send: str, secure_sock: socket.socket) -> None:
    """Send one newline-delimited UTF-8 message.

    The function guarantees:
    - the payload is a ``str`` (otherwise ``ProtocolError``),
    - it ends with a newline (adds one if missing),
    - it can be encoded as UTF-8,
    - it is fully transmitted using ``sendall``.

    Args:
        string_to_send (str): Message to send (with or without a trailing ``"\\n"``).
        secure_sock (socket.socket): Connected socket (plain or TLS-wrapped) to send on.

    Raises:
        ProtocolError: If the payload is not a ``str`` or cannot be UTF-8 encoded.
        TransportError: If the underlying socket/TLS layer fails while sending.

    Examples:
        >>> import socket
        >>> a, b = socket.socketpair()
        >>> try:
        ...     send_message("HELLO", a)
        ...     b.recv(16)
        ... finally:
        ...     a.close(); b.close()
        b'HELLO\\n'
    """
    # ensure it's a string object
    if not isinstance(string_to_send, str):
        raise ProtocolError(
            f"Send failed: expected str, got {type(string_to_send).__name__}"
        )

    # ensure that the string ends with endline
    if not string_to_send.endswith("\n"):
        string_to_send += "\n"

    # encode string
    try:
        bstring_to_send = string_to_send.encode("utf-8")
    except UnicodeEncodeError as e:
        raise ProtocolError(f"Send failed: could not encode UTF-8: {e}") from e

    # send message
    try:
        secure_sock.sendall(bstring_to_send)
    except (TimeoutError, ssl.SSLEOFError, ssl.SSLError, OSError, BrokenPipeError) as e:
        string_to_send_no_newline = string_to_send.rstrip("\n")
        raise TransportError(
            f"Send failed while sending {string_to_send_no_newline!r}: {type(e).__name__}: {e}"
        ) from e


def receive_message(secure_sock: socket.socket) -> str:
    """Receive one newline-delimited UTF-8 message.

    Reads from the socket until a newline byte is observed, then decodes as UTF-8
    and returns the string without the trailing newline.

    Args:
        secure_sock (socket.socket): Connected socket (plain or TLS-wrapped) to read from.

    Returns:
        (str): The decoded message with the trailing newline removed.

    Raises:
        ProtocolError: If the peer sends non-bytes, invalid UTF-8, or a line that
            exceeds ``MAX_LINE_LENGTH``.
        TransportError: If the peer closes the connection, a timeout occurs, or
            another network/TLS/OS error happens.

    Examples:
        >>> import socket
        >>> a, b = socket.socketpair()
        >>> try:
        ...     a.sendall(b"HELLOBACK\\n")
        ...     receive_message(b)
        ... finally:
        ...     a.close(); b.close()
        'HELLOBACK'
    """
    buf = bytearray()
    try:
        while True:
            chunk = secure_sock.recv(1024)

            # test for empty string
            if not chunk or chunk == b"":
                raise TransportError("Receive failed: peer closed connection")

            # ensure it's a bytes-like object
            if not isinstance(chunk, bytes):
                raise ProtocolError(
                    f"Receive failed: expected bytes, got {type(chunk).__name__}"
                )

            buf += chunk
            if len(buf) > MAX_LINE_LENGTH:
                raise ProtocolError("Receive failed: line too long")

            # read until newline
            if buf.endswith(b"\n"):
                break

        # test received data to make sure it is UTF-8
        try:
            return buf.decode("utf-8").rstrip("\n")
        except UnicodeDecodeError as e:
            raise ProtocolError(f"Receive failed: invalid UTF-8: {e}") from e

    except TimeoutError as e:
        raise TransportError(f"Receive timeout: {e}") from e

    except ProtocolError as e:
        raise ProtocolError(f"Receive failed: {type(e).__name__}: {e}") from e

    except Exception as e:
        raise TransportError(f"Receive failed: {type(e).__name__}: {e}") from e
