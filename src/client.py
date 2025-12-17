"""Opens a client node that will interact with a defined server.

This follows a set of rules defined in the toy protocol demo. The
specific rules and the external IP address are not quoted here for
confidentiality reasons.  The client connects to the server and then
listens for a list of commands that are answered one by one.  The
first two commands are the handshake and contain 'HELLO' and 'WORK'.
The WORK challenge must be resolved in 2 hours.  This challenge is
resolved by a C++ code called pow_benchmark.cpp.  Multithreading is
used when calling this C++ code.

Functions:
    tls_connect:
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

import errno
import hashlib
import multiprocessing
import os
import re
import socket
import ssl
import stat
import subprocess
import sys
import time
from pathlib import Path

from src.protocol import (
    DEFAULT_CA_CERT,
    DEFAULT_IS_SECURE,
    receive_message,
    send_message,
)

DEFAULT_CPP_BINARY_PATH = "build/pow_benchmark"  # path to c++ executable
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
DEFAULT_SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
DEFAULT_PORTS = [int(p) for p in os.getenv("PORTS", "1234").split(",")]
DEFAULT_PRIVATE_KEY_PATH = "certificates/ec_private_key.pem"
DEFAULT_CLIENT_CERT_PATH = "certificates/client_cert.pem"
DEFAULT_ALL_TIMEOUT = 6
DEFAULT_WORK_TIMEOUT = 7200


def tls_connect(
    ca_cert_path: str,
    client_cert_path: str,
    private_key_path: str,
    server_host: str,
    is_secure: bool = False,
) -> socket.socket:
    """
    Create a connection to the remote server.

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
        raise ValueError(
            f"Refusing insecure TLS to {server_host}. For "
            f"non-local hosts, enable certificate verification."
        )

    # create the client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(DEFAULT_ALL_TIMEOUT)

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
        >>> from src.client import hasher
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
        >>> from src.client import decipher_message
        >>> decipher_message(message, valid_messages)
        Received MAILNUM LGTk
        (0, ['MAILNUM', 'LGTk'])
    """
    args = message.split()

    # check that the message has arguments
    if not args:
        raise ValueError(f"No args in the response: {message}")

    # check that message belongs to list of possible messages
    if args[0] not in valid_messages:
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


def _validate_path(bin_path: Path) -> None:
    """Resolve and vet path."""
    # check if file exists
    if not bin_path.is_file():
        raise FileNotFoundError(f"WORK binary not a regular file: {bin_path}")
    # check if it's a symbolic link
    if bin_path.is_symlink():
        raise PermissionError(f"Refusing to execute symlink: {bin_path}")
    # check if it's executable
    if os.name == "posix" and not os.access(bin_path, os.X_OK):
        """if not executable, change mode to executable
        try:
            bin_path.chmod(
                bin_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            )
        except Exception as e:
            raise PermissionError(
                f"WORK binary at {bin_path} is not executable. chmod failed: {e}"
            ) from e"""
        raise PermissionError(f"WORK binary at {bin_path} is not executable.")
    # check if it's world writable
    if _is_world_writable(bin_path) or _is_world_writable(bin_path.parent):
        raise PermissionError(f"Insecure permissions on {bin_path} or its directory")


def _validate_token(token: str) -> None:
    """Validate token."""
    if not isinstance(token, str):
        raise ValueError(
            "token is not a string.  Exiting since hashing function "
            "will not work correctly"
        )

    if not re.fullmatch(r"[A-Za-z0-9._~-]{1,128}", token):
        raise ValueError("token contains disallowed characters or length")


def _validate_difficulty(difficulty: str) -> None:
    """Cast difficulty to int and error check."""
    try:
        idifficulty = int(difficulty)
    except (ValueError, TypeError) as e:
        raise TypeError("WORK difficulty is not an integer") from e

    if idifficulty < 0 or idifficulty > 64:
        raise ValueError("WORK difficulty is out of range")


def _check_inputs(cpp_binary_path: Path, token: str, difficulty: str) -> None:

    # resolve and vet the executable path
    _validate_path(cpp_binary_path)

    # validate token
    _validate_token(token)

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
        >>> cpp_binary_path = "build/pow_benchmark"
        >>> from src.client import handle_pow_cpp
        >>> handle_pow_cpp(token, difficulty, cpp_binary_path) \
            # doctest: +ELLIPSIS
        WORK difficulty: ...
        WORK benchmark executable not found.
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
            raise ValueError("No RESULT found in WORK output.")

    except FileNotFoundError as e:
        raise FileNotFoundError(
            f"WORK binary not a regular file: {cpp_binary_path}"
        ) from e

    except subprocess.CalledProcessError as e:
        _validate_token(token)
        _validate_difficulty(difficulty)
        raise subprocess.CalledProcessError(
            1,
            cmd="pow_benchmark" + token + difficulty,
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
            >>> cpp_binary_path = "build/pow_benchmark"
            >>> responses = {}
            >>> from src.client import define_response
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
        is_err, result = True, "\n"
    elif args[0] == "WORK":
        difficulty = args[2]

        result = handle_pow_cpp(token, difficulty, cpp_binary_path)
        is_err = False

    elif args[0] in valid_messages:
        _validate_token(token)
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
        raise TimeoutError(f"Connect timeout to {server_host}:{port}") from e
    except ConnectionRefusedError as e:
        exc = e
        raise ConnectionRefusedError(
            f"Connection refused by {server_host}:{port}"
        ) from e
    except socket.gaierror as e:
        exc = e
        raise socket.gaierror(
            f"DNS/addr error for {server_host}:{port}: {e}"
        ) from e  # bad host / not resolvable
    except ssl.SSLCertVerificationError as e:
        exc = e
        # server_host mismatch, expired, unknown CA, etc.
        raise ssl.SSLCertVerificationError(
            f"Certificate verification failed " f"for {server_host}:{port}: {e}"
        ) from e
    except ssl.SSLError as e:
        exc = e
        # other TLS/handshake issues (protocol mismatch, bad
        # record, etc.)
        raise ssl.SSLError(
            f"TLS error during connect to {server_host}:{port}: {e}"
        ) from e
    except OSError as e:
        exc = e
        # catch-all for OS-level socket errors
        if e.errno == errno.EHOSTUNREACH:
            raise OSError(f"OSError. Host unreachable: {server_host}:{port}") from e
        elif e.errno == errno.ENETUNREACH:
            raise OSError(
                f"OSError. Network unreachable when "
                f"connecting to {server_host}:{port}"
            ) from e
        else:
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
        message = receive_message(secure_sock)

        # Error check message and create list from message
        try:
            return decipher_message(message, valid_messages)
        except Exception as e:
            raise Exception(f"Error deciphering message: {e}") from e


def _process_message_with_timeout(
    args: list[str],
    token: str,
    valid_messages: set[str],
    responses: dict[str, str] = DEFAULT_RESPONSES,
    cpp_binary_path: str = DEFAULT_CPP_BINARY_PATH,
    pow_timeout: float = DEFAULT_WORK_TIMEOUT,
    all_timeout: float = DEFAULT_ALL_TIMEOUT,
) -> str:
    """Process message received from server and return response, respecting timeout"""
    # Define timeouts and extract token
    this_timeout = pow_timeout if args and args[0] and args[0] == "WORK" else all_timeout

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
        raise TimeoutError(f"{args[0]} function timed out.")
    else:
        is_err, msg = queue.get()
        if is_err:
            to_send = msg.rstrip("\n")
            if args[0] == "ERROR":
                raise Exception("Internal server error.")
            else:
                raise Exception(f"{args[0]} failed: {to_send}.")
        else:
            return msg


def main() -> int:
    """
    Entry point for the CLI.

    Args:
        argv: sys.argv[1:] is used.

    Returns:
        Process exit code: 0 on success; nonzero on error.

    Side effects:
        Opens network connections, prints to stdout/stderr.
    """
    print("Windows ACLs not checked.  Skipping world-writable test.")

    cpp_binary_path = DEFAULT_CPP_BINARY_PATH
    responses = DEFAULT_RESPONSES
    server_host = DEFAULT_SERVER_HOST
    ports = DEFAULT_PORTS
    ca_cert_path = DEFAULT_CA_CERT
    private_key_path = DEFAULT_PRIVATE_KEY_PATH
    client_cert_path = DEFAULT_CLIENT_CERT_PATH
    valid_messages = DEFAULT_VALID_MESSAGES  # valid messages from the server
    pow_timeout = DEFAULT_WORK_TIMEOUT  # timeout for pow in seconds
    all_timeout = DEFAULT_ALL_TIMEOUT  # timeout for all function except pow in seconds
    is_secure = DEFAULT_IS_SECURE
    token = ""  # this will be set with WORK message from server

    # Create and wrap socket
    print("Client cert exists:", os.path.exists(client_cert_path))
    print("Private key exists:", os.path.exists(private_key_path))

    # Connect to the server using TLS
    # Cycle through possible ports, trying to connect to each until success
    is_connected = False
    for port in ports:
        if not is_connected:
            try:
                secure_sock = tls_connect(
                    ca_cert_path,
                    client_cert_path,
                    private_key_path,
                    server_host,
                    is_secure,
                )
                is_connected = connect_to_server(secure_sock, server_host, port)
            except Exception as e:
                print(f"Error connecting to {server_host}:{port}: {e}")

    if not is_connected:
        print("Not able to connect to any port.  Exiting")
        sys.exit(1)

    print(f"Connected to {port}\n")

    # listen to connection until broken
    try:
        while True:

            args = _receive_and_decipher_message(secure_sock, valid_messages)
            print(f"Received {' '.join(args)}")

            # If no args are received, continue
            if not args or not args[0]:
                print("Problem deciphering message. Continuing.")
                continue

            if args[0] == "WORK":
                token = args[1]

            start = time.time()
            response = _process_message_with_timeout(
                args,
                token,
                valid_messages,
                responses,
                cpp_binary_path,
                pow_timeout,
                all_timeout,
            )
            end = time.time()
            print("The time of execution is :", (end - start), "s")

            if args[0] == "WORK":
                this_hash = hashlib.sha256(  # noqa: S324
                    (args[1] + response.rstrip("\n")).encode()
                ).hexdigest()
                print(
                    f"WORK difficulty: {args[2]}"
                    f"\nAuthdata: {args[1]}\nValid WORK Suffix: {response}"
                    f"Hash: {this_hash}"
                )

            print(f"Sending to server = {response}")
            send_message(response, secure_sock)

            if args[0] == "DONE":
                break

    except TimeoutError as e:
        print(e)

    except Exception as e:
        print(e)

    finally:
        secure_sock.close()
        print("Connection closed.")

    return 0


if __name__ == "__main__":

    main()
