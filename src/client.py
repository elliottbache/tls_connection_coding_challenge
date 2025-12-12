"""Opens a client node that will interact with a defined server.

This follows a set of rules defined in the coding challenge. The
specific rules and the external IP address are not quoted here for
confidentiality reasons.  The client connects to the server and then
listens for a list of commands that are answered one by one.  The
first two commands are the handshake and contain 'HELO' and 'POW'.
The POW challenge must be resolved in 2 hours.  This challenge is
resolved by a C++ code called pow_benchmark.cpp.  Multithreading is
used when calling this C++ code.

Functions:
    tls_connect:
        Create a connection to the remote server.

    hasher:
        Hash a string using SHA1.

    decipher_message:
        Read message and do error checking.

    handle_pow_cpp:
        Takes the authdata and difficulty and finds a suffix that will
        reproduce a hash with the given number of leading zeros.

    define_response:
        Create response to message depending on received message.

    main:
        Main function.

"""

import ssl
import socket
import hashlib
import os
import sys
import time
import multiprocessing
import subprocess
from typing import List, Set
import errno

DEFAULT_CPP_BINARY_PATH = "build/pow_benchmark"  # path to c++ executable
DEFAULT_RESPONSES = {
    "NAME": "Elliott Bache",
    "MAILNUM": "2",
    "MAIL1": "elliottbache@gmail.com",
    "MAIL2": "elliottbache2@gmail.com",
    "SKYPE": "elliottbache@hotmail.com",
    "BIRTHDATE": "99.99.1982",
    "COUNTRY": "USA",
    "ADDRNUM": "2",
    "ADDRLINE1": "234 Evergreen Terrace",
    "ADDRLINE2": "Springfield"
}
DEFAULT_HOSTNAME = os.getenv("HOSTNAME", "localhost")
DEFAULT_PORTS = [int(p) for p in os.getenv("PORTS", "3481").split(",")]
DEFAULT_PRIVATE_KEY_PATH = 'certificates/ec_private_key.pem'
DEFAULT_CLIENT_CERT_PATH = 'certificates/client_cert.pem'


def tls_connect(client_cert_path: str, private_key_path: str, hostname: str) \
        -> socket.socket:
    """
    Create a connection to the remote server.

    Args:
        client_cert_path (str): The path to the client certificate.
        private_key_path (str): The path to the private key file.
        hostname (str): The hostname to connect to.

    Returns:
        socket.socket: The socket object.
    """
    # Check that hostname is local, otherwise raise error so that unsecure
    # connection isn't mistakenly used
    if hostname != 'localhost':
        raise ValueError(f"Refusing insecure TLS to ‘{hostname}’. For "
                         f"non-local hosts, enable certificate verification.")

    # Create the client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Create an SSL context
    context = ssl.create_default_context()

    # Load the client's private key and certificate
    print("Client cert exists:", os.path.exists(client_cert_path))
    print("Private key exists:", os.path.exists(private_key_path))
    context.load_cert_chain(certfile=client_cert_path,
                            keyfile=private_key_path)

    # Disable server certificate verification (not recommended for production)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    return context.wrap_socket(client_socket, server_hostname=hostname)


def hasher(authdata: str, input_string: str) -> str:
    """Hash a string using SHA1.

    Concatenates authdata and input_string and then hashes.

    Args:
        authdata (str): The authdata from the server.
        input_string (str): An ASCII string.

    Returns:
        str: The hashed string.

    Examples:
        >>> authdata = 'gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzu' \
            + 'WROTeTaSmqFCAzuwkwLCRgIIq'
        >>> input_string = 'LGTk'
        >>> from src.client import hasher
        >>> hasher(authdata, input_string)
        'bd8de303197ac9997d5a721a11c46d9ed0450798'
    """
    to_be_hashed = authdata + input_string
    cksum_in_hex = hashlib.sha1(to_be_hashed.encode()).hexdigest()

    return cksum_in_hex


def decipher_message(message: str, valid_messages: Set[str]) \
        -> tuple[int, List[str]]:
    """Read message and do error checking.

    Args:
        message (str): The message to read.
        valid_messages (List[str]): A set of valid messages that can
                                    be received from server.

    Returns:
        Union[int, List[str]]: An error code 0 if no error, 1 if
                               decoding error, and 2 if message is not
                               valid the decoded message
                               split into list.

    Examples:
        >>> message = b'MAILNUM LGTk\\n'
        >>> valid_messages = {'HELO', 'END', 'MAIL2', 'BIRTHDATE', \
         'MAILNUM', 'ADDRNUM', 'MAIL1', 'ADDRLINE2', 'POW', 'ERROR', \
         'SKYPE', 'COUNTRY', 'ADDRLINE1', 'NAME'}
        >>> from src.client import decipher_message
        >>> decipher_message(message, valid_messages)
        Received MAILNUM LGTk
        (0, ['MAILNUM', 'LGTk'])
    """

    # check that we have a UTF-8 message
    try:
        smessage = message.decode('utf-8').replace("\n", "")
        print(f"Received {smessage}")
    except Exception as e:
        print("string is not valid: ", e)
        print("string is probably not UTF-8")
        return 1, [""]

    args = smessage.split()

    if not args:
        print("No args in the response")
        return 2, [""]

    # check that message belongs to list of possible messages
    if args[0] not in valid_messages:
        print("This response is not valid: ", smessage)
        return 2, [""]

    # if only 1 argument is received add another empty string argument
    # to avoid errors since server is supposed to send 2 args.
    if len(args) == 1:
        args.append("")

    return 0, args


def handle_pow_cpp(authdata: str, difficulty: str, cpp_binary_path: str
                   = DEFAULT_CPP_BINARY_PATH) \
        -> tuple[int, bytes]:
    """Find a hash with the given number of leading zeros.

    Takes the authdata and difficulty and find a suffix that will
    reproduce a hash with the given number of leading zeros.

    Args:
        authdata (str): The authdata from the server.
        difficulty (str): The number of leading zeroes required.
        cpp_binary_path (str): The path to the C++ program that solves
            the POW challenge.

    Returns:
        tuple[int, str]: An error code 0 if no error and 4 if an error,
            the suffix that solves the POW challenge.

    Examples:
        >>> import subprocess
        >>> authdata = 'gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzu' \
            + 'WROTeTaSmqFCAzuwkwLCRgIIq'
        >>> difficulty = "6"
        >>> cpp_binary_path = "build/pow_benchmark"
        >>> from src.client import handle_pow_cpp
        >>> handle_pow_cpp(authdata, difficulty, cpp_binary_path) \
            # doctest: +ELLIPSIS
        POW difficulty: ...
        POW benchmark executable not found.
        (4, b'\\n')
    """

    # error check authdata
    if not isinstance(authdata, str):
        print("authdata is not a string.  Exiting since hashing function "
              "will not work correctly")
        return 4, "\n".encode()

    # error check difficulty
    try:
        idifficulty = int(difficulty)
        print(f"POW difficulty: {idifficulty}")
    except (ValueError, TypeError):
        print("POW difficulty is not an integer")
        return 4, "\n".encode()

    # run pre-compiled c++ code for finding suffix
    try:
        result = subprocess.run(
            [cpp_binary_path, authdata, difficulty],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )

        # Extract the single result line
        suffix = None
        for line in result.stdout.splitlines():
            if line.startswith("RESULT:"):
                suffix = line[len("RESULT:"):]
                break

        if suffix:
            hash = hashlib.sha1((authdata + suffix).encode()).hexdigest()
            print(f"Authdata: {authdata}\n"
                  f"Valid POW Suffix: {suffix}\n"
                  f"Hash: {hash}")
            return 0, (suffix + "\n").encode()
        else:
            print("No RESULT found in output.")
            return 4, "\n".encode()

    except FileNotFoundError:
        print("POW benchmark executable not found.")

    except subprocess.CalledProcessError as e:
        print("Error running executable:")
        print(e.stderr)

    return 4, "\n".encode()


def define_response(args: List[str], authdata: str, valid_messages: List[str],
                    queue, responses=DEFAULT_RESPONSES,
                    cpp_binary_path=DEFAULT_CPP_BINARY_PATH):
    """
    Create response to message depending on received message.

    err and result are added to results,
    which are then queued for output in multiprocessing.
    err = 0 -> OK, 1 -> END, 2 -> ERROR, 3 -> timeout,
    4 -> other invalid messages

    Args:
        args (list[str]): The list of arguments to pass to the client.
        authdata (str): The authdata from the server.
        valid_messages (list[str]): The list of valid messages that
            the server can send.
        responses (list[str]): The list of responses to send.
        cpp_binary_path (str): The path to the C++ program that solves
            the POW challenge.

    Returns:
        None: results are added to "results" list where results[0]
            = err (1 for END, 2 for ERROR, 4 if the message is invalid
            or the POW does not produce a valid output, and 0 for all
            other valid messages), and results[1] is the message to
            send to the server.

        Examples:
            >>> args = ["HELO"]
            >>> authdata = 'gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzu' \
            + 'WROTeTaSmqFCAzuwkwLCRgIIq'
            >>> valid_messages = {'HELO', 'END', 'MAIL2', 'BIRTHDATE', \
            'MAILNUM', 'ADDRNUM', 'MAIL1', 'ADDRLINE2', 'POW', 'ERROR', \
            'SKYPE', 'COUNTRY', 'ADDRLINE1', 'NAME'}
            >>> cpp_binary_path = "build/pow_benchmark"
            >>> responses = {}
            >>> from src.client import define_response
            >>> # a tiny queue we can inspect
            >>> class Q:
            ...     def __init__(self): self.items = []
            ...     def put(self, x): self.items.append(x)
            >>> queue = Q()
            >>> define_response(args, authdata, valid_messages,
            ...     queue, responses, cpp_binary_path)
            >>> queue.items
            [[0, b'EHLO\\n']]
    """

    if args[0] == "HELO":
        err, result = 0, "EHLO\n".encode()
    elif args[0] == "END":
        err, result = 1, "OK\n".encode()
    elif args[0] == "ERROR":
        print("Server error: " + " ".join(args[1:]))
        err, result = 2, "\n".encode()
    elif args[0] == "POW":
        difficulty = args[2]

        # record start time
        start = time.time()
        return_list = handle_pow_cpp(authdata, difficulty, cpp_binary_path)

        # record end time
        end = time.time()

        # print the difference between start
        # and end time in milli. secs
        print("The time of execution of POW challenge is :",
              (end-start), "s")

        err, result = return_list[0], return_list[1]

    elif args[0] in valid_messages:
        print("Extra arguments = " + args[1])
        print("Authentification data = " + authdata)
        err, result = 0, (hasher(authdata, args[1]) + " "
                          + responses[args[0]] + "\n").encode()

    else:
        err, result = 4, "\n".encode()

    # double check that newline has been placed on string
    if not result.decode('utf-8').endswith("\n"):
        print("string does not end with new line")
        to_encode = result.decode('utf-8') + "\n"
        result = to_encode.encode()

    results = [err, result]
    queue.put(results)


def connect_to_server(sock: socket.socket, hostname: str, port: int) -> bool:
    """Connect to server and return True if connection was successful.

    Args:
        sock (socket.socket): The socket to connect to.
        hostname (str): The hostname to connect to.
        port (int): The port to connect to.

    Returns:
        bool: True if connection was successful, False otherwise.
    """
    try:
        sock.connect((hostname, int(port)))
        print(f"Connected to {port}\n")
        return True
    except socket.timeout:
        print(f"Connect timeout to {hostname}:{port}")
    except ConnectionRefusedError:
        print(f"Connection refused by {hostname}:{port}")
    except socket.gaierror as e:
        print(f"DNS/addr error for "
              f"{hostname}:{port}: {e}")  # bad host / not resolvable
    except ssl.SSLCertVerificationError as e:
        # hostname mismatch, expired, unknown CA, etc.
        print(f"Certificate verification failed for"
              f" {hostname}:{port}: {e}")
    except ssl.SSLError as e:
        # other TLS/handshake issues (protocol mismatch, bad
        # record, etc.)
        print(f"TLS error during connect to {hostname}:{port}: {e}")
    except OSError as e:
        # catch-all for OS-level socket errors
        if e.errno == errno.EHOSTUNREACH:
            print(f"Host unreachable: {hostname}:{port}")
        elif e.errno == errno.ENETUNREACH:
            print(f"Network unreachable when connecting to "
                  f"{hostname}:{port}")
        else:
            print(f"OS error connecting to {hostname}:{port}: {e}")

    return False

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

    cpp_binary_path = DEFAULT_CPP_BINARY_PATH
    responses = DEFAULT_RESPONSES
    hostname = DEFAULT_HOSTNAME
    ports = DEFAULT_PORTS
    private_key_path = DEFAULT_PRIVATE_KEY_PATH
    client_cert_path = DEFAULT_CLIENT_CERT_PATH

    valid_messages = {
        "HELO", "POW", "ERROR", "END", "NAME", "MAILNUM", "MAIL1", "MAIL2",
        "SKYPE", "BIRTHDATE", "COUNTRY", "ADDRNUM", "ADDRLINE1", "ADDRLINE2"
    }  # valid first arguments coming from the server
    pow_timeout = 7200  # timeout for pow in seconds
    all_timeout = 6  # timeout for all function except pow in seconds
    authdata = ''  # this will be set with POW message from server

    # Create and wrap socket
    secure_sock = tls_connect(client_cert_path, private_key_path, hostname)

    # Connect to the server using TLS
    # Cycle through possible ports, trying to connect to each until success
    is_connected = False
    for port in ports:
        if not is_connected:
            is_connected = connect_to_server(secure_sock, hostname, port)

    if not is_connected:
        print("Not able to connect to any port.  Exiting")
        sys.exit(1)

    # listen to connection until broken
    while True:

        # Receive the message from the server
        message = secure_sock.recv(1024)

        # If nothing is received wait 6 seconds and continue
        if message == b"":
            print("received empty message.  continuing.")
            continue

        # Error check message and create list from message
        err, args = decipher_message(message, valid_messages)
        print(f"Command: {args[0]}")

        # If no args are received, continue
        if err or not args or not args[0]:
            print(f"Problem deciphering message. Error code = {err}."
                  f" continuing.")
            continue

        # Define timeouts
        if args and args[0] and args[0] == "POW":
            this_timeout = pow_timeout
            authdata = args[1]
        else:
            this_timeout = all_timeout

        # use multiprocessing for setting timeout.  Only 1 process is
        # launched at this stage
        queue = multiprocessing.Queue()
        p = multiprocessing.Process(
            target=define_response,
            args=(args, authdata, valid_messages, queue, responses,
                  cpp_binary_path),
        )
        p.start()
        p.join(timeout=this_timeout)  # Wait up to 6 or 7200 seconds
        if p.is_alive():
            p.terminate()  # forcefully stop the process
            p.join()
            err, response = 3, "".encode()
            print(f"{args[0]} Function timed out.")
            continue
        else:
            err, response = queue.get()

        # if correctly handled message (1 for END and 0 for all other
        # correctly handled)
        if err == 0 or err == 1:
            # Send the response
            print(f"Sending to server = {response.decode()}")
            secure_sock.send(response)

        # If END, ERROR, or invalid message received from server, break
        if err == 1 or err == 2 or err == 4:
            break

    # Close the connection
    print("close connection")
    secure_sock.close()

    return 0


if __name__ == "__main__":
    main()
