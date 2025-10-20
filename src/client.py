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

import ssl
import socket
import hashlib
import os
import sys
import time
import multiprocessing
import subprocess
from typing import List, Set, Union

DEFAULT_CPP_BINARY_PATH = "../build/pow_benchmark" # path to c++ executable
DEFAULT_THREADS = "2" # number of threads used in c++ code to find hash
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
    "ADDR_LINE2": "Springfield"
}
DEFAULT_HOSTFULL_NAME = 'localhost' # This PC
DEFAULT_PORTS = [3115, 7883, 8235, 38154, 1234, 55532]
DEFAULT_PRIVATE_KEY_PATH = '../certificates/ec_private_key.pem' # File path for the EC private key
DEFAULT_CLIENT_CERT_PATH = '../certificates/client_cert.pem' # File path for the client certificate


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
    # Create the client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Create an SSL context
    context = ssl.create_default_context()

    # Load the client's private key and certificate
    print("Checking cert and key existence:")
    print("Client cert exists:", os.path.exists(client_cert_path))
    print("Private key exists:", os.path.exists(private_key_path))
    context.load_cert_chain(certfile=client_cert_path, keyfile=private_key_path)

    # Disable server certificate verification (not recommended for production)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    return context.wrap_socket(client_socket, server_hostname=hostname)


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
    cksum_in_hex = hashlib.sha256(to_be_hashed.encode()).hexdigest()

    return cksum_in_hex


def decipher_message(message: str, valid_messages: Set[str]) \
        -> tuple[int, List[str]]:
    """Read message and do error checking.

    Args:
        message (str): The message to read.
        valid_messages (List[str]): A set of valid messages that can
                                    be received from server.

    Returns:
        Union[int, List[str]]: An error code 0 if no error and 1 if
                               decoding error, the decoded message
                               split into list.

    Examples:
        >>> message = b'MAILNUM LGTk\\n'
        >>> valid_messages = {'HELLO', 'DONE', 'EMAIL2', 'BIRTHDATE', \
         'MAILNUM', 'ADDRNUM', 'EMAIL1', 'ADDR_LINE2', 'WORK', 'ERROR', \
         'SOCIAL', 'COUNTRY', 'ADDR_LINE1', 'FULL_NAME'}
        >>> from src.client import decipher_message
        >>> decipher_message(message, valid_messages)
        (0, ['MAILNUM', 'LGTk'])
    """

    # check that we have a UTF-8 message
    try:
        smessage = message.decode('utf-8').replace("\n", "")
    except Exception as e:
        print ("string is not valid: ",e)
        print ("string is probably not UTF-8")
        return 1, ""

    args = smessage.split()

    if not args:
        print("No args in the response")
        return 2, ""

    # check that message belongs to list of possible messages
    if args[0] not in valid_messages:
        print("This response is not valid: ",smessage)
        return 2, ""

    # if only 1 argument is received add another empty string argument
    # to avoid errors since server is supposed to send 2 args.  
    if len(args) == 1: 
        args.append("")

    return 0, args


def handle_pow_cpp(token: str, difficulty: str, cpp_binary_path: str
        = DEFAULT_CPP_BINARY_PATH, threads: str = DEFAULT_THREADS) \
        -> tuple[int, bytes]:
    """Find a hash with the given number of leading zeros.

    Takes the token and difficulty and find a suffix that will
    reproduce a hash with the given number of leading zeros.

    Args:
        token (str): The token from the server.
        difficulty (str): The number of leading zeroes required.
        cpp_binary_path (str): The path to the C++ program that solves
            the WORK challenge.
        threads (str): The number of threads to use for the C++ program.

    Returns:
        tuple[int, str]: An error code 0 if no error and 4 if an error,
            the suffix that solves the WORK challenge.

    Examples:
        >>> import subprocess
        >>> token = 'gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzu' \
            + 'WROTeTaSmqFCAzuwkwLCRgIIq'
        >>> difficulty = "6"
        >>> cpp_binary_path = "build/pow_benchmark"
        >>> threads = "2"
        >>> from src.client import handle_pow_cpp
        >>> handle_pow_cpp(token, difficulty, cpp_binary_path, threads) \
            # doctest: +ELLIPSIS
        WORK difficulty is ...
        Valid WORK Suffix: ... ...
        (0, b'...')
    """

    # error check token
    if not isinstance(token, str):
        print("token is not a string.  Exiting since hashing function " 
                "will not work correctly")
        return 4, "\n".encode()

    # error check difficulty
    try:
        idifficulty = int(float(difficulty))
        print(f"WORK difficulty is {idifficulty}")
    except:
        print("WORK difficulty is not an integer")
        return 4, "\n".encode()

    # run pre-compiled c++ code for finding suffix
    try:
        result = subprocess.run(
            [cpp_binary_path, token, difficulty, threads],
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
            print(f"Valid WORK Suffix: {suffix} "
                  f"{hashlib.sha256((token + suffix).encode()).hexdigest()}")
            return 0, (suffix + "\n").encode()
        else:
            print("No RESULT found in output.")
            return 4, "\n".encode()

    except subprocess.CalledProcessError as e:
        print("Error running executable:")
        print(e.stderr)

    return 4, "\n".encode()


def define_response(args: List[str], token: str, valid_messages: List[str],
                    queue, responses=DEFAULT_RESPONSES, cpp_binary_path
                    =DEFAULT_CPP_BINARY_PATH, threads=DEFAULT_THREADS):
    """
    Create response to message depending on received message.

    err and result are added to results,
    which are then queued for output in multiprocessing.
    err = 0 -> OK, 1 -> DONE, 2 -> ERROR, 3 -> timeout,
    4 -> other invalid messages

    Args:
        args (list[str]): The list of arguments to pass to the client.
        token (str): The token from the server.
        valid_messages (list[str]): The list of valid messages that
            the server can send.
        responses (list[str]): The list of responses to send.
        cpp_binary_path (str): The path to the C++ program that solves
            the WORK challenge.
        threads (str): The number of threads to use for the C++ program.

    Returns:
        None: results are added to "results" list where results[0]
            = err (1 for DONE, 2 for ERROR, 4 if the message is invalid
            or the WORK does not produce a valid output, and 0 for all
            other valid messages), and results[1] is the message to
            send to the server.

        Examples:
            >>> args = ["HELLO"]
            >>> token = 'gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzu' \
            + 'WROTeTaSmqFCAzuwkwLCRgIIq'
            >>> valid_messages = {'HELLO', 'DONE', 'EMAIL2', 'BIRTHDATE', \
            'MAILNUM', 'ADDRNUM', 'EMAIL1', 'ADDR_LINE2', 'WORK', 'ERROR', \
            'SOCIAL', 'COUNTRY', 'ADDR_LINE1', 'FULL_NAME'}
            >>> cpp_binary_path = "build/pow_benchmark"
            >>> threads = "2"
            >>> responses = {}
            >>> from src.client import define_response
            >>> # a tiny queue we can inspect
            >>> class Q:
            ...     def __init__(self): self.items = []
            ...     def put(self, x): self.items.append(x)
            >>> queue = Q()
            >>> define_response(args, token, valid_messages,
            ...     queue, responses, cpp_binary_path, threads)
            >>> queue.items
            [[0, b'HELLOBACK\\n']]
    """

    if args[0] == "HELLO":
        err, result = 0, "HELLOBACK\n".encode()
    elif args[0] == "DONE":
        err, result = 1, "OK\n".encode()
    elif args[0] == "ERROR":
        print ("Server error: " + " ".join(args[1:]))
        err, result = 2, "\n".encode()
    elif args[0] == "WORK":
        difficulty = args[2]

        # record start time
        start = time.time()
        return_list = handle_pow_cpp(token, difficulty, cpp_binary_path,
                                     threads)

        # record end time
        end = time.time()

        # print the difference between start
        # and end time in milli. secs
        print("The time of execution of WORK challenge is :",
          (end-start) , "s")

        err, result = return_list[0], return_list[1]

    elif args[0] in valid_messages:
        print("token = ",token)
        err, result = 0, (hasher(token,args[1]) + " " + responses[args[0]] + "\n").encode()

    else:
        err, result = 4, "\n".encode()

    # double check that newline has been placed on string
    if not result.decode('utf-8').endswith("\n"):
        print ("string does not end with new line")
        to_encode = result.decode('utf-8') + "\n"
        result = to_encode.encode()

    results = [err, result]
    queue.put(results)


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
    threads = DEFAULT_THREADS
    responses = DEFAULT_RESPONSES
    hostname = DEFAULT_HOSTFULL_NAME
    ports = DEFAULT_PORTS
    private_key_path = DEFAULT_PRIVATE_KEY_PATH
    client_cert_path = DEFAULT_CLIENT_CERT_PATH

    valid_messages = {
        "HELLO", "WORK", "ERROR", "DONE", "FULL_NAME", "MAILNUM", "EMAIL1", "EMAIL2",
        "SOCIAL", "BIRTHDATE", "COUNTRY", "ADDRNUM", "ADDR_LINE1", "ADDR_LINE2"
    }  # valid first arguments coming from the server
    pow_timeout = 7200  # timeout for pow in seconds
    all_timeout = 6  # timeout for all function except pow in seconds
    token = '' # this will be set with WORK message from server

    # Create and wrap socket
    secure_sock = tls_connect(client_cert_path, private_key_path, hostname)

    # Connect to the server using TLS
    # Cycle through possible ports, trying to connect to each until success
    is_connected = False
    for port in ports:
        if not is_connected:
            try:
                secure_sock.connect((hostname,int(port)))
                is_connected = True
                print(f"Connected to {port}\n")
            except:
                print(f"Cannot connect to {port}")

    if not is_connected:
        print("Not able to connect to any port.  Exiting")
        sys.exit()

    # listen to connection until broken
    while True:

        # Receive the message from the server
        message = secure_sock.recv(1024)
        print(f"received = {message}")

        # If nothing is received wait 6 seconds and continue
        if message == b"":
            print("received empty message.  continuing.")
            continue

        # Error check message and create list from message
        err, args = decipher_message(message, valid_messages)
        print(decipher_message(message, valid_messages))

        # If no args are received, continue
        if err:
            print(f"Problem deciphering message. Error code = {err}.  continuing.")
            continue

        # Define timeouts
        if args and args[0] == "WORK":
            this_timeout = pow_timeout
            token = args[1]
        else:
            this_timeout = all_timeout

        # use multiprocessing for setting timeout.  Only 1 process is
        # launched at this stage
        queue = multiprocessing.Queue()
        p = multiprocessing.Process(target=define_response, args=(args, token, valid_messages, queue, responses, cpp_binary_path, threads))
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

        # if correctly handled message (1 for DONE and 0 for all other
        # correctly handled)
        if err == 0 or err == 1:
            # Send the response
            print(f"sending to server = {response}\n")
            secure_sock.send(response)

        # If DONE or ERROR received from server, break
        if err == 1 or err == 2:
            break

    # Close the connection
    print("close connection")
    secure_sock.close()

    return 0

if __name__ == "__main__":
    main()
