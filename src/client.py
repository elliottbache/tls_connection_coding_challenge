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
    tls_connect: FILL IN!!!!
"""

import ssl
import socket
import hashlib
import os
import sys
import time
import multiprocessing
import subprocess

DEFAULT_CPP_BINARY_PATH = "../build/pow_benchmark" # path to c++ executable
DEFAULT_THREADS = "2" # number of threads used in c++ code to find hash
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
DEFAULT_HOSTNAME = 'localhost' # This PC
DEFAULT_PORTS = [3336, 8083, 8446, 49155, 3481, 65532]
DEFAULT_PRIVATE_KEY_PATH = '../certificates/ec_private_key.pem' # File path for the EC private key
DEFAULT_CLIENT_CERT_PATH = '../certificates/client_cert.pem' # File path for the client certificate


def tls_connect(client_cert_path: str, private_key_path: str, hostname: str) \
        -> socket.socket:
    """
    Create a connection to the remote server defined in the global variables.

    Args:
    Inputs: None
    Outputs: socket
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


def hasher(authdata,input_string):
    """
    Hashes as string using SHA1.
    Inputs: authdata = auth data from the server, input_string = an ASCII string
    Outputs: cksum_in_hex = checksum in hex
    """
    to_be_hashed = authdata + input_string
    cksum_in_hex = hashlib.sha1(to_be_hashed.encode()).hexdigest()

    return cksum_in_hex

def decipher_message(message, valid_messages):
    """
    Read message and do error checking
    Inputs: message = in UTF-8
    Outputs: err = 0 if no error or 1 if decoding error or 2 if invalid command,
            args = message split into list
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

def has_leading_zero_bits(digest, full_bytes, remaining_bits):
    """
    Checks whether the digest starts with 0's in the first full_bytes and 
    remaining_bits
    Inputs: digest = digest from the SHA1, full_bytes = number of full bytes
        given by the difficulty, remaining_bits = the bits that along with 
        full_bytes is equal to the difficulty
    """
    # Check full zero bytes
    for i in range(full_bytes):
        if digest[i] != 0:
            return False

    # Check partial byte if needed
    if remaining_bits:
        mask = 0xFF << (8 - remaining_bits) & 0xFF
        if digest[full_bytes] & mask:
            return False

    return True

def handle_pow_cpp(authdata, difficulty, cpp_binary_path=DEFAULT_CPP_BINARY_PATH, threads=DEFAULT_THREADS):
    """
    Takes the authdata and difficulty and finds a suffix that will reproduce
    a hash with the given number of leading zeros
    Inputs: authdata = input from the server, difficulty = number 
        of leading in the valid hash
    Outputs: error code, formatted response in UTF-8
    """
    # error check authdata
    if not isinstance(authdata, str):
        print("authdata is not a string.  Exiting since hashing function " 
                "will not work correctly")
        return 4, "\n".encode()

    # error check difficulty
    try:
        idifficulty = int(float(difficulty))
        print(f"POW difficulty is {idifficulty}")
    except:
        print("POW difficulty is not an integer")
        return 4, "\n".encode()

    # run pre-compiled c++ code for finding suffix
    try:
        result = subprocess.run(
            [cpp_binary_path, authdata, difficulty, threads],
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
            print(f"Valid POW Suffix: {suffix} {hashlib.sha1((authdata + suffix).encode()).hexdigest()}")
            return 0, (suffix + "\n").encode()
        else:
            print("No RESULT found in output.")
            return 4, "\n".encode()

    except subprocess.CalledProcessError as e:
        print("Error running executable:")
        print(e.stderr)

    return 4, "\n".encode()


def define_response(args, authdata, valid_messages, queue, responses=DEFAULT_RESPONSES, cpp_binary_path=DEFAULT_CPP_BINARY_PATH, threads=DEFAULT_THREADS):
    """
    Create response to message depending on received message
    Inputs: args = a list of the arguments from the server's response
    Outputs: err = 0 -> OK, 1 -> END, 2 -> ERROR, 3 -> timeout,
        4 -> other invalid messages
            response = to be sent to server in UTF-8

    Calls response function, queuing up the results
    Inputs: args = args to be sent for response definition, queue = 
        previously defined job queue
    Outputs: None
    """

    if args[0] == "HELO":
        err, result = 0, "EHLO\n".encode()
    elif args[0] == "END":
        err, result = 1, "OK\n".encode()
    elif args[0] == "ERROR":
        print ("Server error: " + " ".join(args[1:]))
        err, result = 2, "\n".encode()
    elif args[0] == "POW":
        difficulty = args[2]

        # record start time
        start = time.time()
        return_list = handle_pow_cpp(authdata, difficulty, cpp_binary_path, threads)

        # record end time
        end = time.time()

        # print the difference between start
        # and end time in milli. secs
        print("The time of execution of above program is :",
          (end-start) , "s")

        err, result = return_list[0], return_list[1]

    elif args[0] in valid_messages:
        print("authdata = ",authdata)
        err, result = 0, (hasher(authdata,args[1]) + " " + responses[args[0]] + "\n").encode()

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

    cpp_binary_path = DEFAULT_CPP_BINARY_PATH
    threads = DEFAULT_THREADS
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
    authdata = '' # this will be set with POW message from server

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

        # If no args are received, continue
        if err:
            print(f"Problem deciphering message. Error code = {err}.  continuing.")
            continue

        # Define timeouts
        if args and args[0] == "POW":
            this_timeout = pow_timeout
            authdata = args[1]
        else:
            this_timeout = all_timeout

        # use multiprocessing for setting timeout.  Only 1 process is
        # launched at this stage
        queue = multiprocessing.Queue()
        p = multiprocessing.Process(target=define_response, args=(args, authdata, valid_messages, queue, responses, cpp_binary_path, threads))
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
            print(f"sending to server = {response}\n")
            secure_sock.send(response)

        # If END or ERROR received from server, break
        if err == 1 or err == 2:
            break

    # Close the connection
    print("close connection")
    secure_sock.close()

    return 0

if __name__ == "__main__":
    main()
