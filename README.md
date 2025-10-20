# TLS connection coding challenge

[![Documentation Status](https://readthedocs.org/projects/tls-connection-coding-challenge/badge/?version=latest)](https://tls-connection-coding-challenge.readthedocs.io/en/latest/?badge=latest)

This is a coding challenge that requires the client to connect to a server,
complete a POW challenge in under 2 hours, and reply to multiple queries.
This is designed to be run in an interactive session, printing output to the
stdout.

**Table of Contents**

- [Installation](#installation)
- [Execution / Usage](#execution--usage)
- [Technologies](#technologies)
- [Contributing](#contributing)
- [Contributors](#contributors)
- [Author](#author)
- [Change log](#change-log)
- [License](#license)

## Installation
## Creating client and server side certificates
Follow these steps to create the proper certificates for local testing.  These certificates should be placed in the
"certificates" folder.  The steps are for typing in a Linux terminal. 
### Client side
#### Create a certificate authority (CA)
```sh
$ openssl genrsa -out ca_key.pem 2048
```
```sh
$ openssl req -x509 -new -nodes -key ca_key.pem -sha256 -days 3650 -out ca_cert.pem -subj "/CN=My Test CA"`
```
This should create "ca_cert.pem" and "ca_key.pem".

#### Create a client key and certificate signing request (CSR)
```sh
$ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec_private_key.pem
```
```sh
$ openssl req -new -key ec_private_key.pem -out client.csr -subj "/CN=client"
```
This should create "client.csr" and "ec_private_key.pem".

#### Sign the client key with the CA
```sh
$ openssl x509 -req -in client.csr -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out client_cert.pem -days 365
-sha256
```
This creates "ca_cert.srl" and "client_cert.pem".

### Server side
#### Prepare the server certificates
```sh
$ openssl req -x509 -newkey rsa:2048 -keyout server-key.pem -out server-cert.pem -days 365
```


This creates "server-cert.pem" and "server-key.pem".  You will need to answer a few questions and input a password.  
This password will be used every time you launch the server and use the certificate. 

# Compiling C++ code for finding checksum
The C++ code "pow_benchmark.cpp" is used to find a checksum with enough leading zeroes for specified difficulty.  C++
is used rather than Python due to its speed.

In a Linux terminal, enter:
```sh
$ mkdir ../build
```
```sh
$ g++ -O3 -std=c++17 pow_benchmark.cpp -o ../build/pow_benchmark -lssl -lcrypto -pthread
```

## Execution / Usage

This program was developed with Python 3.11.14.  To run TLS connection coding challenge,
fire up a terminal window and run the following command in the src folder:
```sh
$ python server.py
```

Depending on the creation of certificates process, this step may require a password that was defined when creating
the certificates.

Once the server is running, the client can be launched.  This is done by entering the following command:
```sh
$ python client.py
```

The client will connect to the server and answer the various commands sent by the server.  The server will first send a
a handshake set of commands (HELO and POW).  Once the POW challenge is solved by the client under 2 hours, the correct
suffix will be sent to the server and a further 20 random commands will be sent.  If ERROR is randomly selected, the
connection will close.  Otherwise, the final command will be END.

An in-depth description of the modules and functions of this program can be found in the [Read the Docs](https://tls-connection-coding-challenge.readthedocs.io/en/latest/index.html) and the [GitHub](https://github.com/elliottbache/tls_connection_coding_challenge) page.

## Technologies

TLS connection coding challenge uses the following technologies and tools:

- [Python](https://www.python.org/): ![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)

## Contributing

To contribute to the development of TLS connection coding challenge, follow the steps below:

1. Fork TLS connection coding challenge from <https://github.com/elliottbache/tls_connection_coding_challenge/fork>
2. Create your feature branch (`git checkout -b feature-new`)
3. Make your changes
4. Commit your changes (`git commit -am 'Add some new feature'`)
5. Push to the branch (`git push origin feature-new`)
6. Create a new pull request

## Contributors

Here's the list of people who have contributed to TLS connection coding challenge:

- Elliott Bache – elliottbache@gmail.com

The TLS connection coding challenge development team really appreciates and thanks the time and effort that all
these fellows have put into the project's growth and improvement.

## Author

- Elliott Bache – elliottbache@gmail.com

## Change log

- 0.0.1
    - First working version

## License

TLS connection coding challenge is distributed under the MIT license. 

