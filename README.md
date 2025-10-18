# To do
- Explain that cpp code needs to be compiled and give instructions.
- Explain how to run server side locally, and what needs to be selected for these tests.

# TLS line protocol

[![Documentation Status](https://readthedocs.org/projects/<your-rtd-slug>/badge/?version=latest)](https://<your-rtd-slug>.readthedocs.io/en/latest/?badge=latest)

This is a toy protocol demo that requires the client to connect to a server,
complete a WORK challenge in under 2 hours, and reply to multiple queries.

**Table of Contents**

- [Installation](#installation)
- [Execution / Usage](#execution--usage)
- [Technologies](#technologies)
- [Features](#features)
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

This program was developed with Python 3.11.14.  To run TLS line protocol,
fire up a terminal window and run the following command:
```sh
$ python server.py
```

Depending on the creation of certificates process, this step may require a password that was defined when creating
the certificates.





For more examples, please refer to the project's [Wiki](wiki) or [documentation page](docs).

## Technologies

TLS line protocol uses the following technologies and tools:

- [Python](https://www.python.org/): ![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
- ...

## Features

TLS line protocol currently has the following set of features:

- Support for...
- ...

## Contributing

To contribute to the development of TLS line protocol, follow the steps below:

1. Fork TLS line protocol from <https://github.com/elliottbache/tls_line_protocol/fork>
2. Create your feature branch (`git checkout -b feature-new`)
3. Make your changes
4. Commit your changes (`git commit -am 'Add some new feature'`)
5. Push to the branch (`git push origin feature-new`)
6. Create a new pull request

## Contributors

Here's the list of people who have contributed to TLS line protocol:

- Elliott Bache – elliottbache@gmail.com

The TLS line protocol development team really appreciates and thanks the time and effort that all
these fellows have put into the project's growth and improvement.

## Author

- Elliott Bache – elliottbache@gmail.com

## Change log

- 0.0.1
    - First working version

## License

TLS line protocol is distributed under the MIT license. See [`LICENSE`](LICENSE.md) for more details.

