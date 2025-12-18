<!-- docs:start -->
# TLS Connection Coding Challenge

[![CI](https://github.com/elliottbache/tls_connection_coding_challenge/actions/workflows/ci.yaml/badge.svg?branch=master)](https://github.com/elliottbache/tls_connection_coding_challenge/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/github/elliottbache/tls_connection_coding_challenge/branch/master/graph/badge.svg?token=GGLIJMZ736)](https://codecov.io/github/elliottbache/tls_connection_coding_challenge) 
[![Docs](https://img.shields.io/badge/docs-Read%20the%20Docs-brightgreen)](https://tls-connection-coding-challenge.readthedocs.io/en/latest/?badge=latest)
[![Release](https://img.shields.io/github/v/release/elliottbache/tls_connection_coding_challenge)](https://github.com/elliottbache/tls_connection_coding_challenge/releases)
[![License: GPL-3.0](https://img.shields.io/badge/license-%20%20GNU%20GPLv3%20-green?style=plastic)](https://github.com/elliottbache/tls_connection_coding_challenge/blob/main/LICENSE)

> **60-second summary**
> - Linux/WSL-based minimal client/server that perform a TLS handshake, then a **HELO → POW → info requests → END** flow.
> - POW solved by a fast C++ helper (multi-threaded) invoked from Python.
> - Fully testable: unit tests for parsing & hashing; integration test creates a throwaway TLS server and exercises the full round-trip.

---

## Architecture (at a glance)

```{mermaid}
sequenceDiagram
  autonumber
  participant C as Client
  participant S as Server

  S->>C: HELO\n
  C->>S: EHLO\n

  S->>C: POW <authdata> <difficulty>\n
  C->>C: find suffix so that SHA1(authdata+suffix) has N hex zeros
  C->>S: <suffix>\n

  S->>C: MAILNUM <arg>\n (and other info requests)
  C->>S: <sha1(authdata+arg)> <response>\n

  S->>C: END\n
  C->>S: OK\n
```

This is a coding challenge that requires the client to connect to a server,
complete a POW challenge using SHA1 in under 2 hours, and reply to multiple queries.
This is designed to be run in an interactive session, printing output to the
stdout.  The choice of this hasher was made by the entity who created the challenge
and must not be changed in this project.

**Table of Contents**

- [Quickstart](#quickstart)
- [Installation](#installation)
- [Execution / Usage](#execution--usage)
- [Technologies](#technologies)
- [Contributing](#contributing)
- [Contributors](#contributors)
- [Author](#author)
- [Change log](#change-log)
- [License](#license)

## Quickstart
### Option A: No Docker
1. Create & activate a venv
```bash
python -m venv .venv
. .venv/bin/activate 
```
2. Install
```bash
pip install -U pip
pip install -e .[dev]   # if you define extras in pyproject; otherwise: pip install -r requirements.txt
```
3. Build the C++ POW helper
```bash
cmake -S . -B build
cmake --build build --config Release
```
4. Generate local certs (CA, server, client)
```bash
bash scripts/make-certs.sh
```
5. Run demo server (listens on localhost, verifies client by default)
```bash
python -m src.server
```
6. In another terminal, run the client
```bash
python -m src.client
```

### Option B: Docker
1. Build the POW helper on host (or inside a client Dockerfile stage)
```bash
cmake -S . -B build && cmake --build build --config Release
```
2. Generate local certs (CA, server, client)
```bash
bash scripts/make-certs.sh
```
3. Start a docker container
```bash
docker start <name>
```
4. Then run
```bash
docker compose up --build
```

## Installation
### Creating client and server side certificates
Follow these steps to create the proper certificates for local testing.  These same commands may be found in
```scripts/make-certs.sh```.  

A "certificates" folder should be created and
these certificates should be placed in the "certificates" folder.  The steps are for typing in a Linux terminal from the
project root folder. 
```sh
$ mkdir certificates
```
```sh
$ cd certificates
```

#### Client side
##### Create a certificate authority (CA)
```sh
$ openssl genrsa -out ca_key.pem 2048
$ openssl req -x509 -new -nodes -key ca_key.pem -sha256 -days 3650 -out ca_cert.pem -subj "/CN=My Test CA"
```
This should create "ca_cert.pem" and "ca_key.pem".

##### Create a client key and certificate signing request (CSR)
```sh
$ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec_private_key.pem
$ openssl req -new -key ec_private_key.pem -out client.csr -subj "/CN=client"
```
This should create "client.csr" and "ec_private_key.pem".

##### Sign the client key with the CA
```sh
$ openssl x509 -req -in client.csr -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out client_cert.pem -days 365
-sha256
```
This creates "ca_cert.srl" and "client_cert.pem".

#### Server side
##### Prepare the server certificates
```sh
$ openssl req -x509 -newkey rsa:2048 -nodes -keyout server-key.pem -out server-cert.pem -days 365 -subj "/CN=localhost"
```


This creates "server-cert.pem" and "server-key.pem".  You will need to answer a few questions and input a password.  
This password will be used every time you launch the server and use the certificate. 

## Compiling C++ code for finding checksum
The C++ code "pow_challenge.cpp" is used to find a checksum with enough leading zeroes for specified difficulty.  C++
is used rather than Python due to its speed.

In a Linux terminal from the "src" folder, enter:
```sh
$ mkdir ../build
$ g++ -O3 -std=c++17 pow_challenge.cpp pow_core.cpp -o ../build/pow_challenge -lssl -lcrypto -pthread
```

## Execution / Usage

This program was developed with Python 3.11.14.  It is intended for use in Linux, and some of the security 
checks are not available in Windows (such as checking that the POW challenge binary file launched with 
subprocess.run is not world writable).  

To run TLS connection coding challenge, fire up a terminal window and run the following command in the "src" folder:
```sh
$ python server.py
```
Various flags are available for running in CLI.  e.g.
```bash
# Run demo server on localhost:3481 with difficulty 6
python -m src.server --host 127.0.0.1 --port 3481 \
  --ca-cert certificates/ca_cert.pem \
  --server-cert certificates/server-cert.pem \
  --server-key certificates/server-key.pem \
  --difficulty 6
```
Depending on the creation of certificates process, this step may require a password that was defined when creating
the certificates.

Once the server is running, the client can be launched.  This is done by entering the following command:
```sh
$ python client.py
```
Various flags are available for running in CLI.  e.g.
```sh
# Connect to same host/port, using local pow_challenge
python -m src.client --host localhost --ports 3481 \
  --pow-bin build/pow_challenge --insecure

```

The client will connect to the server and answer the various commands sent by the server.  The server will first send a
a handshake set of commands (HELO and POW).  Once the POW challenge is solved by the client under 2 hours, the correct
suffix will be sent to the server and a further 20 random commands will be sent.  If ERROR is randomly selected, the
connection will close.  Otherwise, the final command will be END.

## Development
An in-depth description of the modules and functions of this program can be found in the [Read the Docs](https://tls-connection-coding-challenge.readthedocs.io/en/latest/index.html) and the [GitHub](https://github.com/elliottbache/tls_connection_coding_challenge) page.

### Make commands
A list of make commands is made available through ``Makefile``.  The following list comes from using ``make help``:
- make venv: Create virtualenv (.venv)
- make install-dev: Install project + dev deps
- make test: Run pytest
- make lint: Run ruff (lint), black --check, isort --check, codespell
- make format: Run ruff --fix, black, isort
- make typecheck: Run mypy
- make docs: Build Sphinx HTML docs
- make run-server: Run server (local)
- make run-client: Run client (local)
- make bench: Quick benchmark for pow (example)
- make clean: Remove caches and build artifacts

### Sphinx in PyCharm
In order to create Sphinx documentation from the docstrings in PyCharm, a new run task must be created: 
Run > Edit Configurations... > + (top-left) > Sphinx task.  In the window that opens, name the Sphinx task in the
"Name" field, select "html" under the "Command:" dropdown, select the docs folder in the root folder in the "Input:"
field, and select the docs/_build folder in the "Output:" field.  If the docs or docs/_build folder do not already
exist, they will perhaps need to be created.  The Sphinx documentation can now be created by going to Run > Run... and
selecting the Sphinx task name.

### Testing
#### C++ code
To run the C++ tests, you must run from the root directory:
```bash
cmake -S . -B build 
cmake --build build --config Release
ctest ./build/pow_core_test <authdata> <difficulty>
```

## Technologies

TLS connection coding challenge uses the following technologies and tools:

- [![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)](https://www.python.org/)
- [![Sphinx](https://img.shields.io/badge/Sphinx-3B4D92?style=for-the-badge&logo=sphinx&logoColor=white)](https://www.sphinx-doc.org/en/master/)

## Security

This project is a coding challenge/demo. The default configuration uses **local,
unverified TLS** between client and server to simplify running the sample.

For production hardening, this repo includes a documented path that enables
**mutual TLS (mTLS)**. 

### Basic TLS vs. mTLS

This repo includes a flag allowing to choose between basic TLS and mTLS:

- **mTLS for client authentication**: the server can be configured to require a client certificate
  (`ssl.CERT_REQUIRED`) and verify it against a local CA.
- **No secrets committed**: tests generate throwaway certificates at runtime (via `trustme`), so
  no real private keys/PEMs need to live in the repo.
- **Integration test proves mTLS**: one test asserts the handshake **fails** without a client cert,
  and another asserts it **succeeds** when the client presents a cert trusted by the server’s CA.
- **Docker demo option**: run client/server in two containers on the same network where the server
  hostname is validated via **SAN** (e.g., `DNS:server`) and both sides trust the same CA 
  (see [Quickstart](#quickstart)).
- Basic TLS can be set by making ``DEFAULT_IS_SECURE = False`` in "src/protocol.py" or by changing
  from ``is_secure = DEFAULT_IS_SECURE`` to ``is_secure = False`` in "src/server.py" and "src/client.py".

## Contributing

To contribute to the development of TLS connection coding challenge, follow the steps below:

1. Fork TLS connection coding challenge from <https://github.com/elliottbache/tls_connection_coding_challenge/fork>
2. Create your feature branch (`git checkout -b feature-new`)
3. Make your changes
4. Commit your changes (`git commit -am 'Add some new feature'`)
5. Push to the branch (`git push origin feature-new`)
6. Create a new pull request

More in-depth information can be found in [CONTRIBUTING.md](CONTRIBUTING.md).

## Contributors

Here's the list of people who have contributed to TLS connection coding challenge:

- Elliott Bache – elliottbache@gmail.com

The TLS connection coding challenge development team really appreciates and thanks the time and effort that all
these fellows have put into the project's growth and improvement.

## Author

- Elliott Bache – elliottbache@gmail.com

## Change log

- v0.1.0
    - TLS Client/Server Challenge with POW, PyTest Suite & Sphinx Docs

## License

TLS connection coding challenge is distributed under the GPL-3.0 license. 

<!-- docs:end -->
