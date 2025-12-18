<!-- docs:start -->
# TLS Line Protocol

[![CI](https://github.com/elliottbache/tls_line_protocol/actions/workflows/ci.yaml/badge.svg?branch=master)](https://github.com/elliottbache/tls_line_protocol/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/github/elliottbache/tls_line_protocol/branch/master/graph/badge.svg?token=GGLIJMZ736)](https://codecov.io/github/elliottbache/tls_line_protocol) 
[![Docs](https://img.shields.io/badge/docs-Read%20the%20Docs-brightgreen)](https://tls-line-protocol.readthedocs.io/en/latest/?badge=latest)
[![Release](https://img.shields.io/github/v/release/elliottbache/tls_line_protocol)](https://github.com/elliottbache/tls_line_protocol/releases)
[![License: GPL-3.0](https://img.shields.io/badge/license-%20%20GNU%20GPLv3%20-green?style=plastic)](https://github.com/elliottbache/tls_line_protocol/blob/main/LICENSE)

> **60-second summary**
> - Linux/WSL-based minimal client/server that perform a TLS handshake, then a **HELLO → WORK → info requests → DONE** flow.
> - WORK solved by a fast C++ helper (multi-threaded) invoked from Python.
> - Fully testable: unit tests for parsing & hashing; integration test creates a throwaway TLS server and exercises the full round-trip.

---

## Architecture (at a glance)

```{mermaid}
sequenceDiagram
  autonumber
  participant C as Client
  participant S as Server

  S->>C: HELLO\n
  C->>S: HELLOBACK\n

  S->>C: WORK <token> <difficulty>\n
  C->>C: find suffix so that SHA256(token+suffix) has N hex zeros
  C->>S: <suffix>\n

  S->>C: MAILNUM <arg>\n (and other info requests)
  C->>S: <sha256(token+arg)> <response>\n

  S->>C: DONE\n
  C->>S: OK\n
```

This is a toy protocol demo that requires the client to connect to a server,
complete a WORK challenge using SHA256 in under 2 hours, and reply to multiple queries.
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
The following commands are made available by ```Makefile``` and a more detailed description of the various
options may be found in [Make commands](#make-commands).

### Quick installation
```bash
make all
```

### Option A: No Docker
```bash
make run-server
```
In another terminal, run the client
```bash
make run-client
```

### Option B: Docker
#### Launch Docker daemon
On WSL:
```bash
sudo service docker start
```
On Linux:
```bash
sudo systemctl status docker
```

#### Start a docker container
```bash
docker start <name>
```
#### Then run
```bash
docker compose up --build
```

## Installation
This package is intended for use in Linux/WSL.  All installation and execution instructions are for these
distributions.  

The quickest and easiest way to install the various components of this package can be found in [Quickstart](#quickstart).
The following steps are for manual installation.
### Create a Python virtual environment with dependencies (skip this if using Docker)
#### Create & activate a venv
```bash
python -m venv .venv
. .venv/bin/activate 
```
#### Install dependencies
```bash
pip install -U pip
pip install -e .[dev]
```

### Compile C++ WORK challenge binary
The C++ code ```pow_challenge.cpp``` is used to find a checksum with enough leading zeroes for specified difficulty.  C++
is used rather than Python due to its speed.
#### Build binary
```bash
cmake -S . -B build
cmake --build build --config Release
```
It can also be compiled directly without 
CMake or the Makefile in a Linux terminal from the ```cpp``` folder, enter:
```bash
$ mkdir ../build
$ g++ -O3 -std=c++17 pow_challenge.cpp pow_core.cpp -o ../build/pow_challenge -lssl -lcrypto -pthread
```

#### Move files to binary directory
```bash
mkdir -p src/tlslp/_bin
cp build/pow_challenge src/tlslp/_bin/
```

### Create client and server side certificates
#### Easy creation with script
Follow these steps to create the proper certificates for local testing.  These same commands may be found in
```scripts/make-certs.sh```, which can be run with the following:
```bash
bash scripts/make-certs.sh
```

#### Manual certificates creation
A ```certificates``` folder should be created and
these certificates should be placed in the ```certificates``` folder.  The steps are for typing in a Linux terminal from the
project root folder. 
```sh
$ mkdir certificates
```
```sh
$ cd certificates
```

##### Client side
###### Create a certificate authority (CA)
```sh
openssl genrsa -out ca_key.pem 2048
openssl req -x509 -new -nodes -key ca_key.pem -sha256 -days 3650 -out ca_cert.pem -subj "/CN=My Test CA"

```
This should create ```ca_cert.pem``` and ```ca_key.pem```.

###### Create a client key and certificate signing request (CSR)
```sh
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec_private_key.pem
openssl req -new -key ec_private_key.pem -out client.csr -subj "/CN=client"
```
This should create ```client.csr``` and ```ec_private_key.pem```.

###### Sign the client key with the CA
```sh
openssl x509 -req -in client.csr -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out \
client_cert.pem -days 365 -sha256
```
This creates ```ca_cert.srl``` and ```client_cert.pem```.

##### Server side
###### Prepare the server key and CSR
```sh
openssl genrsa -out server-key.pem 2048
openssl req -new -key server-key.pem -out server.csr -subj "/CN=localhost"
```

##### Prepare server certificate signed by CA
```bash
# server cert extensions file
cat > server.ext <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

# server cert signed by CA
openssl x509 -req -in server.csr -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial \
  -out server-cert.pem -days 365 -sha256 -extfile server.ext
```
This creates ```server-cert.pem``` and ```server-key.pem```.   



## Execution / Usage

This program was developed with Python 3.11.14.  It is intended for use in Linux/WSL, and some of the security 
checks are not available in Windows (such as checking that the WORK challenge binary file launched with 
subprocess.run is not world writable).  

### Option A: No Docker
#### Run demo server (listens on localhost, verifies client by default)
```bash
tlslp-server
```
Various flags are available for running in CLI.  e.g.
```bash
# Run demo server on localhost:1234 with difficulty 6
tlslp-server --host 127.0.0.1 --port 1234 \
  --ca-cert certificates/ca_cert.pem \
  --server-cert certificates/server-cert.pem \
  --server-key certificates/server-key.pem \
  --difficulty 6
```
For a complete list, run
```bash
# Run demo server on localhost:1234 with difficulty 6
tlslp-server -help
```

#### In another terminal, run the client
```bash
tlslp-client
```
Various flags are available for running in CLI.  e.g.
```sh
# Connect to same host/port, using local pow_challenge
tlslp-client --host localhost --ports 1234 \
  --pow-bin build/pow_challenge --insecure
```

### Option B: Docker

3. Start a docker container
```bash
docker start <name>
```
4. Then run
```bash
docker compose up --build
```

### What is happening?
The client will connect to the server and answer the various commands sent by the server.  The server will first send a
a handshake set of commands (HELLO and WORK).  Once the WORK challenge is solved by the client under 2 hours, the correct
suffix will be sent to the server and a further 20 random commands will be sent.  If ERROR is randomly selected, the
connection will close.  Otherwise, the final command will be DONE.

## Development
An in-depth description of the modules and functions of this program can be found in the [Read the Docs](https://tls-line-protocol.readthedocs.io/en/latest/index.html) and the [GitHub](https://github.com/elliottbache/tls_line_protocol) page.

### Make commands
A list of make commands is made available through ``Makefile``.  The following list comes from using ``make help``:
- make all:  Makes all except run-server and run-client
- make clean: Remove caches and build artifacts"
- make venv: Create virtualenv (.venv)
- make install-dev: Install project + dev deps
- make certs: Creates the certificates necessary for mTLS
- make build-cpp: Builds the C++ WORK challenge binary and places it in _bin
- make docs: Build Sphinx HTML docs
- make lint: Run ruff (lint), black --check, isort --check, codespell
- make format: Run ruff --fix, black, isort
- make typecheck: Run mypy
- make test: Run pytest
- make run-server: Run server (local)
- make run-client: Run client (local)
- make bench: Quick benchmark for pow (example)

### Sphinx in PyCharm
In order to create Sphinx documentation from the docstrings in PyCharm, a new run task must be created: 
Run > Edit Configurations... > + (top-left) > Sphinx task.  In the window that opens, name the Sphinx task in the
```Name``` field, select ```html``` under the ```Command:``` dropdown, select the docs folder in the root folder in the ```Input:```
field, and select the docs/_build folder in the ```Output:``` field.  If the docs or docs/_build folder do not already
exist, they will perhaps need to be created.  The Sphinx documentation can now be created by going to Run > Run... and
selecting the Sphinx task name.

### Testing
#### Python code
The Python tests can be run from the root directory with
```bash
pytest -q
```
or with 
```bash
make test
```

#### C++ code
To run the C++ tests, you can simply use
```bash
make test-cpp token=<token> difficulty=<difficulty>
```
where token is by default "gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzuWROTeTaSmqFCAzuwkwLCRgIIq",
and difficulty is by default 5.  To run the CTest manually, you can use:
```bash
ctest src/tlslp/_bin/pow_core_test <token> <difficulty>
```

## Technologies

TLS line protocol uses the following technologies and tools:

- [![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)](https://www.python.org/)
- [![Sphinx](https://img.shields.io/badge/Sphinx-3B4D92?style=for-the-badge&logo=sphinx&logoColor=white)](https://www.sphinx-doc.org/en/master/)

## Security

This project is a toy protocol demo/demo. The default configuration uses **local,
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
- Basic TLS can be set by making ``DEFAULT_IS_SECURE = False`` in ```src/protocol.py``` or by changing
  from ``is_secure = DEFAULT_IS_SECURE`` to ``is_secure = False`` in ```src/server.py``` and ```src/client.py```.

## Contributing

To contribute to the development of TLS line protocol, follow the steps below:

1. Fork TLS line protocol from <https://github.com/elliottbache/tls_line_protocol/fork>
2. Create your feature branch (`git checkout -b feature-new`)
3. Make your changes
4. Commit your changes (`git commit -am 'Add some new feature'`)
5. Push to the branch (`git push origin feature-new`)
6. Create a new pull request

More in-depth information can be found in [CONTRIBUTING.md](https://github.com/elliottbache/tls_line_protocol/blob/master/CONTRIBUTING.md).

## Contributors

Here's the list of people who have contributed to TLS line protocol:

- Elliott Bache – elliottbache@gmail.com

The TLS line protocol development team really appreciates and thanks the time and effort that all
these fellows have put into the project's growth and improvement.

## Author

- Elliott Bache – elliottbache@gmail.com

## Change log

- v0.1.0
    - TLS Client/Server Challenge with WORK, PyTest Suite & Sphinx Docs

## License

TLS line protocol is distributed under the GPL-3.0 license. 

<!-- docs:end -->
