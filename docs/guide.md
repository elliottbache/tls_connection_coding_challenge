# Guide - How it works
## Overview

This project demonstrates a minimal **TLS client/server** that speaks a simple, line-based
protocol and includes a **Proof-of-Work (POW)** step solved by a fast **C++ helper**. You also 
get a thorough **pytest** suite (unit + integration) and **Sphinx** docs/doctests.

## How to run
![Demo](docs/demo.gif)
For complete instructions, see 
[Installation](https://github.com/elliottbache/tls_connection_coding_challenge/blob/master/README.md#installation)
and [Execution and usage](https://github.com/elliottbache/tls_connection_coding_challenge/blob/master/README.md#execution--usage).
 


### High-level flow
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

### Key properties
- **TLS** for transport security (optionally mutual auth).
- **Deterministic protocol** (plain text, newline-terminated).
- **Time-bounded POW** (2h cap) with multi-threaded C++ backend.
- **Portable tests** that mock subprocess/SSL or use a throwaway TLS server.

---

## Architecture
### Components
- **Client** (src/client.py)
  - ``prepare_client_socket(...)`` – Create SSL context and return a TLS-wrapped socket.
  - ``connect_to_server(...)`` – Connect + error reporting.
  - ``decipher_message(...)`` – Validate/parse incoming lines.
  - ``hasher(...)`` – ``SHA1(authdata + payload)``.
  - ``handle_pow_cpp(...)`` – Invoke ``build/pow_challenge`` (C++), parse ``RESULT:<suffix>``.
  - ``define_response(...)`` – Handle commands. Returns bytes to send.
  - ``main()`` – Orchestrates receive/dispatch with per-command timeouts.
- **Server** (``src/server.py``)
  - ``prepare_socket(...)`` – TLS server context w/ CA & server cert.
  - ``send_message(...)`` / ``receive_message(...)`` – Protocol helpers.
  - ``is_succeed_send_and_receive(...)`` – One-step request/response w/ validations.
- **C++ POW Solver** (``src/pow_challenge.cpp``)
  - Counter-based suffix generator.
  - Bit-precise leading-zero check (``difficulty * 4`` bits for hex).
  - Multi-thread sharding, CPU only.

### Repository layout
```text
.
├── .dockerignore
├── .github
│   ├── ISSUE_TEMPLATE
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   ├── PULL_REQUEST_TEMPLATE.md
│   ├── codeql
│   │   └── codeql-config.yaml
│   ├── dependabot.yaml
│   └── workflows
│       ├── ci.yaml
│       ├── codeql.yaml
│       └── pages.yaml
├── .gitignore
├── .pre-commit-config.yaml
├── .readthedocs.yaml
├── CMakeLists.txt
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── LICENSE
├── Makefile
├── README.md
├── docker
│   ├── client.Dockerfile
│   └── server.Dockerfile
├── docker-compose.yaml
├── docs
│   ├── Doxyfile
│   ├── Makefile
│   ├── conf.py
│   ├── cpp_api.rst
│   ├── guide.md
│   ├── index.rst
│   ├── intro.md
│   ├── make.bat
│   ├── python_api.rst
│   └── requirements.txt
├── pyproject.toml
├── scripts
│   ├── code-tools.sh
│   └── make-certs.sh
└── src
    ├── client.py
    ├── pow_challenge.cpp
    ├── pow_core.cpp
    ├── pow_core.h
    ├── pow_core_internal.h
    ├── protocol.py
    ├── server.py
    └── tests
        ├── conftest.py
        ├── helpers.py
        ├── pow_core_test.cpp
        ├── test_client.py
        ├── test_protocol.py
        ├── test_server.py
        └── test_tls.py
```
Generated with:
```bash
tree -a -L 4 -I ".git|.venv|__pycache__|*.egg-info|.pytest_cache|.mypy_cache|.ruff_cache|build|_build|_codeql_build_dir|certificates"
```

## Dataflow (client-side)
1. TLS connect → read command line.
2. Parse.
3. Reply, respecting per-command timeouts (multiprocessing).
    - For ``POW``, call binary → return suffix.
    - For info commands, compute checksum and reply.

The following should be taken into account:
- Multiline messages are not supported since this was not part of the coding
challenge.  Each command sent by the server was meant to be answered with 
a single-line.  Any more lines would fall outside the scope of the proper
functioning of this program and should thus be treated as an exception.
- Multiprocessing is used to take into account the imposed timeouts.  All 
commands have a timeout of 6 seconds except the POW challenge, which has a
2-hour timeout.


## Protocol
- **Transport**: TLS.
- **Encoding**: UTF-8 text.
- **Line format**: ``COMMAND [ARG]...\n``
- Hasher: SHA1.

### Commands (server → client)
- ``HELO\n`` → client must reply ``EHLO\n``.
- ``POW <authdata> <difficulty>\n`` → client replies with a valid ``<suffix>``.
    - **Validity**: ``SHA1(authdata + suffix)`` starts with ``<difficulty>`` hex zeros.
- Info requests (examples below use ``<arg>`` as server-provided string):
  - ``NAME <arg>\n``
  - ``MAILNUM <arg>\n``
  - ``MAIL1 <arg>\n``
  - ``MAIL2 <arg>\n``
  - ``SKYPE <arg>\n``
  - ``BIRTHDATE <arg>\n``
  - ``COUNTRY <arg>\n``
  - ``ADDRNUM <arg>\n``
  - ``ADDRLINE1 <arg>\n``
  - ``ADDRLINE2 <arg>\n``
- ``ERROR <reason>\n`` → client should stop.
- ``END\n`` → client replies OK and closes.

### Client responses
Client reply format:
- ``EHLO\n`` for ``HELO\n``.
- ``<suffix>\n`` for ``POW\n``.
- ``<sha1(authdata + arg)> <value>\n`` for info commands.
- ``OK\n`` for ``END\n``.

### Error handling
- Malformed input, invalid commands, UTF-8 failure, or missing newline → treat as 
error and close.
- Command timeouts: ``POW`` 7200s; others 6s.
- Socket timeout: 24h.

---

## TLS Setup

You can run **insecure** (disabled verification) for development purposes and 
**mutual TLS (mTLS)**  for production. Basic TLS can be set by:
- Using the ```--insecure``` flag on the CLI
- Making ``DEFAULT_IS_SECURE = False`` in ```src/protocol.py``` or
- Changing from ``is_secure = DEFAULT_IS_SECURE`` to ``is_secure = False`` in ```src/server.py```
and ```src/client.py```.


### Basic TLS for quick testing
- Client: ``verify_mode = ssl.CERT_NONE``, ``check_hostname = False``.
- Server: ``verify_mode = ssl.CERT_NONE``.
- Use **only** for local tests!

### mTLS for production testing
- Client: ``verify_mode = ssl.CERT_REQUIRED``, ``check_hostname = True``, ``cafile=ca_cert_path``.
- Server: ``verify_mode = ssl.CERT_REQUIRED``, ``cafile=ca_cert_path``.

### What’s tested (and why it matters)

The test suite can validate the key security properties:

- **Server authentication**: the client trusts a local CA and verifies the server certificate
  (including hostname/SAN).
- **Client authentication (mTLS)**: the server requires a client certificate and rejects clients
  that don’t present one.
- **Ephemeral certs in tests**: integration tests can generate short-lived CA/server/client certs
  at runtime (e.g., with `trustme`), keeping the repo free of committed keys.
- A guide for **certificate generation** ca be found at [Installation](https://github.com/elliottbache/tls_connection_coding_challenge/blob/master/README.md#installation).

---

## Security implementation
This repo is a coding-challenge/demo, but it’s still useful to treat it as if it exposed beyond localhost.  
In the future, extended this repo to a production-grade project will be easier this way.  The goal is to 
fail closed: treat all network input as untrusted, validate aggressively, and stop on protocol violations.

### Timeouts
**Why**: Prevent hangs (slowloris-style reads, stuck handshakes, blocked subprocesses), and make failure 
modes predictable.

**How** this is done:
- Set **Socket timeout** for the whole connection (done via socket.settimeout(TIMEOUT) where
TIMEOUT is 24h by default).
- Enforce **per-operation timeouts**:
  - POW can be long (e.g., 2h) but still bounded.
  - Everything else should have a short upper bound (e.g., 6s).
- Treat timeout as a **hard error** (close connection; do not continue parsing).

Typical places:
- On connect: ```socket.create_connection(..., timeout=...)```
- On read loop: ```sock.settimeout(...) + receive_message()``` bounded by timeouts
- On POW solver: ```subprocess.run(..., timeout=...)``` 
- On per-command handling: multiprocessing join timeout

### Message size limits
**Why**: Avoid memory growth / DoS by sending huge lines.

**How** this is done:
- Use a strict **line-based protocol**: UTF-8, **single line**, newline-terminated (\n).
- Enforce a **maximum line length** (i.e. MAX_LINE_LENGTH = 1000).
- Reject:
    - non-UTF-8 bytes
    - missing newline (if the peer never sends \n, you’ll time out)
    - overlong lines
    - unexpected extra tokens for commands that require a fixed arity
Notes:

If you read “until newline”, a “no newline” input will typically surface as a **timeout** (good), not 
a “no newline” error. This situation is tested in the pytest suite (src.test_protocol.test_receive_message_no_newline).

### Validating server commands
**Why**: The server controls the client’s behavior. Tight validation prevents weird edge cases and reduces 
attack surface.

**How** this is done:
- Parse exactly one line, then:
    - split into tokens
    - require ```COMMAND``` in ```DEFAULT_VALID_MESSAGES```
    - enforce expected argument count:
        - ```HELO``` → 1 token
        - ```END``` → 1 token
        - ```POW <authdata> <difficulty>``` → 3 tokens
        - ```<INFO> <arg>``` → 2 tokens
        - ```ERROR <reason...>``` → at least 1 token ($n$ are accepted, but nothing is executed)
    - Reject unknown commands and **close**.
Also:
- Validate **authdata** (charset and length) and ```difficulty``` bounds before using them (done for 
POW + hashing).
- Treat protocol violations as ```ProtocolError``` and network/TLS failures as ```TransportError```
(defined in a separate file ```protocol.py```).

### Retry + backoff
**Why**: Make connection behavior stable under transient errors without turning retries into a self-DoS or brute force loop.

**How** this is done:
- Retry only on **connect-stage** failures that come from trying different ports defined by user.
- Do **not** retry on:
    - protocol violations (invalid UTF-8, invalid command, invalid checksum/suffix)
    - certificate verification failures (that’s a security boundary)

### Subprocess safety
The POW solver is intentionally an external executable.  It is treated like untrusted input/output.

**How** this is done:
- Never use ```shell=True```.
- Pass args as a list: ```["/abs/path/pow_benchmark", authdata, difficulty]``` (you do this).
- Resolve and vet the binary path:
    - ```Path(...).resolve(strict=True)``` (prevents PATH tricks)
    - refuse symlinks
    - in POSIX:
        - reject world-writable binary or directory (this is not done in Windows)
        - require executable bit
  - Scrub environment:
      - minimal env ```{"LC_ALL": "C"}```
  - Bound resource usage:
      - ```timeout=...``` (you do this)
  - Parse output defensively:
      - parse exactly one RESULT:<suffix> line
      - enforce suffix character set and max length

### Sanitizing paths
**Why**: If you ever accept paths from configuration/CLI, you want deterministic, safe behavior.

**How** this is done:
- Convert to ```Path```, then:
    - ```resolve(strict=True)```
    - ```is_file()```
    - not ```is_symlink()```
    - check permissions (e.g., not world writable)
- Prefer an allowlist approach:
  - keep binaries/certs under known directories (```./build```, ```./certificates```)
  - reject anything outside that root (```path.is_relative_to(root)```)

### TLS hardening: versions, ciphers, and options
**Why**: TLS defaults are usually okay, but should be documented.

**How** this is done:
- Require TLS 1.2+:
  - context.minimum_version = ssl.TLSVersion.TLSv1_2
- Use hostname verification when “secure mode” is on:
  - check_hostname = True
  - verify_mode = ssl.CERT_REQUIRED

### For future implementations:
- Certificate pinning

**Why**: Even with CA verification, pinning reduces risk if a CA is compromised 
or for tighter control.

---

## POW Solver (C++)
**Goal**: Find a ``suffix`` so that ``SHA1(authdata + suffix)`` starts with 
``N`` hex ``0``s (i.e., ``bits = 4*N`` zero bits).

### Strategy
- **SHA1** was imposed as a coding constraint in the challenge.
- SHA1 is **initialized** with ```authdata```, then a copy is **updated** with each new suffix. 
- **Counter-based suffix** (deterministic, minimal RNG use).
- **Thread sharding**: each thread walks different counters (``base + tid``, ``step = total_threads``).
- **Bit test**: Check full zero bytes; then mask remaining bits:
```cpp
bool has_leading_zeros(const uint8_t* d, int bits) {
    int full = bits/8, rem = bits%8;
    for (int i=0; i<full; ++i) if (d[i] != 0) return false;
    if (rem) {
        uint8_t mask = 0xFF << (8 - rem);
        if ((d[full] & mask) != 0) return false;
    }
    return true;
}
```
- **Keyspace size**: 
  - In hex, each digit represents 4 bits. e.g. for difficulty $d = 5$, we need 
  $5 \times 4 = 20 \text{bits}$.
  - The expected number of trials to find a hex with $n$ leading zeros is $2^{4d}$.  
  For $d=5$, we would have $2^{20} \approx 1 \times 10^6$ expected trials.
  - Therefore, the suffix length is defined so that keyspace $k ≥ 2^{4d}$.
  - With a string that is $s$ long and a $c$ large character set (e.g. $c=26$ for 
  the lowercase alphabet), the number of unique strings that can be generated is 
  $k = c^s$.  For $c=64$ and $s=4$, we have $k=64^4 \approx 17 \times 10^6$.
  - This would be enough string characters for a $16^5 = \approx 1 \times 10^6$ expected trials
  to find a hex that has 5 leading zeros. 
  
### Build
```bash
mkdir -p build
g++ -O3 -std=c++17 pow_challenge.cpp pow_core.cpp -o ../build/pow_challenge -lssl -lcrypto -pthread
```

### Run:
```bash
pow_challenge <authdata> <difficulty>
# stdout line: RESULT:<suffix>\n
```
### Benchmarking 
Tests were carried out for various difficulties on a standard laptop (Intel i5-1235U, 1300 MHz, 10 cores).
The tool automatically created 12 threads.  The calculation times for the average of multiple runs are 
shown in the following table.   
| **Difficulty**        | **4** | **5** | **6** | **7** | **8** | **9** |
|-----------------------|-------|-------|-------|-------|-------|-------|
| **Number of runs**    |   100    |  100     |  100     |  100     |   100    |   100    |
| **Total run time (s)**    |   5    |  9     |  25     |    787   |   4678    |   24764    |
| **Average run time (s)**    |   0.05    |  0.09     |  0.25     |   7.87    |   46.78    |   247.64    |

---

## Testing
### Unit tests (fast, isolated)
- **Mock** ``subprocess.run`` to avoid invoking a real binary.
- **Mock SSL context creation** to assert cert loading without tying to OS.
- **Socketpair** for local in-process send/recv without a network.
- ``capsys`` to assert stdout/stderr.

Example (mocking subprocess):
```python
def test_handle_pow_cpp_success(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(client.subprocess, "run",
        lambda *a, **k: SimpleNamespace(stdout="RESULT:sfx\n", stderr="", returncode=0))
    err, resp = client.handle_pow_cpp("AUTH", "5", "x", "2")
    assert err == 0 and resp == b"sfx\n"
```

### Integration tests (end-to-end)
- Start a **real TLS server** on an ephemeral port (use ``trustme`` for throwaway certs).
- Patch client defaults to point at your server and **fake POW binary** (a tiny Python 
script that prints ``RESULT:testsuffix``).
- TODO!!! Run client ``main()`` and assert the session transcript.

### Sphinx doctests
- Use ``# doctest: +ELLIPSIS`` for variable output.
- Use ``# doctest: +SKIP`` for platform-specific paths/binaries.

---

## Security Notes
- In production:
  - **Don’t** disable verification in production. Use CERT_REQUIRED and verify hostnames.
  - Keep keys/PEMs with restricted file permissions.
  - Treat **all server input** as untrusted; never eval or exec remote data.
- The POW solver uses only deterministic hashing—no code execution.

---

## Add to Sphinx

If you’re using ``.rst``:
```rst
.. toctree::
   :maxdepth: 2

   guide
```