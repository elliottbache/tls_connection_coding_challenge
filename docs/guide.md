# Guide - How it works
## Overview

This project demonstrates a minimal **TLS client/server** that speaks a simple, line-based
protocol and includes a **Proof-of-Work (WORK)** step solved by a fast **C++ helper**. You also 
get a thorough **pytest** suite (unit + integration) and **Sphinx** docs/doctests.

---

## How to run
![Demo](demo.gif)
For complete instructions, see 
[Installation](https://github.com/elliottbache/tls_line_protocol/blob/master/README.md#installation)
and [Execution and usage](https://github.com/elliottbache/tls_line_protocol/blob/master/README.md#execution--usage). 
 

---


## High-level flow
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
README shows a static snapshot; this Mermaid diagram is the source.  Changes made to this diagram can be 
compiled in an online editor, exported as ```.svg```, and placed in ```docs/_static/``` to replace the 
current diagram in README.md.

## Key properties
- **TLS** for transport security (optionally mutual auth).
- **Deterministic protocol** (plain text, newline-terminated).
- **Time-bounded WORK** (2h cap) with multi-threaded C++ backend.
- **Portable tests** that mock subprocess/SSL or use a throwaway TLS server.

---

## Architecture
### Components
- **Python package** (`src/tlslp/`)
  - `tlslp.protocol`
    - `send_message(...)` / `receive_message(...)` – newline-delimited UTF-8 transport helpers.
    - `ProtocolError` / `TransportError` – consistent exceptions for protocol vs transport/TLS failures.
    - `_parse_positive_int(...)` – CLI helper for positive integer arguments.
  - `tlslp.server`
    - `prepare_server_socket(...)` – bind/listen and create a TLS server `SSLContext`.
    - `send_and_receive(...)` – one request/response with validation (checksum / WORK suffix).
    - `handle_one_session(...)` – run handshake + message loop for one client connection.
    - `main(...)` – CLI entrypoint.
  - `tlslp.client`
    - `prepare_client_socket(...)` – build TLS client context and return a wrapped socket.
    - `connect_to_server(...)` – connect with clear error reporting.
    - `decipher_message(...)` – validate/parse incoming line into tokens.
    - `run_pow_binary(...)` / `handle_pow_cpp(...)` – run external WORK solver and parse `RESULT:<suffix>`.
    - `define_response(...)` – generate a response string for a command.
    - `_process_message_with_timeout(...)` – enforce per-command timeouts (WORK vs others).
    - `main(...)` – CLI entrypoint.
  - `tlslp.logging_utils`
    - `configure_logging(...)` – root logger setup (file + stderr).

- **C++ WORK solver** (`cpp/`)
  - `pow_challenge.cpp` + `pow_core.*` – compiled to an executable that prints a `RESULT:<suffix>` line.
  - Default runtime location is `src/tlslp/_bin/pow_challenge` (override with `--pow-binary`).


### Repository layout
```text
├── .dockerignore
├── .gitattributes
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
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── LICENSE
├── Makefile
├── README.md
├── cpp
│   ├── CMakeLists.txt
│   ├── pow_challenge.cpp
│   ├── pow_core.cpp
│   ├── pow_core.h
│   ├── pow_core_internal.h
│   └── tests
│       └── pow_core_test.cpp
├── docker
│   ├── client.Dockerfile
│   └── server.Dockerfile
├── docker-compose.yaml
├── docs
│   ├── Doxyfile
│   ├── Makefile
│   ├── _static
│   │   └── flow_diagram.svg
│   ├── conf.py
│   ├── cpp_api.rst
│   ├── demo.cast
│   ├── demo.gif
│   ├── guide.md
│   ├── index.rst
│   ├── intro.md
│   ├── make.bat
│   ├── python_api.rst
│   └── requirements.txt
├── pyproject.toml
├── scripts
│   ├── compare_tutorial_logs.sh
│   ├── install-cpp-deps.sh
│   ├── install-python-deps.sh
│   └── make-certs.sh
├── src
│   └── tlslp
│       ├── __init__.py
│       ├── client.py
│       ├── logging_utils.py
│       ├── protocol.py
│       └── server.py
└── tests
    ├── _helpers.py
    ├── conftest.py
    ├── test_client.py
    ├── test_protocol.py
    ├── test_server.py
    └── test_tls.py
```
Generated with:
```bash
tree -a -L 4 -I ".git|.venv|__pycache__|*.egg-info|.pytest_cache|.mypy_cache|.ruff_cache|build|_build|_codeql_build_dir|certificates"
```

---

## Dataflow (client-side)
1. Establish a TLS connection (optionally insecure for localhost development).
2. Receive **exactly one line** (newline-delimited UTF-8) via `receive_message(...)`.
3. Parse into tokens with `decipher_message(...)` and validate the command name.
4. Generate a response, enforcing per-command timeouts:
   - Non-WORK commands use a short timeout (default 6s, configurable).
   - WORK can be long (default 2h, configurable) and is solved by an external binary.
5. Send the response using `send_message(...)` (adds `\n` if missing).
6. Stop on `ERROR` from the server or after responding to `DONE`.

The following should be taken into account:
- Multiline messages are not supported since this was not part of the coding
challenge.  Each command sent by the server was meant to be answered with 
a single-line.  Any more lines would fall outside the scope of the proper
functioning of this program and should thus be treated as an exception.
- Multiprocessing is used to take into account the imposed timeouts.  All 
commands have a timeout of 6 seconds except the WORK challenge, which has a
2-hour timeout.

---

## Protocol
- **Transport**: TLS.
- **Encoding**: UTF-8 text.
- **Framing**: newline-delimited (`\n`). `receive_message(...)` returns the line **without** the trailing newline.
- **Size limits**: single line must not exceed `MAX_LINE_LENGTH` bytes.
- **Hasher**: SHA256 is used by the challenge for checksums / WORK validity.

### Commands (server → client)
- `HELLO\n` → client replies `HELLOBACK\n`.
- `WORK <token> <difficulty>\n` → client replies with a valid `<suffix>\n`.
  - **Validity**: `SHA256(token + suffix)` starts with `<difficulty>` hex zeros.
- Info requests (examples below use `<arg>` as server-provided string):
  - `FULL_NAME <arg>\n`
  - `MAILNUM <arg>\n`
  - `EMAIL1 <arg>\n`
  - `EMAIL2 <arg>\n`
  - `SOCIAL <arg>\n`
  - `BIRTHDATE <arg>\n`
  - `COUNTRY <arg>\n`
  - `ADDRNUM <arg>\n`
  - `ADDR_LINE1 <arg>\n`
  - `ADDR_LINE2 <arg>\n`
- `ERROR <reason>\n` → client should stop.
- `DONE\n` → client replies `OK\n` and closes.

### Client responses
Client reply format:
- `HELLOBACK\n` for `HELLO\n`.
- `<suffix>\n` for `WORK\n`.
- `<sha256(token + arg)> <value>\n` for info commands.
- `OK\n` for `DONE\n`.

### Error handling
- Invalid UTF-8, missing newline (typically surfaces as a timeout), overlong line, or unexpected tokenization → treat as a protocol/transport error and stop.
- Timeouts are enforced **per operation**:
  - Client: WORK vs non-WORK handling is bounded (`--pow-timeout` / `--other-timeout`).
  - Server: socket timeouts are set per request/response step.


---

## TLS Setup

This repo supports two modes:

### Insecure mode (local dev)
Enable with `--insecure`.

- Client disables server certificate verification:
  - `verify_mode = ssl.CERT_NONE`
  - `check_hostname = False`
- Server does not require a client certificate:
  - `verify_mode = ssl.CERT_NONE`

Use this **only** for localhost development and tests where you explicitly want to skip verification.

### Secure mode (mTLS)
Default mode (when `--insecure` is not set).

- Client verifies the server certificate against the provided CA cert **and** presents a client cert:
  - `verify_mode = ssl.CERT_REQUIRED`
  - `check_hostname = True`
  - `cafile = <ca_cert_path>`
  - `load_cert_chain(client_cert, private_key)`
- Server requires and verifies a client certificate:
  - `verify_mode = ssl.CERT_REQUIRED`
  - `load_verify_locations(cafile=<ca_cert_path>)`

Important: in secure mode, `--host` must match the server certificate’s hostname/SAN, because hostname verification is enabled.

### What’s tested (and why it matters)

The test suite validates the key security properties:

- **Server authentication**: a client trusts a CA and verifies the server certificate (including hostname via `server_hostname`).
- **Client authentication (mTLS)**: the server requires a client certificate and rejects clients that don’t present one.
- **Ephemeral certs in tests**: integration tests generate short-lived CA/server/client certs at runtime (via `trustme`), keeping the repo free of committed keys.
- A guide for certificate generation is linked from the README installation section.

---

## Testing
This repo uses **pytest** for unit tests. The goal is fast feedback locally while still validating 
the core TLS behaviors end-to-end.
### Run everything
```make test```
or
```pytest```

What this covers:
- Protocol helpers (```send_message```, ```receive_message```) using ```socket.socketpair()``` (no network).
- Client/server logic using faked sockets and faked SSL contexts.
- WORK handling by mocking ```subprocess.run``` (no real C++ binary execution).
 
### Sphinx doctests
Doctests are treated as **documentation checks**, not full integration coverage.
When running doctests:
- It is preferred to run them as part of the docs build (Sphinx doctest) or with pytest configured to 
include doctests.
- Doctests are kept deterministic, they avoid:
  - needing real certificate files
  - binding to real ports
  - time-based output

If a doctest needs TLS objects, a **mocked contexts** approach is used (e.g. FakeContext) rather than
real files on disk.

---

## Security implementation
This repo is a coding-challenge/demo, but it’s still useful to treat it as if it exposed beyond localhost.  
In the future, extended this repo to a production-grade project will be easier this way.  The goal is to 
fail closed: treat all network input as untrusted, validate aggressively, and stop on protocol violations.

### Security Notes
- In production:
  - **Don’t** disable verification in production. Use CERT_REQUIRED and verify hostnames.
  - Keep keys/PEMs with restricted file permissions.
  - Treat **all server input** as untrusted; never eval or exec remote data.
- The WORK solver uses only deterministic hashing—no code execution.

### Timeouts
**Why**: Prevent hangs (slowloris-style reads, stuck handshakes, blocked subprocesses), and make failure modes predictable.

**How** this is done:
- Use **per-operation socket timeouts** rather than an unbounded read loop.
  - Server: each request/response step sets a timeout appropriate to the step (WORK vs non-WORK).
  - Client: command handling is bounded with a hard timeout (WORK vs non-WORK) enforced in `_process_message_with_timeout(...)`.
- Bound the WORK solver execution time:
  - `subprocess.run(..., timeout=...)` inside `run_pow_binary(...)`.

Defaults are chosen for the challenge (short for non-WORK, long for WORK), and are configurable via CLI flags.

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
**Why**: The server controls the client’s behavior. Tight validation prevents weird edge cases and reduces attack surface.

**How** this is done:
- Parse exactly one line, then:
  - split into tokens
  - require the command token to be in the allowlist (`DEFAULT_VALID_MESSAGES`)
- Treat protocol violations as `ProtocolError` and network/TLS failures as `TransportError`.
- Validate sensitive inputs before using them for hashing / subprocess calls:
  - `token` character set / length
  - `difficulty` is an integer in a reasonable range
- On server side, validate:
  - WORK suffix correctness
  - checksum correctness for info replies

### Retry strategy
**Why**: The client may be asked to try multiple ports.

**How** this is done:
- The client iterates the configured port list and attempts to connect until one succeeds.
- There is no exponential backoff (kept intentionally simple for the challenge).
- The client does not “retry” after protocol violations during an established session.

### Subprocess safety
The WORK solver is intentionally an external executable.  It is treated like untrusted input/output.

**How** this is done:
- Never use ```shell=True```.
- Pass args as a list: ```["/abs/path/pow_benchmark", token, difficulty]``` (you do this).
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

## WORK Solver (C++)
**Goal**: Find a ``suffix`` so that ``SHA256(token + suffix)`` starts with 
``N`` hex ``0``s (i.e., ``bits = 4*N`` zero bits).

### Strategy
- **SHA256** was imposed as a coding constraint in the challenge.
- SHA256 is **initialized** with ```token```, then a copy is **updated** with each new suffix. 
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
The Python client expects an executable WORK solver. By default, it looks for it at:
`src/tlslp/_bin/pow_challenge` (override with `--pow-binary`).
#### Recommended
```bash
make build-cpp
```
#### Manual build
If you build manually (alternative to [Recommended](#recommended)) from cpp/, compile and then copy 
the binary into the package’s _bin/ directory (so the default path works).  From root:
```bash
mkdir -p build
cd cpp
g++ -O3 -std=c++17 pow_challenge.cpp pow_core.cpp -o ../build/pow_challenge -lssl -lcrypto -pthread
cp ../build/pow_challenge ../src/tlslp/_bin/pow_challenge
```

### Run:
From root:
```bash
./src/tlslp/_bin/pow_challenge <token> <difficulty>
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

## Future work
- Create integration test asserting full transcript from main().