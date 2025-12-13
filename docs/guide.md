# Guide - How it works
## Overview

This project demonstrates a minimal **TLS client/server** that speaks a simple, line-based
protocol and includes a **Proof-of-Work (WORK)** step solved by a fast **C++ helper**. You also 
get a thorough **pytest** suite (unit + integration) and **Sphinx** docs/doctests.

### High-level flow
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

### Key properties
- **TLS** for transport security (optionally mutual auth).
- **Deterministic protocol** (plain text, newline-terminated).
- **Time-bounded WORK** (2h cap) with multi-threaded C++ backend.
- **Portable tests** that mock subprocess/SSL or use a throwaway TLS server.

---

## Architecture
### Components
- **Client** (src/client.py)
  - ``tls_connect(...)`` – Create SSL context and return a TLS-wrapped socket.
  - ``connect_to_server(...)`` – Connect + error reporting.
  - ``decipher_message(...)`` – Validate/parse incoming lines.
  - ``hasher(...)`` – ``SHA256(token + payload)``.
  - ``handle_pow_cpp(...)`` – Invoke ``build/pow_benchmark`` (C++), parse ``RESULT:<suffix>``.
  - ``define_response(...)`` – Handle commands. Returns bytes to send.
  - ``main()`` – Orchestrates receive/dispatch with per-command timeouts.
- **Server** (``src/server.py``)
  - ``prepare_socket(...)`` – TLS server context w/ CA & server cert.
  - ``send_message(...)`` / ``receive_message(...)`` – Protocol helpers.
  - ``is_succeed_send_and_receive(...)`` – One-step request/response w/ validations.
- **C++ WORK Solver** (``src/pow_benchmark.cpp``)
  - Counter-based suffix generator.
  - Bit-precise leading-zero check (``difficulty * 4`` bits for hex).
  - Multi-thread sharding, CPU only.

## Dataflow (client-side)
1. TLS connect → read command line.
2. Parse.
3. Reply, respecting per-command timeouts (multiprocessing).
    - For ``WORK``, call binary → return suffix.
    - For info commands, compute checksum and reply.

---

## Protocol
- **Transport**: TLS.
- **Encoding**: UTF-8 text.
- **Line format**: ``COMMAND [ARG]...\n``
- Hasher: SHA256.

### Commands (server → client)
- ``HELLO\n`` → client must reply ``HELLOBACK\n``.
- ``WORK <token> <difficulty>\n`` → client replies with a valid ``<suffix>``.
    - **Validity**: ``SHA256(token + suffix)`` starts with ``<difficulty>`` hex zeros.
- Info requests (examples below use ``<arg>`` as server-provided string):
  - ``FULL_NAME <arg>\n``
  - ``MAILNUM <arg>\n``
  - ``EMAIL1 <arg>\n``
  - ``EMAIL2 <arg>\n``
  - ``SOCIAL <arg>\n``
  - ``BIRTHDATE <arg>\n``
  - ``COUNTRY <arg>\n``
  - ``ADDRNUM <arg>\n``
  - ``ADDR_LINE1 <arg>\n``
  - ``ADDR_LINE2 <arg>\n``
- ``ERROR <reason>\n`` → client should stop.
- ``DONE\n`` → client replies OK and closes.

### Client responses
Client reply format:
- ``HELLOBACK\n`` for ``HELLO\n``.
- ``<suffix>\n`` for ``WORK\n``.
- ``<sha256(token + arg)> <value>\n`` for info commands.
- ``OK\n`` for ``DONE\n``.

### Error handling
- Malformed input, invalid commands, UTF-8 failure, or missing newline → treat as 
error and close.
- Command timeouts: ``WORK`` 7200s; others 6s.

---

## TLS Setup

You can run **insecure local** (disabled verification) for development, or **mutual TLS** 
in stricter environments.

### Local (insecure) for quick testing
- Client: ``verify_mode = ssl.CERT_NONE``, ``check_hostname = False``.
- Server: ``verify_mode = ssl.CERT_NONE``.
- Use **only** for local tests!

### Proper test chain (self-signed CA)
See [Installation](https://github.com/elliottbache/tls_line_protocol/blob/master/README.md). 

---

## WORK Solver (C++)
**Goal**: Find a ``suffix`` so that ``SHA256(token + suffix)`` starts with 
``N`` hex ``0``s (i.e., ``bits = 4*N`` zero bits).

### Strategy
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

### Build
```bash
mkdir -p build
g++ -O3 -std=c++17 pow_benchmark.cpp pow_core.cpp -o ../build/pow_benchmark -lssl -lcrypto -pthread
```

### Run:
```bash
pow_benchmark <token> <difficulty>
# stdout line: RESULT:<suffix>\n
```

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
- Patch client defaults to point at your server and **fake WORK binary** (a tiny Python 
script that prints ``RESULT:testsuffix``).
- Run client ``main()`` and assert the session transcript.

### Sphinx doctests
- Use ``# doctest: +ELLIPSIS`` for variable output.
- Use ``# doctest: +SKIP`` for platform-specific paths/binaries.

---

## Security Notes
- **Don’t** disable verification in production. Use CERT_REQUIRED and verify hostnames.
- Keep keys/PEMs with restricted file permissions.
- Treat **all server input** as untrusted; never eval or exec remote data.
- The WORK solver uses only deterministic hashing—no code execution.

---

## Add to Sphinx

If you’re using ``.rst``:
```rst
.. toctree::
   :maxdepth: 2

   guide
```