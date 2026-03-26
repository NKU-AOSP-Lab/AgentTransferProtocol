<div align="center">

# ATP: Agent Transfer Protocol

**Secure agent-to-agent communication over the Internet.**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![IETF Draft](https://img.shields.io/badge/IETF-draft--li--atp-orange.svg)](https://datatracker.ietf.org/doc/draft-li-atp/)
[![Tests](https://img.shields.io/badge/tests-195%20passed-brightgreen.svg)]()

A communication protocol for agent-to-agent transfer.<br>
DNS-based discovery, mandatory Ed25519 signing, server-mediated delivery.

```
  Agent A           ATP Server A          ATP Server B          Agent B
    |                    |                     |                    |
    |---[1. Submit]----->|                     |                    |
    |                    |                     |                    |
    |                    |   2. ATS Verify     |                    |
    |                    |   3. ATK Verify     |                    |
    |                    |                     |                    |
    |                    |  4. DNS SVCB Query  |                    |
    |                    |  5. TLS 1.3 + POST  |                    |
    |                    |----[6. Transfer]--->|                    |
    |                    |                     |                    |
    |                    |                     |   7. ATS Verify    |
    |                    |                     |   8. ATK Verify    |
    |                    |                     |                    |
    |<---[202 Accepted]--|                     |---[9. Deliver]--->|
    |                    |                     |                    |
```

[Quick Start](#quick-start) · [Python SDK](#python-sdk) · [CLI Reference](#cli-reference) · [Documentation](#documentation)

</div>

---

## Why ATP?

Agents need a standard way to communicate across the Internet: securely, without a central registry, using infrastructure that already exists.

| Feature | How |
|---------|-----|
| **Identity** | `local@domain` format, powered by DNS |
| **Discovery** | DNS SVCB records, no central registry needed |
| **Signing** | Ed25519 on every message, verified at every hop |
| **Authorization** | ATS policies in DNS, control who can send for your domain |
| **Delivery** | Store-and-forward with retry, messages don't get lost |

## Install

```bash
pip install atp
```

> Requires Python 3.11+

## Quick Start

```bash
# 1. Generate an Ed25519 key pair
atp keys generate

# 2. Start a server
atp server start --domain example.com --port 7443 --local

# 3. Send a message (from another terminal)
atp send agent@remote.org --from mybot@example.com --body "Hello!" --local

# 4. Check server status
atp status --server localhost:7443 --local
```

### Try It: Two Servers Talking

Run two servers locally and send messages between them, no DNS needed:

```bash
# Terminal 1
atp server start --domain alice.local --port 7443 --local --peers peers.toml

# Terminal 2
atp server start --domain bob.local --port 7444 --local --peers peers.toml

# Terminal 3: Alice sends to Bob
atp send agent@bob.local \
  --from agent@alice.local \
  --server localhost:7443 \
  --local \
  --body "Hello Bob!"

# Terminal 4: Bob receives
atp recv --agent-id agent@bob.local --server localhost:7444 --local
```

<details>
<summary><code>peers.toml</code></summary>

```toml
["alice.local"]
host = "127.0.0.1"
port = 7443

["bob.local"]
host = "127.0.0.1"
port = 7444
```

</details>

## Python SDK

```python
import asyncio
from atp.client.client import ATPClient

async def main():
    client = ATPClient(
        agent_id="mybot@example.com",
        server_url="localhost:7443",
        local_mode=True,
    )

    # Send
    result = await client.send("target@remote.org", body="Hello from SDK")
    print(result)  # {"status": "accepted", "nonce": "msg-..."}

    # Receive
    messages = await client.recv()
    for msg in messages:
        print(f"{msg.from_id}: {msg.payload}")

    await client.close()

asyncio.run(main())
```

## CLI Reference

### Core Commands

| Command | Description |
|---------|-------------|
| `atp server start` | Start ATP server |
| `atp send <to>` | Send a message |
| `atp recv` | Receive messages |

### Key Management

| Command | Description |
|---------|-------------|
| `atp keys generate` | Generate Ed25519 key pair |
| `atp keys show` | Show key info |
| `atp keys list` | List all keys |
| `atp keys rotate` | Rotate to a new key |

### Operations

| Command | Description |
|---------|-------------|
| `atp status` | Show server status and metrics |
| `atp inspect <nonce>` | Inspect a specific message |

### DNS

| Command | Description |
|---------|-------------|
| `atp dns generate` | Generate DNS records for your domain |
| `atp dns check` | Verify DNS records are configured |

Run `atp <command> --help` for options.

## Production Deployment

For production, configure DNS records. ATP generates them for you:

```bash
# Step 1: Generate the records
atp dns generate --domain example.com --ip 203.0.113.1

# Step 2: Add them to your DNS provider (Cloudflare, Route53, etc.)

# Step 3: Verify
atp dns check --domain example.com

# Step 4: Start with TLS
atp server start --domain example.com --cert server.crt --key server.key
```

See the [DNS Setup Guide](docs/dns-setup.md) for details.

## Security

ATP provides three layers of security, inspired by email's battle-tested approach:

| Layer | ATP | Email Equivalent | Purpose |
|-------|-----|-----------------|---------|
| Transport | TLS 1.3 | STARTTLS | Encrypted connections |
| Authorization | ATS | SPF | Who can send for a domain |
| Integrity | ATK (Ed25519) | DKIM | Message signing & verification |

Every message is cryptographically signed. Every hop verifies independently.

## Documentation

| | |
|---|---|
| [Quick Start](docs/quickstart.md) | Full walkthrough with two servers |
| [Configuration](docs/configuration.md) | CLI options, config file, retry policy |
| [DNS Setup](docs/dns-setup.md) | Production DNS configuration |
| [Security Model](docs/security.md) | ATS, ATK, TLS explained in depth |
| [Python SDK](docs/sdk.md) | API reference for developers |
| [Architecture](docs/architecture.md) | Module design for contributors |

## Protocol Specification

ATP is defined as an IETF Internet-Draft (Standards Track):

> **Agent Transfer Protocol (ATP)**
> draft-li-atp · March 2026
> Xiang Li, Lu Sun, Yuqi Qiu, Nankai University, AOSP Laboratory
>
> [IETF Datatracker](https://datatracker.ietf.org/doc/draft-li-atp/) · [Full Text](../Agent%20Transfer%20Protocol%20(ATP).md)

## Contributing

```bash
git clone https://github.com/AospLab/atp.git
cd atp
pip install -e ".[dev]"
python -m pytest tests/ -v    # 195 tests
```

See [Architecture](docs/architecture.md) for module design and development guide.

## License

[MIT](LICENSE)
