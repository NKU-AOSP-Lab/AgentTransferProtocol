# ATP — Agent Transfer Protocol

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Secure agent-to-agent communication over the Internet.

ATP enables autonomous agents to discover, authenticate, and exchange messages across domains — like email for AI agents.

```
Agent A ──▶ ATP Server A ════Internet══════▶ ATP Server B ──▶ Agent B
              ATS ✅  ATK ✅                   ATS ✅  ATK ✅
```

## Install

```bash
pip install atp
```

## Quick Start

### 1. Generate keys

```bash
atp keys generate
```

### 2. Start a server

```bash
atp server start --domain example.com --port 7443 --local
```

### 3. Send a message

```bash
atp send agent@remote.org --from mybot@example.com --body "Hello!" --local
```

### 4. Receive messages

```bash
atp recv --agent-id agent@example.com --server localhost:7443 --local
```

## Local Development (Two Servers)

Run two servers on your machine and send messages between them — no DNS required:

```bash
# Terminal 1: Server A
atp server start --domain alice.local --port 7443 --local --peers peers.toml

# Terminal 2: Server B
atp server start --domain bob.local --port 7444 --local --peers peers.toml

# Terminal 3: Send from Alice to Bob
atp send agent@bob.local --from agent@alice.local --server localhost:7443 --local --body "Hello Bob!"

# Terminal 4: Bob receives
atp recv --agent-id agent@bob.local --server localhost:7444 --local
```

Create `peers.toml`:

```toml
["alice.local"]
host = "127.0.0.1"
port = 7443

["bob.local"]
host = "127.0.0.1"
port = 7444
```

## Python SDK

```python
import asyncio
from atp import ATPClient

async def main():
    client = ATPClient(agent_id="mybot@example.com", server_url="localhost:7443", local_mode=True)

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

| Command | Description |
|---------|-------------|
| `atp server start` | Start ATP server |
| `atp send <to>` | Send a message |
| `atp recv` | Receive messages |
| `atp keys generate` | Generate Ed25519 key pair |
| `atp keys show` | Show key info |
| `atp keys list` | List all keys |
| `atp keys rotate` | Rotate to a new key |
| `atp dns generate` | Generate DNS records for your domain |
| `atp dns check` | Verify DNS records are configured |

Run `atp <command> --help` for detailed options.

## Production Deployment

For production, you need real DNS records. ATP provides a helper:

```bash
# Generate the records you need to add
atp dns generate --domain example.com --ip 203.0.113.1

# Verify they're configured correctly
atp dns check --domain example.com

# Start server with TLS
atp server start --domain example.com --cert server.crt --key server.key
```

See the [DNS Setup Guide](docs/dns-setup.md) for details.

## Security

ATP provides three layers of security:

- **TLS 1.3** — Mandatory encrypted transport
- **ATS** (Agent Transfer Sender) — DNS-based sender authorization (like SPF for email)
- **ATK** (Agent Transfer Key) — Ed25519 message signatures (like DKIM for email)

Every message is signed. Every hop verifies independently.

## Documentation

- [Quick Start Guide](docs/quickstart.md)
- [Configuration Reference](docs/configuration.md)
- [DNS Setup Guide](docs/dns-setup.md)
- [Security Model](docs/security.md)
- [Python SDK Reference](docs/sdk.md)
- [Architecture Overview](docs/architecture.md)

## Protocol Specification

ATP is defined in [draft-li-atp-00](../Agent%20Transfer%20Protocol%20(ATP).md) (Internet-Draft, Standards Track).

## License

MIT
