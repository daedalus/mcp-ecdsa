# mcp-ecdsa

> MCP server for ECDSA cryptography

[![PyPI](https://img.shields.io/pypi/v/mcp-ecdsa.svg)](https://pypi.org/project/mcp-ecdsa/)
[![Python](https://img.shields.io/pypi/pyversions/mcp-ecdsa.svg)](https://pypi.org/project/mcp-ecdsa/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

mcp-name: io.github.daedalus/mcp-ecdsa

## Install

```bash
pip install mcp-ecdsa
```

## Usage

### As MCP Server

Configure in your MCP client:

```json
{
  "mcpServers": {
    "mcp-ecdsa": {
      "command": "mcp-ecdsa"
    }
  }
}
```

### Python API

```python
from mcp_ecdsa import generate_key, sign_data, verify_signature

# Generate key pair
result = await generate_key({"curve": "NIST256p"})
data = json.loads(result[0].text)

# Sign data
sign_result = await sign_data({
    "private_key": data["private_key"],
    "data": "Hello, World!"
})

# Verify signature
verify_result = await verify_signature({
    "public_key": data["public_key"],
    "signature": json.loads(sign_result[0].text)["signature"],
    "data": "Hello, World!"
})
```

## Tools

| Tool | Description |
|------|-------------|
| `generate_key` | Generate ECDSA key pair |
| `sign_data` | Sign data (with hashing) |
| `sign_digest` | Sign pre-hashed digest |
| `verify_signature` | Verify signature over data |
| `verify_digest_signature` | Verify signature over digest |
| `import_private_key` | Import from PEM/DER/base64 |
| `import_public_key` | Import from PEM/DER/base64 |
| `export_private_key` | Export to PEM/DER/base64/SSH |
| `export_public_key` | Export to PEM/DER/base64/SSH |
| `get_key_info` | Get key information |
| `recover_public_key` | Recover public keys from signature |

### Supported Curves

- NIST192p, NIST224p, NIST256p, NIST384p, NIST521p
- SECP256k1
- Ed25519, Ed448

### Supported Hash Functions

- SHA1, SHA224, SHA256, SHA384, SHA512
- SHA3-256, SHA3-384, SHA3-512

## Development

```bash
git clone https://github.com/daedalus/mcp-ecdsa.git
cd mcp-ecdsa
pip install -e ".[test]"

# run tests
pytest

# format
ruff format src/ tests/

# lint
ruff check src/ tests/

# type check
mypy src/
```
