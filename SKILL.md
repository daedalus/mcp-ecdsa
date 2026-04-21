# MCP ECDSA

MCP server for ECDSA cryptography operations.

## When to use this skill

Use this skill when you need to:
- Generate ECDSA key pairs
- Sign data with ECDSA
- Verify ECDSA signatures
- Import/export ECDSA keys

## Tools

- `generate_key` - Generate ECDSA key pair
- `sign_data` - Sign data (with hashing)
- `sign_digest` - Sign pre-hashed digest
- `verify_signature` - Verify signature over data
- `verify_digest_signature` - Verify signature over digest
- `import_private_key` - Import from PEM/DER/base64
- `import_public_key` - Import from PEM/DER/base64
- `export_private_key` - Export to PEM/DER/base64/SSH
- `export_public_key` - Export to PEM/DER/base64/SSH
- `get_key_info` - Get key information
- `recover_public_key` - Recover public keys from signature

## Supported Curves

NIST192p, NIST224p, NIST256p, NIST384p, NIST521p, SECP256k1, Ed25519, Ed448

## Install

```bash
pip install mcp-ecdsa
```