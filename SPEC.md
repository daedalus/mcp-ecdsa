# SPEC.md — mcp-ecdsa

## Purpose
MCP server that exposes ECDSA cryptographic functionality (key generation, signing, verification) from the python-ecdsa library via the Model Context Protocol.

## Scope
- What IS in scope:
  - ECDSA key pair generation (NIST192p, NIST224p, NIST256p, NIST384p, NIST521p, SECP256k1, Ed25519, Ed448)
  - Signing data (with hashing) and digests (pre-hashed)
  - Signature verification for both data and digests
  - Key import/export (PEM, DER, base64, SSH formats)
  - Public key recovery from signatures
  - Multiple hash functions (SHA1, SHA224, SHA256, SHA384, SHA512, SHA3 variants)
  - Multiple signature encodings (string/raw, DER)

- What is NOT in scope:
  - Encryption (only signatures)
  - Key exchange
  - Certificate handling
  - SSH key authentication (beyond format support)

## Public API / Interface

### MCP Tools

| Tool | Description | Input | Output |
|------|-------------|-------|--------|
| `generate_key` | Generate ECDSA key pair | `curve` (str), `hashfunc` (str) | `private_key` (base64), `public_key` (base64), `curve` (str) |
| `sign_data` | Sign data (hashed) | `private_key`, `data`, `curve`, `hashfunc`, `sigencode`, `deterministic` | `signature` (base64) |
| `sign_digest` | Sign pre-hashed digest | `private_key`, `digest` (hex), `curve`, `sigencode`, `deterministic` | `signature` (base64) |
| `verify_signature` | Verify signature over data | `public_key`, `signature`, `data`, `curve`, `hashfunc`, `sigdecode` | `valid` (bool) |
| `verify_digest_signature` | Verify signature over digest | `public_key`, `signature`, `digest` (hex), `curve`, `sigdecode` | `valid` (bool) |
| `import_private_key` | Import private key | `key_data`, `format`, `curve`, `hashfunc` | `private_key`, `public_key`, `curve` |
| `import_public_key` | Import public key | `key_data`, `format`, `curve`, `hashfunc` | `public_key`, `curve` |
| `export_private_key` | Export private key | `private_key`, `curve`, `format`, `pem_format` | `key` |
| `export_public_key` | Export public key | `public_key`, `curve`, `format`, `point_encoding` | `key` |
| `get_key_info` | Get key information | `private_key`, `public_key`, `curve` | key details |
| `recover_public_key` | Recover public keys from signature | `signature`, `data`, `curve`, `hashfunc` | `keys` (array) |

### Supported Values
- **Curves**: NIST192p, NIST224p, NIST256p, NIST384p, NIST521p, SECP256k1, Ed25519, Ed448
- **Hash functions**: sha1, sha224, sha256, sha384, sha512, sha3_256, sha3_384, sha3_512
- **Key formats**: pem, der, base64, ssh
- **Signature encodings**: string (raw), der

## Data Formats
- Keys: base64-encoded raw bytes for internal use, PEM/DER/SSH for import/export
- Signatures: base64-encoded bytes
- Digests: hex-encoded strings

## Edge Cases
1. Invalid base64 in key/signature input raises error
2. Invalid curve name raises error
3. Invalid hash function name raises error
4. Verification with wrong key returns `valid: false` (not exception)
5. Signing with wrong curve for key raises error
6. Importing corrupted PEM/DER raises appropriate ecdsa exception
7. Empty data to sign is valid
8. Ed25519/Ed448 use deterministic signing only

## Performance & Constraints
- Pure Python implementation (python-ecdsa)
- No O(n) requirements specified
- No external API dependencies

## Acceptance Criteria
- [ ] All 11 tools implemented and functional
- [ ] Key generation works for all supported curves
- [ ] Signing and verification works correctly
- [ ] Key import/export roundtrips work
- [ ] Invalid inputs are handled gracefully
- [ ] MCP server runs via stdio transport
