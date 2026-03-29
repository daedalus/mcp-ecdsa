"""Tests for MCP ECDSA server."""

import asyncio
import json

import pytest

from mcp_ecdsa.server import (
    export_private_key,
    export_public_key,
    generate_key,
    get_key_info,
    import_private_key,
    import_public_key,
    recover_public_key,
    sign_data,
    sign_digest,
    verify_digest_signature,
    verify_signature,
)


@pytest.fixture
def keys_nist256p() -> dict:
    """Generate key pair for NIST256p curve."""
    result = asyncio.run(generate_key({"curve": "NIST256p", "hashfunc": "sha256"}))
    return json.loads(result[0].text)


class TestGenerateKey:
    """Tests for generate_key function."""

    async def test_generate_nist256p(self) -> None:
        """Test key generation with NIST256p curve."""
        result = await generate_key({})
        data = json.loads(result[0].text)
        assert "private_key" in data
        assert "public_key" in data
        assert "curve" in data

    async def test_generate_with_curve(self) -> None:
        """Test key generation with specific curve."""
        result = await generate_key({"curve": "NIST384p"})
        data = json.loads(result[0].text)
        assert data["curve"] == "NIST384p"

    async def test_generate_secp256k1(self) -> None:
        """Test key generation with SECP256k1 curve."""
        result = await generate_key({"curve": "SECP256k1"})
        data = json.loads(result[0].text)
        assert data["curve"] == "SECP256k1"


class TestSignData:
    """Tests for sign_data function."""

    async def test_sign_data_basic(self, keys_nist256p: dict) -> None:
        """Test basic data signing."""
        result = await sign_data(
            {
                "private_key": keys_nist256p["private_key"],
                "data": "Hello, World!",
            }
        )
        data = json.loads(result[0].text)
        assert "signature" in data
        assert len(data["signature"]) > 0

    async def test_sign_data_empty(self, keys_nist256p: dict) -> None:
        """Test signing empty data."""
        result = await sign_data(
            {
                "private_key": keys_nist256p["private_key"],
                "data": "",
            }
        )
        data = json.loads(result[0].text)
        assert "signature" in data

    async def test_sign_deterministic(self, keys_nist256p: dict) -> None:
        """Test deterministic signing produces same result."""
        result1 = await sign_data(
            {
                "private_key": keys_nist256p["private_key"],
                "data": "Test",
                "deterministic": True,
            }
        )
        result2 = await sign_data(
            {
                "private_key": keys_nist256p["private_key"],
                "data": "Test",
                "deterministic": True,
            }
        )
        sig1 = json.loads(result1[0].text)["signature"]
        sig2 = json.loads(result2[0].text)["signature"]
        assert sig1 == sig2


class TestVerifySignature:
    """Tests for verify_signature function."""

    async def test_verify_valid_signature(self, keys_nist256p: dict) -> None:
        """Test verification of valid signature."""
        sign_result = await sign_data(
            {
                "private_key": keys_nist256p["private_key"],
                "data": "Hello, World!",
            }
        )
        signature = json.loads(sign_result[0].text)["signature"]

        result = await verify_signature(
            {
                "public_key": keys_nist256p["public_key"],
                "signature": signature,
                "data": "Hello, World!",
            }
        )
        data = json.loads(result[0].text)
        assert data["valid"] is True

    async def test_verify_invalid_signature(self, keys_nist256p: dict) -> None:
        """Test verification with wrong data."""
        sign_result = await sign_data(
            {
                "private_key": keys_nist256p["private_key"],
                "data": "Hello, World!",
            }
        )
        signature = json.loads(sign_result[0].text)["signature"]

        result = await verify_signature(
            {
                "public_key": keys_nist256p["public_key"],
                "signature": signature,
                "data": "Wrong message!",
            }
        )
        data = json.loads(result[0].text)
        assert data["valid"] is False

    async def test_verify_wrong_key(self) -> None:
        """Test verification with wrong public key."""
        key1_result = await generate_key({"curve": "NIST256p"})
        key1 = json.loads(key1_result[0].text)
        key2_result = await generate_key({"curve": "NIST256p"})
        key2 = json.loads(key2_result[0].text)

        sign_result = await sign_data(
            {
                "private_key": key1["private_key"],
                "data": "Hello, World!",
            }
        )
        signature = json.loads(sign_result[0].text)["signature"]

        result = await verify_signature(
            {
                "public_key": key2["public_key"],
                "signature": signature,
                "data": "Hello, World!",
            }
        )
        data = json.loads(result[0].text)
        assert data["valid"] is False


class TestSignDigest:
    """Tests for sign_digest function."""

    async def test_sign_digest_basic(self, keys_nist256p: dict) -> None:
        """Test basic digest signing."""
        digest = "a" * 64  # 32 bytes = 256 bits

        result = await sign_digest(
            {
                "private_key": keys_nist256p["private_key"],
                "digest": digest,
            }
        )
        data = json.loads(result[0].text)
        assert "signature" in data


class TestVerifyDigestSignature:
    """Tests for verify_digest_signature function."""

    async def test_verify_digest_valid(self, keys_nist256p: dict) -> None:
        """Test verification of valid digest signature."""
        digest = "a" * 64

        sign_result = await sign_digest(
            {
                "private_key": keys_nist256p["private_key"],
                "digest": digest,
            }
        )
        signature = json.loads(sign_result[0].text)["signature"]

        result = await verify_digest_signature(
            {
                "public_key": keys_nist256p["public_key"],
                "signature": signature,
                "digest": digest,
            }
        )
        data = json.loads(result[0].text)
        assert data["valid"] is True


class TestImportExport:
    """Tests for import/export functions."""

    async def test_export_private_key_pem(self, keys_nist256p: dict) -> None:
        """Test exporting private key to PEM."""
        result = await export_private_key(
            {
                "private_key": keys_nist256p["private_key"],
                "curve": "NIST256p",
                "format": "pem",
            }
        )
        data = json.loads(result[0].text)
        assert "-----BEGIN EC PRIVATE KEY-----" in data["key"]

    async def test_export_public_key_pem(self, keys_nist256p: dict) -> None:
        """Test exporting public key to PEM."""
        result = await export_public_key(
            {
                "public_key": keys_nist256p["public_key"],
                "curve": "NIST256p",
                "format": "pem",
            }
        )
        data = json.loads(result[0].text)
        assert "-----BEGIN PUBLIC KEY-----" in data["key"]

    async def test_import_export_roundtrip(self, keys_nist256p: dict) -> None:
        """Test import/export roundtrip."""
        # Export to PEM
        export_result = await export_private_key(
            {
                "private_key": keys_nist256p["private_key"],
                "curve": "NIST256p",
                "format": "pem",
            }
        )
        pem_key = json.loads(export_result[0].text)["key"]

        # Import back
        import_result = await import_private_key(
            {
                "key_data": pem_key,
                "format": "pem",
            }
        )
        imported = json.loads(import_result[0].text)

        assert imported["private_key"] == keys_nist256p["private_key"]


class TestGetKeyInfo:
    """Tests for get_key_info function."""

    async def test_get_key_info_from_private(self, keys_nist256p: dict) -> None:
        """Test getting key info from private key."""
        result = await get_key_info(
            {
                "private_key": keys_nist256p["private_key"],
                "curve": "NIST256p",
            }
        )
        data = json.loads(result[0].text)
        assert "private_key" in data
        assert "public_key" in data

    async def test_get_key_info_from_public(self, keys_nist256p: dict) -> None:
        """Test getting key info from public key."""
        result = await get_key_info(
            {
                "public_key": keys_nist256p["public_key"],
                "curve": "NIST256p",
            }
        )
        data = json.loads(result[0].text)
        assert "public_key" in data


class TestRecoverPublicKey:
    """Tests for recover_public_key function."""

    async def test_recover_public_key(self, keys_nist256p: dict) -> None:
        """Test public key recovery from signature."""
        sign_result = await sign_data(
            {
                "private_key": keys_nist256p["private_key"],
                "data": "Hello, World!",
            }
        )
        signature = json.loads(sign_result[0].text)["signature"]

        result = await recover_public_key(
            {
                "signature": signature,
                "data": "Hello, World!",
                "curve": "NIST256p",
            }
        )
        data = json.loads(result[0].text)
        assert "keys" in data
        assert len(data["keys"]) > 0


class TestEd25519:
    """Tests for Ed25519 curve."""

    async def test_generate_ed25519(self) -> None:
        """Test Ed25519 key generation."""
        result = await generate_key({"curve": "Ed25519"})
        data = json.loads(result[0].text)
        assert data["curve"] == "Ed25519"

    async def test_sign_verify_ed25519(self) -> None:
        """Test signing and verification with Ed25519."""
        key_result = await generate_key({"curve": "Ed25519"})
        key = json.loads(key_result[0].text)

        sign_result = await sign_data(
            {
                "private_key": key["private_key"],
                "data": "Test message",
                "curve": "Ed25519",
            }
        )
        signature = json.loads(sign_result[0].text)["signature"]

        verify_result = await verify_signature(
            {
                "public_key": key["public_key"],
                "signature": signature,
                "data": "Test message",
                "curve": "Ed25519",
            }
        )
        data = json.loads(verify_result[0].text)
        assert data["valid"] is True


class TestExportFormats:
    """Tests for various export formats."""

    async def test_export_private_key_der(self, keys_nist256p: dict) -> None:
        """Test exporting private key to DER format."""
        result = await export_private_key(
            {
                "private_key": keys_nist256p["private_key"],
                "curve": "NIST256p",
                "format": "der",
            }
        )
        data = json.loads(result[0].text)
        assert len(data["key"]) > 0

    async def test_export_private_key_base64(self, keys_nist256p: dict) -> None:
        """Test exporting private key to base64 format."""
        result = await export_private_key(
            {
                "private_key": keys_nist256p["private_key"],
                "curve": "NIST256p",
                "format": "base64",
            }
        )
        data = json.loads(result[0].text)
        assert data["key"] == keys_nist256p["private_key"]

    async def test_export_public_key_der(self, keys_nist256p: dict) -> None:
        """Test exporting public key to DER format."""
        result = await export_public_key(
            {
                "public_key": keys_nist256p["public_key"],
                "curve": "NIST256p",
                "format": "der",
            }
        )
        data = json.loads(result[0].text)
        assert len(data["key"]) > 0

    async def test_export_public_key_base64(self, keys_nist256p: dict) -> None:
        """Test exporting public key to base64 format."""
        result = await export_public_key(
            {
                "public_key": keys_nist256p["public_key"],
                "curve": "NIST256p",
                "format": "base64",
            }
        )
        data = json.loads(result[0].text)
        assert data["key"] == keys_nist256p["public_key"]

    async def test_export_public_key_compressed(self, keys_nist256p: dict) -> None:
        """Test exporting public key with compressed encoding."""
        result = await export_public_key(
            {
                "public_key": keys_nist256p["public_key"],
                "curve": "NIST256p",
                "format": "pem",
                "point_encoding": "compressed",
            }
        )
        data = json.loads(result[0].text)
        assert "-----BEGIN PUBLIC KEY-----" in data["key"]


class TestImportFormats:
    """Tests for various import formats."""

    async def test_import_private_key_base64(self) -> None:
        """Test importing private key from base64."""
        key_result = await generate_key({"curve": "NIST256p"})
        key = json.loads(key_result[0].text)

        result = await import_private_key(
            {
                "key_data": key["private_key"],
                "format": "base64",
                "curve": "NIST256p",
            }
        )
        data = json.loads(result[0].text)
        assert data["private_key"] == key["private_key"]

    async def test_import_public_key_base64(self) -> None:
        """Test importing public key from base64."""
        key_result = await generate_key({"curve": "NIST256p"})
        key = json.loads(key_result[0].text)

        result = await import_public_key(
            {
                "key_data": key["public_key"],
                "format": "base64",
                "curve": "NIST256p",
            }
        )
        data = json.loads(result[0].text)
        assert data["public_key"] == key["public_key"]

    async def test_import_public_key_pem(self) -> None:
        """Test importing public key from PEM."""
        key_result = await generate_key({"curve": "NIST256p"})
        key = json.loads(key_result[0].text)

        export_result = await export_public_key(
            {
                "public_key": key["public_key"],
                "curve": "NIST256p",
                "format": "pem",
            }
        )
        pem_key = json.loads(export_result[0].text)["key"]

        result = await import_public_key(
            {
                "key_data": pem_key,
                "format": "pem",
            }
        )
        data = json.loads(result[0].text)
        assert data["public_key"] == key["public_key"]


class TestVerifyDigest:
    """Tests for digest verification edge cases."""

    async def test_verify_digest_invalid(self, keys_nist256p: dict) -> None:
        """Test verification with wrong digest."""
        sign_result = await sign_digest(
            {
                "private_key": keys_nist256p["private_key"],
                "digest": "a" * 64,
            }
        )
        signature = json.loads(sign_result[0].text)["signature"]

        result = await verify_digest_signature(
            {
                "public_key": keys_nist256p["public_key"],
                "signature": signature,
                "digest": "b" * 64,
            }
        )
        data = json.loads(result[0].text)
        assert data["valid"] is False


class TestSignDigestDeterministic:
    """Tests for sign_digest with different options."""

    async def test_sign_digest_non_deterministic(self, keys_nist256p: dict) -> None:
        """Test non-deterministic digest signing."""
        digest = "a" * 64

        result1 = await sign_digest(
            {
                "private_key": keys_nist256p["private_key"],
                "digest": digest,
                "deterministic": False,
            }
        )
        result2 = await sign_digest(
            {
                "private_key": keys_nist256p["private_key"],
                "digest": digest,
                "deterministic": False,
            }
        )
        sig1 = json.loads(result1[0].text)["signature"]
        sig2 = json.loads(result2[0].text)["signature"]
        assert sig1 != sig2


class TestCurves:
    """Tests for various curves."""

    async def test_nist192p(self) -> None:
        """Test NIST192p curve."""
        result = await generate_key({"curve": "NIST192p"})
        data = json.loads(result[0].text)
        assert data["curve"] == "NIST192p"

    async def test_nist224p(self) -> None:
        """Test NIST224p curve."""
        result = await generate_key({"curve": "NIST224p"})
        data = json.loads(result[0].text)
        assert data["curve"] == "NIST224p"

    async def test_nist384p(self) -> None:
        """Test NIST384p curve."""
        result = await generate_key({"curve": "NIST384p"})
        data = json.loads(result[0].text)
        assert data["curve"] == "NIST384p"

    async def test_nist521p(self) -> None:
        """Test NIST521p curve."""
        result = await generate_key({"curve": "NIST521p"})
        data = json.loads(result[0].text)
        assert data["curve"] == "NIST521p"

    async def test_sign_verify_nist384p(self) -> None:
        """Test signing and verification with NIST384p."""
        key_result = await generate_key({"curve": "NIST384p"})
        key = json.loads(key_result[0].text)

        sign_result = await sign_data(
            {
                "private_key": key["private_key"],
                "data": "Test",
                "curve": "NIST384p",
            }
        )
        signature = json.loads(sign_result[0].text)["signature"]

        verify_result = await verify_signature(
            {
                "public_key": key["public_key"],
                "signature": signature,
                "data": "Test",
                "curve": "NIST384p",
            }
        )
        data = json.loads(verify_result[0].text)
        assert data["valid"] is True


class TestHashFunctions:
    """Tests for various hash functions."""

    async def test_sha256(self) -> None:
        """Test with SHA256."""
        key_result = await generate_key({"hashfunc": "sha256"})
        key = json.loads(key_result[0].text)
        result = await sign_data(
            {
                "private_key": key["private_key"],
                "data": "Test",
                "hashfunc": "sha256",
            }
        )
        assert "signature" in json.loads(result[0].text)

    async def test_sha384(self) -> None:
        """Test with SHA384."""
        key_result = await generate_key({"hashfunc": "sha384"})
        key = json.loads(key_result[0].text)
        result = await sign_data(
            {
                "private_key": key["private_key"],
                "data": "Test",
                "hashfunc": "sha384",
            }
        )
        assert "signature" in json.loads(result[0].text)

    async def test_sha512(self) -> None:
        """Test with SHA512."""
        key_result = await generate_key({"hashfunc": "sha512"})
        key = json.loads(key_result[0].text)
        result = await sign_data(
            {
                "private_key": key["private_key"],
                "data": "Test",
                "hashfunc": "sha512",
            }
        )
        assert "signature" in json.loads(result[0].text)


class TestSignatureEncodings:
    """Tests for signature encodings."""

    async def test_sign_der_encoding(self) -> None:
        """Test signing with DER encoding."""
        key_result = await generate_key({"curve": "NIST256p"})
        key = json.loads(key_result[0].text)
        result = await sign_data(
            {
                "private_key": key["private_key"],
                "data": "Test",
                "sigencode": "der",
            }
        )
        data = json.loads(result[0].text)
        assert "signature" in data

    async def test_verify_der_encoding(self) -> None:
        """Test verification with DER encoding."""
        key_result = await generate_key({"curve": "NIST256p"})
        key = json.loads(key_result[0].text)

        sign_result = await sign_data(
            {
                "private_key": key["private_key"],
                "data": "Test",
                "sigencode": "der",
            }
        )
        signature = json.loads(sign_result[0].text)["signature"]

        verify_result = await verify_signature(
            {
                "public_key": key["public_key"],
                "signature": signature,
                "data": "Test",
                "sigdecode": "der",
            }
        )
        data = json.loads(verify_result[0].text)
        assert data["valid"] is True
