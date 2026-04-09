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
    result = generate_key(curve="NIST256p", hashfunc="sha256")
    return json.loads(result)


class TestGenerateKey:
    """Tests for generate_key function."""

    def test_generate_nist256p(self) -> None:
        """Test key generation with NIST256p curve."""
        result = generate_key()
        data = json.loads(result)
        assert "private_key" in data
        assert "public_key" in data
        assert "curve" in data

    def test_generate_with_curve(self) -> None:
        """Test key generation with specific curve."""
        result = generate_key(curve="NIST384p")
        data = json.loads(result)
        assert data["curve"] == "NIST384p"

    def test_generate_secp256k1(self) -> None:
        """Test key generation with SECP256k1 curve."""
        result = generate_key(curve="SECP256k1")
        data = json.loads(result)
        assert data["curve"] == "SECP256k1"


class TestSignData:
    """Tests for sign_data function."""

    def test_sign_data_basic(self, keys_nist256p: dict) -> None:
        """Test basic data signing."""
        result = sign_data(
            private_key=keys_nist256p["private_key"],
            data="Hello, World!",
        )
        data = json.loads(result)
        assert "signature" in data
        assert len(data["signature"]) > 0

    def test_sign_data_empty(self, keys_nist256p: dict) -> None:
        """Test signing empty data."""
        result = sign_data(
            private_key=keys_nist256p["private_key"],
            data="",
        )
        data = json.loads(result)
        assert "signature" in data

    def test_sign_deterministic(self, keys_nist256p: dict) -> None:
        """Test deterministic signing produces same result."""
        result1 = sign_data(
            private_key=keys_nist256p["private_key"],
            data="Test",
            deterministic=True,
        )
        result2 = sign_data(
            private_key=keys_nist256p["private_key"],
            data="Test",
            deterministic=True,
        )
        sig1 = json.loads(result1)["signature"]
        sig2 = json.loads(result2)["signature"]
        assert sig1 == sig2

    def test_sign_non_deterministic(self, keys_nist256p: dict) -> None:
        """Test non-deterministic signing produces different results."""
        result1 = sign_data(
            private_key=keys_nist256p["private_key"],
            data="Test",
            deterministic=False,
        )
        result2 = sign_data(
            private_key=keys_nist256p["private_key"],
            data="Test",
            deterministic=False,
        )
        sig1 = json.loads(result1)["signature"]
        sig2 = json.loads(result2)["signature"]
        assert sig1 != sig2


class TestVerifySignature:
    """Tests for verify_signature function."""

    def test_verify_valid_signature(self, keys_nist256p: dict) -> None:
        """Test verification of valid signature."""
        sign_result = sign_data(
            private_key=keys_nist256p["private_key"],
            data="Hello, World!",
        )
        signature = json.loads(sign_result)["signature"]

        result = verify_signature(
            public_key=keys_nist256p["public_key"],
            signature=signature,
            data="Hello, World!",
        )
        data = json.loads(result)
        assert data["valid"] is True

    def test_verify_invalid_signature(self, keys_nist256p: dict) -> None:
        """Test verification with wrong data."""
        sign_result = sign_data(
            private_key=keys_nist256p["private_key"],
            data="Hello, World!",
        )
        signature = json.loads(sign_result)["signature"]

        result = verify_signature(
            public_key=keys_nist256p["public_key"],
            signature=signature,
            data="Wrong message!",
        )
        data = json.loads(result)
        assert data["valid"] is False

    def test_verify_wrong_key(self) -> None:
        """Test verification with wrong public key."""
        key1_result = generate_key(curve="NIST256p")
        key1 = json.loads(key1_result)
        key2_result = generate_key(curve="NIST256p")
        key2 = json.loads(key2_result)

        sign_result = sign_data(
            private_key=key1["private_key"],
            data="Hello, World!",
        )
        signature = json.loads(sign_result)["signature"]

        result = verify_signature(
            public_key=key2["public_key"],
            signature=signature,
            data="Hello, World!",
        )
        data = json.loads(result)
        assert data["valid"] is False


class TestSignDigest:
    """Tests for sign_digest function."""

    def test_sign_digest_basic(self, keys_nist256p: dict) -> None:
        """Test basic digest signing."""
        digest = "a" * 64  # 32 bytes = 256 bits

        result = sign_digest(
            private_key=keys_nist256p["private_key"],
            digest=digest,
        )
        data = json.loads(result)
        assert "signature" in data


class TestVerifyDigestSignature:
    """Tests for verify_digest_signature function."""

    def test_verify_digest_valid(self, keys_nist256p: dict) -> None:
        """Test verification of valid digest signature."""
        digest = "a" * 64

        sign_result = sign_digest(
            private_key=keys_nist256p["private_key"],
            digest=digest,
        )
        signature = json.loads(sign_result)["signature"]

        result = verify_digest_signature(
            public_key=keys_nist256p["public_key"],
            signature=signature,
            digest=digest,
        )
        data = json.loads(result)
        assert data["valid"] is True


class TestImportExport:
    """Tests for import/export functions."""

    def test_export_private_key_pem(self, keys_nist256p: dict) -> None:
        """Test exporting private key to PEM."""
        result = export_private_key(
            private_key=keys_nist256p["private_key"],
            curve="NIST256p",
            format="pem",
        )
        data = json.loads(result)
        assert "-----BEGIN EC PRIVATE KEY-----" in data["key"]

    def test_export_public_key_pem(self, keys_nist256p: dict) -> None:
        """Test exporting public key to PEM."""
        result = export_public_key(
            public_key=keys_nist256p["public_key"],
            curve="NIST256p",
            format="pem",
        )
        data = json.loads(result)
        assert "-----BEGIN PUBLIC KEY-----" in data["key"]

    def test_import_export_roundtrip(self, keys_nist256p: dict) -> None:
        """Test import/export roundtrip."""
        export_result = export_private_key(
            private_key=keys_nist256p["private_key"],
            curve="NIST256p",
            format="pem",
        )
        pem_key = json.loads(export_result)["key"]

        import_result = import_private_key(
            key_data=pem_key,
            format="pem",
        )
        imported = json.loads(import_result)

        assert imported["private_key"] == keys_nist256p["private_key"]


class TestGetKeyInfo:
    """Tests for get_key_info function."""

    def test_get_key_info_no_key(self) -> None:
        """Test getting key info with no key provided."""
        result = get_key_info(curve="NIST256p")
        data = json.loads(result)
        assert data["curve"] == "NIST256p"

    def test_get_key_info_from_private(self, keys_nist256p: dict) -> None:
        """Test getting key info from private key."""
        result = get_key_info(
            private_key=keys_nist256p["private_key"],
            curve="NIST256p",
        )
        data = json.loads(result)
        assert "private_key" in data
        assert "public_key" in data

    def test_get_key_info_from_public(self, keys_nist256p: dict) -> None:
        """Test getting key info from public key."""
        result = get_key_info(
            public_key=keys_nist256p["public_key"],
            curve="NIST256p",
        )
        data = json.loads(result)
        assert "public_key" in data


class TestRecoverPublicKey:
    """Tests for recover_public_key function."""

    def test_recover_public_key(self, keys_nist256p: dict) -> None:
        """Test public key recovery from signature."""
        sign_result = sign_data(
            private_key=keys_nist256p["private_key"],
            data="Hello, World!",
        )
        signature = json.loads(sign_result)["signature"]

        result = recover_public_key(
            signature=signature,
            data="Hello, World!",
            curve="NIST256p",
        )
        data = json.loads(result)
        assert "keys" in data
        assert len(data["keys"]) > 0


class TestEd25519:
    """Tests for Ed25519 curve."""

    def test_generate_ed25519(self) -> None:
        """Test Ed25519 key generation."""
        result = generate_key(curve="Ed25519")
        data = json.loads(result)
        assert data["curve"] == "Ed25519"

    def test_sign_verify_ed25519(self) -> None:
        """Test signing and verification with Ed25519."""
        key_result = generate_key(curve="Ed25519")
        key = json.loads(key_result)

        sign_result = sign_data(
            private_key=key["private_key"],
            data="Test message",
            curve="Ed25519",
        )
        signature = json.loads(sign_result)["signature"]

        verify_result = verify_signature(
            public_key=key["public_key"],
            signature=signature,
            data="Test message",
            curve="Ed25519",
        )
        data = json.loads(verify_result)
        assert data["valid"] is True


class TestExportFormats:
    """Tests for various export formats."""

    def test_export_private_key_invalid_format(self, keys_nist256p: dict) -> None:
        """Test exporting private key with invalid format."""
        result = export_private_key(
            private_key=keys_nist256p["private_key"],
            curve="NIST256p",
            format="invalid",
        )
        assert "Unknown format" in result

    def test_export_private_key_ssh(self) -> None:
        """Test exporting private key to SSH format."""
        key_result = generate_key(curve="Ed25519")
        key = json.loads(key_result)
        result = export_private_key(
            private_key=key["private_key"],
            curve="Ed25519",
            format="ssh",
        )
        data = json.loads(result)
        assert len(data["key"]) > 0

    def test_export_private_key_der(self, keys_nist256p: dict) -> None:
        """Test exporting private key to DER format."""
        result = export_private_key(
            private_key=keys_nist256p["private_key"],
            curve="NIST256p",
            format="der",
        )
        data = json.loads(result)
        assert len(data["key"]) > 0

    def test_export_private_key_base64(self, keys_nist256p: dict) -> None:
        """Test exporting private key to base64 format."""
        result = export_private_key(
            private_key=keys_nist256p["private_key"],
            curve="NIST256p",
            format="base64",
        )
        data = json.loads(result)
        assert data["key"] == keys_nist256p["private_key"]

    def test_export_public_key_der(self, keys_nist256p: dict) -> None:
        """Test exporting public key to DER format."""
        result = export_public_key(
            public_key=keys_nist256p["public_key"],
            curve="NIST256p",
            format="der",
        )
        data = json.loads(result)
        assert len(data["key"]) > 0

    def test_export_public_key_base64(self, keys_nist256p: dict) -> None:
        """Test exporting public key to base64 format."""
        result = export_public_key(
            public_key=keys_nist256p["public_key"],
            curve="NIST256p",
            format="base64",
        )
        data = json.loads(result)
        assert data["key"] == keys_nist256p["public_key"]

    def test_export_public_key_compressed(self, keys_nist256p: dict) -> None:
        """Test exporting public key with compressed encoding."""
        result = export_public_key(
            public_key=keys_nist256p["public_key"],
            curve="NIST256p",
            format="pem",
            point_encoding="compressed",
        )
        data = json.loads(result)
        assert "-----BEGIN PUBLIC KEY-----" in data["key"]

    def test_export_public_key_invalid_format(self, keys_nist256p: dict) -> None:
        """Test exporting public key with invalid format."""
        result = export_public_key(
            public_key=keys_nist256p["public_key"],
            curve="NIST256p",
            format="invalid",
        )
        assert "Unknown format" in result

    def test_export_public_key_ssh(self) -> None:
        """Test exporting public key to SSH format."""
        key_result = generate_key(curve="Ed25519")
        key = json.loads(key_result)
        result = export_public_key(
            public_key=key["public_key"],
            curve="Ed25519",
            format="ssh",
        )
        data = json.loads(result)
        assert len(data["key"]) > 0


class TestImportPrivateKeyFormats:
    """Tests for import private key format edge cases."""

    def test_import_private_key_der(self) -> None:
        """Test importing private key from DER."""
        import base64

        key_result = generate_key(curve="NIST256p")
        key = json.loads(key_result)

        export_result = export_private_key(
            private_key=key["private_key"],
            curve="NIST256p",
            format="der",
        )
        der_key = json.loads(export_result)["key"]
        der_bytes = base64.b64decode(der_key)

        result = import_private_key(
            key_data=der_bytes,
            format="der",
            curve="NIST256p",
        )
        data = json.loads(result)
        assert data["private_key"] == key["private_key"]

    def test_import_private_key_invalid_format(self) -> None:
        """Test importing private key with invalid format."""
        result = import_private_key(
            key_data="invalid",
            format="invalid_format",
            curve="NIST256p",
        )
        assert "Unknown format" in result

    def test_import_private_key_pem(self) -> None:
        """Test importing private key from PEM."""
        key_result = generate_key(curve="NIST256p")
        key = json.loads(key_result)

        export_result = export_private_key(
            private_key=key["private_key"],
            curve="NIST256p",
            format="pem",
        )
        pem_key = json.loads(export_result)["key"]

        result = import_private_key(
            key_data=pem_key,
            format="pem",
        )
        data = json.loads(result)
        assert data["private_key"] == key["private_key"]


class TestImportFormats:
    """Tests for various import formats."""

    def test_import_private_key_base64(self) -> None:
        """Test importing private key from base64."""
        key_result = generate_key(curve="NIST256p")
        key = json.loads(key_result)

        result = import_private_key(
            key_data=key["private_key"],
            format="base64",
            curve="NIST256p",
        )
        data = json.loads(result)
        assert data["private_key"] == key["private_key"]

    def test_import_public_key_base64(self) -> None:
        """Test importing public key from base64."""
        key_result = generate_key(curve="NIST256p")
        key = json.loads(key_result)

        result = import_public_key(
            key_data=key["public_key"],
            format="base64",
            curve="NIST256p",
        )
        data = json.loads(result)
        assert data["public_key"] == key["public_key"]

    def test_import_public_key_pem(self) -> None:
        """Test importing public key from PEM."""
        key_result = generate_key(curve="NIST256p")
        key = json.loads(key_result)

        export_result = export_public_key(
            public_key=key["public_key"],
            curve="NIST256p",
            format="pem",
        )
        pem_key = json.loads(export_result)["key"]

        result = import_public_key(
            key_data=pem_key,
            format="pem",
        )
        data = json.loads(result)
        assert data["public_key"] == key["public_key"]

    def test_import_public_key_der(self) -> None:
        """Test importing public key from DER."""
        import base64

        key_result = generate_key(curve="NIST256p")
        key = json.loads(key_result)

        export_result = export_public_key(
            public_key=key["public_key"],
            curve="NIST256p",
            format="der",
        )
        der_key = json.loads(export_result)["key"]
        der_bytes = base64.b64decode(der_key)

        result = import_public_key(
            key_data=der_bytes,
            format="der",
            curve="NIST256p",
        )
        data = json.loads(result)
        assert data["public_key"] == key["public_key"]

    def test_import_public_key_invalid_format(self) -> None:
        """Test importing public key with invalid format."""
        result = import_public_key(
            key_data="invalid",
            format="invalid_format",
            curve="NIST256p",
        )
        assert "Unknown format" in result


class TestVerifyDigest:
    """Tests for digest verification edge cases."""

    def test_verify_digest_invalid(self, keys_nist256p: dict) -> None:
        """Test verification with wrong digest."""
        sign_result = sign_digest(
            private_key=keys_nist256p["private_key"],
            digest="a" * 64,
        )
        signature = json.loads(sign_result)["signature"]

        result = verify_digest_signature(
            public_key=keys_nist256p["public_key"],
            signature=signature,
            digest="b" * 64,
        )
        data = json.loads(result)
        assert data["valid"] is False


class TestSignDigestDeterministic:
    """Tests for sign_digest with different options."""

    def test_sign_digest_non_deterministic(self, keys_nist256p: dict) -> None:
        """Test non-deterministic digest signing."""
        digest = "a" * 64

        result1 = sign_digest(
            private_key=keys_nist256p["private_key"],
            digest=digest,
            deterministic=False,
        )
        result2 = sign_digest(
            private_key=keys_nist256p["private_key"],
            digest=digest,
            deterministic=False,
        )
        sig1 = json.loads(result1)["signature"]
        sig2 = json.loads(result2)["signature"]
        assert sig1 != sig2


class TestCurves:
    """Tests for various curves."""

    def test_nist192p(self) -> None:
        """Test NIST192p curve."""
        result = generate_key(curve="NIST192p")
        data = json.loads(result)
        assert data["curve"] == "NIST192p"

    def test_nist224p(self) -> None:
        """Test NIST224p curve."""
        result = generate_key(curve="NIST224p")
        data = json.loads(result)
        assert data["curve"] == "NIST224p"

    def test_nist384p(self) -> None:
        """Test NIST384p curve."""
        result = generate_key(curve="NIST384p")
        data = json.loads(result)
        assert data["curve"] == "NIST384p"

    def test_nist521p(self) -> None:
        """Test NIST521p curve."""
        result = generate_key(curve="NIST521p")
        data = json.loads(result)
        assert data["curve"] == "NIST521p"

    def test_sign_verify_nist384p(self) -> None:
        """Test signing and verification with NIST384p."""
        key_result = generate_key(curve="NIST384p")
        key = json.loads(key_result)

        sign_result = sign_data(
            private_key=key["private_key"],
            data="Test",
            curve="NIST384p",
        )
        signature = json.loads(sign_result)["signature"]

        verify_result = verify_signature(
            public_key=key["public_key"],
            signature=signature,
            data="Test",
            curve="NIST384p",
        )
        data = json.loads(verify_result)
        assert data["valid"] is True

    def test_generate_ed448(self) -> None:
        """Test Ed448 key generation."""
        result = generate_key(curve="Ed448")
        data = json.loads(result)
        assert data["curve"] == "Ed448"


class TestHashFunctions:
    """Tests for various hash functions."""

    def test_sha256(self) -> None:
        """Test with SHA256."""
        key_result = generate_key(hashfunc="sha256")
        key = json.loads(key_result)
        result = sign_data(
            private_key=key["private_key"],
            data="Test",
            hashfunc="sha256",
        )
        assert "signature" in json.loads(result)

    def test_sha384(self) -> None:
        """Test with SHA384."""
        key_result = generate_key(hashfunc="sha384")
        key = json.loads(key_result)
        result = sign_data(
            private_key=key["private_key"],
            data="Test",
            hashfunc="sha384",
        )
        assert "signature" in json.loads(result)

    def test_sha512(self) -> None:
        """Test with SHA512."""
        key_result = generate_key(hashfunc="sha512")
        key = json.loads(key_result)
        result = sign_data(
            private_key=key["private_key"],
            data="Test",
            hashfunc="sha512",
        )
        assert "signature" in json.loads(result)


class TestListTools:
    """Tests for list_tools function."""

    def test_list_tools(self) -> None:
        """Test listing all available tools."""
        from mcp_ecdsa.server import app

        async def run_test() -> list:
            tools = await app.list_tools()
            return tools

        tools = asyncio.run(run_test())
        assert len(tools) == 11
        tool_names = [t.name for t in tools]
        assert "_generate_key" in tool_names
        assert "_sign_data" in tool_names
        assert "_sign_digest" in tool_names
        assert "_verify_signature" in tool_names
        assert "_verify_digest_signature" in tool_names
        assert "_import_private_key" in tool_names
        assert "_import_public_key" in tool_names
        assert "_export_private_key" in tool_names
        assert "_export_public_key" in tool_names
        assert "_get_key_info" in tool_names
        assert "_recover_public_key" in tool_names


class TestCallTool:
    """Tests for call_tool function."""

    def test_call_tool_unknown(self) -> None:
        """Test calling unknown tool."""
        from mcp_ecdsa.server import app

        async def run_test() -> str | None:
            try:
                await app.call_tool("unknown_tool", {})
            except Exception as e:
                return str(e)
            return None

        result = asyncio.run(run_test())
        assert result is not None and "unknown_tool" in result.lower()


class TestSignatureEncodings:
    """Tests for signature encodings."""

    def test_sign_der_encoding(self) -> None:
        """Test signing with DER encoding."""
        key_result = generate_key(curve="NIST256p")
        key = json.loads(key_result)
        result = sign_data(
            private_key=key["private_key"],
            data="Test",
            sigencode="der",
        )
        data = json.loads(result)
        assert "signature" in data

    def test_verify_der_encoding(self) -> None:
        """Test verification with DER encoding."""
        key_result = generate_key(curve="NIST256p")
        key = json.loads(key_result)

        sign_result = sign_data(
            private_key=key["private_key"],
            data="Test",
            sigencode="der",
        )
        signature = json.loads(sign_result)["signature"]

        verify_result = verify_signature(
            public_key=key["public_key"],
            signature=signature,
            data="Test",
            sigdecode="der",
        )
        data = json.loads(verify_result)
        assert data["valid"] is True
