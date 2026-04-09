import base64
import hashlib
import json
from collections.abc import Callable
from typing import Any

from ecdsa import (
    Ed448,
    Ed25519,
    NIST192p,
    NIST224p,
    NIST256p,
    NIST384p,
    NIST521p,
    SECP256k1,
    SigningKey,
    VerifyingKey,
)
from ecdsa.curves import Curve
from ecdsa.util import sigdecode_der, sigdecode_string, sigencode_der, sigencode_string
from mcp.server.fastmcp import FastMCP
from mcp.types import TextContent

app = FastMCP("mcp-ecdsa")

CURVES: dict[str, Curve] = {
    "NIST192p": NIST192p,
    "NIST224p": NIST224p,
    "NIST256p": NIST256p,
    "NIST384p": NIST384p,
    "NIST521p": NIST521p,
    "SECP256k1": SECP256k1,
    "Ed25519": Ed25519,
    "Ed448": Ed448,
}

HASH_FUNCTIONS: dict[str, Callable[[], Any]] = {
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
    "sha3_384": hashlib.sha3_384,
    "sha3_512": hashlib.sha3_512,
}


def get_curve(curve_name: str) -> Curve:
    return CURVES.get(curve_name, NIST256p)


def get_hash_func(hash_name: str) -> Callable[[], Any]:
    return HASH_FUNCTIONS.get(hash_name, hashlib.sha256)


def generate_key(curve: str = "NIST256p", hashfunc: str = "sha256") -> str:
    """Generate a new ECDSA key pair"""
    curve_obj = get_curve(curve)
    hashfunc_obj = get_hash_func(hashfunc)

    sk = SigningKey.generate(curve=curve_obj, hashfunc=hashfunc_obj)
    vk = sk.get_verifying_key()

    return json.dumps(
        {
            "private_key": base64.b64encode(sk.to_string()).decode("utf-8"),
            "public_key": base64.b64encode(vk.to_string()).decode("utf-8"),
            "curve": curve,
        }
    )


@app.tool()
def _generate_key(
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
) -> str:
    """Generate a new ECDSA key pair"""
    return generate_key(curve, hashfunc)


def sign_data(
    private_key: str,
    data: str,
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
    sigencode: str = "string",
    deterministic: bool = True,
) -> str:
    """Sign data using ECDSA"""
    curve_obj = get_curve(curve)
    hashfunc_obj = get_hash_func(hashfunc)
    sigencode_func = sigencode_der if sigencode == "der" else sigencode_string

    private_key_bytes = base64.b64decode(private_key)
    sk = SigningKey.from_string(
        private_key_bytes, curve=curve_obj, hashfunc=hashfunc_obj
    )

    if deterministic:
        signature = sk.sign_deterministic(
            data.encode("utf-8"), hashfunc=hashfunc_obj, sigencode=sigencode_func
        )
    else:
        signature = sk.sign(
            data.encode("utf-8"), hashfunc=hashfunc_obj, sigencode=sigencode_func
        )

    return json.dumps(
        {
            "signature": base64.b64encode(signature).decode("utf-8"),
        }
    )


@app.tool()
def _sign_data(
    private_key: str,
    data: str,
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
    sigencode: str = "string",
    deterministic: bool = True,
) -> str:
    """Sign data using ECDSA"""
    return sign_data(private_key, data, curve, hashfunc, sigencode, deterministic)


def sign_digest(
    private_key: str,
    digest: str,
    curve: str = "NIST256p",
    sigencode: str = "string",
    deterministic: bool = True,
) -> str:
    """Sign a digest directly using ECDSA (no hashing)"""
    curve_obj = get_curve(curve)
    sigencode_func = sigencode_der if sigencode == "der" else sigencode_string

    private_key_bytes = base64.b64decode(private_key)
    digest_bytes = bytes.fromhex(digest)
    sk = SigningKey.from_string(private_key_bytes, curve=curve_obj)

    if deterministic:
        signature = sk.sign_digest_deterministic(digest_bytes, sigencode=sigencode_func)
    else:
        signature = sk.sign_digest(digest_bytes, sigencode=sigencode_func)

    return json.dumps(
        {
            "signature": base64.b64encode(signature).decode("utf-8"),
        }
    )


@app.tool()
def _sign_digest(
    private_key: str,
    digest: str,
    curve: str = "NIST256p",
    sigencode: str = "string",
    deterministic: bool = True,
) -> str:
    """Sign a digest directly using ECDSA (no hashing)"""
    return sign_digest(private_key, digest, curve, sigencode, deterministic)


def verify_signature(
    public_key: str,
    signature: str,
    data: str,
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
    sigdecode: str = "string",
) -> str:
    """Verify an ECDSA signature"""
    curve_obj = get_curve(curve)
    hashfunc_obj = get_hash_func(hashfunc)
    sigdecode_func = sigdecode_der if sigdecode == "der" else sigdecode_string

    public_key_bytes = base64.b64decode(public_key)
    signature_bytes = base64.b64decode(signature)

    vk = VerifyingKey.from_string(
        public_key_bytes, curve=curve_obj, hashfunc=hashfunc_obj
    )

    try:
        vk.verify(
            signature_bytes,
            data.encode("utf-8"),
            hashfunc=hashfunc_obj,
            sigdecode=sigdecode_func,
        )
        result = {"valid": True}
    except Exception:
        result = {"valid": False}

    return json.dumps(result)


@app.tool()
def _verify_signature(
    public_key: str,
    signature: str,
    data: str,
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
    sigdecode: str = "string",
) -> str:
    """Verify an ECDSA signature"""
    return verify_signature(public_key, signature, data, curve, hashfunc, sigdecode)


def verify_digest_signature(
    public_key: str,
    signature: str,
    digest: str,
    curve: str = "NIST256p",
    sigdecode: str = "string",
) -> str:
    """Verify a signature over a digest"""
    curve_obj = get_curve(curve)
    sigdecode_func = sigdecode_der if sigdecode == "der" else sigdecode_string

    public_key_bytes = base64.b64decode(public_key)
    signature_bytes = base64.b64decode(signature)
    digest_bytes = bytes.fromhex(digest)

    vk = VerifyingKey.from_string(public_key_bytes, curve=curve_obj)

    try:
        vk.verify_digest(signature_bytes, digest_bytes, sigdecode=sigdecode_func)
        result = {"valid": True}
    except Exception:
        result = {"valid": False}

    return json.dumps(result)


@app.tool()
def _verify_digest_signature(
    public_key: str,
    signature: str,
    digest: str,
    curve: str = "NIST256p",
    sigdecode: str = "string",
) -> str:
    """Verify a signature over a digest"""
    return verify_digest_signature(public_key, signature, digest, curve, sigdecode)


def import_private_key(
    key_data: str,
    format: str,
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
) -> str:
    """Import a private key from various formats"""
    curve_obj = get_curve(curve)
    hashfunc_obj = get_hash_func(hashfunc)

    if format == "pem":
        sk = SigningKey.from_pem(key_data, hashfunc=hashfunc_obj)
    elif format == "der":
        sk = SigningKey.from_der(key_data, hashfunc=hashfunc_obj)
    elif format == "base64":
        sk = SigningKey.from_string(
            base64.b64decode(key_data), curve=curve_obj, hashfunc=hashfunc_obj
        )
    else:
        return json.dumps({"error": f"Unknown format: {format}"})

    vk = sk.get_verifying_key()
    actual_curve = sk.curve.name

    return json.dumps(
        {
            "private_key": base64.b64encode(sk.to_string()).decode("utf-8"),
            "public_key": base64.b64encode(vk.to_string()).decode("utf-8"),
            "curve": actual_curve,
        }
    )


@app.tool()
def _import_private_key(
    key_data: str,
    format: str,
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
) -> str:
    """Import a private key from various formats"""
    return import_private_key(key_data, format, curve, hashfunc)


def import_public_key(
    key_data: str,
    format: str,
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
) -> str:
    """Import a public key from various formats"""
    curve_obj = get_curve(curve)
    hashfunc_obj = get_hash_func(hashfunc)

    if format == "pem":
        vk = VerifyingKey.from_pem(key_data, hashfunc=hashfunc_obj)
    elif format == "der":
        vk = VerifyingKey.from_der(key_data, hashfunc=hashfunc_obj)
    elif format == "base64":
        vk = VerifyingKey.from_string(
            base64.b64decode(key_data), curve=curve_obj, hashfunc=hashfunc_obj
        )
    else:
        return json.dumps({"error": f"Unknown format: {format}"})

    actual_curve = vk.curve.name

    return json.dumps(
        {
            "public_key": base64.b64encode(vk.to_string()).decode("utf-8"),
            "curve": actual_curve,
        }
    )


@app.tool()
def _import_public_key(
    key_data: str,
    format: str,
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
) -> str:
    """Import a public key from various formats"""
    return import_public_key(key_data, format, curve, hashfunc)


def export_private_key(
    private_key: str,
    curve: str = "NIST256p",
    format: str = "pem",
    pem_format: str = "ssleay",
) -> str:
    """Export a private key to various formats"""
    curve_obj = get_curve(curve)

    private_key_bytes = base64.b64decode(private_key)
    sk = SigningKey.from_string(private_key_bytes, curve=curve_obj)

    if format == "pem":
        output = sk.to_pem(format=pem_format).decode("utf-8")
    elif format == "der":
        output = base64.b64encode(sk.to_der(format=pem_format)).decode("utf-8")
    elif format == "base64":
        output = base64.b64encode(sk.to_string()).decode("utf-8")
    elif format == "ssh":
        output = base64.b64encode(sk.to_ssh()).decode("utf-8")
    else:
        return json.dumps({"error": f"Unknown format: {format}"})

    return json.dumps({"key": output})


@app.tool()
def _export_private_key(
    private_key: str,
    curve: str = "NIST256p",
    format: str = "pem",
    pem_format: str = "ssleay",
) -> str:
    """Export a private key to various formats"""
    return export_private_key(private_key, curve, format, pem_format)


def export_public_key(
    public_key: str,
    curve: str = "NIST256p",
    format: str = "pem",
    point_encoding: str = "uncompressed",
) -> str:
    """Export a public key to various formats"""
    curve_obj = get_curve(curve)

    public_key_bytes = base64.b64decode(public_key)
    vk = VerifyingKey.from_string(public_key_bytes, curve=curve_obj)

    if format == "pem":
        output = vk.to_pem(point_encoding=point_encoding).decode("utf-8")
    elif format == "der":
        output = base64.b64encode(vk.to_der(point_encoding=point_encoding)).decode(
            "utf-8"
        )
    elif format == "base64":
        output = base64.b64encode(vk.to_string()).decode("utf-8")
    elif format == "ssh":
        output = base64.b64encode(vk.to_ssh()).decode("utf-8")
    else:
        return json.dumps({"error": f"Unknown format: {format}"})

    return json.dumps({"key": output})


@app.tool()
def _export_public_key(
    public_key: str,
    curve: str = "NIST256p",
    format: str = "pem",
    point_encoding: str = "uncompressed",
) -> str:
    """Export a public key to various formats"""
    return export_public_key(public_key, curve, format, point_encoding)


def get_key_info(
    private_key: str | None = None,
    public_key: str | None = None,
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
) -> str:
    """Get information about a key"""
    curve_obj = get_curve(curve)
    hashfunc_obj = get_hash_func(hashfunc)

    if private_key:
        private_key_bytes = base64.b64decode(private_key)
        sk = SigningKey.from_string(
            private_key_bytes, curve=curve_obj, hashfunc=hashfunc_obj
        )
        vk = sk.get_verifying_key()
        result = {
            "curve": sk.curve.name,
            "private_key": base64.b64encode(sk.to_string()).decode("utf-8"),
            "public_key": base64.b64encode(vk.to_string()).decode("utf-8"),
        }
    elif public_key:
        public_key_bytes = base64.b64decode(public_key)
        vk = VerifyingKey.from_string(
            public_key_bytes, curve=curve_obj, hashfunc=hashfunc_obj
        )
        result = {
            "curve": vk.curve.name,
            "public_key": base64.b64encode(vk.to_string()).decode("utf-8"),
        }
    else:
        result = {"curve": curve}

    return json.dumps(result)


@app.tool()
def _get_key_info(
    private_key: str | None = None,
    public_key: str | None = None,
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
) -> str:
    """Get information about a key"""
    return get_key_info(private_key, public_key, curve, hashfunc)


def recover_public_key(
    signature: str,
    data: str,
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
) -> str:
    """Recover public keys from a signature and signed data"""
    curve_obj = get_curve(curve)
    hashfunc_obj = get_hash_func(hashfunc)

    signature_bytes = base64.b64decode(signature)

    recovered_keys = VerifyingKey.from_public_key_recovery(
        signature_bytes, data.encode("utf-8"), curve_obj, hashfunc=hashfunc_obj
    )

    result = {
        "keys": [
            base64.b64encode(vk.to_string()).decode("utf-8") for vk in recovered_keys
        ]
    }

    return json.dumps(result)


@app.tool()
def _recover_public_key(
    signature: str,
    data: str,
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
) -> str:
    """Recover public keys from a signature and signed data"""
    return recover_public_key(signature, data, curve, hashfunc)


def main() -> None:
    app.run()


async def generate_key_wrapper(
    arguments: dict[str, Any],
) -> list[TextContent]:
    """Backward-compatible async wrapper for tests."""
    result = _generate_key(
        curve=arguments.get("curve", "NIST256p"),
        hashfunc=arguments.get("hashfunc", "sha256"),
    )
    return [TextContent(type="text", text=result)]


async def sign_data_wrapper(arguments: dict[str, Any]) -> list[TextContent]:
    """Backward-compatible async wrapper for tests."""
    result = _sign_data(
        private_key=arguments["private_key"],
        data=arguments["data"],
        curve=arguments.get("curve", "NIST256p"),
        hashfunc=arguments.get("hashfunc", "sha256"),
        sigencode=arguments.get("sigencode", "string"),
        deterministic=arguments.get("deterministic", True),
    )
    return [TextContent(type="text", text=result)]


async def sign_digest_wrapper(arguments: dict[str, Any]) -> list[TextContent]:
    """Backward-compatible async wrapper for tests."""
    result = _sign_digest(
        private_key=arguments["private_key"],
        digest=arguments["digest"],
        curve=arguments.get("curve", "NIST256p"),
        sigencode=arguments.get("sigencode", "string"),
        deterministic=arguments.get("deterministic", True),
    )
    return [TextContent(type="text", text=result)]


async def verify_signature_wrapper(arguments: dict[str, Any]) -> list[TextContent]:
    """Backward-compatible async wrapper for tests."""
    result = _verify_signature(
        public_key=arguments["public_key"],
        signature=arguments["signature"],
        data=arguments["data"],
        curve=arguments.get("curve", "NIST256p"),
        hashfunc=arguments.get("hashfunc", "sha256"),
        sigdecode=arguments.get("sigdecode", "string"),
    )
    return [TextContent(type="text", text=result)]


async def verify_digest_signature_wrapper(
    arguments: dict[str, Any],
) -> list[TextContent]:
    """Backward-compatible async wrapper for tests."""
    result = _verify_digest_signature(
        public_key=arguments["public_key"],
        signature=arguments["signature"],
        digest=arguments["digest"],
        curve=arguments.get("curve", "NIST256p"),
        sigdecode=arguments.get("sigdecode", "string"),
    )
    return [TextContent(type="text", text=result)]


async def import_private_key_wrapper(arguments: dict[str, Any]) -> list[TextContent]:
    """Backward-compatible async wrapper for tests."""
    result = _import_private_key(
        key_data=arguments["key_data"],
        format=arguments["format"],
        curve=arguments.get("curve", "NIST256p"),
        hashfunc=arguments.get("hashfunc", "sha256"),
    )
    return [TextContent(type="text", text=result)]


async def import_public_key_wrapper(arguments: dict[str, Any]) -> list[TextContent]:
    """Backward-compatible async wrapper for tests."""
    result = _import_public_key(
        key_data=arguments["key_data"],
        format=arguments["format"],
        curve=arguments.get("curve", "NIST256p"),
        hashfunc=arguments.get("hashfunc", "sha256"),
    )
    return [TextContent(type="text", text=result)]


async def export_private_key_wrapper(arguments: dict[str, Any]) -> list[TextContent]:
    """Backward-compatible async wrapper for tests."""
    result = _export_private_key(
        private_key=arguments["private_key"],
        curve=arguments.get("curve", "NIST256p"),
        format=arguments.get("format", "pem"),
        pem_format=arguments.get("pem_format", "ssleay"),
    )
    return [TextContent(type="text", text=result)]


async def export_public_key_wrapper(arguments: dict[str, Any]) -> list[TextContent]:
    """Backward-compatible async wrapper for tests."""
    result = _export_public_key(
        public_key=arguments["public_key"],
        curve=arguments.get("curve", "NIST256p"),
        format=arguments.get("format", "pem"),
        point_encoding=arguments.get("point_encoding", "uncompressed"),
    )
    return [TextContent(type="text", text=result)]


async def get_key_info_wrapper(arguments: dict[str, Any]) -> list[TextContent]:
    """Backward-compatible async wrapper for tests."""
    result = _get_key_info(
        private_key=arguments.get("private_key"),
        public_key=arguments.get("public_key"),
        curve=arguments.get("curve", "NIST256p"),
        hashfunc=arguments.get("hashfunc", "sha256"),
    )
    return [TextContent(type="text", text=result)]


async def recover_public_key_wrapper(arguments: dict[str, Any]) -> list[TextContent]:
    """Backward-compatible async wrapper for tests."""
    result = _recover_public_key(
        signature=arguments["signature"],
        data=arguments["data"],
        curve=arguments.get("curve", "NIST256p"),
        hashfunc=arguments.get("hashfunc", "sha256"),
    )
    return [TextContent(type="text", text=result)]


if __name__ == "__main__":
    main()
