import asyncio
import base64
import hashlib
import json
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
from ecdsa.util import sigdecode_der, sigdecode_string, sigencode_der, sigencode_string
from mcp.server.fastmcp import FastMCP
from mcp.types import TextContent

app = FastMCP("mcp-ecdsa")

CURVES = {
    "NIST192p": NIST192p,
    "NIST224p": NIST224p,
    "NIST256p": NIST256p,
    "NIST384p": NIST384p,
    "NIST521p": NIST521p,
    "SECP256k1": SECP256k1,
    "Ed25519": Ed25519,
    "Ed448": Ed448,
}

HASH_FUNCTIONS = {
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
    "sha3_384": hashlib.sha3_384,
    "sha3_512": hashlib.sha3_512,
}


def get_curve(curve_name: str) -> Any:
    return CURVES.get(curve_name, NIST256p)


def get_hash_func(hash_name: str) -> Any:
    return HASH_FUNCTIONS.get(hash_name, hashlib.sha256)


@app.tool()
def generate_key(
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
) -> str:
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


async def generate_key_async(
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
) -> list[TextContent]:
    result = generate_key(curve=curve, hashfunc=hashfunc)
    return [TextContent(type="text", text=result)]


async def sign_data_async(
    private_key: str,
    data: str,
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
    sigencode: str = "string",
    deterministic: bool = True,
) -> list[TextContent]:
    result = sign_data(
        private_key=private_key,
        data=data,
        curve=curve,
        hashfunc=hashfunc,
        sigencode=sigencode,
        deterministic=deterministic,
    )
    return [TextContent(type="text", text=result)]


async def sign_digest_async(
    private_key: str,
    digest: str,
    curve: str = "NIST256p",
    sigencode: str = "string",
    deterministic: bool = True,
) -> list[TextContent]:
    result = sign_digest(
        private_key=private_key,
        digest=digest,
        curve=curve,
        sigencode=sigencode,
        deterministic=deterministic,
    )
    return [TextContent(type="text", text=result)]


async def verify_signature_async(
    public_key: str,
    signature: str,
    data: str,
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
    sigdecode: str = "string",
) -> list[TextContent]:
    result = verify_signature(
        public_key=public_key,
        signature=signature,
        data=data,
        curve=curve,
        hashfunc=hashfunc,
        sigdecode=sigdecode,
    )
    return [TextContent(type="text", text=result)]


async def verify_digest_signature_async(
    public_key: str,
    signature: str,
    digest: str,
    curve: str = "NIST256p",
    sigdecode: str = "string",
) -> list[TextContent]:
    result = verify_digest_signature(
        public_key=public_key,
        signature=signature,
        digest=digest,
        curve=curve,
        sigdecode=sigdecode,
    )
    return [TextContent(type="text", text=result)]


async def import_private_key_async(
    key_data: str,
    format: str,
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
) -> list[TextContent]:
    result = import_private_key(
        key_data=key_data,
        format=format,
        curve=curve,
        hashfunc=hashfunc,
    )
    return [TextContent(type="text", text=result)]


async def import_public_key_async(
    key_data: str,
    format: str,
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
) -> list[TextContent]:
    result = import_public_key(
        key_data=key_data,
        format=format,
        curve=curve,
        hashfunc=hashfunc,
    )
    return [TextContent(type="text", text=result)]


async def export_private_key_async(
    private_key: str,
    curve: str = "NIST256p",
    format: str = "pem",
    pem_format: str = "ssleay",
) -> list[TextContent]:
    result = export_private_key(
        private_key=private_key,
        curve=curve,
        format=format,
        pem_format=pem_format,
    )
    return [TextContent(type="text", text=result)]


async def export_public_key_async(
    public_key: str,
    curve: str = "NIST256p",
    format: str = "pem",
    point_encoding: str = "uncompressed",
) -> list[TextContent]:
    result = export_public_key(
        public_key=public_key,
        curve=curve,
        format=format,
        point_encoding=point_encoding,
    )
    return [TextContent(type="text", text=result)]


async def get_key_info_async(
    private_key: str | None = None,
    public_key: str | None = None,
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
) -> list[TextContent]:
    result = get_key_info(
        private_key=private_key,
        public_key=public_key,
        curve=curve,
        hashfunc=hashfunc,
    )
    return [TextContent(type="text", text=result)]


async def recover_public_key_async(
    signature: str,
    data: str,
    curve: str = "NIST256p",
    hashfunc: str = "sha256",
) -> list[TextContent]:
    result = recover_public_key(
        signature=signature,
        data=data,
        curve=curve,
        hashfunc=hashfunc,
    )
    return [TextContent(type="text", text=result)]


def main():
    app.run()


if __name__ == "__main__":
    main()
