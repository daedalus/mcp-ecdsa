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
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

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

app = Server("mcp-ecdsa")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="generate_key",
            description="Generate a new ECDSA key pair",
            inputSchema={
                "type": "object",
                "properties": {
                    "curve": {
                        "type": "string",
                        "enum": list(CURVES.keys()),
                        "description": "The elliptic curve to use",
                        "default": "NIST256p",
                    },
                    "hashfunc": {
                        "type": "string",
                        "enum": list(HASH_FUNCTIONS.keys()),
                        "description": "Default hash function for signing/verification",
                        "default": "sha256",
                    },
                },
            },
        ),
        Tool(
            name="sign_data",
            description="Sign data using ECDSA",
            inputSchema={
                "type": "object",
                "properties": {
                    "private_key": {
                        "type": "string",
                        "description": "Base64-encoded private key (raw format)",
                    },
                    "data": {
                        "type": "string",
                        "description": "Data to sign (will be hashed)",
                    },
                    "curve": {
                        "type": "string",
                        "enum": list(CURVES.keys()),
                        "description": "Curve used for the key",
                        "default": "NIST256p",
                    },
                    "hashfunc": {
                        "type": "string",
                        "enum": list(HASH_FUNCTIONS.keys()),
                        "description": "Hash function to use",
                        "default": "sha256",
                    },
                    "sigencode": {
                        "type": "string",
                        "enum": ["string", "der"],
                        "description": "Signature encoding format",
                        "default": "string",
                    },
                    "deterministic": {
                        "type": "boolean",
                        "description": "Use deterministic RFC6979 signing",
                        "default": True,
                    },
                },
                "required": ["private_key", "data"],
            },
        ),
        Tool(
            name="sign_digest",
            description="Sign a digest directly using ECDSA (no hashing)",
            inputSchema={
                "type": "object",
                "properties": {
                    "private_key": {
                        "type": "string",
                        "description": "Base64-encoded private key (raw format)",
                    },
                    "digest": {
                        "type": "string",
                        "description": "Hex-encoded digest to sign",
                    },
                    "curve": {
                        "type": "string",
                        "enum": list(CURVES.keys()),
                        "description": "Curve used for the key",
                        "default": "NIST256p",
                    },
                    "sigencode": {
                        "type": "string",
                        "enum": ["string", "der"],
                        "description": "Signature encoding format",
                        "default": "string",
                    },
                    "deterministic": {
                        "type": "boolean",
                        "description": "Use deterministic RFC6979 signing",
                        "default": True,
                    },
                },
                "required": ["private_key", "digest"],
            },
        ),
        Tool(
            name="verify_signature",
            description="Verify an ECDSA signature",
            inputSchema={
                "type": "object",
                "properties": {
                    "public_key": {
                        "type": "string",
                        "description": "Base64-encoded public key (raw format)",
                    },
                    "signature": {
                        "type": "string",
                        "description": "Base64-encoded signature",
                    },
                    "data": {
                        "type": "string",
                        "description": "Original data that was signed (will be hashed)",
                    },
                    "curve": {
                        "type": "string",
                        "enum": list(CURVES.keys()),
                        "description": "Curve used for the key",
                        "default": "NIST256p",
                    },
                    "hashfunc": {
                        "type": "string",
                        "enum": list(HASH_FUNCTIONS.keys()),
                        "description": "Hash function used",
                        "default": "sha256",
                    },
                    "sigdecode": {
                        "type": "string",
                        "enum": ["string", "der"],
                        "description": "Signature encoding format",
                        "default": "string",
                    },
                },
                "required": ["public_key", "signature", "data"],
            },
        ),
        Tool(
            name="verify_digest_signature",
            description="Verify a signature over a digest",
            inputSchema={
                "type": "object",
                "properties": {
                    "public_key": {
                        "type": "string",
                        "description": "Base64-encoded public key (raw format)",
                    },
                    "signature": {
                        "type": "string",
                        "description": "Base64-encoded signature",
                    },
                    "digest": {
                        "type": "string",
                        "description": "Hex-encoded digest",
                    },
                    "curve": {
                        "type": "string",
                        "enum": list(CURVES.keys()),
                        "description": "Curve used for the key",
                        "default": "NIST256p",
                    },
                    "sigdecode": {
                        "type": "string",
                        "enum": ["string", "der"],
                        "description": "Signature encoding format",
                        "default": "string",
                    },
                },
                "required": ["public_key", "signature", "digest"],
            },
        ),
        Tool(
            name="import_private_key",
            description="Import a private key from various formats",
            inputSchema={
                "type": "object",
                "properties": {
                    "key_data": {
                        "type": "string",
                        "description": "Private key in PEM, DER, or base64 raw format",
                    },
                    "format": {
                        "type": "string",
                        "enum": ["pem", "der", "base64"],
                        "description": "Format of the key",
                    },
                    "curve": {
                        "type": "string",
                        "enum": list(CURVES.keys()),
                        "description": "Curve (required for raw/base64 format)",
                    },
                    "hashfunc": {
                        "type": "string",
                        "enum": list(HASH_FUNCTIONS.keys()),
                        "description": "Default hash function",
                        "default": "sha256",
                    },
                },
                "required": ["key_data", "format"],
            },
        ),
        Tool(
            name="import_public_key",
            description="Import a public key from various formats",
            inputSchema={
                "type": "object",
                "properties": {
                    "key_data": {
                        "type": "string",
                        "description": "Public key in PEM, DER, or base64 raw format",
                    },
                    "format": {
                        "type": "string",
                        "enum": ["pem", "der", "base64"],
                        "description": "Format of the key",
                    },
                    "curve": {
                        "type": "string",
                        "enum": list(CURVES.keys()),
                        "description": "Curve (required for raw/base64 format)",
                    },
                    "hashfunc": {
                        "type": "string",
                        "enum": list(HASH_FUNCTIONS.keys()),
                        "description": "Default hash function",
                        "default": "sha256",
                    },
                },
                "required": ["key_data", "format"],
            },
        ),
        Tool(
            name="export_private_key",
            description="Export a private key to various formats",
            inputSchema={
                "type": "object",
                "properties": {
                    "private_key": {
                        "type": "string",
                        "description": "Base64-encoded private key (raw format)",
                    },
                    "curve": {
                        "type": "string",
                        "enum": list(CURVES.keys()),
                        "description": "Curve used for the key",
                        "default": "NIST256p",
                    },
                    "format": {
                        "type": "string",
                        "enum": ["pem", "der", "base64", "ssh"],
                        "description": "Export format",
                        "default": "pem",
                    },
                    "pem_format": {
                        "type": "string",
                        "enum": ["ssleay", "pkcs8"],
                        "description": "PEM format variant (for PEM format)",
                        "default": "ssleay",
                    },
                },
                "required": ["private_key", "curve"],
            },
        ),
        Tool(
            name="export_public_key",
            description="Export a public key to various formats",
            inputSchema={
                "type": "object",
                "properties": {
                    "public_key": {
                        "type": "string",
                        "description": "Base64-encoded public key (raw format)",
                    },
                    "curve": {
                        "type": "string",
                        "enum": list(CURVES.keys()),
                        "description": "Curve used for the key",
                        "default": "NIST256p",
                    },
                    "format": {
                        "type": "string",
                        "enum": ["pem", "der", "base64", "ssh"],
                        "description": "Export format",
                        "default": "pem",
                    },
                    "point_encoding": {
                        "type": "string",
                        "enum": ["uncompressed", "compressed", "hybrid"],
                        "description": "Point encoding format (for DER/PEM)",
                        "default": "uncompressed",
                    },
                },
                "required": ["public_key", "curve"],
            },
        ),
        Tool(
            name="get_key_info",
            description="Get information about a key",
            inputSchema={
                "type": "object",
                "properties": {
                    "private_key": {
                        "type": "string",
                        "description": "Base64-encoded private key (optional, provide either private or public key)",
                    },
                    "public_key": {
                        "type": "string",
                        "description": "Base64-encoded public key (optional)",
                    },
                    "curve": {
                        "type": "string",
                        "enum": list(CURVES.keys()),
                        "description": "Curve used for the key",
                        "default": "NIST256p",
                    },
                },
            },
        ),
        Tool(
            name="recover_public_key",
            description="Recover public keys from a signature and signed data",
            inputSchema={
                "type": "object",
                "properties": {
                    "signature": {
                        "type": "string",
                        "description": "Base64-encoded signature",
                    },
                    "data": {
                        "type": "string",
                        "description": "Original data that was signed",
                    },
                    "curve": {
                        "type": "string",
                        "enum": list(CURVES.keys()),
                        "description": "Curve used for signing",
                        "default": "NIST256p",
                    },
                    "hashfunc": {
                        "type": "string",
                        "enum": list(HASH_FUNCTIONS.keys()),
                        "description": "Hash function used",
                        "default": "sha256",
                    },
                },
                "required": ["signature", "data"],
            },
        ),
    ]


def get_curve(curve_name: str) -> Any:
    return CURVES.get(curve_name, NIST256p)


def get_hash_func(hash_name: str) -> Any:
    return HASH_FUNCTIONS.get(hash_name, hashlib.sha256)


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "generate_key":
            return await generate_key(arguments)
        elif name == "sign_data":
            return await sign_data(arguments)
        elif name == "sign_digest":
            return await sign_digest(arguments)
        elif name == "verify_signature":
            return await verify_signature(arguments)
        elif name == "verify_digest_signature":
            return await verify_digest_signature(arguments)
        elif name == "import_private_key":
            return await import_private_key(arguments)
        elif name == "import_public_key":
            return await import_public_key(arguments)
        elif name == "export_private_key":
            return await export_private_key(arguments)
        elif name == "export_public_key":
            return await export_public_key(arguments)
        elif name == "get_key_info":
            return await get_key_info(arguments)
        elif name == "recover_public_key":
            return await recover_public_key(arguments)
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]


async def generate_key(arguments: dict) -> list[TextContent]:
    curve = get_curve(arguments.get("curve", "NIST256p"))
    hashfunc = get_hash_func(arguments.get("hashfunc", "sha256"))

    sk = SigningKey.generate(curve=curve, hashfunc=hashfunc)
    vk = sk.get_verifying_key()

    return [
        TextContent(
            type="text",
            text=json.dumps(
                {
                    "private_key": base64.b64encode(sk.to_string()).decode("utf-8"),
                    "public_key": base64.b64encode(vk.to_string()).decode("utf-8"),
                    "curve": arguments.get("curve", "NIST256p"),
                }
            ),
        )
    ]


async def sign_data(arguments: dict) -> list[TextContent]:
    private_key_b64 = arguments["private_key"]
    data = arguments["data"]
    curve = get_curve(arguments.get("curve", "NIST256p"))
    hashfunc = get_hash_func(arguments.get("hashfunc", "sha256"))
    sigencode = (
        sigencode_der if arguments.get("sigencode") == "der" else sigencode_string
    )
    deterministic = arguments.get("deterministic", True)

    private_key_bytes = base64.b64decode(private_key_b64)
    sk = SigningKey.from_string(private_key_bytes, curve=curve, hashfunc=hashfunc)

    if deterministic:
        signature = sk.sign_deterministic(
            data.encode("utf-8"), hashfunc=hashfunc, sigencode=sigencode
        )
    else:
        signature = sk.sign(
            data.encode("utf-8"), hashfunc=hashfunc, sigencode=sigencode
        )

    return [
        TextContent(
            type="text",
            text=json.dumps(
                {
                    "signature": base64.b64encode(signature).decode("utf-8"),
                }
            ),
        )
    ]


async def sign_digest(arguments: dict) -> list[TextContent]:
    private_key_b64 = arguments["private_key"]
    digest_hex = arguments["digest"]
    curve = get_curve(arguments.get("curve", "NIST256p"))
    sigencode = (
        sigencode_der if arguments.get("sigencode") == "der" else sigencode_string
    )
    deterministic = arguments.get("deterministic", True)

    private_key_bytes = base64.b64decode(private_key_b64)
    digest_bytes = bytes.fromhex(digest_hex)
    sk = SigningKey.from_string(private_key_bytes, curve=curve)

    if deterministic:
        signature = sk.sign_digest_deterministic(digest_bytes, sigencode=sigencode)
    else:
        signature = sk.sign_digest(digest_bytes, sigencode=sigencode)

    return [
        TextContent(
            type="text",
            text=json.dumps(
                {
                    "signature": base64.b64encode(signature).decode("utf-8"),
                }
            ),
        )
    ]


async def verify_signature(arguments: dict) -> list[TextContent]:
    public_key_b64 = arguments["public_key"]
    signature_b64 = arguments["signature"]
    data = arguments["data"]
    curve = get_curve(arguments.get("curve", "NIST256p"))
    hashfunc = get_hash_func(arguments.get("hashfunc", "sha256"))
    sigdecode = (
        sigdecode_der if arguments.get("sigdecode") == "der" else sigdecode_string
    )

    public_key_bytes = base64.b64decode(public_key_b64)
    signature_bytes = base64.b64decode(signature_b64)

    vk = VerifyingKey.from_string(public_key_bytes, curve=curve, hashfunc=hashfunc)

    try:
        vk.verify(
            signature_bytes,
            data.encode("utf-8"),
            hashfunc=hashfunc,
            sigdecode=sigdecode,
        )
        result = {"valid": True}
    except Exception:
        result = {"valid": False}

    return [TextContent(type="text", text=json.dumps(result))]


async def verify_digest_signature(arguments: dict) -> list[TextContent]:
    public_key_b64 = arguments["public_key"]
    signature_b64 = arguments["signature"]
    digest_hex = arguments["digest"]
    curve = get_curve(arguments.get("curve", "NIST256p"))
    sigdecode = (
        sigdecode_der if arguments.get("sigdecode") == "der" else sigdecode_string
    )

    public_key_bytes = base64.b64decode(public_key_b64)
    signature_bytes = base64.b64decode(signature_b64)
    digest_bytes = bytes.fromhex(digest_hex)

    vk = VerifyingKey.from_string(public_key_bytes, curve=curve)

    try:
        vk.verify_digest(signature_bytes, digest_bytes, sigdecode=sigdecode)
        result = {"valid": True}
    except Exception:
        result = {"valid": False}

    return [TextContent(type="text", text=json.dumps(result))]


async def import_private_key(arguments: dict) -> list[TextContent]:
    key_data = arguments["key_data"]
    format_type = arguments["format"]
    curve = get_curve(arguments.get("curve", "NIST256p"))
    hashfunc = get_hash_func(arguments.get("hashfunc", "sha256"))

    if format_type == "pem":
        sk = SigningKey.from_pem(key_data, hashfunc=hashfunc)
    elif format_type == "der":
        sk = SigningKey.from_der(key_data, hashfunc=hashfunc)
    elif format_type == "base64":
        sk = SigningKey.from_string(
            base64.b64decode(key_data), curve=curve, hashfunc=hashfunc
        )
    else:
        return [TextContent(type="text", text=f"Unknown format: {format_type}")]

    vk = sk.get_verifying_key()

    return [
        TextContent(
            type="text",
            text=json.dumps(
                {
                    "private_key": base64.b64encode(sk.to_string()).decode("utf-8"),
                    "public_key": base64.b64encode(vk.to_string()).decode("utf-8"),
                    "curve": arguments.get("curve", "NIST256p"),
                }
            ),
        )
    ]


async def import_public_key(arguments: dict) -> list[TextContent]:
    key_data = arguments["key_data"]
    format_type = arguments["format"]
    curve = get_curve(arguments.get("curve", "NIST256p"))
    hashfunc = get_hash_func(arguments.get("hashfunc", "sha256"))

    if format_type == "pem":
        vk = VerifyingKey.from_pem(key_data, hashfunc=hashfunc)
    elif format_type == "der":
        vk = VerifyingKey.from_der(key_data, hashfunc=hashfunc)
    elif format_type == "base64":
        vk = VerifyingKey.from_string(
            base64.b64decode(key_data), curve=curve, hashfunc=hashfunc
        )
    else:
        return [TextContent(type="text", text=f"Unknown format: {format_type}")]

    return [
        TextContent(
            type="text",
            text=json.dumps(
                {
                    "public_key": base64.b64encode(vk.to_string()).decode("utf-8"),
                    "curve": arguments.get("curve", "NIST256p"),
                }
            ),
        )
    ]


async def export_private_key(arguments: dict) -> list[TextContent]:
    private_key_b64 = arguments["private_key"]
    curve = get_curve(arguments.get("curve", "NIST256p"))
    format_type = arguments.get("format", "pem")
    pem_format = arguments.get("pem_format", "ssleay")

    private_key_bytes = base64.b64decode(private_key_b64)
    sk = SigningKey.from_string(private_key_bytes, curve=curve)

    if format_type == "pem":
        output = sk.to_pem(format=pem_format).decode("utf-8")
    elif format_type == "der":
        output = base64.b64encode(sk.to_der(format=pem_format)).decode("utf-8")
    elif format_type == "base64":
        output = base64.b64encode(sk.to_string()).decode("utf-8")
    elif format_type == "ssh":
        output = base64.b64encode(sk.to_ssh()).decode("utf-8")
    else:
        return [TextContent(type="text", text=f"Unknown format: {format_type}")]

    return [TextContent(type="text", text=json.dumps({"key": output}))]


async def export_public_key(arguments: dict) -> list[TextContent]:
    public_key_b64 = arguments["public_key"]
    curve = get_curve(arguments.get("curve", "NIST256p"))
    format_type = arguments.get("format", "pem")
    point_encoding = arguments.get("point_encoding", "uncompressed")

    public_key_bytes = base64.b64decode(public_key_b64)
    vk = VerifyingKey.from_string(public_key_bytes, curve=curve)

    if format_type == "pem":
        output = vk.to_pem(point_encoding=point_encoding).decode("utf-8")
    elif format_type == "der":
        output = base64.b64encode(vk.to_der(point_encoding=point_encoding)).decode(
            "utf-8"
        )
    elif format_type == "base64":
        output = base64.b64encode(vk.to_string()).decode("utf-8")
    elif format_type == "ssh":
        output = base64.b64encode(vk.to_ssh()).decode("utf-8")
    else:
        return [TextContent(type="text", text=f"Unknown format: {format_type}")]

    return [TextContent(type="text", text=json.dumps({"key": output}))]


async def get_key_info(arguments: dict) -> list[TextContent]:
    curve = get_curve(arguments.get("curve", "NIST256p"))
    hashfunc = get_hash_func(arguments.get("hashfunc", "sha256"))

    private_key_b64 = arguments.get("private_key")
    public_key_b64 = arguments.get("public_key")

    result = {"curve": arguments.get("curve", "NIST256p")}

    if private_key_b64:
        private_key_bytes = base64.b64decode(private_key_b64)
        sk = SigningKey.from_string(private_key_bytes, curve=curve, hashfunc=hashfunc)
        vk = sk.get_verifying_key()
        result["private_key"] = base64.b64encode(sk.to_string()).decode("utf-8")
        result["public_key"] = base64.b64encode(vk.to_string()).decode("utf-8")

    if public_key_b64:
        public_key_bytes = base64.b64decode(public_key_b64)
        vk = VerifyingKey.from_string(public_key_bytes, curve=curve, hashfunc=hashfunc)
        result["public_key"] = base64.b64encode(vk.to_string()).decode("utf-8")

    return [TextContent(type="text", text=json.dumps(result))]


async def recover_public_key(arguments: dict) -> list[TextContent]:
    signature_b64 = arguments["signature"]
    data = arguments["data"]
    curve = get_curve(arguments.get("curve", "NIST256p"))
    hashfunc = get_hash_func(arguments.get("hashfunc", "sha256"))

    signature_bytes = base64.b64decode(signature_b64)

    recovered_keys = VerifyingKey.from_public_key_recovery(
        signature_bytes, data.encode("utf-8"), curve, hashfunc=hashfunc
    )

    result = {
        "keys": [
            base64.b64encode(vk.to_string()).decode("utf-8") for vk in recovered_keys
        ]
    }

    return [TextContent(type="text", text=json.dumps(result))]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
