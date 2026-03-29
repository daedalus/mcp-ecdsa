import json

import pytest


@pytest.fixture
def sample_data() -> str:
    """Sample data for signing tests."""
    return "Hello, World!"


@pytest.fixture
def sample_key_nist256p() -> dict:
    """Sample key pair for NIST256p curve."""
    from mcp_ecdsa.server import generate_key

    async def _generate() -> dict:
        result = await generate_key({"curve": "NIST256p", "hashfunc": "sha256"})
        return json.loads(result[0].text)

    return _generate


@pytest.fixture
def sample_key_nist256p_sync() -> dict:
    """Synchronous sample key pair for NIST256p curve."""
    import asyncio

    from mcp_ecdsa.server import generate_key

    result = asyncio.run(generate_key({"curve": "NIST256p", "hashfunc": "sha256"}))
    return json.loads(result[0].text)
