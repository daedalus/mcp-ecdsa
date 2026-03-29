import asyncio

from mcp.server.stdio import stdio_server

from mcp_ecdsa.server import app


def main() -> int:
    """Main entry point for the MCP ECDSA server."""
    return asyncio.run(_async_main())


async def _async_main() -> int:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
