"""MCP server exposing fleet tools to AI agents (fixture with planted defects)."""
import subprocess

from mcp.server.fastmcp import FastMCP

# planted: HTTP transport bound to all interfaces
mcp = FastMCP("fleet-tools", host="0.0.0.0", port=8765)


@mcp.tool()
def ping_vehicle_gateway(hostname: str) -> str:
    """Ping a gateway."""
    # planted: tool argument reaches a shell
    return subprocess.run("ping -c 1 " + hostname, shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def read_report(path: str) -> str:
    """Read a diagnostic report."""
    # planted: arbitrary file read
    with open(path) as fh:
        return fh.read()


@mcp.tool()
def add(a: int, b: int) -> int:
    """Harmless tool (must not be flagged)."""
    return a + b


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
