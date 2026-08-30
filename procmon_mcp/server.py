"""MCP server setup and global state for ProcmonMCP."""
import logging
from importlib.metadata import PackageNotFoundError, version as _package_version
from typing import Optional

from .compat import MCPServer, Context, MCP_SDK_AVAILABLE, MCP_SDK_V2
from .models import ProcmonLogData

logger = logging.getLogger(__name__)

try:
    _VERSION = _package_version("procmon-mcp")
except PackageNotFoundError:
    # Running from a source checkout that was never pip-installed.
    _VERSION = ""

# Global state: holds the single loaded ProcmonLogData instance after successful loading
LOADED_DATA: Optional[ProcmonLogData] = None

# Flag indicating whether a file load is currently in progress
LOADING_IN_PROGRESS: bool = False

# Setup MCP server instance
_SERVER_DESC = (
    "ProcmonMCP - Analyse Process Monitor XML log files. "
    "Use get_status to check state, then load_file to open a Procmon XML capture."
)

# v2 advertises the server's own version to clients and defaults it to an empty
# string. v1's FastMCP has no such parameter (it reported the SDK's version
# instead), so this is passed only where it is accepted.
_server_kwargs = {"instructions": _SERVER_DESC}
if MCP_SDK_V2 and _VERSION:
    _server_kwargs["version"] = _VERSION

if MCP_SDK_AVAILABLE:
    mcp = MCPServer("ProcmonMCP", **_server_kwargs)
else:
    mcp = MCPServer("ProcmonMCP (Mock)", **_server_kwargs)


async def _check_loaded(ctx: Context, tool_name: str) -> ProcmonLogData:
    """Validates data is loaded. Returns the data or raises RuntimeError with consistent messaging."""
    if LOADING_IN_PROGRESS:
        msg = f"[{tool_name}] A file is currently being loaded. Please wait for loading to complete."
        await ctx.error(msg)
        raise RuntimeError(msg)
    if not LOADED_DATA or not LOADED_DATA.is_loaded():
        msg = f"[{tool_name}] No Procmon data loaded. Use the 'load_file' tool to open a Procmon XML file first."
        await ctx.error(msg)
        raise RuntimeError(msg)
    return LOADED_DATA


tool_decorator = mcp.tool() if MCP_SDK_AVAILABLE else lambda func: func
