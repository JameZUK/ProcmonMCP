"""MCP server setup and global state for ProcmonMCP."""
import logging
from typing import Optional

from .compat import FastMCP, Context, MCP_SDK_AVAILABLE
from .models import ProcmonLogData

logger = logging.getLogger(__name__)

# Global state: holds the single loaded ProcmonLogData instance after successful loading
LOADED_DATA: Optional[ProcmonLogData] = None

# Flag indicating whether a file load is currently in progress
LOADING_IN_PROGRESS: bool = False

# Setup MCP server instance
_SERVER_DESC = (
    "ProcmonMCP - Analyse Process Monitor XML log files. "
    "Use get_status to check state, then load_file to open a Procmon XML capture."
)

if MCP_SDK_AVAILABLE:
    mcp = FastMCP("ProcmonMCP", description=_SERVER_DESC)
else:
    mcp = FastMCP("ProcmonMCP (Mock)", description=_SERVER_DESC)


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
