"""MCP server setup and global state for ProcmonMCP."""
import logging
from typing import Optional

from .compat import FastMCP, Context, MCP_SDK_AVAILABLE
from .models import ProcmonLogData

logger = logging.getLogger(__name__)

# Global state: holds the single loaded ProcmonLogData instance after successful loading
LOADED_DATA: Optional[ProcmonLogData] = None

# Setup MCP server instance
if MCP_SDK_AVAILABLE:
    mcp = FastMCP(
        "ProcmonXmlToolRefactored",
        description="A tool to analyze a specific, pre-loaded Procmon XML log file (plain or compressed) using in-memory optimization (Refactored)."
    )
else:
    mcp = FastMCP(
        "ProcmonXmlToolRefactored (Mock)",
        description="Mock Tool: Analyzes pre-loaded Procmon XML files (optimized in-memory, Refactored)."
    )


async def _check_loaded(ctx: Context, tool_name: str) -> ProcmonLogData:
    """Validates data is loaded. Returns the data or raises RuntimeError with consistent messaging."""
    if not LOADED_DATA or not LOADED_DATA.is_loaded():
        msg = f"[{tool_name}] No Procmon data loaded. Load a file with --input-file first."
        await ctx.error(msg)
        raise RuntimeError(msg)
    return LOADED_DATA


tool_decorator = mcp.tool() if MCP_SDK_AVAILABLE else lambda func: func
