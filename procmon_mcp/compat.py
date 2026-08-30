"""Feature detection and compatibility layer for XML parsing, MCP SDK, and system utilities."""
import sys
import logging

from .constants import LOG_FORMAT

# --- Python Version Check ---
MIN_PYTHON_VERSION = (3, 7)
if sys.version_info < MIN_PYTHON_VERSION:
    version_str = ".".join(map(str, MIN_PYTHON_VERSION))
    sys.stderr.write(
        f"CRITICAL ERROR: This script requires Python {version_str} or newer.\n"
        f"You are running Python {sys.version_info.major}.{sys.version_info.minor}.\n"
        "Please upgrade your Python environment to run this tool.\n"
    )
    sys.exit(1)

# --- XML Parser Choice ---
LXML_AVAILABLE = False
try:
    from lxml import etree as ET_impl
    LXML_AVAILABLE = True
    # lxml raises XMLSyntaxError on malformed XML.
    XMLSyntaxError = ET_impl.XMLSyntaxError
except ImportError:
    import xml.etree.ElementTree as ET_impl
    # The stdlib ElementTree has no XMLSyntaxError; it raises ParseError. Alias it
    # so callers can `except XMLSyntaxError` regardless of which backend is active.
    XMLSyntaxError = ET_impl.ParseError

# --- Memory Usage Reporting ---
PSUTIL_AVAILABLE = False
try:
    import psutil  # noqa: F401
    PSUTIL_AVAILABLE = True
except ImportError:
    pass

# --- Basic Logging Configuration ---
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)

if LXML_AVAILABLE:
    logger.info("Using lxml library for XML parsing (recommended for speed, but XPath replaced).")
else:
    logger.warning("lxml library not found. Falling back to standard xml.etree.ElementTree for XML parsing.")
    logger.warning("For better performance and memory efficiency with large XML files, install lxml: pip install lxml")

if not PSUTIL_AVAILABLE:
    logger.warning("psutil library not found. Memory usage reporting will be unavailable.")
    logger.warning("To enable memory reporting, install psutil: pip install psutil")

# --- MCP SDK Imports ---
# SDK v2 renamed FastMCP to MCPServer and moved it from `mcp.server.fastmcp` to
# `mcp.server.mcpserver`. The old module is gone entirely -- it is not a
# deprecation shim -- so the import below is tried v2-first. v2 also dropped
# host/port from `mcp.settings` in favour of run() keyword arguments, so callers
# need to know which major version is live; MCP_SDK_V2 carries that.
# https://py.sdk.modelcontextprotocol.io/migration/#fastmcp-renamed-to-mcpserver
#
# v2 is the version this project targets and declares as its dependency. The v1
# branch is a safety net for environments already pinned to mcp<2, not a
# supported configuration.
MCP_SDK_AVAILABLE = False
MCP_SDK_V2 = False
MCP_IMPORT_ERROR = None
try:
    from mcp.server.mcpserver import MCPServer, Context
    MCP_SDK_AVAILABLE = True
    MCP_SDK_V2 = True
    logger.info("MCP SDK found (v2 API: mcp.server.mcpserver.MCPServer).")
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP as MCPServer, Context
        MCP_SDK_AVAILABLE = True
        logger.info("MCP SDK found (v1 API: mcp.server.fastmcp.FastMCP).")
        logger.warning("MCP SDK v1 is deprecated here; upgrade with: pip install --upgrade \"mcp[cli]>=2\"")
    except ImportError:
        # Distinguish "SDK absent" from "SDK present but neither API importable",
        # so the CLI can report something the user can act on.
        try:
            import mcp  # noqa: F401
            MCP_IMPORT_ERROR = (
                "The 'mcp' package is installed, but neither the v2 "
                "(mcp.server.mcpserver) nor the v1 (mcp.server.fastmcp) server API "
                "could be imported from it."
            )
        except ImportError:
            MCP_IMPORT_ERROR = "The 'mcp' package is not installed."

        logger.error(f"MCP SDK unavailable: {MCP_IMPORT_ERROR}")
        logger.error("Mock objects will be used for offline execution.")
        logger.error("To run as a server, please install the SDK: pip install \"mcp[cli]>=2\"")

        class MockSettings:
            # Mirrors v2, where host/port are run() arguments rather than settings.
            log_level = "INFO"

        class MockMCP:
            """Offline stand-in for MCPServer, shaped like the v2 API."""

            def __init__(self, name, instructions=""):
                self.name = name
                self.instructions = instructions
                self.app = object()
                self.settings = MockSettings()
                self._run_called_with_transport = None
                self._run_called_with_kwargs = None

            def tool(self):
                return lambda func: func

            def run(self, transport: str = "stdio", **kwargs):
                logger.info(f"MockMCP '{self.name}' run method called with transport='{transport}'.")
                if kwargs:
                    logger.info(f"MockMCP transport options: {kwargs}")
                self._run_called_with_transport = transport
                self._run_called_with_kwargs = kwargs

        MCPServer = MockMCP

        class Context:
            async def info(self, msg):
                logger.info(f"(mock ctx): {msg}")

            async def error(self, msg):
                logger.error(f"(mock ctx): {msg}")

            async def warning(self, msg):
                logger.warning(f"(mock ctx): {msg}")

# Backward-compatible alias for the name this module exported before the v2
# rename. Retained so `from procmon_mcp import FastMCP` keeps working.
FastMCP = MCPServer
