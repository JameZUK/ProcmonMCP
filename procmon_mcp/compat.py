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
except ImportError:
    import xml.etree.ElementTree as ET_impl

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
MCP_SDK_AVAILABLE = False
try:
    from mcp.server.fastmcp import FastMCP, Context
    MCP_SDK_AVAILABLE = True
    logger.info("MCP SDK found.")
except ImportError:
    MCP_SDK_AVAILABLE = False
    logger.error("MCP SDK (mcp[cli]) not found. Mock objects will be used for offline execution.")
    logger.error("To run as a server, please install the SDK: pip install \"mcp[cli]\"")

    class MockSettings:
        host = "127.0.0.1"
        port = 8081
        log_level = "INFO"

    class MockMCP:
        def __init__(self, name, instructions=""):
            self.name = name
            self.instructions = instructions
            self.app = object()
            self.settings = MockSettings()
            self._run_called_with_transport = None

        def tool(self):
            return lambda func: func

        def run(self, transport: str = "stdio"):
            logger.info(f"MockMCP '{self.name}' run method called with transport='{transport}'.")
            logger.info(f"MockMCP settings - Host: {self.settings.host}, Port: {self.settings.port}")
            self._run_called_with_transport = transport

    FastMCP = MockMCP

    class Context:
        async def info(self, msg):
            logger.info(f"(mock ctx): {msg}")

        async def error(self, msg):
            logger.error(f"(mock ctx): {msg}")

        async def warning(self, msg):
            logger.warning(f"(mock ctx): {msg}")
