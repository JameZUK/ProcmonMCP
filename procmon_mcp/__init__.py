"""ProcmonMCP - MCP server for analysing Process Monitor XML log files."""

# Core infrastructure
from .compat import (
    LXML_AVAILABLE, PSUTIL_AVAILABLE, MCP_SDK_AVAILABLE,
    ET_impl, FastMCP, Context,
)
from .constants import (
    LOG_FORMAT,
    PROCMON_TIMESTAMP_FORMAT, PROGRESS_REPORT_INTERVAL, PROGRESS_REPORT_SECONDS,
    BASE_DATE, OP_PROCESS_CREATE, OP_PROCESS_EXIT, NETWORK_OPERATIONS,
    ROLLOVER_THRESHOLD_SECONDS, MAX_REGEX_LEN, MAX_FILTER_STR_LEN,
    IK_PROCESS_NAME, IK_OPERATION, IK_PATH, IK_RESULT, IK_CATEGORY,
    IK_STACK_PATH, IK_STACK_LOCATION,
)

# Helpers
from .helpers import (
    _compile_safe_regex, _strip_namespace, _find_child_ignore_ns,
    _find_text_ignore_ns, find_text_func, _clear_elem,
    _parse_timestamp_str, _format_bytes, parse_network_endpoint,
    parse_network_endpoint_parts, network_direction, repair_mojibake,
)

# Data models
from .models import StringInterner, StackFrame, ProcessInfo, ProcmonLogData

# Parser
from .parser import load_procmon_xml

# User configuration
from .config import load_config, save_config, get_last_file, set_last_file

# Parsed-capture cache
from . import cache

# Filtering and formatting
from .filters import _iter_filtered_event_indices
from .formatters import _get_formatted_event_details

# Server infrastructure
from .server import mcp, _check_loaded, tool_decorator

# Force tool registration by importing the tools module
from . import tools as _tools  # noqa: F401
