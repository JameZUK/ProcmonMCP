import os
import logging
import argparse
from typing import List, Dict, Any, Optional, Tuple
import io
import asyncio
import time # For timing the loading
from collections import defaultdict # For counting

# --- Basic Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
logger = logging.getLogger(__name__)

# --- MCP SDK Imports ---
try:
    from mcp.server.fastmcp import FastMCP, Context
    MCP_SDK_AVAILABLE = True
    logger.info("MCP SDK found.")
except ImportError:
    MCP_SDK_AVAILABLE = False
    logger.error("MCP SDK (modelcontextprotocol) not found. Please install it: pip install modelcontextprotocol")
    # Mock objects
    class MockSettings: host = "127.0.0.1"; port = 8081; log_level = "INFO"
    class MockMCP:
        def __init__(self, name, description=""): self.name = name; self.description = description; self.app = object(); self.settings = MockSettings(); self._run_called_with_transport = None
        def tool(self): decorator = lambda func: func; return decorator
        def run(self, transport: str = "stdio"): logger.info(f"MockMCP '{self.name}' run method called with transport='{transport}'."); logger.info(f"MockMCP settings - Host: {self.settings.host}, Port: {self.settings.port}"); self._run_called_with_transport = transport
    FastMCP = MockMCP
    class Context:
        async def info(self, msg): logger.info(f"(async mock ctx): {msg}")
        async def error(self, msg): logger.error(f"(async mock ctx): {msg}")
        async def warning(self, msg): logger.warning(f"(async mock ctx): {msg}")

# --- Procmon Parser Import ---
try:
    import procmon_parser
    from procmon_parser import ProcmonLogsReader, load_configuration, Rule
    PROCMON_PARSER_AVAILABLE = True
    logger.info("procmon-parser library found.")
except ImportError:
    PROCMON_PARSER_AVAILABLE = False
    logger.error("procmon-parser not found. Please install it (pip install procmon-parser).")
    # Mocks using correct structure based on latest understanding
    class MockPMLData: # Wrapper for loaded PML data
        def __init__(self):
            self.header = self._create_mock_header()
            self.processes = self._create_mock_processes()
            self.events = self._create_mock_events()

        def _create_mock_header(self):
            header = type('MockHeader', (object,), {})()
            header.os_version = "10.0.22621"; header.computer_name = "MOCK-PC"; header.is_64bit_os = True
            header.total_events = 15; header.major_version = 10; header.minor_version = 0
            header.build_number = 22621; header.system_root = "C:\\Windows"
            header.number_of_processors = 8; header.total_physical_memory = 16 * 1024**3
            return header

        def _create_mock_processes(self):
            procs = []
            pid_map = {}
            for pid_val in [1000, 1004, 1008]:
                 proc = type('MockProcess', (object,), {})()
                 proc.pid = pid_val
                 proc.parent_pid = 500 if proc.pid != 1000 else 100
                 proc.image_path = f"C:\\Program Files\\App_{proc.pid}\\process_{(proc.pid-1000)//4}.exe"
                 proc.command_line = f"{proc.image_path} -arg{proc.pid}"
                 proc.user_sid = f"S-1-5-21-..."
                 proc.authentication_id = 0xABCD + ((proc.pid-1000)//4 % 3)
                 proc.session_id = 1
                 proc.is_64bit = True
                 proc.process_name = f"process_{(proc.pid-1000)//4}.exe"
                 proc.create_time = None; proc.exit_time = None
                 proc.modules = [
                     type('MockModule', (object,), {'path': proc.image_path, 'address': 0x7FF00000 + proc.pid, 'size': 0x1000})(),
                     type('MockModule', (object,), {'path': 'C:\\Windows\\System32\\ntdll.dll', 'address': 0x7FF10000, 'size': 0x20000})()
                 ]
                 procs.append(proc)
                 pid_map[proc.pid] = proc
            if 500 not in pid_map:
                 proc = type('MockProcess', (object,), {})()
                 proc.pid = 500; proc.parent_pid = 10; proc.process_name = "parent_500.exe"; proc.image_path = "C:\\Windows\\System32\\parent_500.exe"
                 procs.append(proc); pid_map[500] = proc
            if 100 not in pid_map:
                 proc = type('MockProcess', (object,), {})()
                 proc.pid = 100; proc.parent_pid = 4; proc.process_name = "parent_100.exe"; proc.image_path = "C:\\Windows\\System32\\parent_100.exe"
                 procs.append(proc); pid_map[100] = proc
            if 4 not in pid_map:
                 proc = type('MockProcess', (object,), {})()
                 proc.pid = 4; proc.parent_pid = 0; proc.process_name = "System"; proc.image_path = "System"
                 procs.append(proc); pid_map[4] = proc
            self._temp_pid_map = pid_map
            return procs

        def _create_mock_events(self):
            events = []
            for idx in range(15):
                event = type('MockEvent', (object,), {})()
                event.pid = 1000 + (idx % 3) * 4
                event.tid = 5000 + idx * 10
                event.operation = ["CreateFile", "WriteFile", "RegQueryKey", "TCP Send"][idx % 4]
                event.path = f"C:\\path\\to\\file_{idx}.tmp" if idx % 2 == 0 else "HKLM\\Software\\Mock"
                if idx < 5 : event.result = 0xC0000022 # Simulate ACCESS_DENIED code
                elif idx < 10: event.result = 0 # Simulate SUCCESS code
                else: event.result = ["SUCCESS", "NAME NOT FOUND", "PATH NOT FOUND"][idx % 3] # Simulate string results
                event.duration = 0.001 * idx
                event.timestamp = f"2025-05-02 09:{50+idx//60}:{idx%60}.{100+idx*15}"
                event.detail = f"Detail string for event {idx}"
                event.stacktrace = [0x7FF00000 + i*0x10 + idx*0x100 for i in range(5 + idx % 5)]
                event.process = self._temp_pid_map.get(event.pid)
                event.process_name = getattr(event.process, 'process_name', 'Unknown') if event.process else 'Unknown'
                event.parent_pid = getattr(event.process, 'parent_pid', None) if event.process else None
                event.session_id = 1
                event.authentication_id = 0xABCD + (idx%3)
                event.user_sid = f"S-1-5-21-..."
                event.is_64bit_process = True
                event.category = ["File System", "Registry", "Network"][idx % 3]
                events.append(event)
            del self._temp_pid_map
            return events

    def mock_load_configuration(stream): return {"DestructiveFilter": 0,"FilterRules": [{'column': 'Process Name', 'relation': 'is', 'value': 'System', 'action': 'Exclude'},{'column': 'Process Name', 'relation': 'is', 'value': 'Procmon64.exe', 'action': 'Exclude'}],"HighlightBackColor": 16777215,"HighlightForeColor": 0}
    class Rule: pass

# --- Global State ---
ALLOWED_DIR_CONFIG: Optional[str] = None
LOADED_FILENAME: Optional[str] = None
LOADED_FILE_TYPE: Optional[str] = None
LOADED_DATA: Optional[Dict[str, Any]] = None

# --- Setup MCP ---
if MCP_SDK_AVAILABLE:
    mcp = FastMCP(
        "ProcmonParserTool",
        description="A tool to analyze a specific, pre-loaded Procmon PML log file or PMC configuration file with detailed data access."
    )
else:
    mcp = MockMCP(
         "ProcmonParserTool (Mock)",
         description="Mock Tool: Analyzes pre-loaded Procmon files."
    )


# --- Security Helper ---
def get_secure_path(filename: str) -> str:
    """Validates filename relative to ALLOWED_FILE_DIR and returns full path if safe."""
    if not ALLOWED_DIR_CONFIG: raise RuntimeError("Internal Error: Allowed directory configuration is missing.")
    if not filename or '..' in filename or os.path.isabs(filename) or '\\' in filename : raise ValueError("Invalid relative filename format or potential path traversal.")
    full_path = os.path.join(ALLOWED_DIR_CONFIG, filename)
    normalized_allowed_dir = os.path.abspath(ALLOWED_DIR_CONFIG)
    normalized_full_path = os.path.abspath(full_path)
    logger.debug(f"Checking path: {normalized_full_path} against allowed: {normalized_allowed_dir}")
    if not normalized_full_path.startswith(normalized_allowed_dir): raise PermissionError(f"Access denied: File '{filename}' resolves outside the allowed directory.")
    if not os.path.exists(normalized_full_path): raise FileNotFoundError(f"File not found: {filename} (in {ALLOWED_DIR_CONFIG})")
    if not os.path.isfile(normalized_full_path): raise ValueError(f"Path exists but is not a file: {filename}")
    logger.debug(f"Path validated: {normalized_full_path}")
    return normalized_full_path

# --- Loading Helper ---
def load_and_validate_file(allowed_dir: str, filename_relative: str) -> Tuple[Dict[str, Any], str]:
    """Loads PML/PMC data into standardized dictionary structures."""
    if not PROCMON_PARSER_AVAILABLE:
        raise RuntimeError("Cannot load file: procmon-parser library is not installed.")

    full_path = get_secure_path(filename_relative)
    file_ext = os.path.splitext(filename_relative)[1].lower()

    start_time = time.time()
    loaded_data: Dict[str, Any] = {}

    with open(full_path, "rb") as f:
        if file_ext == ".pml":
            logger.info(f"Loading PML file using ProcmonLogsReader: {full_path}")
            pml_reader = ProcmonLogsReader(f)

            try:
                loaded_data['header'] = getattr(pml_reader, 'header', None)
                if loaded_data['header']: logger.info("Extracted header information.")
                else: logger.warning("Could not extract header information from PML reader.")
            except Exception as e:
                 logger.error(f"Error accessing PML header: {e}", exc_info=True)
                 loaded_data['header'] = None

            logger.info("Iterating through PML reader to extract events and processes...")
            events_list = []
            process_list = []
            seen_pids = set()
            event_count = 0
            try:
                for event in pml_reader:
                    events_list.append(event)
                    event_count += 1
                    process_obj = getattr(event, 'process', None)
                    if process_obj:
                        pid = safe_get_attributes(process_obj, ['pid']).get('pid')
                        if pid is not None and pid not in seen_pids:
                            process_list.append(process_obj)
                            seen_pids.add(pid)
                            logger.debug(f"Stored new process object for PID {pid}")
                    if event_count % 10000 == 0: logger.info(f"Processed {event_count} events...")
            except Exception as e: logger.error(f"Error iterating through PML reader: {e}", exc_info=True)

            loaded_data['events'] = events_list
            loaded_data['processes'] = process_list
            logger.info(f"Finished extracting PML data: {len(events_list)} events, {len(process_list)} unique processes.")
            file_type = 'pml'

        elif file_ext == ".pmc":
            logger.info(f"Loading PMC file using load_configuration: {full_path}")
            loaded_data = load_configuration(f)
            file_type = 'pmc'
        else:
            raise ValueError(f"Unsupported file type: {file_ext}. Only .pml and .pmc are supported.")

    end_time = time.time()
    logger.info(f"File loading and processing took {end_time - start_time:.2f} seconds.")
    return loaded_data, file_type

# --- Helper to Safely Get Attributes (Improved Casing Checks) ---
def safe_get_attributes(obj: Any, attributes: List[str]) -> Dict[str, Any]:
    """
    Safely gets multiple attributes from an object, checking common casing variations.
    Returns a dictionary with lowercase keys matching the input attributes list.
    Args:
        obj: The object to get attributes from.
        attributes: A list of desired attribute names (preferably lowercase).
    """
    result = {}
    if obj is None:
        return {attr: None for attr in attributes}

    for attr_lower in attributes:
        value = None
        possible_names = [
            attr_lower,
            attr_lower.capitalize(),
            attr_lower.title().replace("_",""),
            attr_lower.replace("_", " ").title(),
        ]
        if attr_lower == "stacktrace": possible_names.append("stacktrace")
        if attr_lower == "process_name": possible_names.append("Process Name")
        if attr_lower == "pid": possible_names.append("Pid")

        possible_names = list(dict.fromkeys(possible_names))

        for name_attempt in possible_names:
            if hasattr(obj, name_attempt):
                value = getattr(obj, name_attempt, None)
                if value is not None:
                    break

        if isinstance(value, (bytes, bytearray)):
            try: result[attr_lower] = value.decode('utf-8', errors='replace')
            except Exception: result[attr_lower] = repr(value)
        elif not isinstance(value, (str, int, float, bool, list, dict, type(None))):
             result[attr_lower] = str(value)
        else:
            result[attr_lower] = value
    return result


# --- MCP Tools ---
tool_decorator = mcp.tool() if MCP_SDK_AVAILABLE else lambda func: func

# --- Tool Functions ---

@tool_decorator
async def get_loaded_file_summary(ctx: Context) -> Dict[str, Any]:
    """
    Returns a basic summary of the pre-loaded Procmon file (PML or PMC).
    Accesses the data loaded into memory at server startup.
    Returns:
        A dictionary containing summary information (filename, type, counts).
        Errors if no file is loaded.
    """
    await ctx.info(f"Request received for summary of pre-loaded file.")
    if not LOADED_DATA or not LOADED_FILENAME or not LOADED_FILE_TYPE:
        await ctx.error("No Procmon file was pre-loaded at server startup using --load-file.")
        raise RuntimeError("Operation failed: No Procmon file is pre-loaded.")

    summary = {"loaded_filename": LOADED_FILENAME, "file_type": LOADED_FILE_TYPE}
    try:
        if LOADED_FILE_TYPE == 'pml':
            summary["event_count"] = len(LOADED_DATA.get('events', []))
            summary["process_count"] = len(LOADED_DATA.get('processes', []))
            header = LOADED_DATA.get('header')
            if header:
                 summary.update(safe_get_attributes(header, ['os_version', 'computer_name', 'is_64bit_os']))
        elif LOADED_FILE_TYPE == 'pmc':
            summary["filter_rule_count"] = len(LOADED_DATA.get('FilterRules', []))
            summary["destructive_filter"] = LOADED_DATA.get('DestructiveFilter')

        await ctx.info(f"Successfully generated summary for {LOADED_FILENAME}.")
        return summary
    except Exception as e:
        await ctx.error(f"Error generating summary for {LOADED_FILENAME}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error generating summary: {e}")

@tool_decorator
async def query_loaded_pml_events(
    filter_process: Optional[str] = None,
    filter_operation: Optional[str] = None,
    filter_result: Optional[str] = None,
    filter_path_contains: Optional[str] = None,
    filter_process_contains: Optional[str] = None,
    limit: int = 50,
    *,
    ctx: Context
) -> List[Dict[str, Any]]:
    """
    Queries events from the pre-loaded PML file, returning summaries including the event index.
    Filtering by process name relies on the name associated with the event's linked process object.
    Use the returned 'event_index' with 'get_pml_event_details' and 'get_pml_event_stack_trace' for more info.

    Args:
        filter_process: Optional exact process name to filter events by (case-insensitive). For non-ASCII names, try using Unicode escape sequences (e.g., '\\uXXXX\\uYYYY.exe').
        filter_operation: Optional operation name to filter events by (case-insensitive).
        filter_result: Optional result string (or hex '0x...' code) to filter events by (case-insensitive string match, or exact integer match for hex).
        filter_path_contains: Optional string that must be contained in the event path (case-insensitive).
        filter_process_contains: Optional string that must be contained in the process name (case-insensitive). For non-ASCII names, try using Unicode escape sequences.
        limit: Maximum number of event summaries to return.

    Returns:
        A list of dictionaries, each summarizing a matching Procmon event including its 'event_index'. Returns an empty list if no events match.
    """
    await ctx.info(f"Request received to query PML summaries. Filters: Process='{filter_process}', Op='{filter_operation}', Result='{filter_result}', PathContains='{filter_path_contains}', ProcessContains='{filter_process_contains}', Limit={limit}")
    if LOADED_FILE_TYPE != 'pml' or not LOADED_DATA:
        await ctx.error(f"Query failed: The pre-loaded file '{LOADED_FILENAME}' is not a PML file or no file is loaded.")
        raise TypeError("Operation requires a PML file to be pre-loaded.")

    try:
        filtered_event_summaries = []
        count = 0
        events_list = LOADED_DATA.get('events', [])
        logger.debug(f"Starting event query on {len(events_list)} events.")

        # Pre-process filter_result
        filter_result_lower_str = None
        filter_result_int = None
        is_hex_filter = False
        if filter_result:
            filter_result_lower = filter_result.lower()
            if filter_result_lower.startswith("0x"):
                try:
                    filter_result_int = int(filter_result_lower, 16)
                    is_hex_filter = True
                    logger.debug(f"Interpreting result_filter '{filter_result}' as hex integer: {filter_result_int}")
                except ValueError:
                    logger.warning(f"Could not parse result_filter '{filter_result}' as hex, treating as string.")
                    filter_result_lower_str = filter_result_lower
            else:
                filter_result_lower_str = filter_result_lower

        for idx, event in enumerate(events_list):
            if count >= limit:
                logger.debug(f"Query limit ({limit}) reached.")
                break

            # Get attributes
            process_obj = getattr(event, 'process', None)
            process_name = safe_get_attributes(process_obj, ['process_name']).get('process_name', '') or ''
            event_attrs = safe_get_attributes(event, ['operation', 'result', 'path', 'pid', 'timestamp'])
            operation = event_attrs.get('operation', '') or ''
            result_val = event_attrs.get('result', '')
            path = event_attrs.get('path', '') or ''
            pid = event_attrs.get('pid')
            if pid is None and process_obj: pid = safe_get_attributes(process_obj, ['pid']).get('pid')
            timestamp = event_attrs.get('timestamp')

            result_str = str(result_val)

            # Apply filters
            match = True
            if filter_process is not None and process_name.lower() != filter_process.lower():
                match = False
            if match and filter_operation is not None and operation.lower() != filter_operation.lower():
                match = False
            if match and filter_result is not None:
                if is_hex_filter:
                    if isinstance(result_val, int) and result_val == filter_result_int: match = True
                    else: match = False
                else:
                    if result_str.lower() != filter_result_lower_str: match = False
            if match and filter_path_contains is not None and filter_path_contains.lower() not in path.lower():
                match = False
            if match and filter_process_contains is not None and filter_process_contains.lower() not in process_name.lower():
     