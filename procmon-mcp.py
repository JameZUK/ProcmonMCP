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
                match = False

            if match:
                 event_summary = {
                     'event_index': idx,
                     'timestamp': str(timestamp),
                     'process_name': process_name,
                     'pid': pid,
                     'operation': operation,
                     'path': path,
                     'result': result_val,
                 }
                 filtered_event_summaries.append(event_summary)
                 count += 1

        await ctx.info(f"Found {len(filtered_event_summaries)} matching event summaries in {LOADED_FILENAME}.")
        return filtered_event_summaries

    except Exception as e:
        await ctx.error(f"Failed to query pre-loaded PML file {LOADED_FILENAME}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error querying PML file: {e}")


@tool_decorator
async def get_loaded_pmc_rules(ctx: Context) -> List[Dict[str, Any]]:
    """
    Returns the filter rules from the loaded Procmon Configuration (PMC) file data.
    Fails if the pre-loaded file is not a PMC file.
    Returns:
        A list of dictionaries, where each dictionary represents a filter rule.
    """
    await ctx.info(f"Request received for rules from pre-loaded PMC file.")
    if LOADED_FILE_TYPE != 'pmc' or not LOADED_DATA:
        await ctx.error(f"Get rules failed: The pre-loaded file '{LOADED_FILENAME}' is not a PMC file or no file is loaded.")
        raise TypeError("Operation requires a PMC file to be pre-loaded.")

    pmc_config_dict = LOADED_DATA
    try:
        rules_raw = pmc_config_dict.get('FilterRules', [])
        rules_processed = []
        if not rules_raw:
             logger.debug("No filter rules found in PMC data.")
        elif isinstance(rules_raw[0], dict):
             logger.debug("PMC rules are already dictionaries.")
             rules_processed = rules_raw
        else:
             logger.debug("Converting PMC rule objects to dictionaries.")
             rule_attributes = ['column', 'relation', 'value', 'action']
             for rule_obj in rules_raw:
                 rules_processed.append(safe_get_attributes(rule_obj, rule_attributes))

        await ctx.info(f"Extracted {len(rules_processed)} rules from pre-loaded file {LOADED_FILENAME}.")
        return rules_processed
    except Exception as e:
        await ctx.error(f"Failed to get rules from pre-loaded PMC file {LOADED_FILENAME}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error processing PMC file: {e}")

@tool_decorator
async def get_pml_event_details(event_index: int, ctx: Context) -> Dict[str, Any]:
    """
    Retrieves detailed properties for a specific event from the loaded PML data, referenced by its index.
    Uses 'query_loaded_pml_events' first to find the index of the event.
    Args:
        event_index: The zero-based index of the event in the loaded event list.
    Returns:
        A dictionary containing available properties of the specified event (e.g., timestamp, pid, tid, operation, path, result, detail, category). Includes a summary of the linked process.
    """
    await ctx.info(f"Request received for details of event index: {event_index}")
    if LOADED_FILE_TYPE != 'pml' or not LOADED_DATA:
        await ctx.error(f"Get details failed: The pre-loaded file '{LOADED_FILENAME}' is not a PML file or no file is loaded.")
        raise TypeError("Operation requires a PML file to be pre-loaded.")

    try:
        events = LOADED_DATA.get('events', [])
        if not 0 <= event_index < len(events):
            await ctx.error(f"Invalid event index: {event_index}. Must be between 0 and {len(events)-1}.")
            raise IndexError(f"Event index {event_index} is out of bounds.")

        event = events[event_index]
        logger.debug(f"Retrieving details for event object at index {event_index}: {vars(event) if hasattr(event, '__dict__') else event}")

        event_attributes = [
            'timestamp', 'pid', 'tid', 'parent_pid',
            'operation', 'path', 'result', 'duration', 'detail', 'category',
            'user_sid', 'session_id', 'authentication_id', 'is_64bit_process',
        ]
        details = safe_get_attributes(event, event_attributes)
        details['event_index'] = event_index

        process_obj = getattr(event, 'process', None)
        if process_obj:
            process_attrs = safe_get_attributes(process_obj, ['pid', 'process_name', 'image_path', 'parent_pid'])
            details['process_name'] = process_attrs.get('process_name')
            details['process_details_summary'] = process_attrs
            if details.get('pid') is None and process_attrs.get('pid') is not None:
                 details['pid'] = process_attrs.get('pid')
            if details.get('parent_pid') is None and process_attrs.get('parent_pid') is not None:
                 details['parent_pid'] = process_attrs.get('parent_pid')
        else:
             details['process_name'] = 'Unknown'
             details['process_details_summary'] = None

        await ctx.info(f"Successfully retrieved details for event index {event_index}.")
        logger.debug(f"Event details retrieved: {details}")
        return details

    except IndexError as e:
        logger.debug(f"IndexError retrieving event details for index {event_index}.")
        raise e
    except Exception as e:
        await ctx.error(f"Failed to get details for event {event_index} in {LOADED_FILENAME}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving event details: {e}")

@tool_decorator
async def get_pml_event_stack_trace(event_index: int, ctx: Context) -> List[str]:
    """
    Retrieves the call stack trace for a specific event from the loaded PML data.
    Uses 'query_loaded_pml_events' first to find the event index. Accesses the 'stacktrace' attribute of the event object.
    Args:
        event_index: The zero-based index of the event in the loaded event list.
    Returns:
        A list of strings, each representing a memory address in hexadecimal format (e.g., "0x7FFA...") from the call stack. Returns an empty list if no stack trace is available or parsed.
    """
    await ctx.info(f"Request received for stack trace of event index: {event_index}")
    if LOADED_FILE_TYPE != 'pml' or not LOADED_DATA:
        await ctx.error(f"Get stack trace failed: The pre-loaded file '{LOADED_FILENAME}' is not a PML file or no file is loaded.")
        raise TypeError("Operation requires a PML file to be pre-loaded.")

    try:
        events = LOADED_DATA.get('events', [])
        if not 0 <= event_index < len(events):
            await ctx.error(f"Invalid event index: {event_index}. Must be between 0 and {len(events)-1}.")
            raise IndexError(f"Event index {event_index} is out of bounds.")

        event = events[event_index]
        stack_trace_raw = safe_get_attributes(event, ['stacktrace']).get('stacktrace', [])
        if not isinstance(stack_trace_raw, list):
             stack_trace_raw = []
        logger.debug(f"Raw stack trace for event {event_index}: {stack_trace_raw}")
        stack_trace_hex = [f"0x{addr:X}" for addr in stack_trace_raw if isinstance(addr, int)]

        await ctx.info(f"Successfully retrieved stack trace (length: {len(stack_trace_hex)}) for event index {event_index}.")
        logger.debug(f"Formatted stack trace: {stack_trace_hex}")
        return stack_trace_hex

    except IndexError as e:
        logger.debug(f"IndexError retrieving stack trace for index {event_index}.")
        raise e
    except Exception as e:
        await ctx.error(f"Failed to get stack trace for event {event_index} in {LOADED_FILENAME}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving event stack trace: {e}")


@tool_decorator
async def list_pml_processes(ctx: Context) -> List[Dict[str, Any]]:
    """
    Lists summary information for all unique processes found in the loaded PML file data.
    Use 'get_pml_process_details' with a PID from this list to get full details.
    Fails if the pre-loaded file is not a PML file.
    Returns:
        A list of dictionaries, each summarizing a unique process (pid, process_name, image_path).
    """
    await ctx.info("Request received to list processes from pre-loaded PML file.")
    if LOADED_FILE_TYPE != 'pml' or not LOADED_DATA:
        await ctx.error(f"List processes failed: The pre-loaded file '{LOADED_FILENAME}' is not a PML file or no file is loaded.")
        raise TypeError("Operation requires a PML file to be pre-loaded.")

    try:
        process_list = LOADED_DATA.get('processes', [])
        logger.debug(f"Found {len(process_list)} processes in process list.")
        process_summaries = []
        summary_attributes = ['pid', 'process_name', 'image_path']

        for process_obj in process_list:
             summary = safe_get_attributes(process_obj, summary_attributes)
             if 'pid' not in summary or summary['pid'] is None:
                 logger.warning(f"Process object missing PID: {vars(process_obj) if hasattr(process_obj, '__dict__') else process_obj}")
                 continue
             process_summaries.append(summary)

        await ctx.info(f"Found {len(process_summaries)} process summaries in {LOADED_FILENAME}.")
        return process_summaries
    except Exception as e:
        await ctx.error(f"Failed to list processes from {LOADED_FILENAME}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error listing processes: {e}")


@tool_decorator
async def get_pml_process_details(pid: int, ctx: Context) -> Dict[str, Any]:
    """
    Retrieves detailed information for a specific process from the loaded PML data using its PID.
    Searches the list of unique process objects extracted during file load.
    Use 'list_pml_processes' first to see available PIDs.
    Args:
        pid: The Process ID of the process to retrieve details for.
    Returns:
        A dictionary containing detailed properties (e.g., pid, parent_pid, process_name, image_path, command_line, modules_summary) of the specified process. Returns an error if the PID is not found.
    """
    await ctx.info(f"Request received for details of PID: {pid}")
    if LOADED_FILE_TYPE != 'pml' or not LOADED_DATA:
        await ctx.error(f"Get process details failed: The pre-loaded file '{LOADED_FILENAME}' is not a PML file or no file is loaded.")
        raise TypeError("Operation requires a PML file to be pre-loaded.")

    try:
        process_list = LOADED_DATA.get('processes', [])
        process_obj = None
        for p_obj in process_list:
            if safe_get_attributes(p_obj, ['pid']).get('pid') == pid:
                process_obj = p_obj
                break

        logger.debug(f"Looking for PID {pid} in process list. Found: {process_obj is not None}")

        if not process_obj:
            await ctx.error(f"Process with PID {pid} not found in the process list of {LOADED_FILENAME}.")
            raise ValueError(f"Process with PID {pid} not found.")

        process_attributes = [
            'pid', 'parent_pid', 'process_name', 'image_path', 'command_line',
            'user_sid', 'session_id', 'authentication_id',
            'is_64bit', 'create_time', 'exit_time', 'modules'
        ]
        details = safe_get_attributes(process_obj, process_attributes)
        if 'pid' not in details or details['pid'] is None:
             details['pid'] = pid

        modules_list = details.get('modules')
        if isinstance(modules_list, list):
             details['modules_summary'] = [safe_get_attributes(mod, ['path', 'address', 'size']) for mod in modules_list[:5]]
             if 'modules' in details: del details['modules']

        await ctx.info(f"Successfully retrieved details for PID {pid}.")
        logger.debug(f"Process details retrieved for PID {pid}: {details}")
        return details

    except ValueError as e:
        logger.debug(f"ValueError retrieving process details for PID {pid}.")
        raise e
    except Exception as e:
        await ctx.error(f"Failed to get details for PID {pid} in {LOADED_FILENAME}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving process details: {e}")

@tool_decorator
async def get_pml_metadata(ctx: Context) -> Dict[str, Any]:
    """
    Retrieves metadata information potentially stored in the header of the loaded PML file.
    Note: Header extraction may fail depending on the PML file and parser library version.
    Fails if the pre-loaded file is not a PML file.
    Returns:
        A dictionary containing available metadata (e.g., os_version, computer_name) or a message indicating unavailability. Also includes actual loaded event/process counts.
    """
    await ctx.info("Request received for PML metadata.")
    if LOADED_FILE_TYPE != 'pml' or not LOADED_DATA:
        await ctx.error(f"Get metadata failed: The pre-loaded file '{LOADED_FILENAME}' is not a PML file or no file is loaded.")
        raise TypeError("Operation requires a PML file to be pre-loaded.")

    try:
        header = LOADED_DATA.get('header')
        metadata = {}
        if header:
            logger.debug(f"Retrieving metadata from header object: {vars(header) if hasattr(header, '__dict__') else header}")
            header_attributes = [
                'os_version', 'major_version', 'minor_version', 'build_number',
                'computer_name', 'system_root',
                'is_64bit_os', 'number_of_processors', 'total_physical_memory',
                'total_events', # Count from header
            ]
            metadata = safe_get_attributes(header, header_attributes)
            metadata["header_found"] = True
        else:
            await ctx.warning(f"No header information found in the loaded PML file: {LOADED_FILENAME}")
            metadata["header_found"] = False
            metadata["message"] = "No header information available from PML reader."


        metadata['event_count_loaded'] = len(LOADED_DATA.get('events', []))
        metadata['process_count_loaded'] = len(LOADED_DATA.get('processes', []))

        await ctx.info(f"Successfully retrieved metadata from {LOADED_FILENAME}.")
        logger.debug(f"PML metadata retrieved: {metadata}")
        return metadata

    except Exception as e:
        await ctx.error(f"Failed to get metadata from {LOADED_FILENAME}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving PML metadata: {e}")

# --- Analysis Tools ---

@tool_decorator
async def count_events_by_process(ctx: Context) -> Dict[str, int]:
    """
    Counts the number of events associated with each process name in the loaded PML file.
    Process name is retrieved from the event's linked process object.
    Returns:
        A dictionary where keys are process names and values are the event counts. Returns empty dict if no events.
    """
    await ctx.info("Request received to count events by process name.")
    if LOADED_FILE_TYPE != 'pml' or not LOADED_DATA:
        await ctx.error("Operation failed: No PML file is loaded.")
        raise TypeError("Operation requires a PML file to be pre-loaded.")

    try:
        event_counts = defaultdict(int)
        events_list = LOADED_DATA.get('events', [])
        for event in events_list:
            process_obj = getattr(event, 'process', None)
            process_name = safe_get_attributes(process_obj, ['process_name']).get('process_name', 'Unknown') or 'Unknown'
            event_counts[process_name] += 1

        await ctx.info(f"Counted events for {len(event_counts)} processes.")
        logger.debug(f"Event counts by process: {dict(event_counts)}")
        return dict(event_counts)
    except Exception as e:
        await ctx.error(f"Failed to count events by process: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error counting events by process: {e}")

@tool_decorator
async def summarize_operations_by_process(process_name_filter: str, ctx: Context) -> Dict[str, int]:
    """
    Counts the occurrences of each operation type for a specific process name (case-sensitive exact match).
    Process name is retrieved from the event's linked process object.
    Args:
        process_name_filter: The exact process name to summarize operations for.
    Returns:
        A dictionary where keys are operation names and values are the counts for the specified process. Returns empty dict if process not found or has no events.
    """
    await ctx.info(f"Request received to summarize operations for process: {process_name_filter}")
    if LOADED_FILE_TYPE != 'pml' or not LOADED_DATA:
        await ctx.error("Operation failed: No PML file is loaded.")
        raise TypeError("Operation requires a PML file to be pre-loaded.")
    if not process_name_filter:
        await ctx.error("Process name filter cannot be empty.")
        raise ValueError("Process name filter is required.")

    try:
        operation_counts = defaultdict(int)
        events_list = LOADED_DATA.get('events', [])
        event_count_for_process = 0
        for event in events_list:
            process_obj = getattr(event, 'process', None)
            process_name = safe_get_attributes(process_obj, ['process_name']).get('process_name', '') or ''
            # Use exact case-sensitive match as requested
            if process_name == process_name_filter:
                event_count_for_process += 1
                operation = safe_get_attributes(event, ['operation']).get('operation', 'Unknown') or 'Unknown'
                operation_counts[operation] += 1

        await ctx.info(f"Summarized {len(operation_counts)} operation types for process '{process_name_filter}' from {event_count_for_process} events.")
        logger.debug(f"Operation counts for '{process_name_filter}': {dict(operation_counts)}")
        if event_count_for_process == 0:
            await ctx.warning(f"No events found for process name '{process_name_filter}'.")
        return dict(operation_counts)
    except Exception as e:
        await ctx.error(f"Failed to summarize operations for process '{process_name_filter}': {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error summarizing operations: {e}")

@tool_decorator
async def find_events_by_result(
    result_filter: str,
    limit: int = 50,
    *,
    ctx: Context
) -> List[Dict[str, Any]]:
    """
    Finds event summaries matching a specific result value.
    Compares against the event's 'result' attribute.
    If 'result_filter' starts with '0x', it's treated as a hexadecimal integer and compared numerically against integer results.
    Otherwise, it performs a case-insensitive string comparison against the string representation of the event's result.
    Args:
        result_filter: The result value (e.g., 'SUCCESS', 'ACCESS DENIED', '0', '3221225506', '0xc0000022') to filter by.
        limit: Maximum number of event summaries to return.
    Returns:
        A list of dictionaries, each summarizing a matching Procmon event including its 'event_index'. Returns empty list if no matches.
    """
    await ctx.info(f"Request received to find events by result: '{result_filter}', Limit={limit}")
    if LOADED_FILE_TYPE != 'pml' or not LOADED_DATA:
        await ctx.error("Operation failed: No PML file is loaded.")
        raise TypeError("Operation requires a PML file to be pre-loaded.")
    if not result_filter:
        await ctx.error("Result filter cannot be empty.")
        raise ValueError("Result filter is required.")

    try:
        filtered_event_summaries = []
        count = 0
        events_list = LOADED_DATA.get('events', [])
        logger.debug(f"Starting event search by result '{result_filter}' on {len(events_list)} events.")

        # Pre-process filter_result
        filter_result_lower_str = None
        filter_result_int = None
        is_hex_filter = False
        if result_filter.lower().startswith("0x"):
            try:
                filter_result_int = int(result_filter, 16)
                is_hex_filter = True
                logger.debug(f"Interpreting result_filter '{result_filter}' as hex integer: {filter_result_int} (0x{filter_result_int:X})")
            except ValueError:
                logger.warning(f"Could not parse result_filter '{result_filter}' as hex, treating as string.")
                filter_result_lower_str = result_filter.lower()
        else:
            filter_result_lower_str = result_filter.lower()

        for idx, event in enumerate(events_list):
            if count >= limit:
                logger.debug(f"Query limit ({limit}) reached.")
                break

            event_attrs = safe_get_attributes(event, ['result', 'timestamp', 'pid', 'operation', 'path'])
            result_val = event_attrs.get('result')

            match = False
            if is_hex_filter:
                event_result_int = None
                if isinstance(result_val, int):
                    event_result_int = result_val
                elif isinstance(result_val, str) and result_val.isdigit():
                     try: event_result_int = int(result_val)
                     except ValueError: pass

                if event_result_int is not None and event_result_int == filter_result_int:
                    match = True
                    logger.debug(f"Event {idx}: Matched hex filter. Event result (int): {event_result_int}, Filter int: {filter_result_int}")

            elif filter_result_lower_str is not None:
                result_str = str(result_val)
                if result_str.lower() == filter_result_lower_str:
                    match = True
                    logger.debug(f"Event {idx}: Matched string filter. Event result_str.lower(): '{result_str.lower()}', Filter lower: '{filter_result_lower_str}'")

            if match:
                 process_obj = getattr(event, 'process', None)
                 process_name = safe_get_attributes(process_obj, ['process_name']).get('process_name', '') or ''
                 pid = event_attrs.get('pid')
                 if pid is None and process_obj: pid = safe_get_attributes(process_obj, ['pid']).get('pid')

                 event_summary = {
                     'event_index': idx,
                     'timestamp': str(event_attrs.get('timestamp')),
                     'process_name': process_name,
                     'pid': pid,
                     'operation': event_attrs.get('operation', ''),
                     'path': event_attrs.get('path', ''),
                     'result': result_val,
                 }
                 filtered_event_summaries.append(event_summary)
                 count += 1

        await ctx.info(f"Found {len(filtered_event_summaries)} events matching result '{result_filter}'.")
        return filtered_event_summaries

    except Exception as e:
        await ctx.error(f"Failed to find events by result '{result_filter}': {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error finding events by result: {e}")

@tool_decorator
async def get_process_tree(ctx: Context) -> Dict[int, Dict[str, Any]]:
    """
    Constructs and returns the process tree based on parent PIDs found in the loaded PML data.
    Returns:
        A dictionary representing the process tree. Keys are PIDs. Values are dictionaries containing
        'process_name', 'image_path', and 'children' (a dictionary mapping child PIDs to their nodes).
        Processes with no known parent in the log are listed under the root.
    """
    await ctx.info("Request received to get process tree.")
    if LOADED_FILE_TYPE != 'pml' or not LOADED_DATA:
        await ctx.error("Operation failed: No PML file is loaded.")
        raise TypeError("Operation requires a PML file to be pre-loaded.")

    try:
        process_list = LOADED_DATA.get('processes', [])
        if not process_list:
            await ctx.warning("No process information available to build tree.")
            return {}

        process_map = {}
        for p_obj in process_list:
            pid = safe_get_attributes(p_obj, ['pid']).get('pid')
            if pid is not None:
                process_map[pid] = {
                    'obj': p_obj,
                    'children': []
                }

        roots = []
        all_pids = set(process_map.keys())
        for pid, p_data in process_map.items():
            parent_pid = safe_get_attributes(p_data['obj'], ['parent_pid']).get('parent_pid')
            if parent_pid is not None and parent_pid in process_map:
                process_map[parent_pid]['children'].append(pid)
            elif parent_pid is None or parent_pid not in all_pids:
                 if pid not in roots:
                    roots.append(pid)


        def build_tree_node(pid):
            p_data = process_map.get(pid)
            if not p_data: return None
            p_obj = p_data['obj']
            node_attrs = safe_get_attributes(p_obj, ['process_name', 'image_path'])
            node = {
                'pid': pid,
                'process_name': node_attrs.get('process_name', 'Unknown'),
                'image_path': node_attrs.get('image_path'),
                'children': {}
            }
            children_pids = sorted(p_data.get('children', []))
            for child_pid in children_pids:
                child_node = build_tree_node(child_pid)
                if child_node:
                     node['children'][child_pid] = child_node
            if not node['children']:
                 del node['children']
            return node

        process_tree_output = {}
        for root_pid in sorted(roots):
            root_node = build_tree_node(root_pid)
            if root_node:
                process_tree_output[root_pid] = root_node

        await ctx.info(f"Constructed process tree with {len(roots)} root(s).")
        logger.debug(f"Process tree: {process_tree_output}")
        return process_tree_output

    except Exception as e:
        await ctx.error(f"Failed to build process tree: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error building process tree: {e}")


# --- Main Execution Block ---
if __name__ == "__main__":
    if not MCP_SDK_AVAILABLE:
        print("Error: Model Context Protocol SDK (modelcontextprotocol) is not installed. Cannot start server.")
        exit(1)

    parser = argparse.ArgumentParser(description="MCP Server for analyzing a specific Procmon file.")
    parser.add_argument("--allowed-dir", required=True, help="REQUIRED: The secure base directory containing Procmon files.")
    parser.add_argument("--load-file", required=False, help="Optional: The specific PML or PMC filename (relative to --allowed-dir) to pre-load and analyze.")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse transport), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8081,
                        help="Port to run MCP server on (only used for sse transport), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    parser.add_argument("--debug", action='store_true', help="Enable debug logging.")

    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.getLogger().setLevel(log_level)
    logger.info(f"Logging level set to: {logging.getLevelName(log_level)}")

    if not os.path.isdir(args.allowed_dir):
        logger.critical(f"Error: The specified allowed directory does not exist: {args.allowed_dir}")
        exit(1)

    ALLOWED_DIR_CONFIG = os.path.abspath(args.allowed_dir)
    logger.info(f"Allowed Directory set to: {ALLOWED_DIR_CONFIG}")

    if args.load_file:
        try:
            LOADED_DATA, LOADED_FILE_TYPE = load_and_validate_file(ALLOWED_DIR_CONFIG, args.load_file)
            LOADED_FILENAME = args.load_file
            logger.info(f"Successfully pre-loaded {LOADED_FILE_TYPE} file: {LOADED_FILENAME}")
            if args.debug and LOADED_DATA:
                 if LOADED_FILE_TYPE == 'pml':
                      logger.debug(f"PML Load Summary: Events={len(LOADED_DATA.get('events',[]))}, Processes={len(LOADED_DATA.get('processes',[]))}, Header={LOADED_DATA.get('header') is not None}")
                 elif LOADED_FILE_TYPE == 'pmc':
                      logger.debug(f"PMC Load Summary: Rules={len(LOADED_DATA.get('FilterRules',[]))}")

        except (ValueError, PermissionError, FileNotFoundError, TypeError) as e:
            logger.critical(f"Error pre-loading file specified by --load-file: {e}")
            exit(1)
        except RuntimeError as e:
             logger.critical(f"Error: {e}")
             exit(1)
        except Exception as e:
            logger.critical(f"An unexpected error occurred during file pre-loading: {e}", exc_info=args.debug)
            exit(1)
    else:
        logger.info("No specific file pre-loaded. Tools operating on loaded data will report errors.")

    server_started = False
    try:
        if args.transport == "sse":
            if hasattr(mcp, 'settings'):
                logger.info("Configuring MCP for SSE transport...")
                mcp.settings.host = args.mcp_host
                mcp.settings.port = args.mcp_port
                mcp.settings.log_level = logging.getLevelName(log_level)
                logger.info(f"  MCP Host: {mcp.settings.host}")
                logger.info(f"  MCP Port: {mcp.settings.port}")
                logger.info(f"  MCP Log Level: {mcp.settings.log_level}")
            else:
                 logger.warning("MCP object does not have 'settings' attribute. Cannot configure host/port/log_level for SSE.")

            logger.info("Starting MCP server with SSE transport...")
            mcp.run(transport="sse")
            server_started = True

        else: # Default to stdio
            logger.info("Starting MCP server with STDIO transport...")
            mcp.run() # No arguments needed for stdio
            server_started = True

    except Exception as e:
        logger.critical(f"Failed during server startup: {e}", exc_info=args.debug)

    if not server_started:
         logger.critical("Server did not start.")
         exit(1)
    else:
         logger.info("Server finished.")
