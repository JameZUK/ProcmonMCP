# -*- coding: utf-8 -*-
import os
import logging
import argparse
from typing import List, Dict, Any, Optional, Tuple, Iterator, IO
import io
import asyncio
import time # For timing the loading
from collections import defaultdict # For counting
import dataclasses # For XML data structures
import re # For regex filtering
from datetime import datetime, timezone # For time-based filtering & UTC timestamps

# Standard library compression formats
import gzip
import bz2
import lzma

# --- XML Parser Choice ---
LXML_AVAILABLE = False
try:
    from lxml import etree as ET_impl # Use lxml etree as the primary implementation
    LXML_AVAILABLE = True
    # Logger defined after basicConfig below
except ImportError:
    import xml.etree.ElementTree as ET_impl # Fallback to standard library
    # Logger defined after basicConfig below

# --- Basic Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
logger = logging.getLogger(__name__) # Define logger after basicConfig

# Log XML parser choice after logger is defined
if LXML_AVAILABLE:
    logger.info("Using lxml library for XML parsing (recommended).")
else:
    logger.warning("lxml library not found. Falling back to standard xml.etree.ElementTree for XML parsing.")
    logger.warning("For better performance and memory efficiency with large XML files, install lxml: pip install lxml")


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
        # Basic mock context for offline execution/testing
        async def info(self, msg): logger.info(f"(mock ctx): {msg}")
        async def error(self, msg): logger.error(f"(mock ctx): {msg}")
        async def warning(self, msg): logger.warning(f"(mock ctx): {msg}")

# XML parser code is integrated
PROCMON_XML_PARSER_AVAILABLE = True

# --- Constants ---
PROCMON_TIMESTAMP_FORMAT = "%H:%M:%S.%f"
PROGRESS_REPORT_INTERVAL = 250000 # Report progress every N events during loading/processing

# --- String Interning Helper ---
class StringInterner:
    """Manages mapping strings to unique integer IDs and back."""
    def __init__(self):
        self.str_to_id: Dict[str, int] = {}
        self.id_to_str: List[str] = []
        self.next_id: int = 0

    def get_id(self, s: Optional[str]) -> Optional[int]:
        """Gets the integer ID for a string, adding it if new. Returns None for None input."""
        if s is None:
            return None
        if s not in self.str_to_id:
            self.str_to_id[s] = self.next_id
            self.id_to_str.append(s)
            self.next_id += 1
        return self.str_to_id[s]

    def get_str(self, id_val: Optional[int]) -> Optional[str]:
        """Gets the string for an integer ID. Returns None for None input or invalid ID."""
        if id_val is None or not (0 <= id_val < self.next_id):
            return None
        return self.id_to_str[id_val]

# --- XML Parser Data Structures (Used during initial parsing) ---
@dataclasses.dataclass
class StackFrame:
    """Represents a single frame in a call stack parsed from a <frame> element."""
    depth: Optional[int] = None
    address: Optional[str] = None
    path: Optional[str] = None
    location: Optional[str] = None

    @classmethod
    def from_xml_element(cls, elem: ET_impl.Element) -> 'StackFrame':
        depth_text = elem.findtext('depth')
        try: depth = int(depth_text) if depth_text and depth_text.isdigit() else None
        except (ValueError, TypeError): depth = None
        address = elem.findtext('address')
        path = elem.findtext('path')
        location = elem.findtext('location')
        return cls(depth=depth, address=address, path=path, location=location)

    def to_dict(self) -> Dict[str, Any]:
        """Convert StackFrame to dictionary for tool output."""
        return dataclasses.asdict(self)

    def to_optimized_list(self, path_interner: StringInterner, location_interner: StringInterner) -> list:
        """Converts StackFrame to a more compact list representation for storage."""
        return [
            self.depth,
            self.address, # Keep address as string
            path_interner.get_id(self.path),
            location_interner.get_id(self.location)
        ]

@dataclasses.dataclass
class ProcessInfo:
    """Represents information about a single process from the <processlist>."""
    process_index: Optional[int] = None
    process_id: Optional[int] = None
    parent_process_id: Optional[int] = None
    parent_process_index: Optional[int] = None
    authentication_id: Optional[str] = None
    create_time: Optional[str] = None # Keep as string, parse if needed
    finish_time: Optional[str] = None # Keep as string, parse if needed
    is_virtualized: Optional[bool] = None
    is_64bit: Optional[bool] = None
    integrity: Optional[str] = None
    owner: Optional[str] = None
    process_name: Optional[str] = None
    image_path: Optional[str] = None
    command_line: Optional[str] = None
    company_name: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None

    @property
    def pid(self): return self.process_id
    @property
    def parent_pid(self): return self.parent_process_id
    @property
    def user_sid(self): return self.owner

    @staticmethod
    def _safe_find_text(elem: ET_impl.Element, tag: str) -> Optional[str]:
        child = elem.find(tag)
        return child.text.strip() if child is not None and child.text else None
    @staticmethod
    def _safe_text_to_int(text: Optional[str]) -> Optional[int]:
        if text is None: return None
        text = text.strip()
        if text.startswith('0x'):
            try: return int(text, 16)
            except (ValueError, TypeError): return None
        elif text.isdigit() or (text.startswith('-') and text[1:].isdigit()):
            try: return int(text)
            except (ValueError, TypeError): return None
        else: return None
    @staticmethod
    def _safe_text_to_bool(text: Optional[str]) -> Optional[bool]:
        if text:
            text = text.strip()
            if text == '1': return True
            if text == '0': return False
        return None

    @classmethod
    def from_xml_element(cls, elem: ET_impl.Element) -> 'ProcessInfo':
        data = {}
        data['process_index'] = cls._safe_text_to_int(cls._safe_find_text(elem, 'ProcessIndex'))
        data['process_id'] = cls._safe_text_to_int(cls._safe_find_text(elem, 'ProcessId'))
        data['parent_process_id'] = cls._safe_text_to_int(cls._safe_find_text(elem, 'ParentProcessId'))
        data['parent_process_index'] = cls._safe_text_to_int(cls._safe_find_text(elem, 'ParentProcessIndex'))
        data['authentication_id'] = cls._safe_find_text(elem, 'AuthenticationId')
        data['create_time'] = cls._safe_find_text(elem, 'CreateTime')
        data['finish_time'] = cls._safe_find_text(elem, 'FinishTime')
        data['is_virtualized'] = cls._safe_text_to_bool(cls._safe_find_text(elem, 'IsVirtualized'))
        data['is_64bit'] = cls._safe_text_to_bool(cls._safe_find_text(elem, 'Is64bit'))
        data['integrity'] = cls._safe_find_text(elem, 'Integrity')
        data['owner'] = cls._safe_find_text(elem, 'Owner')
        data['process_name'] = cls._safe_find_text(elem, 'ProcessName')
        data['image_path'] = cls._safe_find_text(elem, 'ImagePath')
        data['command_line'] = cls._safe_find_text(elem, 'CommandLine')
        data['company_name'] = cls._safe_find_text(elem, 'CompanyName')
        data['version'] = cls._safe_find_text(elem, 'Version')
        data['description'] = cls._safe_find_text(elem, 'Description')
        return cls(**data)

# --- XML Parsing Logic ---
def _clear_elem(elem: ET_impl.Element):
    """Helper to clear element memory using lxml/ET specific methods."""
    elem.clear()
    if LXML_AVAILABLE:
        while elem.getprevious() is not None:
            try:
                parent = elem.getparent()
                if parent is not None: del parent[0]
                else: break
            except (IndexError, AttributeError): break

def _parse_xml_processes_only(source_stream: IO[bytes]) -> Dict[int, ProcessInfo]:
    """
    Parses only the <processlist> from the XML stream and returns the process dictionary.
    Stops parsing after the </processlist> tag.
    """
    processes_dict: Dict[int, ProcessInfo] = {}
    parsing_stage = "seeking_procmon"
    tags_of_interest = ('process', 'processlist', 'procmon') # Only need process tags
    try:
        context = ET_impl.iterparse(source_stream, events=('end',), tag=tags_of_interest)
    except Exception as e:
        logger.error(f"Unexpected error initializing XML parser for process list: {e}", exc_info=True)
        raise RuntimeError("Failed to initialize XML parser for process list") from e

    try:
        for event_type, elem in context:
            if parsing_stage == "seeking_procmon":
                 if elem.tag == 'procmon': # Found the end of the root, shouldn't happen first
                     logger.warning("Found end of procmon before processlist.")
                     break
                 # Assume we are inside procmon if we get process or processlist
                 parsing_stage = "seeking_processlist"

            if parsing_stage == "seeking_processlist":
                if elem.tag == 'process':
                    parsing_stage = "parsing_processlist" # Fallthrough to parse
                elif elem.tag == 'processlist':
                     # Found end of processlist while seeking it? Means it was empty.
                     logger.info("Found empty <processlist>.")
                     _clear_elem(elem)
                     break # Stop parsing processes

            if parsing_stage == "parsing_processlist":
                if elem.tag == 'process':
                    try:
                        proc_info = ProcessInfo.from_xml_element(elem)
                        if proc_info.process_index is not None and proc_info.process_index >= 0:
                            processes_dict[proc_info.process_index] = proc_info
                        else: logger.warning(f"Parsed process element with invalid index.")
                    except Exception as e: logger.warning(f"Failed to parse <process> element: {e}", exc_info=False)
                    _clear_elem(elem)
                elif elem.tag == 'processlist':
                    # Finished parsing the process list normally
                    logger.debug(f"Finished parsing <processlist> tag.")
                    _clear_elem(elem)
                    break # Stop parsing after processlist is done

            # Stop if we somehow reach the end of the document early
            if elem.tag == 'procmon':
                 logger.warning("Reached end of <procmon> while parsing processes.")
                 break

    except ET_impl.XMLSyntaxError as e: logger.error(f"XML Parse Error during process parsing: {e}"); raise
    except Exception as e: logger.error(f"Unexpected error during process parsing: {e}", exc_info=True); raise

    return processes_dict


def _parse_xml_stream_for_loading(
    source_stream: IO[bytes],
    interners: Dict[str, StringInterner],
    processes: Dict[int, ProcessInfo] # Pass in the pre-loaded processes
) -> Iterator[Dict[str, Any]]:
    """
    Internal helper optimized for initial loading into memory.
    Parses events and converts them to optimized dictionaries using interners.
    Assumes process list is already parsed and passed in `processes`.

    Yields:
        Optimized event dictionaries.
    """
    parsing_stage = "seeking_eventlist" # Start assuming processes are done
    tags_of_interest = ('event', 'eventlist', 'procmon') # Only need event-related tags now
    try:
        context = ET_impl.iterparse(source_stream, events=('end',), tag=tags_of_interest)
    except Exception as e:
        logger.error(f"Unexpected error initializing XML parser for event loading: {e}", exc_info=True)
        raise RuntimeError("Failed to initialize XML parser for events") from e

    event_count = 0
    start_time = time.time()
    try:
        for event_type, elem in context:
            # Skip elements until we are inside the eventlist
            if parsing_stage == "seeking_eventlist":
                 if elem.tag == 'eventlist':
                      logger.debug("Entered <eventlist> for event loading.")
                      parsing_stage = "parsing_events"
                      _clear_elem(elem) # Clear the eventlist tag itself
                      continue # Move to next element
                 elif elem.tag == 'procmon': # Reached end before finding eventlist
                      logger.warning("Reached end of <procmon> before finding <eventlist>.")
                      break
                 # Ignore other tags like 'process' if they somehow appear here
                 _clear_elem(elem)
                 continue

            if parsing_stage == "parsing_events":
                if elem.tag == 'event':
                    try:
                        # 1. Parse XML element into temporary ProcmonEvent object
                        # Pass processes dict for enrichment during parsing
                        temp_event = ProcmonEvent.from_xml_element(elem, processes)

                        # 2. Convert ProcmonEvent to optimized dictionary using interners
                        opt_event: Dict[str, Any] = {}
                        opt_event['seq'] = temp_event.sequence_number
                        opt_event['pid'] = temp_event.pid
                        opt_event['tid'] = temp_event.tid
                        opt_event['ppid'] = temp_event.parent_pid
                        opt_event['dur'] = temp_event.duration
                        ts = temp_event.timestamp # Access property to parse
                        opt_event['ts'] = ts.replace(tzinfo=timezone.utc).timestamp() if ts else None
                        opt_event['op_id'] = interners['operation'].get_id(temp_event.operation)
                        opt_event['path_id'] = interners['path'].get_id(temp_event.path)
                        opt_event['res_id'] = interners['result'].get_id(temp_event.result)
                        opt_event['cat_id'] = interners['category'].get_id(temp_event.category)
                        opt_event['pname_id'] = interners['process_name'].get_id(temp_event.process_name)
                        opt_event['detail'] = temp_event.detail # Keep detail string

                        if temp_event.stack:
                            opt_event['stack'] = [
                                frame.to_optimized_list(interners['stack_path'], interners['stack_location'])
                                for frame in temp_event.stack
                            ]
                        else:
                            opt_event['stack'] = None

                        yield opt_event
                        event_count += 1
                        if event_count % PROGRESS_REPORT_INTERVAL == 0:
                             elapsed = time.time() - start_time
                             logger.info(f" Loaded {event_count} events... ({elapsed:.1f}s)")

                    except Exception as e: logger.warning(f"Failed to parse/convert <event> element: {e}", exc_info=False)
                    _clear_elem(elem) # Clear event element after processing
                elif elem.tag == 'eventlist':
                    logger.info(f"Finished processing <eventlist>.")
                    _clear_elem(elem)
                    # Continue parsing until </procmon> in case of trailing elements
                elif elem.tag == 'procmon':
                    logger.debug("Reached end of <procmon> during event loading.")
                    break # Stop iteration

        logger.info(f"Total events loaded and optimized: {event_count}")

    except ET_impl.XMLSyntaxError as e: logger.error(f"XML Parse Error during event loading stream: {e}"); raise
    except Exception as e: logger.error(f"Unexpected error during event loading stream: {e}", exc_info=True); raise


# --- Global State ---
ALLOWED_DIR_CONFIG: Optional[str] = None
LOADED_FILENAME: Optional[str] = None
LOADED_FILE_TYPE: Optional[str] = None # Should always be 'xml' if loaded
LOADED_COMPRESSION: Optional[str] = None
# Store Processes as objects (relatively small number)
LOADED_PROCESSES: Optional[Dict[int, ProcessInfo]] = None
# Store Events as optimized dictionaries
LOADED_EVENTS: Optional[List[Dict[str, Any]]] = None
# Store String Interning Maps
GLOBAL_INTERNERS: Dict[str, StringInterner] = {}


# --- Setup MCP ---
if MCP_SDK_AVAILABLE:
    mcp = FastMCP(
        "ProcmonXmlTool",
        description="A tool to analyze a specific, pre-loaded Procmon XML log file (plain or compressed) using in-memory optimization." # Updated description
    )
else:
    mcp = MockMCP(
         "ProcmonXmlTool (Mock)",
         description="Mock Tool: Analyzes pre-loaded Procmon XML files (optimized in-memory)." # Updated description
    )

# --- Security Helper ---
def get_secure_path(filename: str) -> str:
    """ Validates filename relative to ALLOWED_FILE_DIR and returns absolute path. """
    if not ALLOWED_DIR_CONFIG: raise RuntimeError("Internal Error: Allowed directory configuration is missing.")
    if not filename: raise ValueError("Filename cannot be empty.")
    if os.path.isabs(filename): raise ValueError("Invalid filename format: Absolute paths are not allowed.")
    try:
        full_path = os.path.join(ALLOWED_DIR_CONFIG, filename)
        normalized_allowed_dir = os.path.abspath(ALLOWED_DIR_CONFIG)
        normalized_full_path = os.path.abspath(full_path)
        logger.debug(f"Checking path: {normalized_full_path} against allowed: {normalized_allowed_dir}")
        common_prefix = os.path.commonpath([normalized_allowed_dir, normalized_full_path])
        if common_prefix != normalized_allowed_dir: raise PermissionError(f"Access denied: File '{filename}' resolves outside allowed directory.")
        if not os.path.exists(normalized_full_path): raise FileNotFoundError(f"File not found: {filename} (resolves to {normalized_full_path})")
        if not os.path.isfile(normalized_full_path): raise ValueError(f"Path exists but is not a file: {filename} (resolves to {normalized_full_path})")
        logger.debug(f"Path validated: {normalized_full_path}")
        return normalized_full_path
    except ValueError as e: logger.error(f"Path validation error for '{filename}': {e}"); raise ValueError(f"Invalid path specified: {filename}") from e


# --- Loading Helper (Loads Processes AND Optimized Events) ---
def load_and_validate_file(allowed_dir: str, filename_relative: str):
    """
    Loads XML file: Parses processes, then streams events, converting them
    to an optimized in-memory format using string interning. Stores results globally.

    Raises:
        FileNotFoundError, ValueError, PermissionError, RuntimeError, ET_impl.XMLSyntaxError
    """
    global LOADED_FILENAME, LOADED_FILE_TYPE, LOADED_COMPRESSION, LOADED_PROCESSES, LOADED_EVENTS, GLOBAL_INTERNERS

    abs_full_path = get_secure_path(filename_relative)
    fname_lower = filename_relative.lower()
    file_type: str = "xml"
    compression: Optional[str] = None

    # Determine compression type
    if fname_lower.endswith(".xml"): compression = None
    elif fname_lower.endswith(".xml.gz"): compression = 'gz'
    elif fname_lower.endswith(".xml.bz2"): compression = 'bz2'
    elif fname_lower.endswith(".xml.xz"): compression = 'xz'
    elif fname_lower.endswith(".gz"): compression = 'gz'; logger.warning(f"Assuming '.gz' file contains XML.")
    elif fname_lower.endswith(".bz2"): compression = 'bz2'; logger.warning(f"Assuming '.bz2' file contains XML.")
    elif fname_lower.endswith(".xz"): compression = 'xz'; logger.warning(f"Assuming '.xz' file contains XML.")
    else: raise ValueError(f"Unsupported file extension: {fname_lower}. Expecting .xml, .xml.gz, .xml.bz2, .xml.xz.")

    start_time = time.time()
    processes_dict: Dict[int, ProcessInfo] = {}
    optimized_events: List[Dict[str, Any]] = []

    # Initialize interners
    interners: Dict[str, StringInterner] = {
        "process_name": StringInterner(),
        "operation": StringInterner(),
        "path": StringInterner(),
        "result": StringInterner(),
        "category": StringInterner(),
        "stack_path": StringInterner(),
        "stack_location": StringInterner(),
    }

    try:
        open_func: Any = open
        if compression == 'gz': open_func = gzip.open
        elif compression == 'bz2': open_func = bz2.open
        elif compression == 'xz': open_func = lzma.open

        comp_str = f" ({compression} compressed)" if compression else ""
        logger.info(f"Loading and optimizing{comp_str} XML file: {abs_full_path}")

        # --- Pass 1: Parse Processes Only ---
        logger.info("Parsing process list...")
        with open_func(abs_full_path, "rb") as f_stream:
             # Call the dedicated process parsing function
             processes_dict = _parse_xml_processes_only(f_stream)
             if processes_dict is None: processes_dict = {}; logger.error("Failed to parse process dictionary.") # Should not happen if func raises error
        logger.info(f"Finished parsing process list: {len(processes_dict)} processes found.")

        # --- Pass 2: Parse Events and Optimize ---
        logger.info("Parsing and optimizing events...")
        with open_func(abs_full_path, "rb") as f_stream:
             # Use the dedicated loading streamer which applies interning
             # Pass the already loaded processes_dict
             event_iterator = _parse_xml_stream_for_loading(f_stream, interners, processes_dict)
             # Consume the iterator and store optimized events
             optimized_events = list(event_iterator)

        # --- Store results globally ---
        LOADED_FILENAME = filename_relative
        LOADED_FILE_TYPE = file_type
        LOADED_COMPRESSION = compression
        LOADED_PROCESSES = processes_dict
        LOADED_EVENTS = optimized_events
        GLOBAL_INTERNERS = interners # Store interners for later lookup

        end_time = time.time()
        logger.info(f"Successfully loaded and optimized {len(optimized_events)} events from {filename_relative}.")
        logger.info(f"Total loading and optimization time: {end_time - start_time:.2f} seconds.")
        # Log interner stats for debugging memory usage
        if logger.isEnabledFor(logging.DEBUG):
            for name, interner in interners.items():
                logger.debug(f" Interner '{name}': {interner.next_id} unique strings.")

    except FileNotFoundError as e: logger.error(f"File not found: {abs_full_path}"); raise
    except PermissionError as e: logger.error(f"Permission denied: {abs_full_path}"); raise
    except ET_impl.XMLSyntaxError as e: logger.error(f"XML Syntax Error in {filename_relative}: {e}", exc_info=True); raise RuntimeError(f"Invalid XML: {e}") from e
    # Corrected Exception Handling for Decompression
    except (gzip.BadGzipFile, OSError, lzma.LZMAError) as e: # Catch OSError for bz2, keep others specific
         logger.error(f"Decompression or I/O error for {filename_relative}: {e}")
         # Check if it's specifically a bz2 error if needed, otherwise treat as general decompression/IO error
         if isinstance(e, bz2.BZ2File) and 'Not a bzip2 file' in str(e): # Example check
             raise RuntimeError(f"File '{filename_relative}' is not a valid BZ2 file.") from e
         raise RuntimeError(f"Decompression or file read failed for '{filename_relative}'.") from e
    except Exception as e:
         logger.error(f"Error loading/optimizing file {filename_relative}: {e}", exc_info=True)
         LOADED_FILENAME = None; LOADED_FILE_TYPE = None; LOADED_COMPRESSION = None; LOADED_PROCESSES = None; LOADED_EVENTS = None; GLOBAL_INTERNERS = {}
         raise RuntimeError(f"Failed to load/optimize file: {e}") from e

# --- Helper to Safely Get Attributes (Not needed for optimized dicts) ---

# --- Helper to get string from ID ---
def get_string(interner_name: str, id_val: Optional[int]) -> Optional[str]:
    """Looks up a string from its ID using the global interners."""
    if id_val is None: return None
    interner = GLOBAL_INTERNERS.get(interner_name)
    if interner:
        return interner.get_str(id_val)
    logger.warning(f"Interner '{interner_name}' not found.")
    return f"<Unknown ID:{id_val}>"

# --- Helper to get ID from string ---
def get_id(interner_name: str, s: Optional[str]) -> Optional[int]:
    """Looks up an ID from its string using the global interners. Does NOT add new strings."""
    if s is None: return None
    interner = GLOBAL_INTERNERS.get(interner_name)
    if interner:
        # Only return existing IDs during filtering
        return interner.str_to_id.get(s) # Return None if string wasn't seen during load
    logger.warning(f"Interner '{interner_name}' not found.")
    return None


# --- MCP Tools (Adapted for In-Memory Optimized Data) ---
tool_decorator = mcp.tool() if MCP_SDK_AVAILABLE else lambda func: func

@tool_decorator
async def get_loaded_file_summary(ctx: Context) -> Dict[str, Any]:
    """
    Returns a basic summary of the pre-loaded Procmon XML file.
    Event count is now accurate as events are loaded in memory.
    """
    await ctx.info(f"Request received for summary of pre-loaded file.")
    if not LOADED_PROCESSES or LOADED_EVENTS is None or not LOADED_FILENAME or LOADED_FILE_TYPE != 'xml':
        await ctx.error("No Procmon XML file data was pre-loaded via --load-file.")
        raise RuntimeError("Operation failed: No Procmon file data is loaded.")

    summary = {
        "loaded_filename": LOADED_FILENAME, "file_type": LOADED_FILE_TYPE,
        "compression": LOADED_COMPRESSION,
        "process_count": len(LOADED_PROCESSES),
        "event_count": len(LOADED_EVENTS), # Now we have the count
        "os_version": "N/A (XML)", "computer_name": "N/A (XML)", "is_64bit_os": None
    }
    try:
        # Add interner stats for context
        summary["interner_stats"] = {name: interner.next_id for name, interner in GLOBAL_INTERNERS.items()}
        await ctx.info(f"Successfully generated summary for {LOADED_FILENAME}.")
        return summary
    except Exception as e:
        await ctx.error(f"Error generating summary for {LOADED_FILENAME}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error generating summary: {e}")

@tool_decorator
async def query_events(
    # Standard Filters
    filter_process: Optional[str] = None,
    filter_operation: Optional[str] = None,
    filter_result: Optional[str] = None,
    filter_path_contains: Optional[str] = None,
    filter_process_contains: Optional[str] = None,
    # Time Filters (Unix Timestamp float or HH:MM:SS.ffffff string)
    filter_start_time: Optional[Any] = None, # Allow float or string
    filter_end_time: Optional[Any] = None,   # Allow float or string
    # Regex Filters (Caution: Performance)
    filter_path_regex: Optional[str] = None,
    filter_process_regex: Optional[str] = None,
    filter_detail_regex: Optional[str] = None,
    # Stack Filter (Caution: Performance)
    filter_stack_module_path: Optional[str] = None,
    # Limit
    limit: int = 50,
    *,
    ctx: Context
) -> List[Dict[str, Any]]:
    """
    Queries events from the optimized in-memory data, applying multiple filters (AND logic).
    Returns event summaries including the event index. Use 'get_event_details'/'get_event_stack_trace' with index.

    Filtering Behavior:
    - All provided filters must match (AND logic).
    - String contains filters are case-insensitive. Exact match filters (process, op, result) use the interned IDs.
    - Result filter handles hex ('0x...') or case-insensitive string matching before ID lookup.
    - Time filters accept HH:MM:SS.ffffff strings (parsed to time) or float Unix timestamps. Assumes same day if only time string is given.
    - Regex filters apply to the original string values (requires ID lookup). WARNING: Can impact performance.
    - Stack module filter checks original string paths in stack frames. WARNING: Very performance intensive.

    Args:
        filter_process: Exact process name.
        filter_operation: Exact operation name.
        filter_result: Result string or hex '0x...' code.
        filter_path_contains: Substring in path (case-insensitive).
        filter_process_contains: Substring in process name (case-insensitive).
        filter_start_time: Minimum event time (float timestamp or HH:MM:SS.ffffff string).
        filter_end_time: Maximum event time (float timestamp or HH:MM:SS.ffffff string).
        filter_path_regex: Regex pattern for Path field.
        filter_process_regex: Regex pattern for Process Name field.
        filter_detail_regex: Regex pattern for Detail field.
        filter_stack_module_path: Substring in any stack frame's module path (case-insensitive). VERY SLOW.
        limit: Maximum number of event summaries to return.

    Returns:
        List of dictionaries, each summarizing a matching event including 'event_index'.
    """
    await ctx.info(f"Request received to query in-memory events with multiple filters. Limit={limit}")
    if logger.isEnabledFor(logging.DEBUG):
         filters_applied = {k:v for k,v in locals().items() if k.startswith('filter_') and v is not None}
         logger.debug(f"Filters Applied: {filters_applied}")

    if LOADED_EVENTS is None or LOADED_PROCESSES is None or not GLOBAL_INTERNERS:
        await ctx.error(f"Query failed: Event data or interners not loaded.")
        raise TypeError("Operation requires optimized event data to be loaded.")

    try:
        filtered_event_summaries = []
        count = 0
        start_time = time.time() # For timing

        # --- Pre-process Filters ---
        path_regex = re.compile(filter_path_regex) if filter_path_regex else None
        process_regex = re.compile(filter_process_regex) if filter_process_regex else None
        detail_regex = re.compile(filter_detail_regex) if filter_detail_regex else None
        start_ts: Optional[float] = None
        end_ts: Optional[float] = None
        # Time parsing
        try:
            if isinstance(filter_start_time, str):
                # Parse only time part if no date is present
                dt_obj = datetime.strptime(filter_start_time, PROCMON_TIMESTAMP_FORMAT)
                start_ts = (dt_obj.hour * 3600 + dt_obj.minute * 60 + dt_obj.second + dt_obj.microsecond / 1e6)
                # Note: This comparison assumes all events fall on the same day or uses relative time.
                # For absolute timestamps, store full float timestamp in event_dict['ts']
                logger.warning("Comparing only time part for string timestamp filters.")
            elif isinstance(filter_start_time, (int, float)):
                start_ts = float(filter_start_time)

            if isinstance(filter_end_time, str):
                dt_obj = datetime.strptime(filter_end_time, PROCMON_TIMESTAMP_FORMAT)
                end_ts = (dt_obj.hour * 3600 + dt_obj.minute * 60 + dt_obj.second + dt_obj.microsecond / 1e6)
                logger.warning("Comparing only time part for string timestamp filters.")
            elif isinstance(filter_end_time, (int, float)):
                end_ts = float(filter_end_time)
        except ValueError as e:
            await ctx.error(f"Invalid time format for start/end time filter: {e}. Expected HH:MM:SS.ffffff or float timestamp.")
            raise ValueError("Invalid time format for filter.") from e

        # Get IDs for exact match filters (case-sensitive lookup in interner)
        process_id_filter = get_id("process_name", filter_process) if filter_process else None
        operation_id_filter = get_id("operation", filter_operation) if filter_operation else None
        result_id_filter: Optional[int] = None
        if filter_result:
             if filter_result.lower().startswith("0x"):
                  result_id_filter = get_id("result", filter_result) # Lookup hex string
             else:
                  result_id_filter = get_id("result", filter_result)

        # Lowercase for contains filters
        filter_path_contains_lower = filter_path_contains.lower() if filter_path_contains else None
        filter_process_contains_lower = filter_process_contains.lower() if filter_process_contains else None
        filter_stack_module_path_lower = filter_stack_module_path.lower() if filter_stack_module_path else None

        # --- Iterate and Filter In-Memory Data ---
        processed_count = 0
        for idx, event_dict in enumerate(LOADED_EVENTS):
            processed_count += 1
            if processed_count % (PROGRESS_REPORT_INTERVAL * 2) == 0: # Report less often
                 try:
                     elapsed = time.time() - start_time
                     await ctx.info(f" Query scanned {processed_count}/{len(LOADED_EVENTS)} events... ({elapsed:.1f}s)")
                 except Exception as progress_err:
                      logger.warning(f"Failed to send progress update during query: {progress_err}")


            if count >= limit: break

            match = True # Assume match

            # --- Apply Filters using IDs and optimized data ---
            # Exact match filters (using IDs)
            if process_id_filter is not None and event_dict.get('pname_id') != process_id_filter: match = False
            if match and operation_id_filter is not None and event_dict.get('op_id') != operation_id_filter: match = False
            if match and result_id_filter is not None and event_dict.get('res_id') != result_id_filter: match = False

            # Time Filter (using float timestamp)
            if match and (start_ts or end_ts):
                event_ts = event_dict.get('ts')
                if event_ts is None: match = False # Cannot compare
                else:
                    # Adjust comparison based on whether filter was time string or full timestamp
                    current_event_time_val = event_ts
                    if isinstance(filter_start_time, str) or isinstance(filter_end_time, str):
                         # If filter was time string, compare only time part of event
                         event_dt_obj = datetime.fromtimestamp(event_ts, timezone.utc)
                         current_event_time_val = (event_dt_obj.hour * 3600 + event_dt_obj.minute * 60 + event_dt_obj.second + event_dt_obj.microsecond / 1e6)

                    if start_ts and current_event_time_val < start_ts: match = False
                    if match and end_ts and current_event_time_val > end_ts: match = False

            # Contains / Regex / Stack filters require converting IDs back to strings
            if match and (filter_path_contains_lower or filter_process_contains_lower or path_regex or process_regex or detail_regex or filter_stack_module_path_lower):
                # Get original strings (potentially slow if done for every event)
                # Optimization: Only get strings if the specific filter is active.
                path_str = get_string("path", event_dict.get('path_id')) or "" if match and (filter_path_contains_lower or path_regex) else ""
                pname_str = get_string("process_name", event_dict.get('pname_id')) or "" if match and (filter_process_contains_lower or process_regex) else ""
                detail_str = event_dict.get('detail') or "" if match and detail_regex else "" # Detail not interned

                # Contains filters
                if match and filter_path_contains_lower and filter_path_contains_lower not in path_str.lower(): match = False
                if match and filter_process_contains_lower and filter_process_contains_lower not in pname_str.lower(): match = False

                # Regex Filters
                if match and path_regex and not path_regex.search(path_str): match = False
                if match and process_regex and not process_regex.search(pname_str): match = False
                if match and detail_regex and not detail_regex.search(detail_str): match = False

                # Stack Module Filter (Expensive)
                if match and filter_stack_module_path_lower:
                    stack_list = event_dict.get('stack') # List of [depth, addr, path_id, loc_id]
                    found_in_stack = False
                    if stack_list:
                        for frame_list in stack_list:
                            if len(frame_list) > 2 and frame_list[2] is not None: # Check path_id exists
                                frame_path_str = get_string("stack_path", frame_list[2])
                                if frame_path_str and filter_stack_module_path_lower in frame_path_str.lower():
                                    found_in_stack = True
                                    break
                    if not found_in_stack: match = False

            # --- Add to results if all filters passed ---
            if match:
                 # Create summary, converting IDs back to strings
                 event_summary = {
                     'event_index': idx, # Use list index now
                     'sequence_number': event_dict.get('seq'),
                     'timestamp': str(datetime.fromtimestamp(event_dict['ts'], timezone.utc).strftime(PROCMON_TIMESTAMP_FORMAT)) if event_dict.get('ts') else None,
                     'process_name': get_string("process_name", event_dict.get('pname_id')),
                     'pid': event_dict.get('pid'),
                     'operation': get_string("operation", event_dict.get('op_id')),
                     'path': get_string("path", event_dict.get('path_id')),
                     'result': get_string("result", event_dict.get('res_id')),
                 }
                 filtered_event_summaries.append(event_summary)
                 count += 1

        elapsed = time.time() - start_time
        await ctx.info(f"Query finished in {elapsed:.2f}s. Found {len(filtered_event_summaries)} matching events in memory.")
        return filtered_event_summaries

    except re.error as e:
        await ctx.error(f"Invalid Regex pattern provided: {e}")
        raise ValueError(f"Invalid regex pattern: {e}") from e
    except Exception as e:
        await ctx.error(f"Failed to query in-memory events: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error querying events: {e}")

@tool_decorator
async def get_event_details(event_index: int, ctx: Context) -> Dict[str, Any]:
    """
    Retrieves detailed properties for a specific event from the optimized in-memory data,
    referenced by its list index. Use 'query_events' first to find the index.

    Args:
        event_index: The zero-based index of the event in the loaded event list.

    Returns:
        A dictionary containing available properties of the specified event.
    """
    await ctx.info(f"Request received for details of event index: {event_index}")
    if LOADED_EVENTS is None or LOADED_PROCESSES is None or not GLOBAL_INTERNERS:
        await ctx.error(f"Get details failed: Event data or interners not loaded.")
        raise TypeError("Operation requires optimized event data to be loaded.")

    try:
        if not 0 <= event_index < len(LOADED_EVENTS):
            await ctx.error(f"Invalid event index: {event_index}. Must be between 0 and {len(LOADED_EVENTS)-1}.")
            raise IndexError(f"Event index {event_index} is out of bounds.")

        event_dict = LOADED_EVENTS[event_index]

        # Convert optimized dict back to a more user-friendly format
        details: Dict[str, Any] = {}
        details['event_index'] = event_index
        details['sequence_number'] = event_dict.get('seq')
        details['pid'] = event_dict.get('pid')
        details['tid'] = event_dict.get('tid')
        details['parent_pid'] = event_dict.get('ppid')
        details['duration'] = event_dict.get('dur')
        details['detail'] = event_dict.get('detail')
        ts_float = event_dict.get('ts')
        details['timestamp'] = str(datetime.fromtimestamp(ts_float, timezone.utc).strftime(PROCMON_TIMESTAMP_FORMAT)) if ts_float else None
        details['timestamp_unix'] = ts_float # Also include raw timestamp

        # Convert IDs back to strings
        details['operation'] = get_string("operation", event_dict.get('op_id'))
        details['path'] = get_string("path", event_dict.get('path_id'))
        details['result'] = get_string("result", event_dict.get('res_id'))
        details['category'] = get_string("category", event_dict.get('cat_id'))
        details['process_name'] = get_string("process_name", event_dict.get('pname_id'))

        # Add enriched process info by looking up process object via PID
        process_obj: Optional[ProcessInfo] = None
        if details['pid'] is not None:
             # Find the process object (could be optimized if processes were dict keyed by PID)
             for proc in LOADED_PROCESSES.values():
                  if proc.pid == details['pid']:
                       process_obj = proc
                       break

        if process_obj:
             details['process_details_summary'] = {
                  'pid': process_obj.pid, 'process_name': process_obj.process_name,
                  'image_path': process_obj.image_path, 'parent_pid': process_obj.parent_pid,
                  'command_line': process_obj.command_line, 'user_sid': process_obj.user_sid,
                  'is_64bit_process': process_obj.is_64bit, 'integrity': process_obj.integrity,
                  'owner': process_obj.owner, 'create_time': process_obj.create_time # Add more fields from ProcessInfo
             }
             details['user_sid'] = process_obj.user_sid # Ensure top-level field is populated
             details['is_64bit_process'] = process_obj.is_64bit
        else:
             details['process_details_summary'] = {"pid": details['pid'], "process_name": details['process_name']} # Simplified
             details['user_sid'] = None
             details['is_64bit_process'] = None


        # Note: We don't store all original fields in the optimized dict (e.g., completion_time, relative_time)
        details['completion_time'] = None
        details['relative_time'] = None


        await ctx.info(f"Successfully retrieved details for event index {event_index}.")
        return details

    except IndexError as e:
        logger.debug(f"IndexError retrieving event details: index {event_index}.")
        raise e
    except Exception as e:
        await ctx.error(f"Failed to get details for event {event_index}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving event details: {e}")

@tool_decorator
async def get_event_stack_trace(event_index: int, ctx: Context) -> List[Dict[str, Any]]:
    """
    Retrieves the detailed call stack trace for a specific event from the optimized in-memory data,
    referenced by its list index.

    Args:
        event_index: The zero-based index of the event.

    Returns:
        A list of dictionaries representing stack frames ('depth', 'address', 'path', 'location').
    """
    await ctx.info(f"Request received for stack trace of event index: {event_index}")
    if LOADED_EVENTS is None or not GLOBAL_INTERNERS:
        await ctx.error(f"Get stack trace failed: Event data or interners not loaded.")
        raise TypeError("Operation requires optimized event data to be loaded.")

    try:
        if not 0 <= event_index < len(LOADED_EVENTS):
            await ctx.error(f"Invalid event index: {event_index}. Must be between 0 and {len(LOADED_EVENTS)-1}.")
            raise IndexError(f"Event index {event_index} is out of bounds.")

        event_dict = LOADED_EVENTS[event_index]
        stack_list_optimized = event_dict.get('stack') # List of [depth, addr, path_id, loc_id]

        detailed_stack = []
        if stack_list_optimized:
            for frame_data in stack_list_optimized:
                try:
                    # Reconstruct StackFrame dict
                    frame_dict = {
                        'depth': frame_data[0],
                        'address': frame_data[1],
                        'path': get_string("stack_path", frame_data[2]),
                        'location': get_string("stack_location", frame_data[3])
                    }
                    detailed_stack.append(frame_dict)
                except IndexError:
                    logger.warning(f"Malformed optimized stack frame data for event index {event_index}: {frame_data}")
                    continue # Skip malformed frame

        await ctx.info(f"Successfully retrieved stack trace (length: {len(detailed_stack)}) for event index {event_index}.")
        return detailed_stack

    except IndexError as e:
        logger.debug(f"IndexError retrieving stack trace: index {event_index}.")
        raise e
    except Exception as e:
        await ctx.error(f"Failed to get stack trace for event {event_index}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving event stack trace: {e}")

# --- Tools operating on LOADED_PROCESSES (remain mostly the same) ---
@tool_decorator
async def list_processes(ctx: Context) -> List[Dict[str, Any]]:
    """ Lists summary info (pid, process_name, image_path) from the loaded process list. """
    await ctx.info(f"Request received to list processes from pre-loaded process list.")
    if LOADED_PROCESSES is None:
        await ctx.error(f"List processes failed: Process list not loaded.")
        raise TypeError("Operation requires an XML file's process list to be pre-loaded.")
    try:
        process_list = list(LOADED_PROCESSES.values())
        process_summaries = []
        summary_attributes = ['pid', 'process_name', 'image_path']
        for process_obj in process_list:
            summary = {attr: getattr(process_obj, attr, None) for attr in summary_attributes}
            if summary.get('pid') is None: continue
            process_summaries.append(summary)
        await ctx.info(f"Generated {len(process_summaries)} process summaries.")
        return process_summaries
    except Exception as e:
        await ctx.error(f"Failed to list processes from loaded data: {e}"); raise RuntimeError(f"Internal error listing processes: {e}")

@tool_decorator
async def get_process_details(pid: int, ctx: Context) -> Dict[str, Any]:
    """ Retrieves detailed info for a specific PID from the loaded process list. """
    await ctx.info(f"Request received for details of PID: {pid} from loaded process list.")
    if LOADED_PROCESSES is None:
        await ctx.error(f"Get process details failed: Process list not loaded.")
        raise TypeError("Operation requires an XML file's process list to be pre-loaded.")
    try:
        process_obj: Optional[ProcessInfo] = None
        for proc in LOADED_PROCESSES.values():
            if proc.pid == pid: process_obj = proc; break
        if not process_obj: raise ValueError(f"Process with PID {pid} not found in pre-loaded list.")
        details = dataclasses.asdict(process_obj)
        details['pid'] = process_obj.pid; details['parent_pid'] = process_obj.parent_pid
        details['user_sid'] = process_obj.user_sid; details['is_64bit_process'] = process_obj.is_64bit
        if 'parent_process_index' in details: del details['parent_process_index']
        details['modules_summary'] = None
        await ctx.info(f"Successfully retrieved details for PID {pid}.")
        return details
    except ValueError as e: await ctx.error(str(e)); raise e
    except Exception as e: await ctx.error(f"Failed to get details for PID {pid}: {e}"); raise RuntimeError(f"Internal error retrieving process details: {e}")

@tool_decorator
async def get_metadata(ctx: Context) -> Dict[str, Any]:
    """ Retrieves metadata for the loaded XML file. """
    await ctx.info(f"Request received for metadata from XML file.")
    if LOADED_PROCESSES is None or LOADED_EVENTS is None or not LOADED_FILENAME:
        await ctx.error(f"Get metadata failed: Data not fully loaded.")
        raise TypeError("Operation requires file data to be pre-loaded.")
    try:
        metadata = {
             "loaded_filename": LOADED_FILENAME, "file_type": LOADED_FILE_TYPE,
             "compression": LOADED_COMPRESSION, "header_found": False,
             "message": "Header info N/A for XML.", "os_version": None, "computer_name": None,
             "process_count_loaded": len(LOADED_PROCESSES),
             "event_count_loaded": len(LOADED_EVENTS) # Now available
        }
        await ctx.info(f"Successfully retrieved metadata from {LOADED_FILENAME}.")
        return metadata
    except Exception as e: await ctx.error(f"Failed to get metadata: {e}"); raise RuntimeError(f"Internal error retrieving metadata: {e}")

# --- Analysis Tools (Operating on In-Memory Optimized Data) ---

@tool_decorator
async def count_events_by_process(ctx: Context) -> Dict[str, int]:
    """ Counts events per process name from the loaded in-memory data. """
    await ctx.info(f"Request received to count events by process name (in-memory).")
    if LOADED_EVENTS is None or not GLOBAL_INTERNERS:
        await ctx.error("Operation failed: Optimized event data not loaded.")
        raise TypeError("Operation requires optimized event data to be loaded.")

    try:
        event_counts = defaultdict(int)
        start_time = time.time()
        total_events = len(LOADED_EVENTS)

        for i, event_dict in enumerate(LOADED_EVENTS):
            # Progress reporting for potentially long loops on huge datasets
            if i > 0 and i % (PROGRESS_REPORT_INTERVAL * 2) == 0: # Report less often for in-memory
                 elapsed = time.time() - start_time
                 await ctx.info(f" Counting... processed {i}/{total_events} events ({elapsed:.1f}s)")

            process_name = get_string("process_name", event_dict.get('pname_id')) or 'Unknown'
            event_counts[process_name] += 1

        elapsed = time.time() - start_time
        await ctx.info(f"Counted {total_events} total events for {len(event_counts)} processes ({elapsed:.2f}s).")
        return dict(event_counts)
    except Exception as e:
        await ctx.error(f"Failed to count events by process: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error counting events by process: {e}")

@tool_decorator
async def summarize_operations_by_process(process_name_filter: str, ctx: Context) -> Dict[str, int]:
    """ Counts operations for a specific process name (case-sensitive) from loaded data. """
    await ctx.info(f"Request to summarize operations for process: {process_name_filter} (in-memory).")
    if LOADED_EVENTS is None or not GLOBAL_INTERNERS:
        await ctx.error("Operation failed: Optimized event data not loaded.")
        raise TypeError("Operation requires optimized event data to be loaded.")
    if not process_name_filter:
        await ctx.error("Process name filter cannot be empty."); raise ValueError("Process name filter is required.")

    try:
        operation_counts = defaultdict(int)
        event_count_for_process = 0
        start_time = time.time()
        total_events = len(LOADED_EVENTS)

        # Get the target process ID only once
        target_pname_id = get_id("process_name", process_name_filter)
        if target_pname_id is None:
            await ctx.warning(f"Process name '{process_name_filter}' not found in loaded data.")
            return {}

        for i, event_dict in enumerate(LOADED_EVENTS):
            if i > 0 and i % (PROGRESS_REPORT_INTERVAL * 2) == 0:
                 elapsed = time.time() - start_time
                 await ctx.info(f" Summarizing... processed {i}/{total_events} events ({elapsed:.1f}s)")

            if event_dict.get('pname_id') == target_pname_id:
                event_count_for_process += 1
                operation = get_string("operation", event_dict.get('op_id')) or 'Unknown'
                operation_counts[operation] += 1

        elapsed = time.time() - start_time
        await ctx.info(f"Summarized {len(operation_counts)} ops for '{process_name_filter}' ({event_count_for_process} events found) ({elapsed:.2f}s).")
        if event_count_for_process == 0: await ctx.warning(f"No events found for process name '{process_name_filter}'.")
        return dict(operation_counts)

    except Exception as e:
        await ctx.error(f"Failed to summarize operations for '{process_name_filter}': {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error summarizing operations: {e}")

@tool_decorator
async def get_timing_statistics(
    group_by: str = "process", # 'process' or 'operation'
    *,
    ctx: Context
) -> Dict[str, Dict[str, Any]]:
    """
    Calculates event duration statistics from the loaded in-memory data,
    grouped by either process name or operation type.

    Args: group_by: 'process' (default) or 'operation'.
    Returns: Dictionary of statistics per group.
    """
    await ctx.info(f"Request received to calculate timing statistics grouped by '{group_by}' (in-memory).")
    if group_by not in ["process", "operation"]:
        await ctx.error("Invalid group_by value."); raise ValueError("Invalid group_by value.")
    if LOADED_EVENTS is None or not GLOBAL_INTERNERS:
        await ctx.error("Operation failed: Optimized event data not loaded.")
        raise TypeError("Operation requires optimized event data to be loaded.")

    try:
        stats = defaultdict(lambda: {'min': float('inf'), 'max': float('-inf'), 'sum': 0.0, 'count': 0})
        total_events = len(LOADED_EVENTS)
        start_time = time.time()

        for i, event_dict in enumerate(LOADED_EVENTS):
            if i > 0 and i % (PROGRESS_REPORT_INTERVAL * 2) == 0:
                 elapsed = time.time() - start_time
                 await ctx.info(f" Calculating stats... processed {i}/{total_events} events ({elapsed:.1f}s)")

            duration = event_dict.get('dur')
            if duration is None: continue

            group_key_id = event_dict.get('pname_id') if group_by == "process" else event_dict.get('op_id')
            interner_name = "process_name" if group_by == "process" else "operation"
            group_key = get_string(interner_name, group_key_id) or 'Unknown'

            group_stats = stats[group_key]
            group_stats['count'] += 1
            group_stats['sum'] += duration
            if duration < group_stats['min']: group_stats['min'] = duration
            if duration > group_stats['max']: group_stats['max'] = duration

        # Calculate averages and format output
        output_stats = {}
        for key, data in stats.items():
            if data['count'] > 0:
                avg = data['sum'] / data['count']
                output_stats[key] = {'count': data['count'], 'min_duration': data['min'] if data['min'] != float('inf') else None, 'max_duration': data['max'] if data['max'] != float('-inf') else None, 'avg_duration': avg, 'total_duration': data['sum']}
            else: output_stats[key] = {'count': 0, 'min_duration': None, 'max_duration': None, 'avg_duration': None, 'total_duration': 0.0}

        elapsed = time.time() - start_time
        await ctx.info(f"Calculated timing statistics for {len(output_stats)} groups ({elapsed:.2f}s).")
        return output_stats

    except Exception as e:
        await ctx.error(f"Failed to calculate timing statistics: {e}"); raise RuntimeError(f"Internal error calculating timing statistics: {e}")

# --- Main Execution Block ---
if __name__ == "__main__":
    if not MCP_SDK_AVAILABLE:
        print("Error: Model Context Protocol SDK (modelcontextprotocol) is not installed.")
        exit(1)

    parser = argparse.ArgumentParser(description="MCP Server for analyzing Procmon XML files (.xml, .xml.gz/bz2/xz) using in-memory optimization.")
    parser.add_argument("--allowed-dir", required=True, help="REQUIRED: Secure base directory containing Procmon XML files.")
    parser.add_argument("--load-file", required=True, # Required now
                        help="REQUIRED: XML file (.xml, .xml.gz/bz2/xz) relative to --allowed-dir (no subdirs) to load and analyze.")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1", help="Host for MCP server (SSE transport), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8081, help="Port for MCP server (SSE transport), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"], help="MCP transport protocol, default: stdio")
    parser.add_argument("--debug", action='store_true', help="Enable debug logging.")

    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.getLogger().setLevel(log_level)
    logger.setLevel(log_level)
    logger.info(f"Logging level set to: {logging.getLevelName(log_level)}")

    if not os.path.isdir(args.allowed_dir):
        logger.critical(f"Error: Allowed directory does not exist: {args.allowed_dir}")
        exit(1)

    ALLOWED_DIR_CONFIG = os.path.abspath(args.allowed_dir)
    logger.info(f"Allowed Directory set to: {ALLOWED_DIR_CONFIG}")

    # --- Load File into Optimized In-Memory Structure ---
    try:
        logger.info(f"Attempting to load and optimize file: {args.load_file}")
        # This function now loads everything into global variables
        load_and_validate_file(ALLOWED_DIR_CONFIG, args.load_file)

        if LOADED_EVENTS is None or LOADED_PROCESSES is None: # Check if loading succeeded
             logger.critical(f"File loading failed for '{args.load_file}'. Check logs.")
             exit(1)

        logger.info(f"Successfully loaded and optimized {args.load_file}.")
        if args.debug:
             logger.debug(f"Load Summary: Processes={len(LOADED_PROCESSES)}, Events={len(LOADED_EVENTS)}, Compression={LOADED_COMPRESSION}")

    except (ValueError, PermissionError, FileNotFoundError, TypeError, IndexError) as e:
        logger.critical(f"Error loading file ('{args.load_file}'): {e}")
        exit(1)
    except ET_impl.XMLSyntaxError as e:
         logger.critical(f"XML Syntax Error loading file ('{args.load_file}'): {e}")
         exit(1)
    except RuntimeError as e:
         logger.critical(f"Runtime Error loading file ('{args.load_file}'): {e}")
         exit(1)
    except Exception as e:
        logger.critical(f"An unexpected error occurred during file loading ('{args.load_file}'): {e}", exc_info=args.debug)
        exit(1)

    # --- Start MCP Server ---
    server_started = False
    try:
        if args.transport == "sse":
            if hasattr(mcp, 'settings'):
                logger.info("Configuring MCP for SSE transport...")
                mcp.settings.host = args.mcp_host; mcp.settings.port = args.mcp_port
                mcp_log_level_name = logging.getLevelName(log_level)
                mcp.settings.log_level = mcp_log_level_name.lower()
                logger.info(f"  MCP Host: {mcp.settings.host}")
                logger.info(f"  MCP Port: {mcp.settings.port}")
                logger.info(f"  MCP Log Level: {mcp.settings.log_level}")
            else: logger.warning("MCP object lacks 'settings'; cannot configure SSE.")
            logger.info("Starting MCP server with SSE transport...")
            mcp.run(transport="sse")
            server_started = True
        else: # Default to stdio
            logger.info("Starting MCP server with STDIO transport...")
            mcp.run()
            server_started = True
    except Exception as e:
        logger.critical(f"Failed during server startup: {e}", exc_info=args.debug)

    if not server_started: logger.critical("Server did not start."); exit(1)
    else: logger.info("Server execution finished."); exit(0)
