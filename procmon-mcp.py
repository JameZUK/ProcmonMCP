# -*- coding: utf-8 -*-
import os
import logging
import argparse
from typing import List, Dict, Any, Optional, Tuple, Iterator, IO, Set, AsyncIterator
import io
import asyncio
import time # For timing
from collections import defaultdict # For counting
import dataclasses # For XML data structures and log data container
import re # For regex filtering
from datetime import datetime, timezone, time as dt_time # For time-based filtering & UTC timestamps
import csv # For CSV export
import json # For JSON export

# Standard library compression formats
import gzip
import bz2
import lzma

# --- XML Parser Choice ---
LXML_AVAILABLE = False
try:
    # Use lxml etree as the primary implementation if available
    from lxml import etree as ET_impl
    LXML_AVAILABLE = True
    # Logger defined after basicConfig below
except ImportError:
    # Fallback to standard library ElementTree
    import xml.etree.ElementTree as ET_impl
    # Logger defined after basicConfig below

# --- Memory Usage Reporting Dependency ---
PSUTIL_AVAILABLE = False
try:
    import psutil # For memory usage reporting
    PSUTIL_AVAILABLE = True
except ImportError:
    # Logger defined after basicConfig below
    pass # Warning will be logged later if needed

# --- Basic Logging Configuration ---
# Configure basicConfig first, we might modify handlers later based on args
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT) # Set default level
logger = logging.getLogger(__name__) # Define logger after basicConfig

# Log XML parser choice after logger is defined
if LXML_AVAILABLE:
    logger.info("Using lxml library for XML parsing (recommended).")
else:
    logger.warning("lxml library not found. Falling back to standard xml.etree.ElementTree for XML parsing.")
    logger.warning("For better performance and memory efficiency with large XML files, install lxml: pip install lxml")

# Log psutil availability
if not PSUTIL_AVAILABLE:
    logger.warning("psutil library not found. Memory usage reporting will be unavailable.")
    logger.warning("To enable memory reporting, install psutil: pip install psutil")


# --- MCP SDK Imports ---
# Check for MCP SDK and provide mock if not found
try:
    from mcp.server.fastmcp import FastMCP, Context
    MCP_SDK_AVAILABLE = True
    logger.info("MCP SDK found.")
except ImportError:
    MCP_SDK_AVAILABLE = False
    logger.error("MCP SDK (modelcontextprotocol) not found. Please install it: pip install modelcontextprotocol")
    # Mock objects for offline testing/execution
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

# --- Constants ---
PROCMON_TIMESTAMP_FORMAT = "%H:%M:%S.%f" # Format used in Procmon XML Time_of_Day
PROGRESS_REPORT_INTERVAL = 250000 # Report progress every N events during loading/processing
PROGRESS_REPORT_SECONDS = 5.0 # Also report progress every N seconds
# Define a base date (epoch) for creating full timestamps from Time_of_Day.
# This is necessary because XML only provides time, not date. Assumes logs don't span midnight relative to this arbitrary date for accurate time-only filtering.
BASE_DATE = datetime(1970, 1, 1, tzinfo=timezone.utc)
# Known operation strings for specific tools
OP_PROCESS_CREATE = "Process Create"
OP_PROCESS_EXIT = "Process Exit"
NETWORK_OPERATIONS = {"TCP Connect", "TCP Send", "TCP Receive", "UDP Send", "UDP Receive"} # Case-sensitive

# --- Interner Keys (Constants) ---
IK_PROCESS_NAME = "process_name"
IK_OPERATION = "operation"
IK_PATH = "path"
IK_RESULT = "result"
IK_CATEGORY = "category"
IK_STACK_PATH = "stack_path"
IK_STACK_LOCATION = "stack_location"

# --- Standalone XML Helper Functions ---
def _strip_namespace(tag: str) -> str:
    """Helper to remove namespace from tag string if present."""
    return tag.split('}', 1)[-1] if '}' in tag else tag

def _find_child_ignore_ns(elem: ET_impl.Element, tag_name: str) -> Optional[ET_impl.Element]:
    """Finds the first direct child element with the given tag name, ignoring namespaces."""
    for child_elem in elem: # Iterate directly for better namespace handling
        if _strip_namespace(child_elem.tag) == tag_name:
            return child_elem
    return None

def _find_text_ignore_ns(elem: ET_impl.Element, tag_name: str) -> Optional[str]:
    """Finds the text of the first direct child element with the given tag name, ignoring namespaces."""
    child = _find_child_ignore_ns(elem, tag_name)
    return child.text.strip() if child is not None and child.text else None

# --- START FIX: Define find_text_func globally for reuse ---
if LXML_AVAILABLE:
    def _find_text_lxml(element, tag_name):
        """Uses lxml XPath to find text, ignoring namespaces."""
        try:
            xpath_query = f"string(./*[local-name()='{tag_name}'][1])"
            xpath_result = element.xpath(xpath_query)
            # REMOVED: Verbose XPath debug logging
            return xpath_result.strip() if xpath_result else None
        except Exception as xpath_e:
            logger.debug(f"lxml elem.xpath failed for '{tag_name}': {xpath_e}")
            return None
    find_text_func = _find_text_lxml
else:
    # Keep original function for standard library xml.etree
    find_text_func = _find_text_ignore_ns
# --- END FIX ---


def _clear_elem(elem: ET_impl.Element):
    """Helper to clear element memory using lxml/ET specific methods."""
    elem.clear()
    # Clean up preceding siblings to potentially release more memory with lxml
    if LXML_AVAILABLE and hasattr(elem, 'getprevious'):
        while elem.getprevious() is not None:
            try:
                parent = elem.getparent()
                if parent is not None: del parent[0]
                else: break # Stop if no parent
            except (IndexError, AttributeError): # Handle potential errors during cleanup
                break

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

    def lookup_id(self, s: Optional[str]) -> Optional[int]:
        """Looks up an ID from its string. Does NOT add new strings."""
        if s is None: return None
        return self.str_to_id.get(s) # Return None if string wasn't seen during load

# --- XML Parser Data Structures ---

@dataclasses.dataclass
class StackFrame:
    """Represents a single frame in a call stack parsed from a <frame> element."""
    depth: Optional[int] = None
    address: Optional[str] = None # Keep as hex string like '0x...'
    path: Optional[str] = None
    location: Optional[str] = None

    @classmethod
    def from_xml_element(cls, elem: ET_impl.Element) -> 'StackFrame':
        """Parses a <frame> XML element into a StackFrame object, ignoring namespaces."""
        # Use appropriate text finding function
        depth_text = find_text_func(elem, 'depth')
        try: depth = int(depth_text) if depth_text and depth_text.isdigit() else None
        except (ValueError, TypeError): depth = None
        address = find_text_func(elem, 'address')
        path = find_text_func(elem, 'path')
        location = find_text_func(elem, 'location')
        return cls(depth=depth, address=address, path=path, location=location)

    def to_dict(self) -> Dict[str, Any]:
        """Convert StackFrame to dictionary for tool output."""
        return dataclasses.asdict(self)

    def to_optimized_list(self, path_interner: StringInterner, location_interner: StringInterner) -> list:
        """Converts StackFrame to a more compact list representation for storage using interners."""
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
    parent_process_index: Optional[int] = None # Redundant if ParentProcessId is present, but parse anyway
    authentication_id: Optional[str] = None # Usually hex string
    create_time: Optional[str] = None # Keep as string, parse if needed
    finish_time: Optional[str] = None # Keep as string, parse if needed
    is_virtualized: Optional[bool] = None
    is_64bit: Optional[bool] = None
    integrity: Optional[str] = None
    owner: Optional[str] = None # SID string
    process_name: Optional[str] = None
    image_path: Optional[str] = None
    command_line: Optional[str] = None
    company_name: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None

    # --- Properties for consistent naming ---
    @property
    def pid(self): return self.process_id
    @property
    def parent_pid(self): return self.parent_process_id
    @property
    def user_sid(self): return self.owner

    # --- Helper methods for safe parsing ---
    @staticmethod
    def _safe_text_to_int(text: Optional[str]) -> Optional[int]:
        """Safely converts text (decimal or hex '0x...') to int, returning None on failure."""
        if text is None: return None
        text = text.strip()
        if not text: return None
        try:
            if text.lower().startswith('0x'): return int(text, 16)
            else: return int(text)
        except (ValueError, TypeError):
            logger.debug(f"Failed to convert text '{text}' to int.")
            return None

    @staticmethod
    def _safe_text_to_bool(text: Optional[str]) -> Optional[bool]:
        """Safely converts text ('1' or '0') to bool, returning None otherwise."""
        if text:
            text = text.strip()
            if text == '1': return True
            if text == '0': return False
        return None

    @classmethod
    def from_xml_element(cls, elem: ET_impl.Element) -> 'ProcessInfo':
        """Parses a <process> XML element into a ProcessInfo object, ignoring namespaces."""
        # Use global find_text_func here too for consistency
        data = {}
        data['process_index'] = cls._safe_text_to_int(find_text_func(elem, 'ProcessIndex'))
        data['process_id'] = cls._safe_text_to_int(find_text_func(elem, 'ProcessId'))
        data['parent_process_id'] = cls._safe_text_to_int(find_text_func(elem, 'ParentProcessId'))
        data['parent_process_index'] = cls._safe_text_to_int(find_text_func(elem, 'ParentProcessIndex'))
        data['authentication_id'] = find_text_func(elem, 'AuthenticationId')
        data['create_time'] = find_text_func(elem, 'CreateTime')
        data['finish_time'] = find_text_func(elem, 'FinishTime')
        data['is_virtualized'] = cls._safe_text_to_bool(find_text_func(elem, 'IsVirtualized'))
        data['is_64bit'] = cls._safe_text_to_bool(find_text_func(elem, 'Is64bit'))
        data['integrity'] = find_text_func(elem, 'Integrity')
        data['owner'] = find_text_func(elem, 'Owner')
        data['process_name'] = find_text_func(elem, 'ProcessName')
        data['image_path'] = find_text_func(elem, 'ImagePath')
        data['command_line'] = find_text_func(elem, 'CommandLine')
        data['company_name'] = find_text_func(elem, 'CompanyName')
        data['version'] = find_text_func(elem, 'Version')
        data['description'] = find_text_func(elem, 'Description')
        return cls(**data)

# --- Helper function to parse timestamp (moved outside class) ---
def _parse_timestamp_str(ts_str: Optional[str]) -> Optional[float]:
    """
    Parses HH:MM:SS.ffffff[f...] string to a UTC float timestamp relative to BASE_DATE.
    Handles arbitrary digits in fractional seconds by truncating to 6.
    """
    if ts_str is None: return None
    try:
        parts = ts_str.split('.', 1)
        time_part = parts[0]
        fractional_part = parts[1][:6].ljust(6, '0') if len(parts) > 1 else "000000"
        ts_str_corrected = f"{time_part}.{fractional_part}"
        parsed_time: dt_time = datetime.strptime(ts_str_corrected, PROCMON_TIMESTAMP_FORMAT).time()
        full_dt = datetime.combine(BASE_DATE.date(), parsed_time, tzinfo=timezone.utc)
        return full_dt.timestamp()
    except (ValueError, TypeError, IndexError) as e:
        logger.warning(f"Could not parse timestamp string '{ts_str}': {e}")
        return None

# --- Helper to format bytes ---
def _format_bytes(bytes_val: int) -> str:
    """ Formats bytes into a human-readable string (KB, MB, GB). """
    if bytes_val < 1024: return f"{bytes_val} Bytes"
    elif bytes_val < 1024**2: return f"{bytes_val / 1024:.2f} KB"
    elif bytes_val < 1024**3: return f"{bytes_val / (1024**2):.2f} MB"
    else: return f"{bytes_val / (1024**3):.2f} GB"

# --- XML Parsing Logic ---

def _parse_xml_processes_only(source_stream: IO[bytes]) -> Dict[int, ProcessInfo]:
    """
    Parses only the <processlist> from the XML stream and returns the process dictionary
    keyed by ProcessIndex. Stops parsing after the </processlist> tag. Ignores namespaces.
    """
    processes_dict: Dict[int, ProcessInfo] = {}
    parsing_stage = "seeking_procmon"
    tags_of_interest = ('process', 'processlist', 'procmon')
    start_time = time.time()
    process_element_count = 0

    try:
        # Use 'end' event for process list as we need the full element content
        context = ET_impl.iterparse(source_stream, events=('end',), tag=tags_of_interest)
        logger.info("Starting Pass 1: Parsing process list...")
    except Exception as e:
        logger.error(f"Unexpected error initializing XML parser for process list: {e}", exc_info=True)
        raise RuntimeError("Failed to initialize XML parser for process list") from e

    try:
        for event_type, elem in context:
            tag = _strip_namespace(elem.tag)

            if parsing_stage == "seeking_procmon":
                if tag == 'procmon': logger.warning("Found end of procmon before processlist."); break
                parsing_stage = "seeking_processlist"

            if parsing_stage == "seeking_processlist":
                if tag == 'process': parsing_stage = "parsing_processlist" # Fallthrough
                elif tag == 'processlist': logger.info("Found empty <processlist>."); _clear_elem(elem); break

            if parsing_stage == "parsing_processlist":
                if tag == 'process':
                    process_element_count += 1
                    try:
                        # Use ProcessInfo.from_xml_element which now uses find_text_func
                        proc_info = ProcessInfo.from_xml_element(elem)
                        if proc_info.process_index is not None and proc_info.process_index >= 0:
                            processes_dict[proc_info.process_index] = proc_info
                        else:
                            logger.warning(f"Parsed process element missing or invalid ProcessIndex.")
                    except Exception as e:
                        logger.warning(f"Failed to parse <process> element: {e}", exc_info=False)
                    _clear_elem(elem)
                    if process_element_count % 500 == 0:
                        elapsed = time.time() - start_time
                        logger.info(f"  [Pass 1] Parsed {process_element_count:,} process elements... ({elapsed:.1f}s)")
                elif tag == 'processlist':
                    logger.debug(f"Finished parsing <processlist> tag.")
                    _clear_elem(elem)
                    break

            if tag == 'procmon':
                logger.warning("Reached end of <procmon> while parsing processes.")
                break

    except ET_impl.XMLSyntaxError as e: logger.error(f"XML Parse Error during process parsing: {e}"); raise
    except Exception as e: logger.error(f"Unexpected error during process parsing: {e}", exc_info=True); raise

    elapsed = time.time() - start_time
    logger.info(f"Finished Pass 1: Found {len(processes_dict)} unique processes from {process_element_count:,} elements ({elapsed:.2f}s).")
    return processes_dict

# --- UPDATED: Direct parsing into opt_event, simplified logic ---
def _parse_xml_stream_for_loading(
    source_stream: IO[bytes],
    interners: Dict[str, StringInterner],
    processes: Dict[int, ProcessInfo], # Pass in the pre-loaded processes for potential lookups
    load_stack: bool, # Flag for selective loading
    load_extra: bool, # Flag for selective loading
    raw_file_stream: Optional[IO[bytes]] = None, # ADDED: Raw stream for progress
    total_size: Optional[int] = None # Total size for percentage calculation
) -> Iterator[Dict[str, Any]]:
    """
    Internal helper optimized for initial loading into memory. Parses <event> elements
    directly into optimized dictionaries using interners, and yields them.
    Assumes process list is already parsed and passed in `processes`. Reports progress.
    Uses start/end events for iterparse and handles potential XML namespaces.
    Respects selective loading flags. Stricter about missing core fields (pid, ts).
    Logs the XML of skipped events. Includes percentage progress if total_size provided.

    Yields:
        Optimized event dictionaries.
    """
    parsing_stage = "seeking_eventlist"
    try:
        # Use start AND end events to allow capturing element content before clearing
        context = ET_impl.iterparse(source_stream, events=('start', 'end'))
        logger.info("Starting Pass 2: Parsing and optimizing events...")
    except Exception as e:
        logger.error(f"Unexpected error initializing XML parser for event loading: {e}", exc_info=True)
        raise RuntimeError("Failed to initialize XML parser for events") from e

    event_count = 0
    yielded_count = 0
    skipped_count = 0
    start_time = time.time()
    last_report_time = start_time
    current_event_data: Optional[Dict[str, Any]] = None # Store data between start/end
    # --- START FIX: Store list of OPTIMIZED frame data ---
    current_stack_frames: Optional[List[List]] = None
    # --- END FIX ---

    # find_text_func is now defined globally

    try:
        for event_type, elem in context:
            tag = _strip_namespace(elem.tag)

            if parsing_stage == "seeking_eventlist":
                if event_type == 'start' and tag == 'eventlist':
                    logger.debug("Entered <eventlist> (start event).")
                    parsing_stage = "parsing_events"
                elif event_type == 'end' and tag == 'procmon':
                    logger.warning("Reached end of <procmon> before finding <eventlist>.")
                    break
                elif event_type == 'end':
                    _clear_elem(elem) # Clear elements before eventlist
                continue

            elif parsing_stage == "parsing_events":
                # --- START: Process <event> start ---
                if event_type == 'start' and tag == 'event':
                    event_count += 1
                    # --- REMOVED: Verbose raw XML logging ---

                    current_event_data = {} # Initialize temporary storage
                    # --- START FIX: Reset stack frame list ---
                    current_stack_frames = [] if load_stack else None
                    # --- END FIX ---

                    try:
                        # Extract core fields using the defined function
                        pid_str = find_text_func(elem, 'PID')
                        ts_str = find_text_func(elem, 'Time_of_Day')
                        current_event_data['pid_str'] = pid_str # Store raw strings for logging
                        current_event_data['ts_str'] = ts_str
                        current_event_data['pid'] = ProcessInfo._safe_text_to_int(pid_str)
                        current_event_data['ts'] = _parse_timestamp_str(ts_str)

                        # Extract other simple fields needed for optimization/interning
                        current_event_data['seq'] = ProcessInfo._safe_text_to_int(find_text_func(elem, 'SequenceNumber'))
                        current_event_data['tid'] = ProcessInfo._safe_text_to_int(find_text_func(elem, 'ThreadId'))
                        current_event_data['ppid'] = ProcessInfo._safe_text_to_int(find_text_func(elem, 'ParentPID'))
                        current_event_data['detail'] = find_text_func(elem, 'Detail')
                        duration_text = find_text_func(elem, 'Duration')
                        current_event_data['dur'] = None # Default to None
                        if duration_text:
                            try:
                                current_event_data['dur'] = float(duration_text)
                            except (ValueError, TypeError) as dur_err:
                                # --- DEBUG: Log duration conversion failure ---
                                logger.debug(f"Could not convert duration '{duration_text}' to float for event #{event_count}: {dur_err}")
                                current_event_data['dur'] = None


                        current_event_data['process_name_str'] = find_text_func(elem, 'Process_Name')
                        current_event_data['operation_str'] = find_text_func(elem, 'Operation')
                        current_event_data['path_str'] = find_text_func(elem, 'Path')
                        current_event_data['result_str'] = find_text_func(elem, 'Result')
                        current_event_data['category_str'] = find_text_func(elem, 'Category')
                        current_event_data['process_index_str'] = find_text_func(elem, 'ProcessIndex') # Needed for fallback

                        # --- REMOVED: Stack XML string storage here ---

                        # Handle Extra Data (Extract during start if possible)
                        if load_extra:
                            extra_data_dict = {}
                            known_event_tags = {
                                'sequencenumber', 'processindex', 'pid', 'threadid', 'parentpid',
                                'time_of_day', 'operation', 'path', 'result', 'detail', 'duration',
                                'category', 'process_name', 'stack'
                            }
                            for child in elem: # Iterate children while available
                                tag_name_orig = child.tag
                                tag_name_clean = _strip_namespace(tag_name_orig).lower()
                                if tag_name_clean not in known_event_tags:
                                    tag_text = child.text.strip() if child.text else None
                                    if tag_text is not None:
                                        extra_data_dict[tag_name_orig] = tag_text
                            if extra_data_dict: current_event_data['extra_data'] = extra_data_dict


                    except Exception as start_parse_err:
                        logger.warning(f"Error during START event parsing for event #{event_count}: {start_parse_err}", exc_info=True)
                        current_event_data = None # Invalidate data if start parsing fails

                # --- END: Process <event> start ---

                # --- START FIX: Parse <frame> on start and store OPTIMIZED data ---
                elif event_type == 'start' and tag == 'frame' and load_stack and current_stack_frames is not None:
                     try:
                         # Parse frame directly using the element available at 'start'
                         # StackFrame.from_xml_element now uses appropriate find_text_func
                         frame_obj = StackFrame.from_xml_element(elem)
                         # Store the optimized list representation directly
                         current_stack_frames.append(frame_obj.to_optimized_list(
                             interners[IK_STACK_PATH], interners[IK_STACK_LOCATION]
                         ))
                     except Exception as frame_e:
                         logger.warning(f"Failed to parse/optimize stack frame during START for event #{event_count}: {frame_e}", exc_info=False)
                # --- END FIX ---


                # --- START: Process <event> end ---
                elif event_type == 'end' and tag == 'event':
                    if current_event_data: # Proceed only if start parsing was successful
                        parse_successful = True
                        skip_reason = ""
                        opt_event = {}

                        # Validate core fields extracted during start
                        if current_event_data.get('pid') is None:
                            skip_reason += f"Missing/invalid PID ('{current_event_data.get('pid_str')}'). "
                            parse_successful = False
                        if current_event_data.get('ts') is None:
                            skip_reason += f"Missing/invalid Time_of_Day ('{current_event_data.get('ts_str')}'). "
                            parse_successful = False

                        if parse_successful:
                            # Populate opt_event from stored data
                            opt_event['pid'] = current_event_data['pid']
                            opt_event['ts'] = current_event_data['ts']
                            opt_event['seq'] = current_event_data['seq']
                            opt_event['tid'] = current_event_data['tid']
                            opt_event['ppid'] = current_event_data['ppid']
                            opt_event['detail'] = current_event_data['detail']
                            opt_event['dur'] = current_event_data['dur']

                            # Process Name Fallback
                            process_name_str = current_event_data['process_name_str']
                            if process_name_str is None:
                                process_index = ProcessInfo._safe_text_to_int(current_event_data['process_index_str'])
                                if process_index is not None:
                                    proc_info = processes.get(process_index)
                                    if proc_info:
                                        process_name_str = proc_info.process_name
                                        # Update PPID only if it wasn't found directly in the event
                                        if opt_event.get('ppid') is None: opt_event['ppid'] = proc_info.parent_pid
                                    else: logger.warning(f"Event #{event_count} has ProcessIndex {process_index} but process info not found.")

                            # Perform interning using stored strings
                            opt_event['pname_id'] = interners[IK_PROCESS_NAME].get_id(process_name_str)
                            opt_event['op_id'] = interners[IK_OPERATION].get_id(current_event_data['operation_str'])
                            opt_event['path_id'] = interners[IK_PATH].get_id(current_event_data['path_str'])
                            opt_event['res_id'] = interners[IK_RESULT].get_id(current_event_data['result_str'])
                            opt_event['cat_id'] = interners[IK_CATEGORY].get_id(current_event_data['category_str'])

                            # --- START FIX: Assign collected optimized stack frames ---
                            if load_stack and current_stack_frames:
                                opt_event['stack'] = current_stack_frames
                            # --- END FIX ---

                            # Add collected extra data
                            if 'extra_data' in current_event_data:
                                opt_event['extra_data'] = current_event_data['extra_data']

                            # --- Yield optimized event ---
                            yield opt_event
                            yielded_count += 1

                            # --- Progress Reporting ---
                            current_time = time.time()
                            if yielded_count % PROGRESS_REPORT_INTERVAL == 0 or (current_time - last_report_time) > PROGRESS_REPORT_SECONDS:
                                elapsed_total = current_time - start_time
                                rate = yielded_count / elapsed_total if elapsed_total > 0 else 0
                                percent_str = ""
                                # --- START FIX: Use raw_file_stream for tell() ---
                                if raw_file_stream and total_size is not None and total_size > 0:
                                    try:
                                        # Get current position in the RAW stream
                                        current_pos = raw_file_stream.tell()
                                        percent = (current_pos / total_size) * 100
                                        percent_str = f" ({percent:.1f}%)" # Removed tilde
                                    except (OSError, AttributeError, TypeError, io.UnsupportedOperation) as tell_err:
                                        # Handle cases where tell() is not supported or fails
                                        logger.debug(f"Could not get raw stream position for progress: {tell_err}")
                                # --- END FIX ---
                                logger.info(f"  [Pass 2] Yielded {yielded_count:,} events{percent_str}... ({elapsed_total:.1f}s | {rate:,.0f} events/sec)")
                                last_report_time = current_time
                        else:
                            # Log skip reason if parsing failed
                            skipped_count += 1
                            logger.warning(f"Skipping event #{event_count}: {skip_reason.strip()}")
                            # --- START FIX: Only log skipped XML if DEBUG is enabled ---
                            if logger.isEnabledFor(logging.DEBUG):
                                try:
                                    # Attempt to serialize again here for debug purposes if skipping
                                    event_xml_str = ET_impl.tostring(elem, encoding='unicode', method='xml')
                                    logger.debug(f"  Skipped Event XML:\n{event_xml_str[:1500]}...") # Log first 1500 chars
                                except Exception as log_e:
                                    logger.debug(f"  Could not serialize skipped event #{event_count} to string: {log_e}")
                            # --- END FIX ---

                    # Reset temporary storage regardless of success
                    current_event_data = None
                    current_stack_frames = None # Reset stack frame list
                    # Clear the element now that we are done with its end event
                    _clear_elem(elem)
                # --- END: Process <event> end ---

                # --- START: Clear other tags at end ---
                elif event_type == 'end':
                     # Clear other intermediate tags if necessary
                     # We need to be careful NOT to clear <frame> or <stack> here
                     # as their 'start' events might be processed before the parent 'event' start
                     if tag not in ['event', 'frame', 'stack']:
                         # logger.debug(f"Clearing intermediate tag: {tag}")
                         _clear_elem(elem)
                # --- END: Clear other tags at end ---


        elapsed = time.time() - start_time
        logger.info(f"Finished Pass 2: Processed {event_count:,} <event> elements, yielded {yielded_count:,}, skipped {skipped_count:,} ({elapsed:.2f}s).")

    except ET_impl.XMLSyntaxError as e: logger.error(f"XML Parse Error during event loading stream: {e}"); raise
    except Exception as e: logger.error(f"Unexpected error during event loading stream: {e}", exc_info=True); raise

# --- Data Container Class ---
@dataclasses.dataclass
class ProcmonLogData:
    """Holds the loaded and optimized data from a Procmon XML file."""
    # Configuration
    loaded_filename: Optional[str] = None
    loaded_compression: Optional[str] = None
    load_stack_traces: bool = True
    load_extra_data: bool = True

    # Loaded Data
    processes_by_index: Dict[int, ProcessInfo] = dataclasses.field(default_factory=dict)
    processes_by_pid: Dict[int, ProcessInfo] = dataclasses.field(default_factory=dict) # New: PID -> ProcessInfo map
    events: List[Dict[str, Any]] = dataclasses.field(default_factory=list) # Optimized event dictionaries
    interners: Dict[str, StringInterner] = dataclasses.field(default_factory=dict)

    # Indices
    pname_id_index: Dict[int, List[int]] = dataclasses.field(default_factory=lambda: defaultdict(list)) # {pname_id: [event_idx,...]}
    op_id_index: Dict[int, List[int]] = dataclasses.field(default_factory=lambda: defaultdict(list)) # {op_id: [event_idx,...]}

    def get_string(self, interner_key: str, id_val: Optional[int]) -> Optional[str]:
        """Looks up a string from its ID using the stored interners."""
        if id_val is None: return None
        interner = self.interners.get(interner_key)
        if interner:
            return interner.get_str(id_val)
        logger.warning(f"Interner '{interner_key}' not found during string lookup.")
        return f"<Unknown Interner:{interner_key}_ID:{id_val}>"

    def get_id(self, interner_key: str, s: Optional[str]) -> Optional[int]:
        """Looks up an ID from its string using the stored interners. Does NOT add new strings."""
        if s is None: return None
        interner = self.interners.get(interner_key)
        if interner:
            return interner.lookup_id(s) # Use lookup_id method
        logger.warning(f"Interner '{interner_key}' not found during ID lookup.")
        return None

    def is_loaded(self) -> bool:
        """Checks if data appears to be loaded."""
        # Check if events list is not None (even if empty) and filename is set
        return self.events is not None and self.loaded_filename is not None

# --- Global State (Reduced) ---
# Holds the single loaded ProcmonLogData instance after successful loading
LOADED_DATA: Optional[ProcmonLogData] = None

# --- Setup MCP ---
if MCP_SDK_AVAILABLE:
    mcp = FastMCP(
        "ProcmonXmlToolRefactored",
        description="A tool to analyze a specific, pre-loaded Procmon XML log file (plain or compressed) using in-memory optimization (Refactored)."
    )
else:
    mcp = MockMCP(
        "ProcmonXmlToolRefactored (Mock)",
        description="Mock Tool: Analyzes pre-loaded Procmon XML files (optimized in-memory, Refactored)."
     )

# --- REMOVED: Security Helper (get_secure_path) ---

# --- Loading Function ---
def load_procmon_xml(filename_abs: str, load_stack: bool, load_extra: bool) -> ProcmonLogData:
    """
    Loads XML file: Parses processes, then streams events, converting them
    to an optimized in-memory format using string interning. Stores results
    in a ProcmonLogData object. Builds indices.

    Args:
        filename_abs: Absolute path to the input XML file (.xml, .gz, .bz2, .xz).
        load_stack: Whether to load stack traces.
        load_extra: Whether to load extra unknown event fields.

    Returns:
        A populated ProcmonLogData instance.

    Raises:
        FileNotFoundError, ValueError, RuntimeError, ET_impl.XMLSyntaxError,
        Compression errors (e.g., gzip.BadGzipFile, lzma.LZMAError).
    """
    if not os.path.exists(filename_abs): raise FileNotFoundError(f"Input file not found: {filename_abs}")
    if not os.path.isfile(filename_abs): raise ValueError(f"Input path is not a file: {filename_abs}")

    log_data = ProcmonLogData(
        load_stack_traces=load_stack,
        load_extra_data=load_extra,
        loaded_filename=os.path.basename(filename_abs) # Store only basename
    )

    fname_lower = filename_abs.lower()
    compression: Optional[str] = None
    open_func: Any = open
    file_mode = "rb" # Read bytes

    # Determine compression type and open function
    if fname_lower.endswith(".xml"): compression = None
    elif fname_lower.endswith(".gz") or fname_lower.endswith(".xml.gz"):
        compression = 'gz'; open_func = gzip.open
    elif fname_lower.endswith(".bz2") or fname_lower.endswith(".xml.bz2"):
        compression = 'bz2'; open_func = bz2.open
    elif fname_lower.endswith(".xz") or fname_lower.endswith(".xml.xz"):
        compression = 'xz'; open_func = lzma.open
    else:
        logger.warning(f"File extension not recognized for compression type: {filename_abs}. Assuming plain XML.")

    log_data.loaded_compression = compression
    overall_start_time = time.time()

    # --- Get total file size for progress ---
    total_file_size: Optional[int] = None
    try:
        total_file_size = os.path.getsize(filename_abs)
        logger.info(f"Total input file size: {_format_bytes(total_file_size)}")
    except OSError as e:
        logger.warning(f"Could not get file size for progress reporting: {e}")
    # --- End Get total file size ---

    # Initialize interners
    log_data.interners = {
        IK_PROCESS_NAME: StringInterner(),
        IK_OPERATION: StringInterner(),
        IK_PATH: StringInterner(),
        IK_RESULT: StringInterner(),
        IK_CATEGORY: StringInterner(),
        IK_STACK_PATH: StringInterner(),
        IK_STACK_LOCATION: StringInterner(),
    }
    # Pre-intern known operation strings
    log_data.interners[IK_OPERATION].get_id(OP_PROCESS_CREATE)
    log_data.interners[IK_OPERATION].get_id(OP_PROCESS_EXIT)
    for op in NETWORK_OPERATIONS: log_data.interners[IK_OPERATION].get_id(op)

    try:
        comp_str = f" ({compression} compressed)" if compression else ""
        logger.info(f"Loading and optimizing{comp_str} XML file: {filename_abs}")

        # --- START FIX: Open raw file handle alongside compressed stream ---
        raw_f = None
        try:
            raw_f = open(filename_abs, "rb") # Open raw file for tell()

            # --- Pass 1: Parse Processes Only ---
            # Use a separate stream for pass 1 to avoid interfering with pass 2 position
            with open_func(filename_abs, file_mode) as f_stream_pass1:
                log_data.processes_by_index = _parse_xml_processes_only(f_stream_pass1)
                if log_data.processes_by_index is None: log_data.processes_by_index = {} # Safety

            # --- Build PID -> ProcessInfo Map ---
            for proc_info in log_data.processes_by_index.values():
                if proc_info.pid is not None:
                    if proc_info.pid in log_data.processes_by_pid:
                        # This might happen if PIDs are reused quickly, log a warning
                        logger.warning(f"Duplicate PID {proc_info.pid} encountered in process list. Using the last entry found (ProcessIndex: {proc_info.process_index}).")
                    log_data.processes_by_pid[proc_info.pid] = proc_info
            logger.info(f"Built PID-to-ProcessInfo map for {len(log_data.processes_by_pid)} unique PIDs.")


            # --- Pass 2: Parse Events and Optimize ---
            # Pass the raw file handle (raw_f) for progress reporting
            with open_func(raw_f, file_mode) as f_stream_pass2: # Use raw_f with the compression opener
                event_iterator = _parse_xml_stream_for_loading(
                    f_stream_pass2, log_data.interners, log_data.processes_by_index,
                    load_stack=log_data.load_stack_traces,
                    load_extra=log_data.load_extra_data,
                    raw_file_stream=raw_f, # Pass the raw file handle
                    total_size=total_file_size # Pass total size for progress
                )

                logger.info("[Loader] Starting consumption of event iterator...")
                temp_event_list = []
                consumed_count = 0
                try:
                    for idx, opt_event in enumerate(event_iterator): # Use enumerate to get index
                        temp_event_list.append(opt_event)
                        consumed_count += 1

                        # --- Build Indices ---
                        pname_id = opt_event.get('pname_id')
                        op_id = opt_event.get('op_id')
                        if pname_id is not None: log_data.pname_id_index[pname_id].append(idx)
                        if op_id is not None: log_data.op_id_index[op_id].append(idx)
                        # --- End Indexing ---

                        # Removed progress reporting from here, handled in parser now
                except Exception as consume_err:
                    logger.error(f"[Loader] Error during iterator consumption after {consumed_count} events: {consume_err}", exc_info=True)
                finally:
                    logger.info(f"[Loader] Finished consuming event iterator. Total events consumed in loop: {consumed_count}. Final list length: {len(temp_event_list)}")
                log_data.events = temp_event_list

        finally:
            if raw_f:
                raw_f.close() # Ensure raw file handle is closed
        # --- END FIX ---

        overall_end_time = time.time()
        logger.info(f"--- Loading Summary ---")
        logger.info(f" Successfully loaded and optimized {len(log_data.events):,} events from {log_data.loaded_filename}.")
        logger.info(f" Found {len(log_data.processes_by_index)} unique processes (by index).")
        logger.info(f" Built PName index for {len(log_data.pname_id_index)} names and OP index for {len(log_data.op_id_index)} operations.")
        logger.info(f" Total loading and optimization time: {overall_end_time - overall_start_time:.2f} seconds.")
        if logger.isEnabledFor(logging.DEBUG):
            for name, interner in log_data.interners.items():
                logger.debug(f"  Interner '{name}': {interner.next_id:,} unique strings.")

        return log_data # Return the populated object

    except (FileNotFoundError, ValueError) as e: logger.error(f"File error: {e}"); raise
    except ET_impl.XMLSyntaxError as e: logger.error(f"XML Syntax Error in {filename_abs}: {e}"); raise RuntimeError(f"Invalid XML: {e}") from e
    except (gzip.BadGzipFile, lzma.LZMAError, OSError) as e: # Handle compression and general I/O errors
        logger.error(f"File read/decompression error for {filename_abs}: {e}")
        raise RuntimeError(f"File read/decompression failed for '{filename_abs}'.") from e
    except Exception as e:
        logger.error(f"Error loading/optimizing file {filename_abs}: {e}", exc_info=True)
        raise RuntimeError(f"Failed to load/optimize file: {e}") from e


# --- Filtering Logic ---
async def _iter_filtered_event_indices(
    log_data: ProcmonLogData,
    ctx: Context, # For logging progress
    # Filters
    filter_process: Optional[str] = None,
    filter_operation: Optional[str] = None,
    filter_result: Optional[str] = None,
    filter_path_contains: Optional[str] = None,
    filter_process_contains: Optional[str] = None,
    filter_start_time: Optional[Any] = None,
    filter_end_time: Optional[Any] = None,
    filter_path_regex: Optional[str] = None,
    filter_process_regex: Optional[str] = None,
    filter_detail_regex: Optional[str] = None,
    filter_stack_module_path: Optional[str] = None,
) -> AsyncIterator[int]:
    """
    Asynchronously iterates through event indices, applying filters.
    Uses indices for Process Name and Operation if applicable.

    Yields:
        Integer indices of events matching all filters.
    """
    if not log_data or not log_data.is_loaded():
        await ctx.error("Filtering failed: Log data not loaded.")
        raise StopAsyncIteration("Log data not loaded.")
    if not log_data.events:
        await ctx.info("Filtering: No events loaded.")
        raise StopAsyncIteration("No events loaded.")

    try:
        start_time = time.time()

        # Pre-process Filters
        path_regex = re.compile(filter_path_regex, re.IGNORECASE) if filter_path_regex else None
        process_regex = re.compile(filter_process_regex, re.IGNORECASE) if filter_process_regex else None
        detail_regex = re.compile(filter_detail_regex, re.IGNORECASE) if filter_detail_regex else None
        start_ts: Optional[float] = None
        end_ts: Optional[float] = None
        is_start_time_only = False
        is_end_time_only = False
        try:
            if isinstance(filter_start_time, str):
                try:
                    parsed_time_obj = datetime.strptime(filter_start_time, PROCMON_TIMESTAMP_FORMAT).time()
                    start_ts = (parsed_time_obj.hour * 3600 + parsed_time_obj.minute * 60 + parsed_time_obj.second + parsed_time_obj.microsecond / 1e6)
                    is_start_time_only = True; logger.warning("Using time-only string filter for start_time.")
                except ValueError: start_ts = float(filter_start_time) # Try float conversion
            elif isinstance(filter_start_time, (int, float)): start_ts = float(filter_start_time)

            if isinstance(filter_end_time, str):
                try:
                    parsed_time_obj = datetime.strptime(filter_end_time, PROCMON_TIMESTAMP_FORMAT).time()
                    end_ts = (parsed_time_obj.hour * 3600 + parsed_time_obj.minute * 60 + parsed_time_obj.second + parsed_time_obj.microsecond / 1e6)
                    is_end_time_only = True; logger.warning("Using time-only string filter for end_time.")
                except ValueError: end_ts = float(filter_end_time) # Try float conversion
            elif isinstance(filter_end_time, (int, float)): end_ts = float(filter_end_time)
        except ValueError as e:
            await ctx.error(f"Invalid time format for filter: {e}")
            raise ValueError("Invalid time format for filter.") from e

        process_id_filter = log_data.get_id(IK_PROCESS_NAME, filter_process) if filter_process else None
        operation_id_filter = log_data.get_id(IK_OPERATION, filter_operation) if filter_operation else None
        result_id_filter = log_data.get_id(IK_RESULT, filter_result) if filter_result else None
        filter_path_contains_lower = filter_path_contains.lower() if filter_path_contains else None
        filter_process_contains_lower = filter_process_contains.lower() if filter_process_contains else None
        filter_stack_module_path_lower = filter_stack_module_path.lower() if filter_stack_module_path else None

        # --- Indexing Logic ---
        candidate_indices: Optional[Set[int]] = None
        if process_id_filter is not None:
            pid_indices = set(log_data.pname_id_index.get(process_id_filter, []))
            candidate_indices = pid_indices
            if not candidate_indices: await ctx.info(f"Filter Index: No events match PID filter '{filter_process}'."); return
        if operation_id_filter is not None:
            op_indices = set(log_data.op_id_index.get(operation_id_filter, []))
            if candidate_indices is None: candidate_indices = op_indices
            else: candidate_indices.intersection_update(op_indices)
            if not candidate_indices: await ctx.info(f"Filter Index: No events match Operation filter '{filter_operation}'."); return

        # Determine iterator
        if candidate_indices is not None:
            logger.info(f"Using index. Filtering {len(candidate_indices):,} candidate events.")
            indices_to_check = sorted(list(candidate_indices))
            total_to_scan = len(indices_to_check)
        else:
            logger.info("No index applicable. Filtering all events.")
            indices_to_check = range(len(log_data.events)) # Iterate over all indices
            total_to_scan = len(log_data.events)
        # --- End Indexing Logic ---

        processed_count = 0
        last_progress_report_time = start_time

        for idx in indices_to_check:
            event_dict = log_data.events[idx]
            processed_count += 1

            # Progress Reporting
            current_time = time.time()
            report_interval = max(10000, total_to_scan // 10) if total_to_scan > 0 else 10000
            if processed_count % report_interval == 0 or (current_time - last_progress_report_time > PROGRESS_REPORT_SECONDS): # Use constant
                try: await ctx.info(f" Filter scanned {processed_count:,}/{total_to_scan:,} candidate events... ({current_time - start_time:.1f}s)")
                except Exception as progress_err: logger.warning(f"Failed to send progress update during filter: {progress_err}")
                last_progress_report_time = current_time

            # --- Apply Remaining Filters ---
            match = True
            # Skip indexed filters if already applied by candidate_indices selection
            if candidate_indices is not None:
                if process_id_filter is not None and event_dict.get('pname_id') != process_id_filter: continue
                if operation_id_filter is not None and event_dict.get('op_id') != operation_id_filter: continue

            # Apply non-indexed exact match filters
            if match and result_id_filter is not None and event_dict.get('res_id') != result_id_filter: match = False

            # Time Filter
            if match and (start_ts is not None or end_ts is not None):
                event_ts_float = event_dict.get('ts') # Already parsed float
                if event_ts_float is None: match = False # Should not happen due to loading check
                else:
                    current_event_compare_val = event_ts_float
                    if is_start_time_only or is_end_time_only: # Compare only time part
                        try:
                            event_dt_obj = datetime.fromtimestamp(event_ts_float, timezone.utc)
                            current_event_compare_val = (event_dt_obj.hour * 3600 + event_dt_obj.minute * 60 + event_dt_obj.second + event_dt_obj.microsecond / 1e6)
                        except Exception: match = False; logger.warning(f"Could not extract time part from event timestamp {event_ts_float}")
                    if match and start_ts is not None and current_event_compare_val < start_ts: match = False
                    if match and end_ts is not None and current_event_compare_val > end_ts: match = False

            # Contains / Regex / Stack filters
            if match and (filter_path_contains_lower or filter_process_contains_lower or path_regex or process_regex or detail_regex or filter_stack_module_path_lower):
                path_str = ""
                pname_str = ""
                detail_str = event_dict.get('detail') or ""
                if filter_path_contains_lower or path_regex: path_str = log_data.get_string(IK_PATH, event_dict.get('path_id')) or ""
                if filter_process_contains_lower or process_regex: pname_str = log_data.get_string(IK_PROCESS_NAME, event_dict.get('pname_id')) or ""

                if match and filter_path_contains_lower and filter_path_contains_lower not in path_str.lower(): match = False
                if match and filter_process_contains_lower and filter_process_contains_lower not in pname_str.lower(): match = False
                if match and path_regex and not path_regex.search(path_str): match = False
                if match and process_regex and not process_regex.search(pname_str): match = False
                if match and detail_regex and not detail_regex.search(detail_str): match = False

                if match and filter_stack_module_path_lower:
                    if not log_data.load_stack_traces: match = True # Don't filter if stacks aren't loaded
                    else:
                        stack_list_optimized = event_dict.get('stack')
                        found_in_stack = False
                        if stack_list_optimized:
                            for frame_list in stack_list_optimized:
                                if len(frame_list) > 2 and frame_list[2] is not None:
                                    frame_path_str = log_data.get_string(IK_STACK_PATH, frame_list[2])
                                    if frame_path_str and filter_stack_module_path_lower in frame_path_str.lower():
                                        found_in_stack = True; break
                        if not found_in_stack: match = False

            # --- Yield index if all filters passed ---
            if match:
                yield idx

        filter_elapsed = time.time() - start_time
        logger.info(f"Filtering completed in {filter_elapsed:.2f}s.")

    except re.error as e:
        await ctx.error(f"Invalid Regex pattern provided: {e}")
        raise ValueError(f"Invalid regex pattern: {e}") from e
    except Exception as e:
        await ctx.error(f"Failed during event filtering: {e}")
        logger.debug("Filtering exception details:", exc_info=True)
        raise RuntimeError(f"Internal error filtering events: {e}")

# --- Helper to format event details ---
def _get_formatted_event_details(log_data: ProcmonLogData, event_index: int) -> Optional[Dict[str, Any]]:
    """
    Retrieves and formats the full details for a single event by its index.
    Handles string lookups, timestamp formatting, and process enrichment.
    Returns None if index is invalid.
    """
    if not log_data or not log_data.is_loaded() or not (0 <= event_index < len(log_data.events)):
        logger.error(f"Invalid request for event details: Index {event_index} out of bounds or data not loaded.")
        return None

    event_dict = log_data.events[event_index]
    details: Dict[str, Any] = {}

    try:
        details['event_index'] = event_index
        details['sequence_number'] = event_dict.get('seq')
        details['pid'] = event_dict.get('pid')
        details['tid'] = event_dict.get('tid')
        details['parent_pid'] = event_dict.get('ppid')
        details['duration'] = event_dict.get('dur')
        details['detail'] = event_dict.get('detail')

        ts_float = event_dict.get('ts')
        try: details['timestamp'] = datetime.fromtimestamp(ts_float, timezone.utc).strftime(PROCMON_TIMESTAMP_FORMAT) if ts_float else None
        except Exception: details['timestamp'] = "<Invalid Timestamp>"
        details['timestamp_unix'] = ts_float

        details['operation'] = log_data.get_string(IK_OPERATION, event_dict.get('op_id'))
        details['path'] = log_data.get_string(IK_PATH, event_dict.get('path_id'))
        details['result'] = log_data.get_string(IK_RESULT, event_dict.get('res_id'))
        details['category'] = log_data.get_string(IK_CATEGORY, event_dict.get('cat_id'))
        details['process_name'] = log_data.get_string(IK_PROCESS_NAME, event_dict.get('pname_id'))

        if log_data.load_extra_data and 'extra_data' in event_dict:
            details['extra_data'] = event_dict['extra_data']
        else:
             details['extra_data'] = None # Ensure key exists

        # Add stack trace if loaded and present
        if log_data.load_stack_traces and 'stack' in event_dict:
            stack_list = []
            for frame_data in event_dict['stack']:
                try:
                    stack_list.append({
                        'depth': frame_data[0], 'address': frame_data[1],
                        'path': log_data.get_string(IK_STACK_PATH, frame_data[2]),
                        'location': log_data.get_string(IK_STACK_LOCATION, frame_data[3])
                    })
                except (IndexError, TypeError): logger.warning(f"Malformed stack frame data in event {event_index}: {frame_data}")
            details['stack_trace'] = stack_list
        else:
            details['stack_trace'] = None # Ensure key exists

        # Add enriched process info using the PID map
        process_obj = log_data.processes_by_pid.get(details.get('pid')) if details.get('pid') is not None else None
        if process_obj:
            proc_details_dict = dataclasses.asdict(process_obj)
            proc_details_dict.pop('process_index', None); proc_details_dict.pop('parent_process_index', None)
            details['process_details_summary'] = proc_details_dict
            details['user_sid'] = process_obj.owner
            details['is_64bit_process'] = process_obj.is_64bit
            if process_obj.parent_pid is not None: details['parent_pid'] = process_obj.parent_pid # Overwrite if available
            if process_obj.process_name is not None: details['process_name'] = process_obj.process_name # Overwrite if available
        else:
            details['process_details_summary'] = {"pid": details['pid'], "process_name": details['process_name'], "message": "Process details not found in <processlist>."}
            details['user_sid'] = None
            details['is_64bit_process'] = None

        details['completion_time'] = None # Not stored
        details['relative_time'] = None # Not stored

        return details

    except Exception as e:
        logger.error(f"Error formatting details for event {event_index}: {e}", exc_info=True)
        return None # Return None on formatting error

# --- MCP Tools (Adapted for ProcmonLogData) ---
tool_decorator = mcp.tool() if MCP_SDK_AVAILABLE else lambda func: func

@tool_decorator
async def get_loaded_file_summary(ctx: Context) -> Dict[str, Any]:
    """
    Returns a basic summary of the pre-loaded Procmon XML file data.
    """
    await ctx.info(f"Request received for summary of pre-loaded file.")
    # Use the global LOADED_DATA instance
    if not LOADED_DATA or not LOADED_DATA.is_loaded():
        await ctx.error("No Procmon XML file data was successfully pre-loaded.")
        raise RuntimeError("Operation failed: No Procmon file data is loaded.")

    log_data = LOADED_DATA
    try:
        summary = {
            "loaded_filename": log_data.loaded_filename, "file_type": "xml",
            "compression": log_data.loaded_compression,
            "process_count": len(log_data.processes_by_index),
            "event_count": len(log_data.events),
            "os_version": "N/A (XML)", "computer_name": "N/A (XML)", "is_64bit_os": None
        }
        summary["interner_stats"] = {name: interner.next_id for name, interner in log_data.interners.items()}
        summary["index_stats"] = {
            "pname_indexed_count": len(log_data.pname_id_index),
            "op_indexed_count": len(log_data.op_id_index),
        }
        summary["selective_loading"] = {
            "stack_traces": log_data.load_stack_traces,
            "extra_data": log_data.load_extra_data,
        }
        await ctx.info(f"Successfully generated summary for {log_data.loaded_filename}.")
        return summary
    except Exception as e:
        await ctx.error(f"Error generating summary for {log_data.loaded_filename}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error generating summary: {e}")

@tool_decorator
async def query_events(
    # Standard Filters (same as before)
    filter_process: Optional[str] = None, filter_operation: Optional[str] = None,
    filter_result: Optional[str] = None, filter_path_contains: Optional[str] = None,
    filter_process_contains: Optional[str] = None, filter_start_time: Optional[Any] = None,
    filter_end_time: Optional[Any] = None, filter_path_regex: Optional[str] = None,
    filter_process_regex: Optional[str] = None, filter_detail_regex: Optional[str] = None,
    filter_stack_module_path: Optional[str] = None,
    # Limit
    limit: int = 50,
    *, ctx: Context
) -> List[Dict[str, Any]]:
    """
    Queries events from the optimized in-memory data, applying multiple filters (AND logic).
    Uses indices for Process Name and Operation filters if available.
    Returns event summaries including the event index. Use 'get_event_details' with index.
    (See tool docstring in original script for detailed filter behavior notes)
    """
    await ctx.info(f"Request received to query in-memory events with multiple filters. Limit={limit}")
    filters_applied = {k:v for k,v in locals().items() if k.startswith('filter_') and v is not None}
    if filters_applied: logger.debug(f"Filters Applied: {filters_applied}")
    else: logger.debug("No filters applied.")

    if not LOADED_DATA or not LOADED_DATA.is_loaded():
        await ctx.error(f"Query failed: Event data not loaded.")
        raise TypeError("Operation requires optimized event data to be loaded.")
    if not LOADED_DATA.events:
        await ctx.info("Query finished: No events loaded in memory to query.")
        return []

    log_data = LOADED_DATA
    filtered_event_summaries = []
    count = 0
    query_start_time = time.time()

    try:
        # Use the refactored filtering generator
        event_indices_iterator = _iter_filtered_event_indices(
            log_data=log_data, ctx=ctx, # Pass log_data and ctx
            filter_process=filter_process, filter_operation=filter_operation,
            filter_result=filter_result, filter_path_contains=filter_path_contains,
            filter_process_contains=filter_process_contains, filter_start_time=filter_start_time,
            filter_end_time=filter_end_time, filter_path_regex=filter_path_regex,
            filter_process_regex=filter_process_regex, filter_detail_regex=filter_detail_regex,
            filter_stack_module_path=filter_stack_module_path
        )

        async for idx in event_indices_iterator:
            if count >= limit:
                await ctx.info(f"Query limit ({limit}) reached.")
                break # Stop if limit reached

            event_dict = log_data.events[idx]
            try:
                # Create summary (subset of full details)
                ts_display = datetime.fromtimestamp(event_dict['ts'], timezone.utc).strftime(PROCMON_TIMESTAMP_FORMAT) if event_dict.get('ts') else None
                event_summary = {
                    'event_index': idx,
                    'timestamp': ts_display,
                    'process_name': log_data.get_string(IK_PROCESS_NAME, event_dict.get('pname_id')),
                    'pid': event_dict.get('pid'),
                    'operation': log_data.get_string(IK_OPERATION, event_dict.get('op_id')),
                    'path': log_data.get_string(IK_PATH, event_dict.get('path_id')),
                    'result': log_data.get_string(IK_RESULT, event_dict.get('res_id')),
                }
                filtered_event_summaries.append(event_summary)
                count += 1
            except Exception as summary_err:
                await ctx.warning(f"Error creating summary for event index {idx}: {summary_err}")
                logger.debug(f"Summary creation error details:", exc_info=True)

        elapsed = time.time() - query_start_time
        await ctx.info(f"Query finished in {elapsed:.2f}s. Found {len(filtered_event_summaries)} matching event summaries (limit {limit}).")
        return filtered_event_summaries

    except (ValueError, TypeError, RuntimeError, re.error) as e: # Catch errors from filtering or summary creation
        await ctx.error(f"Failed to query events: {e}")
        logger.debug("Query exception details:", exc_info=True)
        # Re-raise specific types if needed, otherwise wrap
        if isinstance(e, (ValueError, TypeError, re.error)): raise e
        else: raise RuntimeError(f"Internal error querying events: {e}") from e

@tool_decorator
async def get_event_details(event_index: int, ctx: Context) -> Dict[str, Any]:
    """
    Retrieves detailed properties for a specific event from the optimized in-memory data,
    referenced by its list index. Use 'query_events' first to find the index.
    Includes 'extra_data' and 'stack_trace' fields if loaded.
    """
    await ctx.info(f"Request received for details of event index: {event_index}")
    if not LOADED_DATA or not LOADED_DATA.is_loaded():
        await ctx.error(f"Get details failed: Event data not loaded.")
        raise TypeError("Operation requires optimized event data to be loaded.")

    try:
        # Use the helper function to get formatted details
        details = _get_formatted_event_details(LOADED_DATA, event_index)

        if details is None:
            # Error should have been logged by the helper, raise appropriate exception
            num_events = len(LOADED_DATA.events)
            upper_bound = num_events - 1 if num_events > 0 else -1
            await ctx.error(f"Invalid event index: {event_index}. Must be between 0 and {upper_bound}.")
            raise IndexError(f"Event index {event_index} is out of bounds or details could not be formatted.")

        await ctx.info(f"Successfully retrieved details for event index {event_index}.")
        return details

    except IndexError as e: raise e # Re-raise index error
    except Exception as e:
        await ctx.error(f"Failed to get details for event {event_index}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving event details: {e}")

@tool_decorator
async def get_event_stack_trace(event_index: int, ctx: Context) -> List[Dict[str, Any]]:
    """
    Retrieves the detailed call stack trace for a specific event from the optimized in-memory data,
    referenced by its list index. Returns empty list if stack not loaded or not present.
    """
    await ctx.info(f"Request received for stack trace of event index: {event_index}")
    if not LOADED_DATA or not LOADED_DATA.is_loaded():
        await ctx.error(f"Get stack trace failed: Event data not loaded.")
        raise TypeError("Operation requires optimized event data to be loaded.")

    log_data = LOADED_DATA
    if not log_data.load_stack_traces:
        await ctx.warning("Stack traces were not loaded (--no-stack-traces). Returning empty list.")
        return []

    try:
        num_events = len(log_data.events)
        if not 0 <= event_index < num_events:
            upper_bound = num_events - 1 if num_events > 0 else -1
            await ctx.error(f"Invalid event index: {event_index}. Must be between 0 and {upper_bound}.")
            raise IndexError(f"Event index {event_index} is out of bounds.")

        event_dict = log_data.events[event_index]
        stack_list_optimized = event_dict.get('stack') # Will be None if not present

        detailed_stack = []
        if stack_list_optimized:
            for frame_data in stack_list_optimized:
                try:
                    if not isinstance(frame_data, (list, tuple)) or len(frame_data) < 4:
                        logger.warning(f"Malformed optimized stack frame data encountered for event index {event_index}: {frame_data}")
                        continue
                    frame_dict = {
                        'depth': frame_data[0],
                        'address': frame_data[1],
                        'path': log_data.get_string(IK_STACK_PATH, frame_data[2]),
                        'location': log_data.get_string(IK_STACK_LOCATION, frame_data[3])
                    }
                    detailed_stack.append(frame_dict)
                except IndexError: logger.warning(f"IndexError processing optimized stack frame for event index {event_index}: {frame_data}")
                except Exception as frame_e: logger.warning(f"Unexpected error processing stack frame for event index {event_index}: {frame_e}", exc_info=False)

        await ctx.info(f"Successfully retrieved stack trace (length: {len(detailed_stack)}) for event index {event_index}.")
        return detailed_stack

    except IndexError as e: raise e
    except Exception as e:
        await ctx.error(f"Failed to get stack trace for event {event_index}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving event stack trace: {e}")

# --- Tools operating on Process Data ---
@tool_decorator
async def list_processes(ctx: Context) -> List[Dict[str, Any]]:
    """ Lists summary info (pid, process_name, image_path, parent_pid) from the loaded process list. """
    await ctx.info(f"Request received to list processes from pre-loaded process list.")
    if not LOADED_DATA or not LOADED_DATA.is_loaded():
        await ctx.error(f"List processes failed: Process list not loaded.")
        raise TypeError("Operation requires process list data to be loaded.")

    log_data = LOADED_DATA
    try:
        # Use processes_by_index as it contains all parsed processes
        process_list = list(log_data.processes_by_index.values())
        process_summaries = []
        summary_attributes = ['pid', 'process_name', 'image_path', 'parent_pid']
        for process_obj in process_list:
            summary = {attr: getattr(process_obj, attr, None) for attr in summary_attributes}
            if summary.get('pid') is None: continue
            process_summaries.append(summary)
        process_summaries.sort(key=lambda x: x.get('pid') or 0) # Sort by PID
        await ctx.info(f"Generated {len(process_summaries)} process summaries.")
        return process_summaries
    except Exception as e:
        await ctx.error(f"Failed to list processes from loaded data: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error listing processes: {e}")

@tool_decorator
async def get_process_details(pid: int, ctx: Context) -> Dict[str, Any]:
    """ Retrieves detailed info for a specific PID from the loaded process list using PID map. """
    await ctx.info(f"Request received for details of PID: {pid} from loaded process list.")
    if not LOADED_DATA or not LOADED_DATA.is_loaded():
        await ctx.error(f"Get process details failed: Process list not loaded.")
        raise TypeError("Operation requires process list data to be loaded.")

    log_data = LOADED_DATA
    try:
        # Use the optimized PID -> ProcessInfo map
        process_obj = log_data.processes_by_pid.get(pid)
        if not process_obj:
            raise ValueError(f"Process with PID {pid} not found in pre-loaded list.")

        details = dataclasses.asdict(process_obj)
        details.pop('process_index', None); details.pop('parent_process_index', None) # Clean up internal fields
        details['modules_summary'] = "N/A (Module info not typically in XML process list)"
        await ctx.info(f"Successfully retrieved details for PID {pid}.")
        return details
    except ValueError as e: await ctx.error(str(e)); raise e
    except Exception as e:
        await ctx.error(f"Failed to get details for PID {pid}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving process details: {e}")

@tool_decorator
async def get_metadata(ctx: Context) -> Dict[str, Any]:
    """ Retrieves metadata for the loaded XML file. """
    await ctx.info(f"Request received for metadata from XML file.")
    if not LOADED_DATA or not LOADED_DATA.is_loaded():
        await ctx.error(f"Get metadata failed: Data not fully loaded.")
        raise TypeError("Operation requires file data to be pre-loaded.")

    log_data = LOADED_DATA
    try:
        metadata = {
            "loaded_filename": log_data.loaded_filename, "file_type": "xml",
            "compression": log_data.loaded_compression, "header_found": False,
            "message": "Standard OS/Header info N/A for XML format.",
            "os_version": None, "computer_name": None,
            "process_count_loaded": len(log_data.processes_by_index),
            "event_count_loaded": len(log_data.events)
        }
        await ctx.info(f"Successfully retrieved metadata from {log_data.loaded_filename}.")
        return metadata
    except Exception as e:
        await ctx.error(f"Failed to get metadata: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving metadata: {e}")

# --- Analysis Tools (Operating on ProcmonLogData) ---

@tool_decorator
async def count_events_by_process(ctx: Context) -> Dict[str, int]:
    """ Counts events per process name from the loaded in-memory data. """
    await ctx.info(f"Request received to count events by process name (in-memory).")
    if not LOADED_DATA or not LOADED_DATA.is_loaded():
        await ctx.error("Operation failed: Optimized event data not loaded.")
        raise TypeError("Operation requires optimized event data to be loaded.")
    if not LOADED_DATA.events:
        await ctx.info("Count events by process: No events loaded.")
        return {}

    log_data = LOADED_DATA
    try:
        event_counts = defaultdict(int)
        start_time = time.time()
        total_events = len(log_data.events)
        last_progress_report_time = start_time

        for i, event_dict in enumerate(log_data.events):
            current_time = time.time()
            if i > 0 and (i % (PROGRESS_REPORT_INTERVAL * 4) == 0 or (current_time - last_progress_report_time > PROGRESS_REPORT_SECONDS)): # Use constant
                elapsed = current_time - start_time
                try: await ctx.info(f" Counting... processed {i:,}/{total_events:,} events ({elapsed:.1f}s)")
                except Exception as progress_err: logger.warning(f"Failed to send progress update during count: {progress_err}")
                last_progress_report_time = current_time

            process_name = log_data.get_string(IK_PROCESS_NAME, event_dict.get('pname_id')) or 'Unknown/Missing'
            event_counts[process_name] += 1

        elapsed = time.time() - start_time
        sorted_counts = dict(sorted(event_counts.items(), key=lambda item: item[1], reverse=True))
        await ctx.info(f"Counted {total_events:,} total events for {len(sorted_counts)} processes ({elapsed:.2f}s).")
        return sorted_counts
    except Exception as e:
        await ctx.error(f"Failed to count events by process: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error counting events by process: {e}")

@tool_decorator
async def summarize_operations_by_process(process_name_filter: str, ctx: Context) -> Dict[str, int]:
    """ Counts operations for a specific process name (case-sensitive match) from loaded data. """
    await ctx.info(f"Request to summarize operations for process: {process_name_filter} (in-memory).")
    if not LOADED_DATA or not LOADED_DATA.is_loaded():
        await ctx.error("Operation failed: Optimized event data not loaded.")
        raise TypeError("Operation requires optimized event data to be loaded.")
    if not process_name_filter:
        await ctx.error("Process name filter cannot be empty."); raise ValueError("Process name filter is required.")
    if not LOADED_DATA.events:
        await ctx.info(f"Summarize operations for '{process_name_filter}': No events loaded.")
        return {}

    log_data = LOADED_DATA
    try:
        operation_counts = defaultdict(int)
        event_count_for_process = 0
        start_time = time.time()

        target_pname_id = log_data.get_id(IK_PROCESS_NAME, process_name_filter)
        if target_pname_id is None:
            await ctx.warning(f"Process name '{process_name_filter}' not found in loaded data. No events will match.")
            return {}

        indices_to_check = log_data.pname_id_index.get(target_pname_id)
        if not indices_to_check:
            await ctx.warning(f"No events found matching process name '{process_name_filter}'.")
            return {}

        await ctx.info(f"Summarizing operations for {len(indices_to_check):,} events matching '{process_name_filter}'...")
        last_progress_report_time = start_time

        for i, idx in enumerate(indices_to_check):
            current_time = time.time()
            if i > 0 and (i % (PROGRESS_REPORT_INTERVAL * 4) == 0 or (current_time - last_progress_report_time > PROGRESS_REPORT_SECONDS)): # Use constant
                elapsed = current_time - start_time
                try: await ctx.info(f" Summarizing '{process_name_filter}'... processed {i:,}/{len(indices_to_check):,} matching events ({elapsed:.1f}s)")
                except Exception as progress_err: logger.warning(f"Failed to send progress update during summarize: {progress_err}")
                last_progress_report_time = current_time

            event_dict = log_data.events[idx]
            event_count_for_process += 1
            operation = log_data.get_string(IK_OPERATION, event_dict.get('op_id')) or 'Unknown'
            operation_counts[operation] += 1

        elapsed = time.time() - start_time
        sorted_counts = dict(sorted(operation_counts.items(), key=lambda item: item[1], reverse=True))
        await ctx.info(f"Summarized {len(sorted_counts)} unique ops for '{process_name_filter}' ({event_count_for_process:,} events found) ({elapsed:.2f}s).")
        return sorted_counts

    except Exception as e:
        await ctx.error(f"Failed to summarize operations for '{process_name_filter}': {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error summarizing operations: {e}")

@tool_decorator
async def get_timing_statistics(group_by: str = "process", *, ctx: Context) -> Dict[str, Dict[str, Any]]:
    """ Calculates event duration statistics grouped by 'process' or 'operation'. """
    await ctx.info(f"Request received to calculate timing statistics grouped by '{group_by}' (in-memory).")
    if group_by not in ["process", "operation"]:
        await ctx.error("Invalid group_by value. Must be 'process' or 'operation'."); raise ValueError("Invalid group_by value.")
    if not LOADED_DATA or not LOADED_DATA.is_loaded():
        await ctx.error("Operation failed: Optimized event data not loaded.")
        raise TypeError("Operation requires optimized event data to be loaded.")
    if not LOADED_DATA.events:
        await ctx.info(f"Get timing statistics grouped by '{group_by}': No events loaded.")
        return {}

    log_data = LOADED_DATA
    try:
        stats = defaultdict(lambda: {'min': float('inf'), 'max': float('-inf'), 'sum': 0.0, 'count': 0})
        total_events = len(log_data.events)
        start_time = time.time()
        events_with_duration = 0
        last_progress_report_time = start_time

        for i, event_dict in enumerate(log_data.events):
            current_time = time.time()
            if i > 0 and (i % (PROGRESS_REPORT_INTERVAL * 4) == 0 or (current_time - last_progress_report_time > PROGRESS_REPORT_SECONDS)): # Use constant
                elapsed = current_time - start_time
                try: await ctx.info(f" Calculating stats... processed {i:,}/{total_events:,} events ({elapsed:.1f}s)")
                except Exception as progress_err: logger.warning(f"Failed to send progress update during timing stats: {progress_err}")
                last_progress_report_time = current_time

            duration = event_dict.get('dur')
            # Ensure duration is a valid float > 0
            if duration is None or not isinstance(duration, (float, int)) or duration <= 0:
                 # --- DEBUG: Log if duration is invalid for stats ---
                 if duration is not None and logger.isEnabledFor(logging.DEBUG):
                     logger.debug(f"Event {i} has invalid duration for stats: '{duration}' (Type: {type(duration)})")
                 # --- END DEBUG ---
                 continue
            events_with_duration += 1
            # --- DEBUG: Log first valid duration found ---
            if events_with_duration == 1 and logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"Event {i} has first valid duration for stats: {duration}")
            # --- END DEBUG ---


            group_key_id = event_dict.get('pname_id') if group_by == "process" else event_dict.get('op_id')
            interner_name = IK_PROCESS_NAME if group_by == "process" else IK_OPERATION
            group_key = log_data.get_string(interner_name, group_key_id) or 'Unknown/Missing'

            group_stats = stats[group_key]
            group_stats['count'] += 1
            group_stats['sum'] += duration
            if duration < group_stats['min']: group_stats['min'] = duration
            if duration > group_stats['max']: group_stats['max'] = duration

        output_stats_list = []
        for key, data in stats.items():
            if data['count'] > 0:
                avg = data['sum'] / data['count']
                output_stats_list.append({
                    'group': key, 'count': data['count'],
                    'min_duration': data['min'] if data['min'] != float('inf') else None,
                    'max_duration': data['max'] if data['max'] != float('-inf') else None,
                    'avg_duration': avg, 'total_duration': data['sum']
                })

        output_stats_list.sort(key=lambda x: x['count'], reverse=True)
        final_output_stats = {item['group']: {k: v for k, v in item.items() if k != 'group'} for item in output_stats_list}

        elapsed = time.time() - start_time
        await ctx.info(f"Calculated timing statistics for {len(final_output_stats)} groups based on {events_with_duration:,} events with duration > 0 ({elapsed:.2f}s).")
        return final_output_stats

    except Exception as e:
        await ctx.error(f"Failed to calculate timing statistics: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error calculating timing statistics: {e}")

@tool_decorator
async def get_process_lifetime(pid: int, ctx: Context) -> Dict[str, Optional[float]]:
    """ Finds the 'Process Create' and 'Process Exit' event timestamps for a given PID. """
    await ctx.info(f"Request received for lifetime of PID: {pid}")
    if not LOADED_DATA or not LOADED_DATA.is_loaded():
        await ctx.error("Operation failed: Event data not loaded.")
        raise TypeError("Operation requires event data to be loaded.")

    log_data = LOADED_DATA
    create_ts: Optional[float] = None
    exit_ts: Optional[float] = None
    create_op_id = log_data.get_id(IK_OPERATION, OP_PROCESS_CREATE)
    exit_op_id = log_data.get_id(IK_OPERATION, OP_PROCESS_EXIT)

    # This still requires iterating, but could potentially be optimized
    # by checking the PID map first to see if the process even exists.
    if pid not in log_data.processes_by_pid:
            await ctx.warning(f"PID {pid} not found in initial process list. It might have started/exited before the list snapshot.")
            # Still scan events as it might appear there

    for event_dict in log_data.events:
        if event_dict.get('pid') == pid:
            op_id = event_dict.get('op_id')
            if op_id == create_op_id and create_ts is None: create_ts = event_dict.get('ts')
            elif op_id == exit_op_id: exit_ts = event_dict.get('ts') # Keep updating to find last exit

    result = {"create_timestamp": create_ts, "exit_timestamp": exit_ts}
    await ctx.info(f"Found lifetime for PID {pid}: {result}")
    return result

@tool_decorator
async def find_file_access(path_contains: str, limit: int = 100, *, ctx: Context) -> List[Dict[str, Any]]:
    """ Finds events related to file system access where the path contains the given substring. """
    await ctx.info(f"Request received to find file access containing: '{path_contains}' (limit={limit})")
    if not LOADED_DATA or not LOADED_DATA.is_loaded():
        await ctx.error("Operation failed: Event data not loaded.")
        raise TypeError("Operation requires event data to be loaded.")
    if not path_contains:
        await ctx.error("path_contains filter cannot be empty."); raise ValueError("path_contains filter is required.")

    log_data = LOADED_DATA
    found_events = []
    count = 0
    path_contains_lower = path_contains.lower()

    # This tool doesn't benefit much from indexing unless we add path indices
    for idx, event_dict in enumerate(log_data.events):
        if count >= limit: break
        path_id = event_dict.get('path_id')
        if path_id is not None:
            path_str = log_data.get_string(IK_PATH, path_id)
            if path_str and path_contains_lower in path_str.lower():
                try:
                    ts_display = datetime.fromtimestamp(event_dict['ts'], timezone.utc).strftime(PROCMON_TIMESTAMP_FORMAT) if event_dict.get('ts') else None
                    summary = {
                        'event_index': idx, 'timestamp': ts_display,
                        'process_name': log_data.get_string(IK_PROCESS_NAME, event_dict.get('pname_id')),
                        'pid': event_dict.get('pid'),
                        'operation': log_data.get_string(IK_OPERATION, event_dict.get('op_id')),
                        'path': path_str,
                        'result': log_data.get_string(IK_RESULT, event_dict.get('res_id')),
                    }
                    found_events.append(summary)
                    count += 1
                except Exception as e:
                    logger.warning(f"Error creating summary for file access event {idx}: {e}")

    await ctx.info(f"Found {len(found_events)} file access events matching '{path_contains}' (limit {limit}).")
    return found_events

@tool_decorator
async def find_network_connections(process_name: str, *, ctx: Context) -> List[str]:
    """ Finds unique remote network endpoints (IP:port) accessed by a specific process. """
    await ctx.info(f"Request received to find network connections for process: '{process_name}'")
    if not LOADED_DATA or not LOADED_DATA.is_loaded():
        await ctx.error("Operation failed: Event data not loaded.")
        raise TypeError("Operation requires event data to be loaded.")
    if not process_name:
        await ctx.error("process_name filter cannot be empty."); raise ValueError("process_name filter is required.")

    log_data = LOADED_DATA
    remote_endpoints = set()
    target_pname_id = log_data.get_id(IK_PROCESS_NAME, process_name)
    network_op_ids = {log_data.get_id(IK_OPERATION, op) for op in NETWORK_OPERATIONS if log_data.get_id(IK_OPERATION, op) is not None}

    if target_pname_id is None:
        await ctx.warning(f"Process name '{process_name}' not found in loaded data. Returning empty list.")
        return []
    if not network_op_ids:
        await ctx.warning(f"Could not find standard network operations in interner. Returning empty list.")
        return []

    indices_to_check = log_data.pname_id_index.get(target_pname_id, [])
    if not indices_to_check:
        await ctx.info(f"No events found for process '{process_name}'.")
        return []

    await ctx.info(f"Scanning {len(indices_to_check):,} events for process '{process_name}' for network activity...")
    endpoint_regex = re.compile(r".* -> \[?([a-fA-F0-9:.]+)\]?:(\d+)")
    processed_count = 0
    start_time = time.time()
    last_progress_report_time = start_time

    for idx in indices_to_check:
        processed_count += 1
        event_dict = log_data.events[idx]
        op_id = event_dict.get('op_id')

        if op_id in network_op_ids:
            path_str = log_data.get_string(IK_PATH, event_dict.get('path_id'))
            if path_str:
                match = endpoint_regex.match(path_str)
                if match: remote_endpoints.add(f"{match.group(1)}:{match.group(2)}")

        current_time = time.time()
        if processed_count % 50000 == 0 or (current_time - last_progress_report_time > PROGRESS_REPORT_SECONDS): # Use constant
            elapsed = current_time - start_time
            try: await ctx.info(f" Network scan progress: {processed_count:,}/{len(indices_to_check):,} events checked ({elapsed:.1f}s)")
            except Exception: pass
            last_progress_report_time = current_time

    sorted_endpoints = sorted(list(remote_endpoints))
    await ctx.info(f"Found {len(sorted_endpoints)} unique remote network endpoints for '{process_name}'.")
    return sorted_endpoints

@tool_decorator
async def export_query_results(
    output_file: str,
    output_format: str = 'csv', # 'csv' or 'json'
    # Filters (same as query_events)
    filter_process: Optional[str] = None, filter_operation: Optional[str] = None,
    filter_result: Optional[str] = None, filter_path_contains: Optional[str] = None,
    filter_process_contains: Optional[str] = None, filter_start_time: Optional[Any] = None,
    filter_end_time: Optional[Any] = None, filter_path_regex: Optional[str] = None,
    filter_process_regex: Optional[str] = None, filter_detail_regex: Optional[str] = None,
    filter_stack_module_path: Optional[str] = None,
    *, ctx: Context
) -> Dict[str, Any]:
    """
    Queries events using the specified filters and exports the full details
    of matching events to a file (CSV or JSON).
    """
    await ctx.info(f"Request received to export events to '{output_file}' in {output_format} format.")
    if output_format.lower() not in ['csv', 'json']:
        raise ValueError("Invalid output_format. Must be 'csv' or 'json'.")
    if not output_file:
         raise ValueError("Output file name cannot be empty.")

    # --- Path Validation (Simplified - assumes CWD or absolute path is okay) ---
    # WARNING: This is less secure than the original get_secure_path.
    # Production use might require re-adding path validation based on deployment context.
    try:
        abs_output_path = os.path.abspath(output_file)
        # Basic check to prevent writing outside current working directory if relative path used
        if not output_file.startswith('/') and not output_file.startswith('\\') and ".." in output_file:
            # A very basic check, might need refinement depending on security needs
            raise ValueError("Output path appears to traverse directories ('..'). Please use absolute paths or paths within the current directory.")
        output_dir = os.path.dirname(abs_output_path)
        if output_dir and not os.path.exists(output_dir):
            try: os.makedirs(output_dir); logger.info(f"Created output directory: {output_dir}")
            except OSError as e: raise ValueError(f"Could not create output directory '{output_dir}': {e}") from e
        await ctx.info(f"Output path set to: {abs_output_path}")
    except ValueError as e:
        await ctx.error(f"Invalid output file path: {e}")
        raise e
    # --- End Simplified Path Validation ---

    if not LOADED_DATA or not LOADED_DATA.is_loaded():
        await ctx.error(f"Export failed: Event data not loaded.")
        raise TypeError("Operation requires optimized event data to be loaded.")
    if not LOADED_DATA.events:
        await ctx.info("Export finished: No events loaded in memory to export.")
        return {"success": True, "output_path": abs_output_path, "events_exported": 0}

    log_data = LOADED_DATA
    events_to_export = []
    events_exported = 0
    export_start_time = time.time()

    try:
        # Use the refactored filtering generator
        await ctx.info("Filtering events for export...")
        event_indices_iterator = _iter_filtered_event_indices(
            log_data=log_data, ctx=ctx, # Pass log_data and ctx
            filter_process=filter_process, filter_operation=filter_operation,
            filter_result=filter_result, filter_path_contains=filter_path_contains,
            filter_process_contains=filter_process_contains, filter_start_time=filter_start_time,
            filter_end_time=filter_end_time, filter_path_regex=filter_path_regex,
            filter_process_regex=filter_process_regex, filter_detail_regex=filter_detail_regex,
            filter_stack_module_path=filter_stack_module_path
        )

        # Collect details for matching events
        await ctx.info("Retrieving full details for matching events...")
        detail_retrieval_start = time.time()
        indices_processed = 0
        async for event_idx in event_indices_iterator:
            indices_processed += 1
            details = _get_formatted_event_details(log_data, event_idx)
            if details:
                events_to_export.append(details)
            else:
                await ctx.warning(f"Could not retrieve details for event index {event_idx}, skipping export.")

            if indices_processed % 10000 == 0:
                 try: await ctx.info(f" Export: Retrieved details for {indices_processed:,} events...")
                 except Exception: pass # Ignore progress errors

        await ctx.info(f"Retrieved details for {len(events_to_export)} events in {time.time() - detail_retrieval_start:.2f}s.")

        # Write to file
        if not events_to_export:
            await ctx.info("No matching events to export.")
            # Optionally create an empty file with headers for CSV
            if output_format.lower() == 'csv':
                 try:
                     with open(abs_output_path, 'w', newline='', encoding='utf-8') as csvfile:
                         # Define expected headers even if no data
                         fieldnames = ['event_index', 'sequence_number', 'timestamp', 'process_name', 'pid', 'tid', 'operation', 'path', 'result', 'detail', 'duration', 'category', 'parent_pid', 'extra_data', 'stack_trace', 'user_sid', 'is_64bit_process', 'process_details_summary']
                         writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                         writer.writeheader()
                     await ctx.info(f"Created empty CSV file with headers: {abs_output_path}")
                 except IOError as e:
                     await ctx.error(f"Error writing empty CSV file '{abs_output_path}': {e}")
                     # Don't raise, just report 0 exported below
            return {"success": True, "output_path": abs_output_path, "events_exported": 0}

        # Write actual data
        if output_format.lower() == 'csv':
            fieldnames = list(events_to_export[0].keys()) # Get headers from first event
            try:
                with open(abs_output_path, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                    writer.writeheader()
                    for row_dict in events_to_export:
                        # Convert complex types to JSON strings for CSV
                        if isinstance(row_dict.get('extra_data'), dict): row_dict['extra_data'] = json.dumps(row_dict['extra_data'])
                        if isinstance(row_dict.get('stack_trace'), list): row_dict['stack_trace'] = json.dumps(row_dict['stack_trace'])
                        if isinstance(row_dict.get('process_details_summary'), dict): row_dict['process_details_summary'] = json.dumps(row_dict['process_details_summary'])
                        writer.writerow(row_dict)
                        events_exported += 1
            except IOError as e:
                await ctx.error(f"Error writing CSV file '{abs_output_path}': {e}")
                raise RuntimeError(f"Failed to write CSV file: {e}") from e
        elif output_format.lower() == 'json':
            try:
                with open(abs_output_path, 'w', encoding='utf-8') as jsonfile:
                    json.dump(events_to_export, jsonfile, indent=2)
                    events_exported = len(events_to_export)
            except IOError as e:
                await ctx.error(f"Error writing JSON file '{abs_output_path}': {e}")
                raise RuntimeError(f"Failed to write JSON file: {e}") from e

        export_elapsed = time.time() - export_start_time
        await ctx.info(f"Successfully exported {events_exported} events to '{output_file}' ({output_format}) in {export_elapsed:.2f}s.")
        return {"success": True, "output_path": abs_output_path, "events_exported": events_exported}

    except Exception as e:
        await ctx.error(f"Failed to export events: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error exporting events: {e}")


# --- Main Execution Block ---
if __name__ == "__main__":
    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(
        description=f"MCP Server for analyzing Procmon XML files (.xml, .gz/bz2/xz) using in-memory optimization (Refactored).",
        epilog=f"Memory reporting requires 'psutil' library (`pip install psutil`)."
    )
    # REMOVED: --allowed-dir
    parser.add_argument("--input-file", required=True,
                        help="REQUIRED: Path to the Procmon XML file (.xml, .gz/bz2/xz) to load and analyze.")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1", help="Host for MCP server (SSE transport), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8081, help="Port for MCP server (SSE transport), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"], help="MCP transport protocol, default: stdio")
    parser.add_argument("--debug", action='store_true', help="Enable debug logging.")
    parser.add_argument("--log-file", type=str, default=None, help="Optional: Path to a file to write logs to instead of console.")
    parser.add_argument("--no-stack-traces", action='store_true', help="Do not parse or store stack traces to save memory.")
    parser.add_argument("--no-extra-data", action='store_true', help="Do not store unknown fields found within <event> tags.")

    args = parser.parse_args()

    # --- Set Loading Flags ---
    load_stacks = not args.no_stack_traces
    load_extra = not args.no_extra_data

    # --- Logging Configuration (Same as before) ---
    log_level = logging.DEBUG if args.debug else logging.INFO
    log_handlers = []
    if args.log_file:
        log_dir = os.path.dirname(args.log_file)
        if log_dir and not os.path.exists(log_dir):
            try: os.makedirs(log_dir)
            except OSError as e: print(f"Error: Could not create directory for log file '{args.log_file}': {e}"); exit(1)
        try:
            file_handler = logging.FileHandler(args.log_file, mode='w')
            file_handler.setLevel(log_level); file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
            log_handlers.append(file_handler)
            print(f"Logging to file: {args.log_file}")
        except Exception as e: print(f"Error: Could not open log file '{args.log_file}': {e}"); exit(1)
    else:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level); console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        log_handlers.append(console_handler)

    root_logger = logging.getLogger(); root_logger.setLevel(log_level)
    for handler in root_logger.handlers[:]: root_logger.removeHandler(handler)
    for handler in log_handlers: root_logger.addHandler(handler)
    logger.setLevel(log_level)
    # Configure MCP/Uvicorn loggers (optional, same as before)
    try:
        logging.getLogger('mcp').setLevel(log_level)
        if args.transport == 'sse':
            logging.getLogger('uvicorn').setLevel(log_level)
            logging.getLogger('uvicorn.error').setLevel(log_level)
            logging.getLogger('uvicorn.access').setLevel(logging.WARNING if not args.debug else logging.DEBUG)
    except Exception: logger.debug("Could not configure MCP/Uvicorn loggers.", exc_info=True)
    logger.info(f"Logging level set to: {logging.getLevelName(log_level)}")
    logger.info(f"Selective loading: Stacks={load_stacks}, ExtraData={load_extra}")

    # --- Dependency Checks ---
    if not MCP_SDK_AVAILABLE:
        logger.critical("CRITICAL: Model Context Protocol SDK (modelcontextprotocol) is not installed.")
        logger.critical("Please install it: pip install modelcontextprotocol")
        exit(1)

    # --- Load File into ProcmonLogData ---
    try:
        input_file_path = os.path.abspath(args.input_file) # Use absolute path
        logger.info(f"Attempting to load and optimize file: {input_file_path}")

        # Load data and store in the global variable
        LOADED_DATA = load_procmon_xml(input_file_path, load_stacks, load_extra)

        if not LOADED_DATA or not LOADED_DATA.is_loaded():
             logger.critical(f"File loading failed for '{input_file_path}'. Check logs above for errors. Exiting.")
             exit(1)
        else:
             logger.info(f"File '{LOADED_DATA.loaded_filename}' loaded successfully (Events: {len(LOADED_DATA.events):,}, Processes: {len(LOADED_DATA.processes_by_index)}).")

        # Memory Usage Reporting (Same as before)
        if PSUTIL_AVAILABLE:
            try:
                process = psutil.Process(os.getpid())
                mem_info = process.memory_info()
                rss_formatted = _format_bytes(mem_info.rss)
                vms_formatted = _format_bytes(mem_info.vms)
                logger.info(f"--- Post-Load Memory Usage (Process RSS): {rss_formatted} ---")
                if args.debug: logger.debug(f"  Detailed Memory: RSS={rss_formatted}, VMS={vms_formatted}")
            except Exception as mem_err: logger.warning(f"Could not retrieve process memory usage: {mem_err}")
        else: logger.info("Memory usage reporting skipped (psutil library not installed).")

        logger.info(f"Ready for MCP connections.")

    except (ValueError, FileNotFoundError, TypeError, IndexError, RuntimeError) as e:
        logger.critical(f"Error loading file '{args.input_file}': {e}")
        if args.debug: logger.exception("Loading error details:")
        exit(1)
    except Exception as e:
        logger.critical(f"An unexpected error occurred during file loading ('{args.input_file}'): {e}", exc_info=args.debug)
        exit(1)

    # --- Start MCP Server ---
    server_started = False
    try:
        if args.transport == "sse":
            if hasattr(mcp, 'settings'):
                logger.info("Configuring MCP for SSE transport...")
                mcp.settings.host = args.mcp_host
                mcp.settings.port = args.mcp_port
                mcp_log_level_name = logging.getLevelName(log_level)
                mcp.settings.log_level = mcp_log_level_name.lower()
                logger.info(f"  MCP Host: {mcp.settings.host}, Port: {mcp.settings.port}, Log Level: {mcp.settings.log_level}")
            else: logger.warning("MCP object lacks 'settings'; cannot configure SSE via arguments.")
            logger.info(f"Starting MCP server with SSE transport on http://{args.mcp_host}:{args.mcp_port}")
            mcp.run(transport="sse") # Blocks
            server_started = True
        else: # Default to stdio
            logger.info("Starting MCP server with STDIO transport...")
            mcp.run(transport="stdio") # Blocks
            server_started = True
    except KeyboardInterrupt: logger.info("Server stopped by user (KeyboardInterrupt).")
    except Exception as e: logger.critical(f"Failed during server startup or execution: {e}", exc_info=args.debug); exit(1)

    # --- Post-Server Execution ---
    if not server_started and args.transport == "sse": logger.critical("SSE Server did not appear to start correctly."); exit(1)
    else: logger.info("Server execution finished."); exit(0)
