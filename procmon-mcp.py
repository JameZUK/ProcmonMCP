# -*- coding: utf-8 -*-
import sys
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
from datetime import datetime, timezone, time as dt_time, timedelta # For time-based filtering & UTC timestamps
import csv # For CSV export
import json # For JSON export

# Standard library compression formats
import gzip
import bz2
import lzma
import contextlib

# --- Profiling Imports ---
import cProfile
import pstats

# --- Python Version Check ---
# This script requires Python 3.7+ for async/await, dataclasses, and modern typing
MIN_PYTHON_VERSION = (3, 7)
if sys.version_info < MIN_PYTHON_VERSION:
    version_str = ".".join(map(str, MIN_PYTHON_VERSION))
    sys.stderr.write(
        f"CRITICAL ERROR: This script requires Python {version_str} or newer.\n"
        f"You are running Python {sys.version_info.major}.{sys.version_info.minor}.\n"
        "Please upgrade your Python environment to run this tool.\n"
    )
    sys.sys.exit(1)
# --- End Python Version Check ---

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
    logger.info("Using lxml library for XML parsing (recommended for speed, but XPath replaced).")
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
    logger.error("MCP SDK (mcp[cli]) not found. Mock objects will be used for offline execution.")
    logger.error("To run as a server, please install the SDK: pip install \"mcp[cli]\"")
    # Mock objects for offline testing/execution
    class MockSettings:
        host = "127.0.0.1"
        port = 8081
        log_level = "INFO"

    class MockMCP:
        def __init__(self, name, description=""):
            self.name = name
            self.description = description
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
        # Basic mock context for offline execution/testing
        async def info(self, msg): logger.info(f"(mock ctx): {msg}")
        async def error(self, msg): logger.error(f"(mock ctx): {msg}")
        async def warning(self, msg): logger.warning(f"(mock ctx): {msg}")

# --- Constants ---
PROCMON_TIMESTAMP_FORMAT = "%H:%M:%S.%f" # Format used in Procmon XML Time_of_Day
PROGRESS_REPORT_INTERVAL = 250000 # Report progress every N events during loading/processing
PROGRESS_REPORT_SECONDS = 5.0 # Also report progress every N seconds
# Define a base date (epoch) for creating full timestamps from Time_of_Day.
# This is necessary because XML only provides time, not date.
# **NOTE**: This is now the *starting* date; the parser will advance this date
#           if it detects a midnight rollover.
BASE_DATE = datetime(1970, 1, 1, tzinfo=timezone.utc)
# Known operation strings for specific tools
OP_PROCESS_CREATE = "Process Create"
OP_PROCESS_EXIT = "Process Exit"
NETWORK_OPERATIONS = {"TCP Connect", "TCP Send", "TCP Receive", "UDP Send", "UDP Receive"} # Case-sensitive
ROLLOVER_THRESHOLD_SECONDS = 3600  # Minimum gap (seconds) to trigger midnight rollover detection
MAX_REGEX_LEN = 500  # Maximum length for user-supplied regex patterns
MAX_FILTER_STR_LEN = 1000  # Maximum length for string filter parameters

# --- Interner Keys (Constants) ---
IK_PROCESS_NAME = "process_name"
IK_OPERATION = "operation"
IK_PATH = "path"
IK_RESULT = "result"
IK_CATEGORY = "category"
IK_STACK_PATH = "stack_path"
IK_STACK_LOCATION = "stack_location"

# --- Safe Regex Helper ---
def _compile_safe_regex(pattern: Optional[str], name: str) -> Optional[re.Pattern]:
    """Compile a regex pattern with length validation to mitigate ReDoS."""
    if pattern is None:
        return None
    if len(pattern) > MAX_REGEX_LEN:
        raise ValueError(
            f"Regex pattern for '{name}' exceeds maximum length of {MAX_REGEX_LEN} characters."
        )
    return re.compile(pattern, re.IGNORECASE)

# --- Standalone XML Helper Functions ---
def _strip_namespace(tag: str) -> str:
    """Helper to remove namespace from tag string if present."""
    # Optimized slightly: check for '}' before splitting
    if '}' in tag:
        try:
            return tag.split('}', 1)[1]
        except IndexError: # Should not happen if '}' is present, but safety first
             return tag
    return tag

def _find_child_ignore_ns(elem: ET_impl.Element, tag_name: str) -> Optional[ET_impl.Element]:
    """Finds the first direct child element with the given tag name, ignoring namespaces."""
    # This is generally faster than XPath for direct children when called repeatedly.
    for child_elem in elem: # elem.iterchildren() might be marginally faster in lxml if needed
        # Inline namespace stripping for performance
        child_tag = child_elem.tag
        if '}' in child_tag:
            try:
                child_tag_stripped = child_tag.split('}', 1)[1]
            except IndexError:
                 child_tag_stripped = child_tag # Fallback
        else:
            child_tag_stripped = child_tag

        if child_tag_stripped == tag_name:
            return child_elem
    return None

def _find_text_ignore_ns(elem: ET_impl.Element, tag_name: str) -> Optional[str]:
    """Finds the text of the first direct child element with the given tag name, ignoring namespaces."""
    # This is the primary function used now, replacing the costly XPath version.
    child = _find_child_ignore_ns(elem, tag_name)
    # Check child.text is not None before stripping
    return child.text.strip() if child is not None and child.text else None

# --- START OPTIMIZATION: Always use the faster iteration-based text finder ---
# Remove the conditional assignment based on LXML_AVAILABLE.
# We always use _find_text_ignore_ns now because profiling showed
# the lxml XPath version (_find_text_lxml) was a major bottleneck.
find_text_func = _find_text_ignore_ns
logger.info("Optimization Applied: Using direct element iteration (_find_text_ignore_ns) for finding text, replacing XPath.")
# --- END OPTIMIZATION ---


def _clear_elem(elem: ET_impl.Element):
    """Helper to clear element memory using lxml/ET specific methods."""
    elem.clear()


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
        # Use dict.setdefault for potential minor speedup
        existing_id = self.str_to_id.get(s)
        if existing_id is not None:
            return existing_id
        else:
            new_id = self.next_id
            self.str_to_id[s] = new_id
            self.id_to_str.append(s)
            self.next_id += 1
            return new_id

    def get_str(self, id_val: Optional[int]) -> Optional[str]:
        """Gets the string for an integer ID. Returns None for None input or invalid ID."""
        if id_val is None or not (0 <= id_val < self.next_id):
            return None
        # Direct list access is efficient
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
        # Use the globally defined (optimized) find_text_func
        depth_text = find_text_func(elem, 'depth')
        try:
             # Check isdigit before int conversion
             depth = int(depth_text) if depth_text and depth_text.isdigit() else None
        except (ValueError, TypeError): depth = None # Catch potential errors during int()
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
            # Check for '0x' prefix case-insensitively
            if text.startswith(('0x', '0X')): return int(text, 16)
            else: return int(text) # Assume decimal
        except (ValueError, TypeError):
            # Keep debug log level for potentially noisy failures
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
        # Use the globally defined (optimized) find_text_func
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
    
    *** WARNING ***: This function does NOT handle midnight rollovers by itself.
    It relies on a fixed BASE_DATE.
    The main loading function _parse_xml_stream_for_loading now contains
    inline logic to handle rollovers and does NOT use this function.
    This function is kept for the time-only filter parsing in 
    _iter_filtered_event_indices.
    """
    if ts_str is None: return None
    try:
        # Split only once
        parts = ts_str.split('.', 1)
        time_part = parts[0]
        # Handle fractional part carefully
        if len(parts) > 1:
            fractional_part = parts[1][:6].ljust(6, '0') # Truncate/pad to 6 digits
        else:
            fractional_part = "000000"
        # Reconstruct corrected string
        ts_str_corrected = f"{time_part}.{fractional_part}"
        # Parse the corrected string
        parsed_time: dt_time = datetime.strptime(ts_str_corrected, PROCMON_TIMESTAMP_FORMAT).time()
        # Combine with base date and convert to UTC timestamp
        full_dt = datetime.combine(BASE_DATE.date(), parsed_time, tzinfo=timezone.utc)
        return full_dt.timestamp()
    except (ValueError, TypeError, IndexError) as e:
        # Log warning if parsing fails
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
    # Define tags of interest for iterparse to potentially filter events early
    tags_of_interest = ('process', 'processlist', 'procmon')
    start_time = time.time()
    process_element_count = 0

    try:
        # Use 'end' event for process list as we need the full element content
        # Pass tag= argument for optimization (lxml only; stdlib supports it from 3.13+)
        if LXML_AVAILABLE:
            context = ET_impl.iterparse(source_stream, events=('end',), tag=tags_of_interest)
        else:
            context = ET_impl.iterparse(source_stream, events=('end',))
        logger.info("Starting Pass 1: Parsing process list...")
    except Exception as e:
        logger.error(f"Unexpected error initializing XML parser for process list: {e}", exc_info=True)
        raise RuntimeError("Failed to initialize XML parser for process list") from e

    try:
        # Iterate through the parsing context
        for event_type, elem in context:
            # Strip namespace from the tag (using optimized helper)
            tag = _strip_namespace(elem.tag)

            # State machine for parsing stages
            if parsing_stage == "seeking_procmon":
                if tag == 'procmon':
                    logger.warning("Found end of procmon before processlist.")
                    break
                parsing_stage = "seeking_processlist"

            if parsing_stage == "seeking_processlist":
                if tag == 'process':
                    parsing_stage = "parsing_processlist"
                elif tag == 'processlist':
                    logger.info("Found empty <processlist>.")
                    _clear_elem(elem)
                    break

            if parsing_stage == "parsing_processlist":
                if tag == 'process':
                    process_element_count += 1
                    try:
                        # Parse the <process> element using the class method
                        # This now uses the optimized find_text_func internally
                        proc_info = ProcessInfo.from_xml_element(elem)
                        # Add to dictionary if ProcessIndex is valid
                        if proc_info.process_index is not None and proc_info.process_index >= 0:
                            processes_dict[proc_info.process_index] = proc_info
                        else:
                            logger.warning(f"Parsed process element missing or invalid ProcessIndex.")
                    except Exception as e:
                        # Log warning on parsing failure for a single element
                        logger.warning(f"Failed to parse <process> element: {e}", exc_info=False)
                    # Clear the element to free memory
                    _clear_elem(elem)
                    # Report progress periodically
                    if process_element_count % 500 == 0:
                        elapsed = time.time() - start_time
                        logger.info(f"  [Pass 1] Parsed {process_element_count:,} process elements... ({elapsed:.1f}s)")
                elif tag == 'processlist':
                    # Reached the end of the process list
                    logger.debug(f"Finished parsing <processlist> tag.")
                    _clear_elem(elem)
                    break # Stop parsing after processlist

            # Safety break if we reach the end of the root element unexpectedly
            if tag == 'procmon':
                logger.warning("Reached end of <procmon> while parsing processes.")
                break

    except ET_impl.XMLSyntaxError as e:
        logger.error(f"XML Parse Error during process parsing: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during process parsing: {e}", exc_info=True)
        raise

    # Log summary of Pass 1
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

    *** NOTE ***: This function now contains stateful logic to handle
    timestamp rollovers (e.g., spanning midnight).

    Yields:
        Optimized event dictionaries.
    """
    parsing_stage = "seeking_eventlist"
    try:
        # Use start AND end events to allow capturing element content before clearing
        # Only parse tags we care about: event, frame, stack, eventlist, procmon
        tags_of_interest = ('event', 'frame', 'stack', 'eventlist', 'procmon')
        # Pass tag= argument for optimization (lxml only; stdlib supports it from 3.13+)
        if LXML_AVAILABLE:
            context = ET_impl.iterparse(source_stream, events=('start', 'end'), tag=tags_of_interest)
        else:
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
    current_stack_frames: Optional[List[List]] = None # Store OPTIMIZED frame data

    # --- ADDED: State variables for timestamp midnight rollover ---
    current_processing_date = BASE_DATE.date() # Start with the base date
    last_parsed_time: Optional[dt_time] = None   # Track the last event's time
    # --- END ADDITION ---

    # find_text_func is now globally set to the faster _find_text_ignore_ns

    try:
        for event_type, elem in context:
            tag = _strip_namespace(elem.tag)

            # --- State Machine for Parsing ---
            if parsing_stage == "seeking_eventlist":
                if event_type == 'start' and tag == 'eventlist':
                    logger.debug("Entered <eventlist> (start event).")
                    parsing_stage = "parsing_events"
                elif event_type == 'end' and tag == 'procmon':
                    logger.warning("Reached end of <procmon> before finding <eventlist>.")
                    break
                elif event_type == 'end': # Clear elements before eventlist (like processlist)
                    _clear_elem(elem)
                continue # Skip further processing until inside <eventlist>

            elif parsing_stage == "parsing_events":
                # --- Process <event> start ---
                if event_type == 'start' and tag == 'event':
                    event_count += 1
                    current_event_data = {} # Initialize temporary storage
                    current_stack_frames = [] if load_stack else None # Reset stack frame list

                    try:
                        # --- Extract Core Fields Efficiently ---
                        pid_str = find_text_func(elem, 'PID')
                        ts_str = find_text_func(elem, 'Time_of_Day')
                        current_event_data['pid_str'] = pid_str # Store raw for logging if needed
                        current_event_data['ts_str'] = ts_str
                        current_event_data['pid'] = ProcessInfo._safe_text_to_int(pid_str)
                        
                        # --- MODIFIED: Inline timestamp parsing to handle midnight rollover ---
                        parsed_time_obj: Optional[dt_time] = None
                        ts_float: Optional[float] = None
                        if ts_str:
                            try:
                                # Parse the time string (logic from _parse_timestamp_str)
                                parts = ts_str.split('.', 1)
                                time_part = parts[0]
                                if len(parts) > 1:
                                    fractional_part = parts[1][:6].ljust(6, '0')
                                else:
                                    fractional_part = "000000"
                                ts_str_corrected = f"{time_part}.{fractional_part}"
                                parsed_time_obj = datetime.strptime(ts_str_corrected, PROCMON_TIMESTAMP_FORMAT).time()

                                # Check for midnight rollover with threshold
                                if last_parsed_time and parsed_time_obj < last_parsed_time:
                                    last_seconds = (last_parsed_time.hour * 3600 + last_parsed_time.minute * 60 +
                                                    last_parsed_time.second + last_parsed_time.microsecond / 1e6)
                                    new_seconds = (parsed_time_obj.hour * 3600 + parsed_time_obj.minute * 60 +
                                                   parsed_time_obj.second + parsed_time_obj.microsecond / 1e6)
                                    time_gap = last_seconds - new_seconds
                                    if time_gap > ROLLOVER_THRESHOLD_SECONDS:
                                        current_processing_date += timedelta(days=1)
                                        logger.info(f"Midnight rollover detected at event #{event_count} "
                                                     f"(gap: {time_gap:.1f}s). Advancing date to {current_processing_date}.")
                                    else:
                                        logger.debug(f"Out-of-order timestamp at event #{event_count} "
                                                      f"(gap: {time_gap:.1f}s < threshold). No rollover.")

                                # Combine with the *current* processing date
                                full_dt = datetime.combine(current_processing_date, parsed_time_obj, tzinfo=timezone.utc)
                                ts_float = full_dt.timestamp()
                                last_parsed_time = parsed_time_obj # Update state

                            except (ValueError, TypeError, IndexError) as e:
                                logger.warning(f"Could not parse timestamp string '{ts_str}': {e}")
                        
                        current_event_data['ts'] = ts_float
                        # --- END MODIFICATION ---


                        # --- Extract Other Simple Fields ---
                        current_event_data['seq'] = ProcessInfo._safe_text_to_int(find_text_func(elem, 'SequenceNumber'))
                        current_event_data['tid'] = ProcessInfo._safe_text_to_int(find_text_func(elem, 'ThreadId'))
                        current_event_data['ppid'] = ProcessInfo._safe_text_to_int(find_text_func(elem, 'ParentPID'))
                        current_event_data['detail'] = find_text_func(elem, 'Detail') # Keep as string
                        duration_text = find_text_func(elem, 'Duration')
                        current_event_data['dur'] = None # Default
                        if duration_text:
                            try: current_event_data['dur'] = float(duration_text)
                            except (ValueError, TypeError): pass # Ignore conversion errors, keep None

                        # --- Extract Fields for Interning ---
                        current_event_data['process_name_str'] = find_text_func(elem, 'Process_Name')
                        current_event_data['operation_str'] = find_text_func(elem, 'Operation')
                        current_event_data['path_str'] = find_text_func(elem, 'Path')
                        current_event_data['result_str'] = find_text_func(elem, 'Result')
                        current_event_data['category_str'] = find_text_func(elem, 'Category')
                        current_event_data['process_index_str'] = find_text_func(elem, 'ProcessIndex') # For fallback

                        # --- Handle Extra Data (if enabled) ---
                        # This requires iterating children, which adds overhead.
                        # Consider if this is truly needed or can be skipped for max performance.
                        if load_extra:
                            extra_data_dict = {}
                            # Define known tags within <event> to exclude them from 'extra'
                            known_event_tags = {
                                'SequenceNumber', 'ProcessIndex', 'PID', 'ThreadId', 'ParentPID',
                                'Time_of_Day', 'Operation', 'Path', 'Result', 'Detail', 'Duration',
                                'Category', 'Process_Name', 'stack' # Note: case sensitive based on XML
                            }
                            # Iterate direct children only
                            for child in elem:
                                child_tag_orig = child.tag
                                child_tag_clean = _strip_namespace(child_tag_orig) # Use optimized strip
                                if child_tag_clean not in known_event_tags:
                                    # Get text only if it exists
                                    tag_text = child.text.strip() if child.text else None
                                    if tag_text is not None:
                                        # Store with original tag name (including namespace if present)
                                        extra_data_dict[child_tag_orig] = tag_text
                            if extra_data_dict:
                                current_event_data['extra_data'] = extra_data_dict

                    except Exception as start_parse_err:
                        logger.warning(f"Error during START event parsing for event #{event_count}: {start_parse_err}", exc_info=True)
                        current_event_data = None # Invalidate data

                # --- Process <frame> start (only if loading stacks) ---
                elif event_type == 'start' and tag == 'frame' and load_stack and current_stack_frames is not None:
                        try:
                            # Parse frame using its class method (now uses optimized find_text_func)
                            frame_obj = StackFrame.from_xml_element(elem)
                            # Convert to optimized list and append
                            current_stack_frames.append(frame_obj.to_optimized_list(
                                interners[IK_STACK_PATH], interners[IK_STACK_LOCATION]
                            ))
                        except Exception as frame_e:
                            logger.warning(f"Failed to parse/optimize stack frame during START for event #{event_count}: {frame_e}", exc_info=False)

                # --- Process <event> end ---
                elif event_type == 'end' and tag == 'event':
                    if current_event_data: # Proceed only if start parsing was successful
                        parse_successful = True
                        skip_reason = ""
                        opt_event = {} # Dictionary for the optimized event data

                        # --- Validate Core Fields ---
                        if current_event_data.get('pid') is None:
                            skip_reason += f"Missing/invalid PID ('{current_event_data.get('pid_str')}'). "
                            parse_successful = False
                        if current_event_data.get('ts') is None:
                            skip_reason += f"Missing/invalid Time_of_Day ('{current_event_data.get('ts_str')}'). "
                            parse_successful = False

                        # --- If Core Fields Valid, Populate Optimized Event ---
                        if parse_successful:
                            opt_event['pid'] = current_event_data['pid']
                            opt_event['ts'] = current_event_data['ts']
                            opt_event['seq'] = current_event_data['seq']
                            opt_event['tid'] = current_event_data['tid']
                            opt_event['ppid'] = current_event_data['ppid']
                            opt_event['detail'] = current_event_data['detail']
                            opt_event['dur'] = current_event_data['dur']

                            # --- Process Name Fallback Logic ---
                            process_name_str = current_event_data['process_name_str']
                            if process_name_str is None:
                                process_index = ProcessInfo._safe_text_to_int(current_event_data['process_index_str'])
                                if process_index is not None:
                                    proc_info = processes.get(process_index) # Lookup in pre-parsed dict
                                    if proc_info:
                                        process_name_str = proc_info.process_name
                                        # Update PPID only if it wasn't found directly in the event
                                        if opt_event.get('ppid') is None: opt_event['ppid'] = proc_info.parent_pid
                                    else:
                                        # Log if index exists but process info doesn't (should be rare)
                                        logger.warning(f"Event #{event_count} has ProcessIndex {process_index} but process info not found.")

                            # --- Perform String Interning ---
                            opt_event['pname_id'] = interners[IK_PROCESS_NAME].get_id(process_name_str)
                            opt_event['op_id'] = interners[IK_OPERATION].get_id(current_event_data['operation_str'])
                            opt_event['path_id'] = interners[IK_PATH].get_id(current_event_data['path_str'])
                            opt_event['res_id'] = interners[IK_RESULT].get_id(current_event_data['result_str'])
                            opt_event['cat_id'] = interners[IK_CATEGORY].get_id(current_event_data['category_str'])

                            # --- Assign Stack Frames (if loaded) ---
                            if load_stack and current_stack_frames:
                                opt_event['stack'] = current_stack_frames

                            # --- Assign Extra Data (if loaded) ---
                            if 'extra_data' in current_event_data:
                                opt_event['extra_data'] = current_event_data['extra_data']

                            # --- Yield the fully optimized event ---
                            yield opt_event
                            yielded_count += 1

                            # --- Progress Reporting ---
                            current_time = time.time()
                            # Report based on count interval OR time interval
                            if yielded_count % PROGRESS_REPORT_INTERVAL == 0 or (current_time - last_report_time) > PROGRESS_REPORT_SECONDS:
                                elapsed_total = current_time - start_time
                                rate = yielded_count / elapsed_total if elapsed_total > 0 else 0
                                percent_str = ""
                                # Calculate percentage based on raw file stream position
                                if raw_file_stream and total_size is not None and total_size > 0:
                                    try:
                                        current_pos = raw_file_stream.tell()
                                        percent = (current_pos / total_size) * 100
                                        percent_str = f" ({percent:.1f}%)"
                                    except (OSError, AttributeError, TypeError, io.UnsupportedOperation) as tell_err:
                                        logger.debug(f"Could not get raw stream position for progress: {tell_err}")
                                # Log progress
                                logger.info(f"  [Pass 2] Yielded {yielded_count:,} events{percent_str}... ({elapsed_total:.1f}s | {rate:,.0f} events/sec)")
                                last_report_time = current_time
                        else:
                            # --- Handle Skipped Event ---
                            skipped_count += 1
                            # --- MODIFICATION START: Only log skip warning if DEBUG is enabled ---
                            if logger.isEnabledFor(logging.DEBUG):
                                logger.warning(f"Skipping event #{event_count}: {skip_reason.strip()}")
                                # Log XML only if debug is enabled
                                try:
                                    event_xml_str = ET_impl.tostring(elem, encoding='unicode', method='xml')
                                    logger.debug(f"  Skipped Event XML:\n{event_xml_str[:1500]}...")
                                except Exception as log_e:
                                    logger.debug(f"  Could not serialize skipped event #{event_count} to string: {log_e}")
                            # --- MODIFICATION END ---

                    # --- Cleanup after <event> end ---
                    current_event_data = None # Reset temp data
                    current_stack_frames = None # Reset stack list
                    _clear_elem(elem) # Clear the processed <event> element

                # --- Clear other potentially large elements at 'end' event ---
                # We clear 'stack' here as its content (<frame>s) is processed on frame start
                elif event_type == 'end' and tag == 'stack':
                     _clear_elem(elem)
                elif event_type == 'end' and tag == 'eventlist':
                     logger.debug("Reached end of <eventlist>.")
                     _clear_elem(elem)
                     # Optionally break here if nothing expected after eventlist
                     # break


        # --- Final Log after Loop ---
        elapsed = time.time() - start_time
        logger.info(f"Finished Pass 2: Processed {event_count:,} <event> elements, yielded {yielded_count:,}, skipped {skipped_count:,} ({elapsed:.2f}s).")

    # --- Error Handling for Parser ---
    except ET_impl.XMLSyntaxError as e:
        logger.error(f"XML Parse Error during event loading stream: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during event loading stream: {e}", exc_info=True)
        raise

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
    elif fname_lower.endswith((".gz", ".xml.gz")):
        compression = 'gz'
        open_func = gzip.open
    elif fname_lower.endswith((".bz2", ".xml.bz2")):
        compression = 'bz2'
        open_func = bz2.open
    elif fname_lower.endswith((".xz", ".xml.xz")):
        compression = 'xz'
        open_func = lzma.open
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
    # Pre-intern known operation strings for potential minor optimization
    log_data.interners[IK_OPERATION].get_id(OP_PROCESS_CREATE)
    log_data.interners[IK_OPERATION].get_id(OP_PROCESS_EXIT)
    for op in NETWORK_OPERATIONS: log_data.interners[IK_OPERATION].get_id(op)

    try:
        comp_str = f" ({compression} compressed)" if compression else ""
        logger.info(f"Loading and optimizing{comp_str} XML file: {filename_abs}")

        # --- Use context managers for file handling ---
        raw_f = None
        try:
            # Open the raw file stream first for progress reporting
            raw_f = open(filename_abs, "rb")

            # --- Pass 1: Parse Processes Only ---
            # Open a separate compressed (or raw) stream for pass 1
            with open_func(filename_abs, file_mode) as f_stream_pass1:
                log_data.processes_by_index = _parse_xml_processes_only(f_stream_pass1)
                # Ensure it's a dict even if parsing failed somehow
                if log_data.processes_by_index is None: log_data.processes_by_index = {}

            # --- Build PID -> ProcessInfo Map ---
            pid_map_start_time = time.time()
            for proc_info in log_data.processes_by_index.values():
                if proc_info.pid is not None:
                    if proc_info.pid in log_data.processes_by_pid:
                        logger.warning(f"Duplicate PID {proc_info.pid} encountered in process list. Using the last entry found (ProcessIndex: {proc_info.process_index}).")
                    log_data.processes_by_pid[proc_info.pid] = proc_info
            logger.info(f"Built PID-to-ProcessInfo map for {len(log_data.processes_by_pid)} unique PIDs in {time.time() - pid_map_start_time:.2f}s.")


            # --- Pass 2: Parse Events and Optimize ---
            # Use the already opened raw_f with the appropriate compression opener
            # This ensures the raw_f handle stays open for the duration of Pass 2
# --- Define a context manager for the stream ---
            # It's either the compression opener (gzip.open, etc.) or a dummy context
            if compression is not None:
                stream_context = open_func(raw_f, file_mode)
            else:
                # If not compressed, open_func is 'open' and must not be used on raw_f.
                # We just use raw_f directly. We need a dummy context manager
                # that just returns raw_f and does nothing on __exit__.
                # (import contextlib should be at top of file)
                stream_context = contextlib.nullcontext(raw_f)

            with stream_context as f_stream_pass2:
                event_iterator = _parse_xml_stream_for_loading(
                    f_stream_pass2, log_data.interners, log_data.processes_by_index,
                    load_stack=log_data.load_stack_traces,
                    load_extra=log_data.load_extra_data,
                    raw_file_stream=raw_f, # Pass the raw file handle for tell()
                    total_size=total_file_size # Pass total size for progress %
                )

                logger.info("[Loader] Starting consumption of event iterator and building indices...")
                # Consume the iterator, build the event list and indices simultaneously
                temp_event_list = []
                consumed_count = 0
                indexing_start_time = time.time()
                try:
                    for idx, opt_event in enumerate(event_iterator): # Use enumerate for index
                        temp_event_list.append(opt_event)
                        consumed_count += 1

                        # --- Build Indices In-Place ---
                        pname_id = opt_event.get('pname_id')
                        op_id = opt_event.get('op_id')
                        if pname_id is not None: log_data.pname_id_index[pname_id].append(idx)
                        if op_id is not None: log_data.op_id_index[op_id].append(idx)
                        # --- End Indexing ---

                        # Progress reporting is now handled within _parse_xml_stream_for_loading
                except Exception as consume_err:
                    logger.error(f"[Loader] Error during iterator consumption/indexing after {consumed_count} events: {consume_err}", exc_info=True)
                finally:
                    logger.info(f"[Loader] Finished consuming event iterator. Total events consumed: {consumed_count}. Final list length: {len(temp_event_list)}. Indexing time: {time.time() - indexing_start_time:.2f}s")
                log_data.events = temp_event_list

        finally:
            # Ensure the raw file handle is closed if it was opened
            if raw_f:
                raw_f.close()

        # --- Final Summary ---
        overall_end_time = time.time()
        logger.info(f"--- Loading Summary ---")
        logger.info(f" Successfully loaded and optimized {len(log_data.events):,} events from {log_data.loaded_filename}.")
        logger.info(f" Found {len(log_data.processes_by_index)} unique processes (by index).")
        logger.info(f" Built PName index for {len(log_data.pname_id_index)} names and OP index for {len(log_data.op_id_index)} operations.")
        logger.info(f" Total loading and optimization time: {overall_end_time - overall_start_time:.2f} seconds.")
        # Log interner sizes at debug level
        if logger.isEnabledFor(logging.DEBUG):
            for name, interner in log_data.interners.items():
                logger.debug(f"  Interner '{name}': {interner.next_id:,} unique strings.")

        return log_data # Return the populated object

    # --- Error Handling for Loading ---
    except (FileNotFoundError, ValueError) as e:
        logger.error(f"File error: {e}")
        raise
    except ET_impl.XMLSyntaxError as e:
        logger.error(f"XML Syntax Error in {filename_abs}: {e}")
        raise RuntimeError(f"Invalid XML: {e}") from e
    except OSError as e: # Catch file read/decompression errors (OSError is base for gzip, bz2, lzma errors)
        logger.error(f"File read/decompression error for {filename_abs}: {e}")
        raise RuntimeError(f"File read/decompression failed for '{filename_abs}'.") from e
    except Exception as e:
        # Catch any other unexpected errors during loading
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
        return
    if not log_data.events:
        await ctx.info("Filtering: No events loaded.")
        return

    try:
        start_time = time.time()

        # --- Validate string filter lengths ---
        for param_name, param_val in [
            ("filter_path_contains", filter_path_contains),
            ("filter_process_contains", filter_process_contains),
            ("filter_stack_module_path", filter_stack_module_path),
        ]:
            if param_val and len(param_val) > MAX_FILTER_STR_LEN:
                await ctx.error(f"Filter '{param_name}' exceeds maximum length of {MAX_FILTER_STR_LEN}.")
                raise ValueError(f"Filter '{param_name}' exceeds maximum length of {MAX_FILTER_STR_LEN}.")

        # --- Pre-compile Regex with safety checks ---
        path_regex_obj = _compile_safe_regex(filter_path_regex, "filter_path_regex")
        process_regex_obj = _compile_safe_regex(filter_process_regex, "filter_process_regex")
        detail_regex_obj = _compile_safe_regex(filter_detail_regex, "filter_detail_regex")
        start_ts: Optional[float] = None
        end_ts: Optional[float] = None
        is_start_time_only = False
        is_end_time_only = False

        # --- Parse Time Filters ---
        # Encapsulate time parsing logic
        def parse_time_filter(time_filter_val: Any) -> Tuple[Optional[float], bool]:
            ts_val = None
            is_time_only = False
            if isinstance(time_filter_val, str):
                try: # Try HH:MM:SS.ffffff format first
                    # Use _parse_timestamp_str but only extract the time part relative to epoch
                    parsed_time_obj = datetime.strptime(time_filter_val, PROCMON_TIMESTAMP_FORMAT).time()
                    # Convert to seconds since midnight for comparison
                    ts_val = (parsed_time_obj.hour * 3600 + parsed_time_obj.minute * 60 +
                              parsed_time_obj.second + parsed_time_obj.microsecond / 1e6)
                    is_time_only = True
                    logger.info(f"Using time-only string filter for: {time_filter_val}")
                except ValueError:
                    try: # Fallback to float (Unix timestamp)
                        ts_val = float(time_filter_val)
                    except ValueError:
                        raise ValueError(f"Invalid time string format: '{time_filter_val}'. Use HH:MM:SS.ffffff or Unix timestamp.")
            elif isinstance(time_filter_val, (int, float)):
                ts_val = float(time_filter_val)
            return ts_val, is_time_only

        try:
            if filter_start_time is not None: start_ts, is_start_time_only = parse_time_filter(filter_start_time)
            if filter_end_time is not None: end_ts, is_end_time_only = parse_time_filter(filter_end_time)
            # Ensure consistency if one is time-only and the other isn't
            if (is_start_time_only and end_ts is not None and not is_end_time_only) or \
               (is_end_time_only and start_ts is not None and not is_start_time_only):
                logger.warning("Mixing time-only string filters and full timestamps might lead to unexpected results.")
        except ValueError as e:
            await ctx.error(f"Invalid time filter: {e}")
            raise e

        # --- Get Interned IDs for Exact Match Filters ---
        process_id_filter = log_data.get_id(IK_PROCESS_NAME, filter_process) if filter_process else None
        operation_id_filter = log_data.get_id(IK_OPERATION, filter_operation) if filter_operation else None
        result_id_filter = log_data.get_id(IK_RESULT, filter_result) if filter_result else None

        # --- Prepare Case-Insensitive Substring Filters ---
        filter_path_contains_lower = filter_path_contains.lower() if filter_path_contains else None
        filter_process_contains_lower = filter_process_contains.lower() if filter_process_contains else None
        filter_stack_module_path_lower = filter_stack_module_path.lower() if filter_stack_module_path else None

        # --- Determine Initial Candidate Set Using Indices ---
        candidate_indices: Optional[Set[int]] = None
        index_used = False
        if process_id_filter is not None:
            # Use the pre-built index for process names
            pid_indices = set(log_data.pname_id_index.get(process_id_filter, []))
            candidate_indices = pid_indices
            index_used = True
            if not candidate_indices:
                await ctx.info(f"Filter Index: No events match Process filter '{filter_process}'.")
                return
        if operation_id_filter is not None:
            # Use the pre-built index for operations
            op_indices = set(log_data.op_id_index.get(operation_id_filter, []))
            if candidate_indices is None: # First index being used
                candidate_indices = op_indices
            else: # Intersect with previous index results
                candidate_indices.intersection_update(op_indices)
            index_used = True
            if not candidate_indices:
                await ctx.info(f"Filter Index: No events match Operation filter '{filter_operation}'.")
                return

        # --- Determine Iterator and Total Scan Count ---
        if index_used and candidate_indices is not None:
            # If indices were used, iterate only over the candidate set
            logger.info(f"Using index. Filtering {len(candidate_indices):,} candidate events.")
            # Sort indices for potentially better cache locality (though may add overhead)
            indices_to_check = sorted(list(candidate_indices))
            total_to_scan = len(indices_to_check)
        else:
            # No applicable index, iterate over all events
            logger.info("No index applicable or used. Filtering all events.")
            indices_to_check = range(len(log_data.events)) # Iterate over all indices 0..N-1
            total_to_scan = len(log_data.events)
        # --- End Indexing Logic ---

        processed_count = 0
        last_progress_report_time = start_time

        # --- Main Filtering Loop ---
        for idx in indices_to_check:
            event_dict = log_data.events[idx]
            processed_count += 1

            # --- Progress Reporting ---
            current_time = time.time()
            # Calculate report interval dynamically, avoiding division by zero
            report_interval = max(10000, total_to_scan // 20) if total_to_scan > 0 else 10000 # Report more often
            if processed_count % report_interval == 0 or (current_time - last_progress_report_time > PROGRESS_REPORT_SECONDS):
                try: await ctx.info(f" Filter scanned {processed_count:,}/{total_to_scan:,} candidate events... ({current_time - start_time:.1f}s)")
                except Exception as progress_err: logger.warning(f"Failed to send progress update during filter: {progress_err}")
                last_progress_report_time = current_time

            # --- Apply Filters Sequentially (Fail Fast) ---
            # NOTE: Order matters slightly for performance. Check cheaper filters first.

            # 1. Indexed Filters (if index wasn't used to create the candidate set)
            #    These are already implicitly applied if candidate_indices is used.
            if not index_used:
                 if process_id_filter is not None and event_dict.get('pname_id') != process_id_filter: continue
                 if operation_id_filter is not None and event_dict.get('op_id') != operation_id_filter: continue

            # 2. Exact Match Filters (non-indexed)
            if result_id_filter is not None and event_dict.get('res_id') != result_id_filter: continue

            # 3. Time Filter
            event_ts_float = event_dict.get('ts')
            if event_ts_float is None: continue # Skip if timestamp is missing (shouldn't happen)
            if start_ts is not None or end_ts is not None:
                # Determine the value to compare (either full timestamp or seconds since midnight)
                current_event_compare_val = event_ts_float
                if is_start_time_only or is_end_time_only: # Compare only time part
                    try:
                        # Use timezone.utc since our loaded timestamps are UTC
                        event_dt_obj = datetime.fromtimestamp(event_ts_float, timezone.utc)
                        current_event_compare_val = (event_dt_obj.hour * 3600 + event_dt_obj.minute * 60 +
                                                     event_dt_obj.second + event_dt_obj.microsecond / 1e6)
                    except Exception: continue # Skip if time extraction fails

                # Apply time bounds
                if start_ts is not None and current_event_compare_val < start_ts: continue
                if end_ts is not None and current_event_compare_val > end_ts: continue

            # 4. String Contains/Regex/Stack Filters (Potentially more expensive)
            #    Only retrieve strings from interner if the corresponding filter is active.
            if filter_path_contains_lower or filter_process_contains_lower or path_regex_obj or process_regex_obj or detail_regex_obj or filter_stack_module_path_lower:
                # --- Path Filters ---
                if filter_path_contains_lower or path_regex_obj:
                    path_str = log_data.get_string(IK_PATH, event_dict.get('path_id')) or ""
                    if filter_path_contains_lower and filter_path_contains_lower not in path_str.lower(): continue
                    if path_regex_obj and not path_regex_obj.search(path_str): continue

                # --- Process Name Filters ---
                if filter_process_contains_lower or process_regex_obj:
                    pname_str = log_data.get_string(IK_PROCESS_NAME, event_dict.get('pname_id')) or ""
                    if filter_process_contains_lower and filter_process_contains_lower not in pname_str.lower(): continue
                    if process_regex_obj and not process_regex_obj.search(pname_str): continue

                # --- Detail Filter ---
                if detail_regex_obj:
                    detail_str = event_dict.get('detail') or ""
                    if not detail_regex_obj.search(detail_str): continue

                # --- Stack Module Path Filter ---
                if filter_stack_module_path_lower:
                    if not log_data.load_stack_traces: continue # Ignore if stacks not loaded
                    stack_list_optimized = event_dict.get('stack')
                    if not stack_list_optimized: continue # Skip if no stack for this event
                    found_in_stack = False
                    for frame_list in stack_list_optimized:
                        # Check frame_list[2] (path_id) exists
                        if len(frame_list) > 2 and frame_list[2] is not None:
                            frame_path_str = log_data.get_string(IK_STACK_PATH, frame_list[2])
                            # Check if path string found and contains the filter substring
                            if frame_path_str and filter_stack_module_path_lower in frame_path_str.lower():
                                found_in_stack = True
                                break
                    if not found_in_stack: continue # Skip event if module not found in stack

            # --- If all filters passed, yield the index ---
            yield idx

        # --- Log Completion ---
        filter_elapsed = time.time() - start_time
        logger.info(f"Filtering completed in {filter_elapsed:.2f}s.")

    # --- Error Handling ---
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
    # Check index bounds and data loaded status
    if not log_data or not log_data.is_loaded() or not (0 <= event_index < len(log_data.events)):
        logger.error(f"Invalid request for event details: Index {event_index} out of bounds or data not loaded.")
        return None

    event_dict = log_data.events[event_index]
    details: Dict[str, Any] = {} # Initialize details dictionary

    try:
        # --- Populate Basic Fields ---
        details['event_index'] = event_index
        details['sequence_number'] = event_dict.get('seq')
        details['pid'] = event_dict.get('pid')
        details['tid'] = event_dict.get('tid')
        details['parent_pid'] = event_dict.get('ppid') # May be overwritten by process info
        details['duration'] = event_dict.get('dur')
        details['detail'] = event_dict.get('detail')

        # --- Format Timestamp ---
        ts_float = event_dict.get('ts')
        details['timestamp_unix'] = ts_float # Store raw float timestamp
        try:
            # Format timestamp string if float exists
            # All our loaded timestamps are UTC
            details['timestamp'] = datetime.fromtimestamp(ts_float, timezone.utc).strftime(PROCMON_TIMESTAMP_FORMAT) if ts_float else None
        except Exception:
            details['timestamp'] = "<Invalid Timestamp>" # Handle formatting errors

        # --- Lookup Interned Strings ---
        details['operation'] = log_data.get_string(IK_OPERATION, event_dict.get('op_id'))
        details['path'] = log_data.get_string(IK_PATH, event_dict.get('path_id'))
        details['result'] = log_data.get_string(IK_RESULT, event_dict.get('res_id'))
        details['category'] = log_data.get_string(IK_CATEGORY, event_dict.get('cat_id'))
        details['process_name'] = log_data.get_string(IK_PROCESS_NAME, event_dict.get('pname_id')) # May be overwritten

        # --- Add Extra Data (if loaded) ---
        details['extra_data'] = event_dict.get('extra_data') if log_data.load_extra_data else None

        # --- Add Stack Trace (if loaded) ---
        details['stack_trace'] = None # Default to None
        if log_data.load_stack_traces and 'stack' in event_dict:
            stack_list = []
            for frame_data in event_dict['stack']:
                try:
                    # Check frame data structure before accessing indices
                    if isinstance(frame_data, (list, tuple)) and len(frame_data) >= 4:
                        stack_list.append({
                            'depth': frame_data[0],
                            'address': frame_data[1],
                            'path': log_data.get_string(IK_STACK_PATH, frame_data[2]),
                            'location': log_data.get_string(IK_STACK_LOCATION, frame_data[3])
                        })
                    else:
                         logger.warning(f"Malformed optimized stack frame data encountered for event index {event_index}: {frame_data}")
                except (IndexError, TypeError):
                    # Log specific errors during frame processing
                    logger.warning(f"Error processing stack frame data in event {event_index}: {frame_data}")
            details['stack_trace'] = stack_list

        # --- Add Enriched Process Info ---
        process_obj = log_data.processes_by_pid.get(details.get('pid')) if details.get('pid') is not None else None
        if process_obj:
            # Convert ProcessInfo object to dict, remove internal fields
            proc_details_dict = dataclasses.asdict(process_obj)
            proc_details_dict.pop('process_index', None)
            proc_details_dict.pop('parent_process_index', None)
            details['process_details_summary'] = proc_details_dict
            # Add potentially useful top-level fields from process info
            details['user_sid'] = process_obj.owner
            details['is_64bit_process'] = process_obj.is_64bit
            # Overwrite event fields if more accurate info is in process list
            if process_obj.parent_pid is not None: details['parent_pid'] = process_obj.parent_pid
            if process_obj.process_name is not None: details['process_name'] = process_obj.process_name
        else:
            # Provide default structure if process info not found
            details['process_details_summary'] = {"pid": details['pid'], "process_name": details['process_name'], "message": "Process details not found in <processlist>."}
            details['user_sid'] = None
            details['is_64bit_process'] = None

        # --- Add Placeholder Fields (Not available in XML) ---
        details['completion_time'] = None
        details['relative_time'] = None

        return details

    except Exception as e:
        # Catch any unexpected errors during formatting
        logger.error(f"Error formatting details for event {event_index}: {e}", exc_info=True)
        return None # Return None on formatting error


# --- MCP Tools (Adapted for ProcmonLogData) ---

async def _check_loaded(ctx: Context, tool_name: str) -> 'ProcmonLogData':
    """Validates data is loaded. Returns the data or raises RuntimeError with consistent messaging."""
    if not LOADED_DATA or not LOADED_DATA.is_loaded():
        msg = f"[{tool_name}] No Procmon data loaded. Load a file with --input-file first."
        await ctx.error(msg)
        raise RuntimeError(msg)
    return LOADED_DATA

tool_decorator = mcp.tool() if MCP_SDK_AVAILABLE else lambda func: func

@tool_decorator
async def get_loaded_file_summary(ctx: Context) -> Dict[str, Any]:
    """
    Returns a basic summary of the pre-loaded Procmon XML file data.
    Includes counts, loading options, and interner/index statistics.
    """
    log_data = await _check_loaded(ctx, "get_loaded_file_summary")
    await ctx.info(f"[get_loaded_file_summary] Starting...")
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
        await ctx.info(f"[get_loaded_file_summary] Completed. File: {log_data.loaded_filename}")
        return summary
    except RuntimeError:
        raise
    except Exception as e:
        await ctx.error(f"[get_loaded_file_summary] Failed: {e}")
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
    Returns a list of event summaries (dictionary) for matching events, up to the specified limit.
    Each summary includes the event index, timestamp, process name, PID, operation, path, and result.
    Use 'get_event_details' with the 'event_index' from the summary to retrieve full event details.

    Filter Notes:
    - Exact match filters (filter_process, filter_operation, filter_result) use case-sensitive matching on the full string.
    - Contains filters (filter_path_contains, filter_process_contains, filter_stack_module_path) perform case-insensitive substring checks. They do NOT support OR logic via '|'.
    - Regex filters (filter_path_regex, filter_process_regex, filter_detail_regex) use Python's 're' module with IGNORECASE. Use these for complex patterns, including OR logic (e.g., "value1|value2"). Remember to escape special regex characters if matching literally (e.g., use '\\.' to match a period).
    - Time filters (filter_start_time, filter_end_time) accept Unix timestamps (float/int) or time strings ("HH:MM:SS.ffffff"). Time strings perform time-only comparisons.
    """
    log_data = await _check_loaded(ctx, "query_events")
    await ctx.info(f"[query_events] Starting with limit={limit}...")
    filters_applied = {k:v for k,v in locals().items() if k.startswith('filter_') and v is not None}
    if filters_applied:
        logger.debug(f"Filters Applied: {filters_applied}")

    if not log_data.events:
        await ctx.info("[query_events] Completed. No events loaded.")
        return []
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
                await ctx.info(f"[query_events] Limit ({limit}) reached.")
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
        await ctx.info(f"[query_events] Completed in {elapsed:.2f}s. {len(filtered_event_summaries)} matches (limit {limit}).")
        return filtered_event_summaries

    except (ValueError, TypeError, RuntimeError, re.error) as e: # Catch errors from filtering or summary creation
        await ctx.error(f"[query_events] Failed: {e}")
        logger.debug("Query exception details:", exc_info=True)
        # Re-raise specific types if needed, otherwise wrap
        if isinstance(e, (ValueError, TypeError, re.error)): raise e
        else: raise RuntimeError(f"Internal error querying events: {e}") from e

@tool_decorator
async def get_event_details(event_index: int, ctx: Context) -> Dict[str, Any]:
    """
    Retrieves detailed properties for a specific event from the optimized in-memory data,
    referenced by its list index (obtained from 'query_events').
    Includes 'extra_data' and 'stack_trace' fields if they were loaded during startup.
    Returns a dictionary containing the event details.
    """
    log_data = await _check_loaded(ctx, "get_event_details")
    await ctx.info(f"[get_event_details] Starting for event index: {event_index}")

    try:
        details = _get_formatted_event_details(log_data, event_index)

        if details is None:
            num_events = len(log_data.events)
            upper_bound = num_events - 1 if num_events > 0 else -1
            await ctx.error(f"[get_event_details] Invalid event index: {event_index}. Must be between 0 and {upper_bound}.")
            raise IndexError(f"Event index {event_index} is out of bounds or details could not be formatted.")

        await ctx.info(f"[get_event_details] Completed for event index {event_index}.")
        return details

    except (IndexError, RuntimeError):
        raise
    except Exception as e:
        await ctx.error(f"[get_event_details] Failed: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving event details: {e}")

@tool_decorator
async def get_event_stack_trace(event_index: int, ctx: Context) -> List[Dict[str, Any]]:
    """
    Retrieves the detailed call stack trace for a specific event, referenced by its list index.
    Requires stack traces to have been loaded (i.e., script run without --no-stack-traces).
    Returns a list of stack frame dictionaries, or an empty list if no stack trace is available or loaded.
    Each frame dictionary contains 'depth', 'address', 'path', and 'location'.
    """
    log_data = await _check_loaded(ctx, "get_event_stack_trace")
    await ctx.info(f"[get_event_stack_trace] Starting for event index: {event_index}")

    if not log_data.load_stack_traces:
        await ctx.warning("[get_event_stack_trace] Stack traces were not loaded (--no-stack-traces). Returning empty list.")
        return []

    try:
        num_events = len(log_data.events)
        if not 0 <= event_index < num_events:
            upper_bound = num_events - 1 if num_events > 0 else -1
            await ctx.error(f"[get_event_stack_trace] Invalid event index: {event_index}. Must be between 0 and {upper_bound}.")
            raise IndexError(f"Event index {event_index} is out of bounds.")

        event_dict = log_data.events[event_index]
        stack_list_optimized = event_dict.get('stack')

        detailed_stack = []
        if stack_list_optimized:
            for frame_data in stack_list_optimized:
                try:
                    if not isinstance(frame_data, (list, tuple)) or len(frame_data) < 4:
                        logger.warning(f"Malformed optimized stack frame data for event index {event_index}: {frame_data}")
                        continue
                    frame_dict = {
                        'depth': frame_data[0],
                        'address': frame_data[1],
                        'path': log_data.get_string(IK_STACK_PATH, frame_data[2]),
                        'location': log_data.get_string(IK_STACK_LOCATION, frame_data[3])
                    }
                    detailed_stack.append(frame_dict)
                except IndexError:
                    logger.warning(f"IndexError processing stack frame for event index {event_index}: {frame_data}")
                except Exception as frame_e:
                    logger.warning(f"Unexpected error processing stack frame for event index {event_index}: {frame_e}", exc_info=False)

        await ctx.info(f"[get_event_stack_trace] Completed. {len(detailed_stack)} frames for event index {event_index}.")
        return detailed_stack

    except (IndexError, RuntimeError):
        raise
    except Exception as e:
        await ctx.error(f"[get_event_stack_trace] Failed: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving event stack trace: {e}")

# --- Tools operating on Process Data ---
@tool_decorator
async def list_processes(ctx: Context) -> List[Dict[str, Any]]:
    """
    Lists summary information for all processes found in the <processlist> section of the loaded XML file.
    Returns a list of dictionaries, each containing 'pid', 'process_name', 'image_path', and 'parent_pid'.
    The list is sorted by PID.
    """
    log_data = await _check_loaded(ctx, "list_processes")
    await ctx.info("[list_processes] Starting...")
    try:
        process_list = list(log_data.processes_by_index.values())
        process_summaries = []
        summary_attributes = ['pid', 'process_name', 'image_path', 'parent_pid']
        for process_obj in process_list:
            summary = {attr: getattr(process_obj, attr, None) for attr in summary_attributes}
            if summary.get('pid') is None:
                continue
            process_summaries.append(summary)
        process_summaries.sort(key=lambda x: x.get('pid') or 0)
        await ctx.info(f"[list_processes] Completed. {len(process_summaries)} processes found.")
        return process_summaries
    except RuntimeError:
        raise
    except Exception as e:
        await ctx.error(f"[list_processes] Failed: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error listing processes: {e}")

@tool_decorator
async def get_process_details(pid: int, ctx: Context) -> Dict[str, Any]:
    """
    Retrieves detailed information for a specific process ID (PID) from the loaded <processlist> data.
    Uses the pre-built PID-to-ProcessInfo map for efficient lookup.
    Returns a dictionary containing all parsed details for the process (e.g., image path, command line, owner, integrity).
    """
    log_data = await _check_loaded(ctx, "get_process_details")
    await ctx.info(f"[get_process_details] Starting for PID: {pid}")
    try:
        process_obj = log_data.processes_by_pid.get(pid)
        if not process_obj:
            await ctx.error(f"[get_process_details] PID {pid} not found in process list.")
            raise ValueError(f"Process with PID {pid} not found in pre-loaded list.")

        details = dataclasses.asdict(process_obj)
        details.pop('process_index', None)
        details.pop('parent_process_index', None)
        details['modules_summary'] = "N/A (Module info not typically in XML process list)"
        await ctx.info(f"[get_process_details] Completed for PID {pid}.")
        return details
    except (ValueError, RuntimeError):
        raise
    except Exception as e:
        await ctx.error(f"[get_process_details] Failed: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving process details: {e}")

@tool_decorator
async def get_metadata(ctx: Context) -> Dict[str, Any]:
    """
    Retrieves metadata about the loaded XML file, such as filename, compression, and event/process counts.
    Note: XML format does not contain OS version or computer name metadata like PML format does.
    """
    log_data = await _check_loaded(ctx, "get_metadata")
    await ctx.info("[get_metadata] Starting...")
    try:
        metadata = {
            "loaded_filename": log_data.loaded_filename, "file_type": "xml",
            "compression": log_data.loaded_compression, "header_found": False,
            "message": "Standard OS/Header info N/A for XML format.",
            "os_version": None, "computer_name": None,
            "process_count_loaded": len(log_data.processes_by_index),
            "event_count_loaded": len(log_data.events)
        }
        await ctx.info(f"[get_metadata] Completed. File: {log_data.loaded_filename}")
        return metadata
    except RuntimeError:
        raise
    except Exception as e:
        await ctx.error(f"[get_metadata] Failed: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving metadata: {e}")

# --- Analysis Tools (Operating on ProcmonLogData) ---

@tool_decorator
async def count_events_by_process(ctx: Context) -> Dict[str, int]:
    """
    Counts the total number of events associated with each unique process name in the loaded data.
    Returns a dictionary where keys are process names and values are the event counts, sorted descending by count.
    """
    log_data = await _check_loaded(ctx, "count_events_by_process")
    await ctx.info("[count_events_by_process] Starting...")
    if not log_data.events:
        await ctx.info("[count_events_by_process] Completed. No events loaded.")
        return {}
    try:
        event_counts: Dict[str, int] = {}
        start_time = time.time()

        # Use the pre-built pname_id index for O(unique_names) instead of O(total_events)
        for pname_id, event_indices in log_data.pname_id_index.items():
            name = log_data.get_string(IK_PROCESS_NAME, pname_id) or 'Unknown/Missing'
            event_counts[name] = len(event_indices)

        elapsed = time.time() - start_time
        # Sort results by count descending
        sorted_counts = dict(sorted(event_counts.items(), key=lambda item: item[1], reverse=True))
        total_counted = sum(sorted_counts.values())
        await ctx.info(f"[count_events_by_process] Counted {total_counted:,} events across {len(sorted_counts)} processes ({elapsed:.2f}s).")
        return sorted_counts
    except Exception as e:
        await ctx.error(f"[count_events_by_process] Failed: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error counting events by process: {e}")

@tool_decorator
async def summarize_operations_by_process(process_name_filter: str, ctx: Context) -> Dict[str, int]:
    """
    Counts the occurrences of each operation type for a specific process name.
    Uses a case-sensitive, exact match for the process name filter.
    Leverages the process name index for faster filtering.
    Returns a dictionary where keys are operation names and values are their counts for the specified process, sorted descending by count.
    """
    log_data = await _check_loaded(ctx, "summarize_operations_by_process")
    await ctx.info(f"[summarize_operations_by_process] Starting for process: '{process_name_filter}'")
    if not process_name_filter:
        await ctx.error("[summarize_operations_by_process] Process name filter cannot be empty.")
        raise ValueError("Process name filter is required.")
    if not log_data.events:
        await ctx.info(f"[summarize_operations_by_process] Completed. No events loaded.")
        return {}
    try:
        operation_counts = defaultdict(int)
        event_count_for_process = 0
        start_time = time.time()

        # Find the interned ID for the target process name
        target_pname_id = log_data.get_id(IK_PROCESS_NAME, process_name_filter)
        if target_pname_id is None:
            await ctx.warning(f"[summarize_operations_by_process] Process name '{process_name_filter}' not found in loaded data.")
            return {}

        # Get the list of event indices for this process from the index
        indices_to_check = log_data.pname_id_index.get(target_pname_id)
        if not indices_to_check:
            await ctx.warning(f"No events found matching process name '{process_name_filter}'.")
            return {}

        await ctx.info(f"[summarize_operations_by_process] Scanning {len(indices_to_check):,} events for '{process_name_filter}'...")
        last_progress_report_time = start_time

        # Iterate only through the relevant event indices
        for i, idx in enumerate(indices_to_check):
            # Progress reporting
            current_time = time.time()
            if i > 0 and (i % (PROGRESS_REPORT_INTERVAL * 4) == 0 or (current_time - last_progress_report_time > PROGRESS_REPORT_SECONDS)):
                elapsed = current_time - start_time
                try: await ctx.info(f"[summarize_operations_by_process] Processed {i:,}/{len(indices_to_check):,} events ({elapsed:.1f}s)")
                except Exception as progress_err: logger.warning(f"Failed to send progress update during summarize: {progress_err}")
                last_progress_report_time = current_time

            # Get operation name and count it
            event_dict = log_data.events[idx]
            event_count_for_process += 1
            operation = log_data.get_string(IK_OPERATION, event_dict.get('op_id')) or 'Unknown'
            operation_counts[operation] += 1

        elapsed = time.time() - start_time
        # Sort results by count descending
        sorted_counts = dict(sorted(operation_counts.items(), key=lambda item: item[1], reverse=True))
        await ctx.info(f"[summarize_operations_by_process] Completed. {len(sorted_counts)} unique ops for '{process_name_filter}' ({event_count_for_process:,} events, {elapsed:.2f}s).")
        return sorted_counts

    except Exception as e:
        await ctx.error(f"[summarize_operations_by_process] Failed: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error summarizing operations: {e}")

@tool_decorator
async def get_timing_statistics(group_by: str = "process", *, ctx: Context) -> Dict[str, Dict[str, Any]]:
    """
    Calculates event duration statistics (min, max, average, total, count) for events that have a duration > 0.
    Groups the statistics either by 'process' name or by 'operation' type.
    Returns a dictionary where keys are the group names (process or operation) and values are dictionaries containing the calculated statistics.
    The outer dictionary is sorted by event count (descending) within each group.
    """
    log_data = await _check_loaded(ctx, "get_timing_statistics")
    await ctx.info(f"[get_timing_statistics] Starting, grouped by '{group_by}'...")
    if group_by not in ["process", "operation"]:
        await ctx.error("[get_timing_statistics] Invalid group_by value. Must be 'process' or 'operation'.")
        raise ValueError("Invalid group_by value.")
    if not log_data.events:
        await ctx.info(f"[get_timing_statistics] Completed. No events loaded.")
        return {}
    try:
        # Use defaultdict to easily accumulate stats
        stats = defaultdict(lambda: {'min': float('inf'), 'max': float('-inf'), 'sum': 0.0, 'count': 0})
        total_events = len(log_data.events)
        start_time = time.time()
        events_with_duration = 0
        last_progress_report_time = start_time

        # Iterate through all events
        for i, event_dict in enumerate(log_data.events):
            # Progress reporting
            current_time = time.time()
            if i > 0 and (i % (PROGRESS_REPORT_INTERVAL * 4) == 0 or (current_time - last_progress_report_time > PROGRESS_REPORT_SECONDS)):
                elapsed = current_time - start_time
                try: await ctx.info(f"[get_timing_statistics] Processed {i:,}/{total_events:,} events ({elapsed:.1f}s)")
                except Exception as progress_err: logger.warning(f"Failed to send progress update during timing stats: {progress_err}")
                last_progress_report_time = current_time

            # Get duration and check if it's valid for statistics
            duration = event_dict.get('dur')
            if duration is None or not isinstance(duration, (float, int)) or duration <= 0:
                if duration is not None and logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Event {i} has invalid duration for stats: '{duration}' (Type: {type(duration)})")
                continue # Skip events without valid positive duration
            events_with_duration += 1
            if events_with_duration == 1 and logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"Event {i} has first valid duration for stats: {duration}")

            # Determine the grouping key (process name or operation name)
            group_key_id = event_dict.get('pname_id') if group_by == "process" else event_dict.get('op_id')
            interner_name = IK_PROCESS_NAME if group_by == "process" else IK_OPERATION
            group_key = log_data.get_string(interner_name, group_key_id) or 'Unknown/Missing'

            # Update statistics for the group
            group_stats = stats[group_key]
            group_stats['count'] += 1
            group_stats['sum'] += duration
            if duration < group_stats['min']: group_stats['min'] = duration
            if duration > group_stats['max']: group_stats['max'] = duration

        # Format the results
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

        # Sort by count descending
        output_stats_list.sort(key=lambda x: x['count'], reverse=True)
        # Convert list of dicts to dict keyed by group name
        final_output_stats = {item['group']: {k: v for k, v in item.items() if k != 'group'} for item in output_stats_list}

        elapsed = time.time() - start_time
        await ctx.info(f"[get_timing_statistics] Completed. {len(final_output_stats)} groups from {events_with_duration:,} events with duration ({elapsed:.2f}s).")
        return final_output_stats

    except Exception as e:
        await ctx.error(f"[get_timing_statistics] Failed: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error calculating timing statistics: {e}")

@tool_decorator
async def get_process_lifetime(pid: int, ctx: Context) -> Dict[str, Optional[float]]:
    """
    Finds the first 'Process Create' and the last 'Process Exit' event timestamps (Unix float) for a given Process ID (PID).
    Scans through the loaded events to find the relevant timestamps.
    Returns a dictionary with 'create_timestamp' and 'exit_timestamp'. Values will be None if the corresponding event is not found.
    """
    log_data = await _check_loaded(ctx, "get_process_lifetime")
    await ctx.info(f"[get_process_lifetime] Starting for PID: {pid}")
    create_ts: Optional[float] = None
    exit_ts: Optional[float] = None
    # Get interned IDs for the specific operations
    create_op_id = log_data.get_id(IK_OPERATION, OP_PROCESS_CREATE)
    exit_op_id = log_data.get_id(IK_OPERATION, OP_PROCESS_EXIT)

    # Check if the PID exists in the process list for a quick warning if not
    if pid not in log_data.processes_by_pid:
            await ctx.warning(f"[get_process_lifetime] PID {pid} not found in initial process list. It might have started/exited before the list snapshot.")
            # Still scan events as it might appear there

    # Use operation indices to narrow the search instead of full linear scan
    # Find first Process Create event for this PID
    if create_op_id is not None:
        create_indices = log_data.op_id_index.get(create_op_id, [])
        for idx in create_indices:
            event_dict = log_data.events[idx]
            if event_dict.get('pid') == pid:
                create_ts = event_dict.get('ts')
                break  # First match (events are ordered)

    # Find last Process Exit event for this PID (iterate in reverse)
    if exit_op_id is not None:
        exit_indices = log_data.op_id_index.get(exit_op_id, [])
        for idx in reversed(exit_indices):
            event_dict = log_data.events[idx]
            if event_dict.get('pid') == pid:
                exit_ts = event_dict.get('ts')
                break  # Last match (since we iterate in reverse)

    result = {"create_timestamp": create_ts, "exit_timestamp": exit_ts}
    await ctx.info(f"[get_process_lifetime] PID {pid}: {result}")
    return result

@tool_decorator
async def find_file_access(path_contains: str, limit: int = 100, *, ctx: Context) -> List[Dict[str, Any]]:
    """
    Finds events related to file system access where the event's 'Path' field contains the given substring (case-insensitive).
    Returns a list of event summaries (up to the specified limit) for matching events.
    Each summary includes index, timestamp, process, PID, operation, path, and result.
    Note: This performs a linear scan; it does not use path-based indexing.
    """
    log_data = await _check_loaded(ctx, "find_file_access")
    await ctx.info(f"[find_file_access] Starting for path containing: '{path_contains}' (limit={limit})")
    if not path_contains:
        await ctx.error("[find_file_access] path_contains filter cannot be empty.")
        raise ValueError("path_contains filter is required.")
    found_events = []
    count = 0
    path_contains_lower = path_contains.lower() # Pre-lower for efficiency

    # Iterate through all events
    for idx, event_dict in enumerate(log_data.events):
        if count >= limit: break # Stop if limit reached

        # Check if path exists and contains the substring
        path_id = event_dict.get('path_id')
        if path_id is not None:
            path_str = log_data.get_string(IK_PATH, path_id)
            if path_str and path_contains_lower in path_str.lower():
                # Create and append summary if match found
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

    await ctx.info(f"[find_file_access] Completed. {len(found_events)} events matching '{path_contains}' (limit {limit}).")
    return found_events

@tool_decorator
async def find_network_connections(process_name: str, *, ctx: Context) -> List[str]:
    """
    Finds unique remote network endpoints (IP:port or Hostname:port) accessed by a specific process.
    Uses a case-sensitive, exact match for the process name.
    Scans events matching the process name for network operations (TCP/UDP Send/Receive/Connect) and extracts endpoints from the 'Path' field.
    Returns a sorted list of unique endpoint strings.
    """
    log_data = await _check_loaded(ctx, "find_network_connections")
    await ctx.info(f"[find_network_connections] Starting for process: '{process_name}'")
    if not process_name:
        await ctx.error("[find_network_connections] process_name filter cannot be empty.")
        raise ValueError("process_name filter is required.")
    remote_endpoints = set()
    # Get interned IDs for target process and network operations
    target_pname_id = log_data.get_id(IK_PROCESS_NAME, process_name)
    network_op_ids = {log_data.get_id(IK_OPERATION, op) for op in NETWORK_OPERATIONS if log_data.get_id(IK_OPERATION, op) is not None}

    # Check if process name and network ops exist
    if target_pname_id is None:
        await ctx.warning(f"[find_network_connections] Process name '{process_name}' not found in loaded data.")
        return []
    if not network_op_ids:
        await ctx.warning(f"[find_network_connections] No standard network operations found in interner.")
        return []

    # Use index to get relevant event indices
    indices_to_check = log_data.pname_id_index.get(target_pname_id, [])
    if not indices_to_check:
        await ctx.info(f"[find_network_connections] No events found for process '{process_name}'.")
        return []

    await ctx.info(f"[find_network_connections] Scanning {len(indices_to_check):,} events for '{process_name}'...")
    # Regex to capture remote endpoint (IP or hostname) and port from Path string (e.g., "Host:Port -> Remote:Port")
    endpoint_regex = re.compile(r".* -> \[?([a-fA-F0-9:.\-]+)\]?:(\d+)") # Added '-' for hostnames
    processed_count = 0
    start_time = time.time()
    last_progress_report_time = start_time

    # Iterate through events for the target process
    for idx in indices_to_check:
        processed_count += 1
        event_dict = log_data.events[idx]
        op_id = event_dict.get('op_id')

        # Check if it's a network operation
        if op_id in network_op_ids:
            path_str = log_data.get_string(IK_PATH, event_dict.get('path_id'))
            if path_str:
                # Attempt to extract endpoint using regex
                match = endpoint_regex.match(path_str)
                if match: remote_endpoints.add(f"{match.group(1)}:{match.group(2)}")

        # Progress reporting
        current_time = time.time()
        if processed_count % 50000 == 0 or (current_time - last_progress_report_time > PROGRESS_REPORT_SECONDS):
            elapsed = current_time - start_time
            try: await ctx.info(f"[find_network_connections] Scanned {processed_count:,}/{len(indices_to_check):,} events ({elapsed:.1f}s)")
            except Exception: pass
            last_progress_report_time = current_time

    # Return sorted list of unique endpoints
    sorted_endpoints = sorted(list(remote_endpoints))
    await ctx.info(f"[find_network_connections] Completed. {len(sorted_endpoints)} unique endpoints for '{process_name}'.")
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
    of matching events to a local file (CSV or JSON format).
    *** SECURITY ***: Output files are restricted to the script's current working
    directory or subdirectories. Absolute paths or paths with '..' are denied.

    Args:
        output_file (str): The desired path for the output file (e.g., 'filtered_events.csv').
                           Must be relative to the script's working directory.
        output_format (str): The desired output format ('csv' or 'json', defaults to 'csv').
        filter_*: Optional filter parameters (see 'query_events' tool for details).

    Filter Notes:
    - Exact match filters (filter_process, filter_operation, filter_result) use case-sensitive matching on the full string.
    - Contains filters (filter_path_contains, filter_process_contains, filter_stack_module_path) perform case-insensitive substring checks. They do NOT support OR logic via '|'.
    - Regex filters (filter_path_regex, filter_process_regex, filter_detail_regex) use Python's 're' module with IGNORECASE. Use these for complex patterns, including OR logic (e.g., "value1|value2"). Remember to escape special regex characters if matching literally (e.g., use '\\.' to match a period).
    - Time filters (filter_start_time, filter_end_time) accept Unix timestamps (float/int) or time strings ("HH:MM:SS.ffffff"). Time strings perform time-only comparisons.

    Returns:
        A dictionary indicating success, the absolute output path, and the number of events exported.
    """
    await ctx.info(f"[export_query_results] Starting export to '{output_file}' ({output_format})...")
    if output_format.lower() not in ['csv', 'json']:
        raise ValueError("Invalid output_format. Must be 'csv' or 'json'.")
    if not output_file:
         raise ValueError("Output file name cannot be empty.")

    # --- MODIFIED: Path Validation (Hardened) ---
    try:
        # Define the single, allowed base directory for all outputs
        allowed_dir = os.path.abspath(os.getcwd())
        
        # Safely join the allowed directory with the user's requested file path
        # This treats 'output_file' as relative *to* 'allowed_dir'
        # If 'output_file' is an absolute path (e.g., /etc/passwd), 
        # os.path.join will discard 'allowed_dir' and just use the absolute path.
        abs_output_path = os.path.abspath(os.path.join(allowed_dir, output_file))
        
        # THE CRITICAL CHECK:
        # Ensure the final, resolved path is still *within* the allowed directory.
        if os.path.commonpath([abs_output_path, allowed_dir]) != allowed_dir:
            await ctx.error(f"[export_query_results] Path traversal denied: '{abs_output_path}' is outside allowed directory '{allowed_dir}'.")
            raise ValueError(f"Invalid output path. Must be relative and inside the directory: {allowed_dir}")
        
        # Now it's safe to check for/create the directory
        output_dir = os.path.dirname(abs_output_path)
        if output_dir and not os.path.exists(output_dir):
            try: 
                os.makedirs(output_dir)
                logger.info(f"Created output directory: {output_dir}")
            except OSError as e: 
                raise ValueError(f"Could not create output directory '{output_dir}': {e}") from e
        
        await ctx.info(f"[export_query_results] Validated output path: {abs_output_path}")

    except ValueError as e:
        await ctx.error(f"Invalid output file path: {e}")
        raise e
    # --- End Hardened Path Validation ---

    log_data = await _check_loaded(ctx, "export_query_results")
    if not log_data.events:
        await ctx.info("[export_query_results] Completed. No events loaded to export.")
        return {"success": True, "output_path": abs_output_path, "events_exported": 0}
    events_to_export = []
    events_exported = 0
    export_start_time = time.time()

    try:
        # Use the refactored filtering generator
        await ctx.info("[export_query_results] Filtering events...")
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
                await ctx.warning(f"[export_query_results] Could not retrieve details for event index {event_idx}, skipping.")

            if indices_processed % 10000 == 0:
                try: await ctx.info(f"[export_query_results] Retrieved details for {indices_processed:,} events...")
                except Exception: pass # Ignore progress errors

        await ctx.info(f"[export_query_results] Retrieved {len(events_to_export)} event details in {time.time() - detail_retrieval_start:.2f}s.")

        # Write to file
        if not events_to_export:
            await ctx.info("[export_query_results] No matching events to export.")
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
                        # Shallow copy to avoid mutating source dicts
                        csv_row = dict(row_dict)
                        # Convert complex types to JSON strings for CSV
                        if isinstance(csv_row.get('extra_data'), dict):
                            csv_row['extra_data'] = json.dumps(csv_row['extra_data'])
                        if isinstance(csv_row.get('stack_trace'), list):
                            csv_row['stack_trace'] = json.dumps(csv_row['stack_trace'])
                        if isinstance(csv_row.get('process_details_summary'), dict):
                            csv_row['process_details_summary'] = json.dumps(csv_row['process_details_summary'])
                        writer.writerow(csv_row)
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
        await ctx.info(f"[export_query_results] Completed. Exported {events_exported} events to '{output_file}' ({output_format}, {export_elapsed:.2f}s).")
        return {"success": True, "output_path": abs_output_path, "events_exported": events_exported}

    except Exception as e:
        await ctx.error(f"[export_query_results] Failed: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error exporting events: {e}")

# --- Main Execution Function (for profiling) ---
def main_execution(args):
    """Encapsulates the main loading and server run logic for profiling."""
    global LOADED_DATA # Allow modification of the global variable

    # --- Set Loading Flags ---
    load_stacks = not args.no_stack_traces
    load_extra = not args.no_extra_data

    # --- Load File into ProcmonLogData ---
    try:
        input_file_path = os.path.abspath(args.input_file) # Use absolute path
        logger.info(f"Attempting to load and optimize file: {input_file_path}")

        # Load data and store in the global variable
        LOADED_DATA = load_procmon_xml(input_file_path, load_stacks, load_extra)

        if not LOADED_DATA or not LOADED_DATA.is_loaded():
             logger.critical(f"File loading failed for '{input_file_path}'. Check logs above for errors. Exiting.")
             sys.exit(1)
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
                if args.debug:
                    logger.debug(f"  Detailed Memory: RSS={rss_formatted}, VMS={vms_formatted}")
            except Exception as mem_err:
                logger.warning(f"Could not retrieve process memory usage: {mem_err}")
        else:
            logger.info("Memory usage reporting skipped (psutil library not installed).")

        logger.info(f"Ready for MCP connections.")

    except (ValueError, FileNotFoundError, TypeError, IndexError, RuntimeError) as e:
        logger.critical(f"Error loading file '{args.input_file}': {e}")
        if args.debug:
            logger.exception("Loading error details:")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"An unexpected error occurred during file loading ('{args.input_file}'): {e}", exc_info=args.debug)
        sys.exit(1)

    # --- Start MCP Server ---
    server_started = False
    try:
        if args.transport == "sse":
            if hasattr(mcp, 'settings'):
                logger.info("Configuring MCP for SSE transport...")
                mcp.settings.host = args.mcp_host
                mcp.settings.port = args.mcp_port
                log_level = logging.DEBUG if args.debug else logging.INFO
                mcp_log_level_name = logging.getLevelName(log_level)
                mcp.settings.log_level = mcp_log_level_name.lower()
                logger.info(f"  MCP Host: {mcp.settings.host}, Port: {mcp.settings.port}, Log Level: {mcp.settings.log_level}")
            else:
                logger.warning("MCP object lacks 'settings'; cannot configure SSE via arguments.")
            logger.info(f"Starting MCP server with SSE transport on http://{args.mcp_host}:{args.mcp_port}")
            mcp.run(transport="sse") # Blocks
            server_started = True
        else: # Default to stdio
            logger.info("Starting MCP server with STDIO transport...")
            mcp.run(transport="stdio") # Blocks
            server_started = True
    except KeyboardInterrupt:
        logger.info("Server stopped by user (KeyboardInterrupt).")
    except Exception as e:
        logger.critical(f"Failed during server startup or execution: {e}", exc_info=args.debug)
        sys.exit(1)

    # --- Post-Server Execution ---
    if not server_started and args.transport == "sse":
        logger.critical("SSE Server did not appear to start correctly.")
        sys.exit(1)
    else:
        logger.info("Server execution finished.")


# --- Main Execution Block ---
if __name__ == "__main__":
    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(
        description=f"MCP Server for analyzing Procmon XML files (.xml, .gz/bz2/xz) using in-memory optimization (Refactored).",
        epilog=f"Memory reporting requires 'psutil' library (`pip install psutil`). Profiling requires '--profile' flag."
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
    # --- ADDED: Profiling arguments ---
    parser.add_argument("--profile", action='store_true', help="Enable profiling and print stats on exit.")
    parser.add_argument("--profile-output", type=str, default="procmon_profile.prof", help="Output file for profiling data (used with --profile).")
    parser.add_argument("--profile-sort", type=str, default="cumulative", help="Sort key for profile stats (e.g., cumulative, tottime, calls).")
    parser.add_argument("--profile-lines", type=int, default=50, help="Number of lines to print in profile stats.")

    args = parser.parse_args()

    # --- Logging Configuration (Same as before) ---
    log_level = logging.DEBUG if args.debug else logging.INFO
    log_handlers = []
    if args.log_file:
        log_dir = os.path.dirname(args.log_file)
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir)
            except OSError as e:
                print(f"Error: Could not create directory for log file '{args.log_file}': {e}")
                sys.exit(1)
        try:
            file_handler = logging.FileHandler(args.log_file, mode='w')
            file_handler.setLevel(log_level)
            file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
            log_handlers.append(file_handler)
            print(f"Logging to file: {args.log_file}")
        except Exception as e:
            print(f"Error: Could not open log file '{args.log_file}': {e}")
            sys.exit(1)
    else:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        log_handlers.append(console_handler)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    for handler in log_handlers:
        root_logger.addHandler(handler)
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
    logger.info(f"Selective loading: Stacks={not args.no_stack_traces}, ExtraData={not args.no_extra_data}")

    # --- Dependency Checks ---
    if not MCP_SDK_AVAILABLE:
        logger.critical("CRITICAL: Model Context Protocol SDK (mcp[cli]) is not installed.")
        logger.critical("Please install it: pip install \"mcp[cli]\"")
        sys.exit(1)

    # --- Profiling Setup ---
    if args.profile:
        logger.info(f"Profiling enabled. Outputting stats to console (sorted by '{args.profile_sort}') and saving raw data to '{args.profile_output}'.")
        profiler = cProfile.Profile()
        profiler.enable()

        # Run main logic under profiler
        try:
            main_execution(args)
        finally:
            profiler.disable()
            logger.info(f"Profiling finished. Saving raw data to '{args.profile_output}'...")
            profiler.dump_stats(args.profile_output)

            # Print stats to console
            s = io.StringIO()
            sortby = args.profile_sort
            ps = pstats.Stats(profiler, stream=s).sort_stats(sortby)
            ps.print_stats(args.profile_lines)
            logger.info(f"\n--- Profiling Stats (Top {args.profile_lines}, sorted by {sortby}) ---\n{s.getvalue()}")
            logger.info(f"--- End Profiling Stats ---")

    else:
        # Run main logic directly without profiling
        main_execution(args)

    sys.exit(0)
