# -*- coding: utf-8 -*-
import os
import logging
import argparse
from typing import List, Dict, Any, Optional, Tuple, Iterator, IO, Set
import io
import asyncio
import time # For timing
from collections import defaultdict # For counting
import dataclasses # For XML data structures
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
# Define a base date (epoch) for creating full timestamps from Time_of_Day.
# This is necessary because XML only provides time, not date. Assumes logs don't span midnight relative to this arbitrary date for accurate time-only filtering.
BASE_DATE = datetime(1970, 1, 1, tzinfo=timezone.utc)
# Known operation strings for specific tools
OP_PROCESS_CREATE = "Process Create"
OP_PROCESS_EXIT = "Process Exit"
NETWORK_OPERATIONS = {"TCP Connect", "TCP Send", "TCP Receive", "UDP Send", "UDP Receive"} # Case-sensitive

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
        # Ensure consistent handling of empty strings if needed (optional)
        # s = s.strip() if s else s # Example: treat "" and " " the same if desired
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

# --- XML Parser Data Structures ---

@dataclasses.dataclass
class StackFrame:
    """Represents a single frame in a call stack parsed from a <frame> element."""
    depth: Optional[int] = None
    address: Optional[str] = None # Keep as hex string like '0x...'
    path: Optional[str] = None
    location: Optional[str] = None

    @staticmethod
    def _strip_namespace(tag):
        """Helper to remove namespace from tag string if present."""
        return tag.split('}', 1)[-1] if '}' in tag else tag

    @classmethod
    def _find_text_ignore_ns(cls, elem: ET_impl.Element, tag_name: str) -> Optional[str]:
         """Finds the text of the first direct child element with the given tag name, ignoring namespaces."""
         for child in elem:
            # Check tag name ignoring namespace
            if cls._strip_namespace(child.tag) == tag_name:
                return child.text.strip() if child.text else None
         return None

    @classmethod
    def from_xml_element(cls, elem: ET_impl.Element) -> 'StackFrame':
        """Parses a <frame> XML element into a StackFrame object, ignoring namespaces."""
        depth_text = cls._find_text_ignore_ns(elem, 'depth')
        try: depth = int(depth_text) if depth_text and depth_text.isdigit() else None
        except (ValueError, TypeError): depth = None
        # Address is typically hex, keep as string
        address = cls._find_text_ignore_ns(elem, 'address')
        path = cls._find_text_ignore_ns(elem, 'path')
        location = cls._find_text_ignore_ns(elem, 'location')
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
    def _strip_namespace(tag):
        """Helper to remove namespace from tag string if present."""
        return tag.split('}', 1)[-1] if '}' in tag else tag

    @classmethod
    def _find_text_ignore_ns(cls, elem: ET_impl.Element, tag_name: str) -> Optional[str]:
         """Finds the text of the first direct child element with the given tag name, ignoring namespaces."""
         for child in elem:
            if cls._strip_namespace(child.tag) == tag_name:
                return child.text.strip() if child.text else None
         return None

    @staticmethod
    def _safe_text_to_int(text: Optional[str]) -> Optional[int]:
        """Safely converts text (decimal or hex '0x...') to int, returning None on failure."""
        if text is None: return None
        text = text.strip()
        if not text: return None # Handle empty string after strip
        try:
            # Check for hex prefix case-insensitively
            if text.lower().startswith('0x'):
                return int(text, 16)
            else:
                # Handle potential negative numbers if needed, though unlikely for IDs
                return int(text)
        except (ValueError, TypeError):
            # Log at debug level as this might happen for non-numeric fields
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
        data = {}
        data['process_index'] = cls._safe_text_to_int(cls._find_text_ignore_ns(elem, 'ProcessIndex'))
        data['process_id'] = cls._safe_text_to_int(cls._find_text_ignore_ns(elem, 'ProcessId'))
        data['parent_process_id'] = cls._safe_text_to_int(cls._find_text_ignore_ns(elem, 'ParentProcessId'))
        data['parent_process_index'] = cls._safe_text_to_int(cls._find_text_ignore_ns(elem, 'ParentProcessIndex'))
        data['authentication_id'] = cls._find_text_ignore_ns(elem, 'AuthenticationId')
        data['create_time'] = cls._find_text_ignore_ns(elem, 'CreateTime') # Keep as string for now
        data['finish_time'] = cls._find_text_ignore_ns(elem, 'FinishTime') # Keep as string for now
        data['is_virtualized'] = cls._safe_text_to_bool(cls._find_text_ignore_ns(elem, 'IsVirtualized'))
        data['is_64bit'] = cls._safe_text_to_bool(cls._find_text_ignore_ns(elem, 'Is64bit'))
        data['integrity'] = cls._find_text_ignore_ns(elem, 'Integrity')
        data['owner'] = cls._find_text_ignore_ns(elem, 'Owner')
        data['process_name'] = cls._find_text_ignore_ns(elem, 'ProcessName') # Corrected based on structure analysis
        data['image_path'] = cls._find_text_ignore_ns(elem, 'ImagePath')
        data['command_line'] = cls._find_text_ignore_ns(elem, 'CommandLine')
        data['company_name'] = cls._find_text_ignore_ns(elem, 'CompanyName')
        data['version'] = cls._find_text_ignore_ns(elem, 'Version')
        data['description'] = cls._find_text_ignore_ns(elem, 'Description')
        return cls(**data)

# --- UPDATED: ProcmonEvent Dataclass with extra_data ---
@dataclasses.dataclass
class ProcmonEvent:
    """Represents data parsed from a single <event> element before optimization."""
    # Known fields
    sequence_number: Optional[int] = None # Might be absent in some XML exports
    process_index: Optional[int] = None # Used to link to ProcessInfo if needed
    pid: Optional[int] = None
    tid: Optional[int] = None
    parent_pid: Optional[int] = None # Often missing in XML event, might need lookup via ProcessInfo
    timestamp_str: Optional[str] = None # Original "HH:MM:SS.ffffff" string
    timestamp_float: Optional[float] = None # Calculated Unix timestamp float (UTC, based on BASE_DATE)
    operation: Optional[str] = None
    path: Optional[str] = None
    result: Optional[str] = None
    detail: Optional[str] = None
    duration_float: Optional[float] = None # Duration in seconds (float)
    category: Optional[str] = None
    process_name: Optional[str] = None # Usually present, fallback to lookup via ProcessIndex if needed
    stack_frames: Optional[List[StackFrame]] = None # Parsed stack frames
    # Field to store unknown/extra data
    extra_data: Optional[Dict[str, str]] = None

    @staticmethod
    def _strip_namespace(tag):
        """Helper to remove namespace from tag string if present."""
        return tag.split('}', 1)[-1] if '}' in tag else tag

    @classmethod
    def _find_child_ignore_ns(cls, elem: ET_impl.Element, tag_name: str) -> Optional[ET_impl.Element]:
        """Finds the first direct child element with the given tag name, ignoring namespaces."""
        for child in elem:
            if cls._strip_namespace(child.tag) == tag_name:
                return child
        return None

    @classmethod
    def _find_text_ignore_ns(cls, elem: ET_impl.Element, tag_name: str) -> Optional[str]:
         """Finds the text of the first direct child element with the given tag name, ignoring namespaces."""
         child = cls._find_child_ignore_ns(elem, tag_name)
         return child.text.strip() if child is not None and child.text else None

    @classmethod
    def from_xml_element(cls, elem: ET_impl.Element, processes: Dict[int, ProcessInfo], load_stack: bool, load_extra: bool) -> 'ProcmonEvent':
        """
        Parses an <event> XML element into a ProcmonEvent object, ignoring namespaces
        and optionally capturing extra fields and stack traces based on flags.
        """
        data = {}
        extra_data_dict = {}
        # Define known tags we handle explicitly (lowercase for case-insensitive comparison)
        known_tags = {
            'sequencenumber', 'processindex', 'pid', 'threadid', 'parentpid',
            'time_of_day', 'operation', 'path', 'result', 'detail', 'duration',
            'category', 'process_name', 'stack'
        }

        # Iterate through all direct children of the event element
        for child in elem:
            tag_name_orig = child.tag
            tag_name_clean = cls._strip_namespace(tag_name_orig).lower() # Use lowercase for matching known tags
            tag_text = child.text.strip() if child.text else None

            # Store known fields in the main data dict
            if tag_name_clean == 'sequencenumber':
                data['sequence_number'] = ProcessInfo._safe_text_to_int(tag_text)
                if tag_text is not None and data['sequence_number'] is None:
                    logger.warning(f"Could not parse SequenceNumber '{tag_text}' for an event.")
            elif tag_name_clean == 'processindex':
                data['process_index'] = ProcessInfo._safe_text_to_int(tag_text)
            elif tag_name_clean == 'pid': # Use PID based on prior analysis
                data['pid'] = ProcessInfo._safe_text_to_int(tag_text)
            elif tag_name_clean == 'threadid':
                data['tid'] = ProcessInfo._safe_text_to_int(tag_text)
            elif tag_name_clean == 'parentpid':
                data['parent_pid'] = ProcessInfo._safe_text_to_int(tag_text)
            elif tag_name_clean == 'time_of_day': # Use Time_of_Day based on prior analysis
                data['timestamp_str'] = tag_text
                data['timestamp_float'] = cls._parse_timestamp_str(tag_text)
            elif tag_name_clean == 'operation':
                data['operation'] = tag_text
            elif tag_name_clean == 'path':
                data['path'] = tag_text
            elif tag_name_clean == 'result':
                data['result'] = tag_text
            elif tag_name_clean == 'detail':
                data['detail'] = tag_text
            elif tag_name_clean == 'duration':
                 try:
                    data['duration_float'] = float(tag_text) if tag_text is not None else None
                 except (ValueError, TypeError):
                    logger.debug(f"Failed to convert duration '{tag_text}' to float for event seq {data.get('sequence_number', '<unknown>')}.")
                    data['duration_float'] = None
            elif tag_name_clean == 'category':
                data['category'] = tag_text
            elif tag_name_clean == 'process_name': # Use Process_Name based on prior analysis
                data['process_name'] = tag_text
            elif tag_name_clean == 'stack':
                # Parse Stack only if requested
                if load_stack:
                    data['stack_frames'] = []
                    for frame_elem in child: # Iterate children of <stack>
                        if cls._strip_namespace(frame_elem.tag) == 'frame':
                            try:
                                data['stack_frames'].append(StackFrame.from_xml_element(frame_elem))
                            except Exception as e:
                                logger.warning(f"Failed to parse a <frame> element for event seq {data.get('sequence_number', '<unknown>')}: {e}", exc_info=False)
                    if not data['stack_frames']: # Set to None if list is empty
                        data['stack_frames'] = None
                else:
                    data['stack_frames'] = None # Explicitly set to None if not loading
            elif load_extra: # Check if we should load extra data
                # Store unknown tags and their text content
                if tag_text is not None: # Only store if there's text
                    # Use the original tag name (with namespace if present) as the key
                    extra_data_dict[tag_name_orig] = tag_text
                    logger.debug(f"  [Event Parse Debug] Found extra field: '{tag_name_orig}' = '{tag_text[:50]}...'")


        # Fallback: If ProcessName missing in event, try lookup via ProcessIndex
        if data.get('process_name') is None and data.get('process_index') is not None:
            proc_info = processes.get(data['process_index'])
            if proc_info:
                data['process_name'] = proc_info.process_name # Assumes ProcessInfo has correct name
                # Also try to get ParentPID from process list if missing from event
                if data.get('parent_pid') is None:
                    data['parent_pid'] = proc_info.parent_pid
            else:
                 logger.debug(f"Event seq {data.get('sequence_number', '<unknown>')} has ProcessIndex {data['process_index']} but not found in process list.")

        # Add the collected extra data if any and if requested
        if load_extra and extra_data_dict:
            data['extra_data'] = extra_data_dict

        return cls(**data)

    @staticmethod
    def _parse_timestamp_str(ts_str: Optional[str]) -> Optional[float]:
        """
        Parses HH:MM:SS.ffffff[f...] string to a UTC float timestamp relative to BASE_DATE.
        Handles arbitrary digits in fractional seconds by truncating to 6.
        """
        if ts_str is None:
            return None
        try:
            # Split into time and fractional seconds
            parts = ts_str.split('.', 1)
            time_part = parts[0]
            fractional_part = ""
            if len(parts) > 1:
                fractional_part = parts[1]

            # Truncate fractional part to 6 digits if longer
            if len(fractional_part) > 6:
                # logger.debug(f"Truncating timestamp fractional part: '{fractional_part}' -> '{fractional_part[:6]}'") # Reduced verbosity
                fractional_part = fractional_part[:6]
            elif len(fractional_part) < 6:
                # Pad with zeros if shorter (less common but possible)
                fractional_part = fractional_part.ljust(6, '0')

            # Reconstruct the string with exactly 6 fractional digits
            ts_str_corrected = f"{time_part}.{fractional_part}"

            # Parse the corrected time string
            parsed_time: dt_time = datetime.strptime(ts_str_corrected, PROCMON_TIMESTAMP_FORMAT).time()

            # Combine with base date (which has UTC timezone set)
            full_dt = datetime.combine(BASE_DATE.date(), parsed_time, tzinfo=timezone.utc)
            # Return Unix timestamp float (seconds since epoch)
            return full_dt.timestamp()
        except (ValueError, TypeError, IndexError) as e:
            # Log warning if timestamp string is invalid
            # Use original ts_str in log message for clarity
            logger.warning(f"Could not parse timestamp string '{ts_str}': {e}")
            return None

# --- Helper to format bytes ---
def _format_bytes(bytes_val: int) -> str:
    """ Formats bytes into a human-readable string (KB, MB, GB). """
    if bytes_val < 1024:
        return f"{bytes_val} Bytes"
    elif bytes_val < 1024**2:
        return f"{bytes_val / 1024:.2f} KB"
    elif bytes_val < 1024**3:
        return f"{bytes_val / (1024**2):.2f} MB"
    else:
        return f"{bytes_val / (1024**3):.2f} GB"


# --- XML Parsing Logic ---
def _clear_elem(elem: ET_impl.Element):
    """Helper to clear element memory using lxml/ET specific methods."""
    elem.clear()
    if LXML_AVAILABLE:
        # Clean up preceding siblings to potentially release more memory with lxml
        while elem.getprevious() is not None:
            try:
                parent = elem.getparent()
                if parent is not None: del parent[0]
                else: break # Stop if no parent
            except (IndexError, AttributeError): # Handle potential errors during cleanup
                break

def _strip_namespace(tag):
    """Helper to remove namespace from tag string if present."""
    return tag.split('}', 1)[-1] if '}' in tag else tag

def _parse_xml_processes_only(source_stream: IO[bytes]) -> Dict[int, ProcessInfo]:
    """
    Parses only the <processlist> from the XML stream and returns the process dictionary
    keyed by ProcessIndex. Stops parsing after the </processlist> tag.
    Reports progress based on element count. Ignores namespaces.
    """
    processes_dict: Dict[int, ProcessInfo] = {}
    parsing_stage = "seeking_procmon"
    # We still filter by tag here for efficiency, assuming these top-level tags don't have namespaces
    # or that the namespace handling happens within from_xml_element if needed.
    tags_of_interest = ('process', 'processlist', 'procmon')
    start_time = time.time()
    process_element_count = 0

    try:
        # Use 'rb' mode for binary reading, required by XML parsers
        context = ET_impl.iterparse(source_stream, events=('end',), tag=tags_of_interest)
        logger.info("Starting Pass 1: Parsing process list...")
    except Exception as e:
        logger.error(f"Unexpected error initializing XML parser for process list: {e}", exc_info=True)
        raise RuntimeError("Failed to initialize XML parser for process list") from e

    try:
        for event_type, elem in context:
            # Strip namespace for reliable comparison
            tag = _strip_namespace(elem.tag)

            if parsing_stage == "seeking_procmon":
                if tag == 'procmon':
                    logger.warning("Found end of procmon before processlist.")
                    break
                parsing_stage = "seeking_processlist"

            if parsing_stage == "seeking_processlist":
                if tag == 'process':
                    parsing_stage = "parsing_processlist"
                    # Fallthrough
                elif tag == 'processlist':
                    logger.info("Found empty <processlist>.")
                    _clear_elem(elem)
                    break

            if parsing_stage == "parsing_processlist":
                if tag == 'process':
                    process_element_count += 1
                    try:
                        # ProcessInfo.from_xml_element needs to handle namespaces internally now
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

    except ET_impl.XMLSyntaxError as e:
        logger.error(f"XML Parse Error during process parsing: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during process parsing: {e}", exc_info=True)
        raise

    elapsed = time.time() - start_time
    logger.info(f"Finished Pass 1: Found {len(processes_dict)} unique processes from {process_element_count:,} elements ({elapsed:.2f}s).")
    return processes_dict


# --- UPDATED: Respect selective loading flags ---
def _parse_xml_stream_for_loading(
    source_stream: IO[bytes],
    interners: Dict[str, StringInterner],
    processes: Dict[int, ProcessInfo], # Pass in the pre-loaded processes for potential lookups
    load_stack: bool, # Flag for selective loading
    load_extra: bool # Flag for selective loading
) -> Iterator[Dict[str, Any]]:
    """
    Internal helper optimized for initial loading into memory.
    Parses <event> elements, converts them to optimized dictionaries using interners,
    and yields them. Assumes process list is already parsed and passed in `processes`.
    Reports progress based on event count. Includes enhanced debug logging.
    Uses start/end events for iterparse and handles potential XML namespaces.
    Respects selective loading flags.

    Yields:
        Optimized event dictionaries.
    """
    parsing_stage = "seeking_eventlist" # Start assuming processes are done
    try:
        # Use start AND end events, without tag filter to handle namespaces/unexpected tags
        context = ET_impl.iterparse(source_stream, events=('start', 'end'))
        logger.info("Starting Pass 2: Parsing and optimizing events...")
    except Exception as e:
        logger.error(f"Unexpected error initializing XML parser for event loading: {e}", exc_info=True)
        raise RuntimeError("Failed to initialize XML parser for events") from e

    event_count = 0
    yielded_count = 0 # Separate counter for yielded events
    start_time = time.time()
    last_report_time = start_time
    try:
        for event_type, elem in context:
            # Strip namespace for reliable comparison
            tag = _strip_namespace(elem.tag)

            # --- State Machine based on Start/End Events ---
            if parsing_stage == "seeking_eventlist":
                if event_type == 'start' and tag == 'eventlist':
                    logger.debug("Entered <eventlist> (start event).")
                    parsing_stage = "parsing_events"
                    # Don't clear yet, wait for end tag
                elif event_type == 'end' and tag == 'procmon': # Reached end before finding eventlist
                    logger.warning("Reached end of <procmon> before finding <eventlist>.")
                    break
                # Ignore other tags before eventlist starts, clear them on end event
                elif event_type == 'end':
                     _clear_elem(elem)
                continue # Continue loop until eventlist start is found

            elif parsing_stage == "parsing_events":
                # *** REMOVED verbose logging of every tag ***
                # logger.debug(f"  [Pass 2 Debug] Encountered tag: '{tag}' (Original: '{elem.tag}'), Event type: {event_type}")

                if event_type == 'end': # Process elements only when they finish
                    if tag == 'event':
                        event_count += 1 # Increment count when <event> tag *ends*
                        seq_num_text = ProcmonEvent._find_text_ignore_ns(elem, 'SequenceNumber') or f'event #{event_count}'
                        logger.debug(f"  [Pass 2 Debug] Found END of <event> tag #{event_count}. Attempting parse...")
                        try:
                            # 1. Parse the raw event data using the dataclass (which now ignores namespaces)
                            logger.debug(f"  [Pass 2 Debug] Calling ProcmonEvent.from_xml_element for event #{event_count}...")
                            # Pass selective loading flags to parser
                            raw_event = ProcmonEvent.from_xml_element(elem, processes, load_stack, load_extra)
                            # Check if sequence number was parsed correctly for logging
                            parsed_seq = raw_event.sequence_number if raw_event else "<parse failed>"
                            # *** REMOVED Check for missing SequenceNumber - Assume it might be missing ***
                            # if parsed_seq is None:
                            #     logger.warning(f"  [Pass 2 Warning] Skipping event ~{seq_num_text} due to missing SequenceNumber after parsing.")
                            #     continue # Skip this event if sequence couldn't be parsed

                            logger.debug(f"  [Pass 2 Debug] Successfully parsed raw_event for event #{event_count} (Sequence: {parsed_seq}). Optimizing...")

                            # --- Optimization Logic ---
                            opt_event: Dict[str, Any] = {}
                            opt_event['seq'] = raw_event.sequence_number # Will be None if tag was missing/unparsable
                            opt_event['pid'] = raw_event.pid
                            opt_event['tid'] = raw_event.tid
                            opt_event['ppid'] = raw_event.parent_pid
                            opt_event['ts'] = raw_event.timestamp_float
                            opt_event['dur'] = raw_event.duration_float
                            opt_event['detail'] = raw_event.detail
                            opt_event['pname_id'] = interners["process_name"].get_id(raw_event.process_name)
                            opt_event['op_id'] = interners["operation"].get_id(raw_event.operation)
                            opt_event['path_id'] = interners["path"].get_id(raw_event.path)
                            opt_event['res_id'] = interners["result"].get_id(raw_event.result)
                            opt_event['cat_id'] = interners["category"].get_id(raw_event.category)

                            # *** ADDED: Store extra_data if loaded ***
                            if load_extra and raw_event.extra_data:
                                opt_event['extra_data'] = raw_event.extra_data # Store the dict directly

                            # *** Store stack trace only if loaded ***
                            if load_stack and raw_event.stack_frames:
                                optimized_stack = []
                                for frame in raw_event.stack_frames:
                                    try:
                                        optimized_stack.append(frame.to_optimized_list(
                                            interners["stack_path"],
                                            interners["stack_location"]
                                        ))
                                    except Exception as frame_e:
                                         logger.warning(f"Failed to optimize stack frame for event seq {parsed_seq}: {frame_e}", exc_info=False)
                                if optimized_stack:
                                    opt_event['stack'] = optimized_stack
                            # --- End Optimization ---

                            logger.debug(f"  [Pass 2 Debug] Yielding optimized event for Sequence {parsed_seq}.")
                            yield opt_event
                            yielded_count += 1 # Increment *after* successful yield

                            # --- Progress Reporting ---
                            current_time = time.time()
                            # Report based on yielded_count
                            if yielded_count % PROGRESS_REPORT_INTERVAL == 0 or (current_time - last_report_time) > 5.0:
                                elapsed_total = current_time - start_time
                                rate = yielded_count / elapsed_total if elapsed_total > 0 else 0
                                # Report yielded count
                                logger.info(f"  [Pass 2] Yielded {yielded_count:,} events... ({elapsed_total:.1f}s | {rate:,.0f} events/sec)")
                                last_report_time = current_time

                        except Exception as e:
                            # Log error parsing this specific event but continue if possible
                            # seq_num_text = ProcmonEvent._find_text_ignore_ns(elem, 'SequenceNumber') or f'event #{event_count}' # Already defined above
                            logger.warning(f"  [Pass 2 Warning] Failed to parse/convert <event> element (Sequence ~{seq_num_text}): {e}", exc_info=False)
                            # Log more details in debug mode
                            if logger.isEnabledFor(logging.DEBUG):
                                try:
                                    # Try to log the raw XML snippet for the failed event
                                    event_xml_str = ET_impl.tostring(elem, encoding='unicode', method='xml')
                                    logger.debug(f"  [Pass 2 Debug] XML for failed event ~{seq_num_text}:\n{event_xml_str[:1000]}...") # Log first 1000 chars
                                except Exception as log_e:
                                    logger.debug(f"  [Pass 2 Debug] Could not serialize failed event element to string: {log_e}")
                                # Log full exception trace in debug mode
                                logger.debug(f"  [Pass 2 Debug] Full exception details for event ~{seq_num_text}:", exc_info=True)

                        finally:
                             logger.debug(f"  [Pass 2 Debug] Clearing element for event #{event_count}.")
                             _clear_elem(elem) # IMPORTANT: Clear event element memory after processing its end tag

                    elif tag == 'eventlist':
                        logger.info(f"Finished processing <eventlist> (end tag).")
                        _clear_elem(elem)
                        # Don't break here, wait for procmon end tag
                    elif tag == 'procmon':
                        logger.debug("Reached end of <procmon> during event loading.")
                        _clear_elem(elem)
                        break # Stop iteration
                    else:
                        # *** REMOVED Premature Clearing ***
                        # If the tag wasn't 'event', 'eventlist', or 'procmon',
                        # it's likely a child of 'event' (like 'PID', 'Path', 'stack', 'frame', etc.)
                        # We MUST NOT clear it here, as the parent 'event' element needs it
                        # when its 'end' event is processed. The clearing happens
                        # in the finally block under "if tag == 'event'".
                        # logger.debug(f"  [Pass 2 Debug] Ignoring end event for intermediate tag '{tag}'.") # Removed this too for less noise
                        _clear_elem(elem) # Clear other intermediate tags to save memory


        elapsed = time.time() - start_time
        # Log the final count of *yielded* events, which populates LOADED_EVENTS
        logger.info(f"Finished Pass 2: Processed {event_count:,} <event> elements, successfully yielded {yielded_count:,} optimized events ({elapsed:.2f}s).")

    except ET_impl.XMLSyntaxError as e:
        logger.error(f"XML Parse Error during event loading stream: {e}")
        raise # Re-raise critical error
    except Exception as e:
        logger.error(f"Unexpected error during event loading stream: {e}", exc_info=True)
        raise # Re-raise


# --- Global State ---
ALLOWED_DIR_CONFIG: Optional[str] = None
LOADED_FILENAME: Optional[str] = None
LOADED_FILE_TYPE: Optional[str] = None # Should always be 'xml' if loaded
LOADED_COMPRESSION: Optional[str] = None
# Store Processes as objects (relatively small number), keyed by ProcessIndex
LOADED_PROCESSES: Optional[Dict[int, ProcessInfo]] = None
# Store Events as optimized dictionaries in a list (maintains order)
LOADED_EVENTS: Optional[List[Dict[str, Any]]] = None
# Store String Interning Maps globally
GLOBAL_INTERNERS: Dict[str, StringInterner] = {}
# *** ADDED: Indices for faster querying ***
PID_INDEX: Dict[int, List[int]] = defaultdict(list) # {pid_id: [event_idx, event_idx,...]}
OP_INDEX: Dict[int, List[int]] = defaultdict(list) # {op_id: [event_idx, event_idx,...]}
# *** ADDED: Selective loading flags (will be set by args) ***
LOAD_STACK_TRACES: bool = True
LOAD_EXTRA_DATA: bool = True

# --- Setup MCP ---
if MCP_SDK_AVAILABLE:
    mcp = FastMCP(
        "ProcmonXmlTool",
        description="A tool to analyze a specific, pre-loaded Procmon XML log file (plain or compressed) using in-memory optimization."
    )
else:
    mcp = MockMCP(
         "ProcmonXmlTool (Mock)",
         description="Mock Tool: Analyzes pre-loaded Procmon XML files (optimized in-memory)."
     )

# --- Security Helper ---
def get_secure_path(filename: str, base_dir: Optional[str] = None, check_exists: bool = True) -> str:
    """
    Validates filename relative to a base directory and returns absolute path.
    Can optionally skip the existence check (for output files).
    """
    if base_dir is None:
        base_dir = ALLOWED_DIR_CONFIG
    if not base_dir: raise RuntimeError("Internal Error: Base directory configuration is missing.")
    if not filename: raise ValueError("Filename cannot be empty.")
    # Prevent escaping the base directory
    if ".." in filename or os.path.isabs(filename):
        raise ValueError("Invalid filename format: Contains '..' or is an absolute path.")

    try:
        # Use os.path.normpath to clean the path initially
        norm_filename = os.path.normpath(filename)
        if norm_filename.startswith("..") or os.path.isabs(norm_filename):
             raise ValueError("Invalid filename format after normalization.") # Double check after normpath

        full_path = os.path.join(base_dir, norm_filename)
        normalized_base_dir = os.path.abspath(base_dir)
        normalized_full_path = os.path.abspath(full_path)
        logger.debug(f"Checking path: {normalized_full_path} against base: {normalized_base_dir}")

        # Use os.path.realpath to resolve symlinks *before* checking common path
        real_base_dir = os.path.realpath(normalized_base_dir)
        # Resolve the potential target path, but allow it not to exist yet for output
        try:
            real_full_path = os.path.realpath(normalized_full_path)
        except OSError: # Handle cases where the path doesn't exist for realpath
             real_full_path = normalized_full_path

        # Check if the resolved path is within the resolved allowed directory
        common_prefix = os.path.commonpath([real_base_dir, real_full_path])
        if common_prefix != real_base_dir:
            raise PermissionError(f"Access denied: Path '{filename}' resolves outside allowed base directory '{real_base_dir}'.")

        # Check existence only if requested
        if check_exists:
            if not os.path.exists(real_full_path):
                raise FileNotFoundError(f"File not found: {filename} (resolves to {real_full_path})")
            if not os.path.isfile(real_full_path):
                raise ValueError(f"Path exists but is not a file: {filename} (resolves to {real_full_path})")

        logger.debug(f"Path validated: {normalized_full_path}")
        # Return the normalized (but not realpath'd) version for consistency
        return normalized_full_path
    except ValueError as e: logger.error(f"Path validation error for '{filename}': {e}"); raise ValueError(f"Invalid path specified: {filename}") from e
    except FileNotFoundError as e: logger.error(f"File not found error for '{filename}': {e}"); raise FileNotFoundError(f"File not found: {filename}") from e
    except PermissionError as e: logger.error(f"Permission error for '{filename}': {e}"); raise PermissionError(f"Permission denied for file: {filename}") from e
    except Exception as e: logger.error(f"Unexpected error validating path '{filename}': {e}", exc_info=True); raise RuntimeError(f"Path validation failed unexpectedly for {filename}") from e


# --- Loading Helper (Loads Processes AND Optimized Events) ---
def load_and_validate_file(allowed_dir: str, filename_relative: str):
    """
    Loads XML file: Parses processes, then streams events, converting them
    to an optimized in-memory format using string interning. Stores results globally.
    Builds PID and Operation indices.

    Raises:
        FileNotFoundError, ValueError, PermissionError, RuntimeError, ET_impl.XMLSyntaxError
    """
    global LOADED_FILENAME, LOADED_FILE_TYPE, LOADED_COMPRESSION, LOADED_PROCESSES, LOADED_EVENTS, GLOBAL_INTERNERS
    global PID_INDEX, OP_INDEX # Declare modification of global indices

    # Reset global state before loading
    LOADED_FILENAME = None
    LOADED_FILE_TYPE = None
    LOADED_COMPRESSION = None
    LOADED_PROCESSES = None
    LOADED_EVENTS = None
    GLOBAL_INTERNERS = {}
    PID_INDEX = defaultdict(list) # Reset indices
    OP_INDEX = defaultdict(list)  # Reset indices

    abs_full_path = get_secure_path(filename_relative, base_dir=allowed_dir, check_exists=True)
    fname_lower = filename_relative.lower()
    file_type: str = "xml"
    compression: Optional[str] = None

    # Determine compression type
    if fname_lower.endswith(".xml"): compression = None
    elif fname_lower.endswith(".xml.gz"): compression = 'gz'
    elif fname_lower.endswith(".xml.bz2"): compression = 'bz2'
    elif fname_lower.endswith(".xml.xz"): compression = 'xz'
    # Allow compressed files without .xml extension too
    elif fname_lower.endswith(".gz"): compression = 'gz'; logger.warning(f"Assuming '.gz' file contains XML.")
    elif fname_lower.endswith(".bz2"): compression = 'bz2'; logger.warning(f"Assuming '.bz2' file contains XML.")
    elif fname_lower.endswith(".xz"): compression = 'xz'; logger.warning(f"Assuming '.xz' file contains XML.")
    else: raise ValueError(f"Unsupported file extension: {fname_lower}. Expecting .xml, .xml.gz, .xml.bz2, .xml.xz, .gz, .bz2, or .xz.")

    overall_start_time = time.time() # Start overall timer
    processes_dict: Dict[int, ProcessInfo] = {}
    optimized_events: List[Dict[str, Any]] = []

    # Initialize interners - keys MUST match usage in _parse_xml_stream_for_loading
    # and in lookup functions (get_string, get_id)
    interners: Dict[str, StringInterner] = {
        "process_name": StringInterner(),
        "operation": StringInterner(),
        "path": StringInterner(),
        "result": StringInterner(),
        "category": StringInterner(),
        "stack_path": StringInterner(), # Interner for stack frame paths
        "stack_location": StringInterner(), # Interner for stack frame locations/symbols
    }
    # Pre-intern known operation strings
    interners["operation"].get_id(OP_PROCESS_CREATE)
    interners["operation"].get_id(OP_PROCESS_EXIT)
    for op in NETWORK_OPERATIONS:
        interners["operation"].get_id(op)


    try:
        open_func: Any = open
        if compression == 'gz': open_func = gzip.open
        elif compression == 'bz2': open_func = bz2.open
        elif compression == 'xz': open_func = lzma.open

        comp_str = f" ({compression} compressed)" if compression else ""
        logger.info(f"Loading and optimizing{comp_str} XML file: {abs_full_path}")

        # --- Pass 1: Parse Processes Only ---
        with open_func(abs_full_path, "rb") as f_stream:
            processes_dict = _parse_xml_processes_only(f_stream)
            if processes_dict is None: processes_dict = {}; logger.error("Failed to parse process dictionary.") # Safety check

        # --- Pass 2: Parse Events and Optimize ---
        with open_func(abs_full_path, "rb") as f_stream:
            # Pass selective loading flags to the parser
            event_iterator = _parse_xml_stream_for_loading(
                f_stream, interners, processes_dict,
                load_stack=LOAD_STACK_TRACES, load_extra=LOAD_EXTRA_DATA
            )
            # *** UPDATED: Manual consumption with logging AND indexing ***
            logger.info("[Loader] Starting consumption of event iterator...")
            temp_event_list = []
            consumed_count = 0
            try:
                for idx, opt_event in enumerate(event_iterator): # Use enumerate to get index
                    temp_event_list.append(opt_event)
                    consumed_count += 1

                    # --- Build Indices ---
                    pid_id = opt_event.get('pname_id')
                    op_id = opt_event.get('op_id')
                    if pid_id is not None:
                        PID_INDEX[pid_id].append(idx) # Store event index (idx)
                    if op_id is not None:
                        OP_INDEX[op_id].append(idx) # Store event index (idx)
                    # --- End Indexing ---

                    # Log progress less frequently during consumption
                    if consumed_count % 50000 == 0:
                        logger.debug(f"[Loader] Consumed {consumed_count:,} events into list.")
            except Exception as consume_err:
                # Log any error during the consumption loop
                logger.error(f"[Loader] Error during iterator consumption after {consumed_count} events: {consume_err}", exc_info=True)
                # Decide whether to proceed with partial list or raise error - proceed for now
            finally:
                 # Log final counts after consumption loop finishes or breaks
                 logger.info(f"[Loader] Finished consuming event iterator. Total events consumed in loop: {consumed_count}. Final list length: {len(temp_event_list)}")
            optimized_events = temp_event_list # Assign the manually built list

        # --- Store results globally ---
        LOADED_FILENAME = filename_relative
        LOADED_FILE_TYPE = file_type
        LOADED_COMPRESSION = compression
        LOADED_PROCESSES = processes_dict
        LOADED_EVENTS = optimized_events # This list now contains the optimized event dicts
        GLOBAL_INTERNERS = interners # Store interners for later lookup
        # Indices (PID_INDEX, OP_INDEX) are already populated globally

        overall_end_time = time.time()
        logger.info(f"--- Loading Summary ---")
        # This count comes from len(optimized_events) which depends on successful yields
        logger.info(f" Successfully loaded and optimized {len(optimized_events):,} events from {filename_relative}.")
        logger.info(f" Found {len(processes_dict)} unique processes.")
        logger.info(f" Built PID index for {len(PID_INDEX)} processes and OP index for {len(OP_INDEX)} operations.")
        logger.info(f" Total loading and optimization time: {overall_end_time - overall_start_time:.2f} seconds.")
        # Log interner stats for debugging memory usage
        if logger.isEnabledFor(logging.DEBUG):
            for name, interner in interners.items():
                logger.debug(f"  Interner '{name}': {interner.next_id:,} unique strings.")

    except FileNotFoundError as e: logger.error(f"File not found: {abs_full_path}"); raise
    except PermissionError as e: logger.error(f"Permission denied: {abs_full_path}"); raise
    except ET_impl.XMLSyntaxError as e: logger.error(f"XML Syntax Error in {filename_relative}: {e}", exc_info=True); raise RuntimeError(f"Invalid XML: {e}") from e
    # *** UPDATED Exception Handling - Removed bz2.BZ2Error ***
    except (gzip.BadGzipFile, lzma.LZMAError) as e: # Handle specific compression errors first
        logger.error(f"Decompression error for {filename_relative}: {e}")
        raise RuntimeError(f"Decompression failed for '{filename_relative}'.") from e
    except OSError as e: # Catch general I/O errors, which might include bz2 issues
        logger.error(f"File read or I/O error for {filename_relative}: {e}")
        raise RuntimeError(f"File read or I/O failed for '{filename_relative}'.") from e
    except Exception as e:
        logger.error(f"Error loading/optimizing file {filename_relative}: {e}", exc_info=True)
        # Clear potentially partially loaded state on error
        LOADED_FILENAME = None; LOADED_FILE_TYPE = None; LOADED_COMPRESSION = None; LOADED_PROCESSES = None; LOADED_EVENTS = None; GLOBAL_INTERNERS = {}; PID_INDEX = defaultdict(list); OP_INDEX = defaultdict(list)
        raise RuntimeError(f"Failed to load/optimize file: {e}") from e


# --- Helper to get string from ID ---
def get_string(interner_name: str, id_val: Optional[int]) -> Optional[str]:
    """Looks up a string from its ID using the global interners."""
    if id_val is None: return None
    interner = GLOBAL_INTERNERS.get(interner_name)
    if interner:
        return interner.get_str(id_val)
    # Only log warning once per missing interner? Could use a set to track.
    logger.warning(f"Interner '{interner_name}' not found during string lookup.")
    return f"<Unknown Interner:{interner_name}_ID:{id_val}>" # More informative unknown string

# --- Helper to get ID from string ---
def get_id(interner_name: str, s: Optional[str]) -> Optional[int]:
    """Looks up an ID from its string using the global interners. Does NOT add new strings."""
    if s is None: return None
    interner = GLOBAL_INTERNERS.get(interner_name)
    if interner:
        # Only return existing IDs during filtering
        return interner.str_to_id.get(s) # Return None if string wasn't seen during load
    logger.warning(f"Interner '{interner_name}' not found during ID lookup.")
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
    # Check LOADED_EVENTS is not None (even if empty) and other required globals
    if LOADED_EVENTS is None or LOADED_PROCESSES is None or not LOADED_FILENAME or LOADED_FILE_TYPE != 'xml':
        await ctx.error("No Procmon XML file data was successfully pre-loaded via --load-file.")
        raise RuntimeError("Operation failed: No Procmon file data is loaded.")

    summary = {
        "loaded_filename": LOADED_FILENAME, "file_type": LOADED_FILE_TYPE,
        "compression": LOADED_COMPRESSION,
        "process_count": len(LOADED_PROCESSES),
        "event_count": len(LOADED_EVENTS), # Should be correct now
        "os_version": "N/A (XML)", "computer_name": "N/A (XML)", "is_64bit_os": None # XML doesn't typically contain OS header info
    }
    try:
        # Add interner stats for context
        summary["interner_stats"] = {name: interner.next_id for name, interner in GLOBAL_INTERNERS.items()}
        # Add index stats
        summary["index_stats"] = {
            "pid_indexed_count": len(PID_INDEX),
            "op_indexed_count": len(OP_INDEX),
        }
        await ctx.info(f"Successfully generated summary for {LOADED_FILENAME}.")
        return summary
    except Exception as e:
        await ctx.error(f"Error generating summary for {LOADED_FILENAME}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error generating summary: {e}")

# --- UPDATED: Query Events with Indexing ---
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
    Uses indices for Process Name and Operation filters if available.
    Returns event summaries including the event index. Use 'get_event_details'/'get_event_stack_trace' with index.

    Filtering Behavior:
    - All provided filters must match (AND logic).
    - String contains filters are case-insensitive. Exact match filters (process, op, result) use the interned IDs.
    - Result filter handles hex ('0x...') or case-insensitive string matching before ID lookup.
    - Time filters accept HH:MM:SS.ffffff strings (parsed to time relative to an arbitrary date) or float Unix timestamps.
      WARNING: Time-only string filters ignore the date and assume events don't cross midnight relative to the base date used during loading. Full timestamps or Unix floats are recommended.
    - Regex filters apply to the original string values (requires ID lookup). WARNING: Can impact performance.
    - Stack module filter checks original string paths in stack frames. WARNING: Very performance intensive.

    Args:
        filter_process: Exact process name (case-sensitive for ID lookup). Uses index.
        filter_operation: Exact operation name (case-sensitive for ID lookup). Uses index.
        filter_result: Exact result string or hex '0x...' code (case-sensitive for ID lookup).
        filter_path_contains: Substring in path (case-insensitive).
        filter_process_contains: Substring in process name (case-insensitive).
        filter_start_time: Minimum event time (float Unix timestamp or HH:MM:SS.ffffff string).
        filter_end_time: Maximum event time (float Unix timestamp or HH:MM:SS.ffffff string).
        filter_path_regex: Regex pattern for Path field (case-insensitive).
        filter_process_regex: Regex pattern for Process Name field (case-insensitive).
        filter_detail_regex: Regex pattern for Detail field (case-insensitive).
        filter_stack_module_path: Substring in any stack frame's module path (case-insensitive). VERY SLOW.
        limit: Maximum number of event summaries to return.

    Returns:
        List of dictionaries, each summarizing a matching event including 'event_index'.
    """
    await ctx.info(f"Request received to query in-memory events with multiple filters. Limit={limit}")
    filters_applied = {k:v for k,v in locals().items() if k.startswith('filter_') and v is not None}
    if filters_applied: logger.debug(f"Filters Applied: {filters_applied}")
    else: logger.debug("No filters applied.")


    if LOADED_EVENTS is None or LOADED_PROCESSES is None or not GLOBAL_INTERNERS:
        await ctx.error(f"Query failed: Event data or interners not loaded.")
        raise TypeError("Operation requires optimized event data to be loaded.")

    # Handle case where there are no events to query
    if not LOADED_EVENTS:
         await ctx.info("Query finished: No events loaded in memory to query.")
         return []

    try:
        filtered_event_summaries = []
        count = 0
        start_time = time.time() # For timing

        # --- Pre-process Filters ---
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
                    start_ts = (parsed_time_obj.hour * 3600 + parsed_time_obj.minute * 60 +
                                parsed_time_obj.second + parsed_time_obj.microsecond / 1e6)
                    is_start_time_only = True
                    logger.warning("Using time-only string filter for start_time. Comparison ignores date.")
                except ValueError:
                    try: start_ts = float(filter_start_time)
                    except ValueError: raise ValueError(f"Invalid start_time format: '{filter_start_time}'. Use float timestamp or HH:MM:SS.ffffff.")
            elif isinstance(filter_start_time, (int, float)):
                start_ts = float(filter_start_time)

            if isinstance(filter_end_time, str):
                 try:
                    parsed_time_obj = datetime.strptime(filter_end_time, PROCMON_TIMESTAMP_FORMAT).time()
                    end_ts = (parsed_time_obj.hour * 3600 + parsed_time_obj.minute * 60 +
                              parsed_time_obj.second + parsed_time_obj.microsecond / 1e6)
                    is_end_time_only = True
                    logger.warning("Using time-only string filter for end_time. Comparison ignores date.")
                 except ValueError:
                    try: end_ts = float(filter_end_time)
                    except ValueError: raise ValueError(f"Invalid end_time format: '{filter_end_time}'. Use float timestamp or HH:MM:SS.ffffff.")
            elif isinstance(filter_end_time, (int, float)):
                end_ts = float(filter_end_time)

        except ValueError as e:
            await ctx.error(f"Invalid time format for filter: {e}")
            raise ValueError("Invalid time format for filter.") from e

        # Get IDs for exact match filters (case-sensitive lookup in interner)
        process_id_filter = get_id("process_name", filter_process) if filter_process else None
        operation_id_filter = get_id("operation", filter_operation) if filter_operation else None
        result_id_filter = get_id("result", filter_result) if filter_result else None

        # Lowercase for contains filters
        filter_path_contains_lower = filter_path_contains.lower() if filter_path_contains else None
        filter_process_contains_lower = filter_process_contains.lower() if filter_process_contains else None
        filter_stack_module_path_lower = filter_stack_module_path.lower() if filter_stack_module_path else None

        # --- *** Indexing Logic *** ---
        candidate_indices: Optional[Set[int]] = None # Start with None (meaning all events)

        # Apply PID index
        if process_id_filter is not None:
            pid_indices = set(PID_INDEX.get(process_id_filter, []))
            logger.debug(f"Found {len(pid_indices)} candidate indices for PID filter.")
            if candidate_indices is None:
                candidate_indices = pid_indices
            else:
                candidate_indices.intersection_update(pid_indices)
            if not candidate_indices: # Early exit if intersection is empty
                await ctx.info(f"Query finished early: No events match PID filter '{filter_process}'.")
                return []

        # Apply Operation index
        if operation_id_filter is not None:
            op_indices = set(OP_INDEX.get(operation_id_filter, []))
            logger.debug(f"Found {len(op_indices)} candidate indices for Operation filter.")
            if candidate_indices is None:
                candidate_indices = op_indices
            else:
                candidate_indices.intersection_update(op_indices)
            if not candidate_indices: # Early exit if intersection is empty
                await ctx.info(f"Query finished early: No events match Operation filter '{filter_operation}'.")
                return []

        # Determine iterator: either all events or only indexed candidates
        if candidate_indices is not None:
            logger.info(f"Using index. Querying {len(candidate_indices):,} candidate events.")
            # Sort indices to process events somewhat chronologically (optional but nice)
            indices_to_check = sorted(list(candidate_indices))
            event_iterator = ((idx, LOADED_EVENTS[idx]) for idx in indices_to_check)
            total_to_scan = len(indices_to_check)
        else:
            logger.info("No index applicable. Querying all events.")
            event_iterator = enumerate(LOADED_EVENTS) # Default: iterate all
            total_to_scan = len(LOADED_EVENTS)
        # --- *** End Indexing Logic *** ---


        # --- Iterate and Filter (potentially reduced set) ---
        processed_count = 0
        last_progress_report_time = start_time

        for idx, event_dict in event_iterator: # Use the chosen iterator
            processed_count += 1
            # --- Add progress reporting within the query itself for long queries ---
            current_time = time.time()
            # Adjust progress report frequency based on total_to_scan
            report_interval = max(10000, total_to_scan // 10) # Report roughly 10 times or every 10k
            if processed_count % report_interval == 0 or (current_time - last_progress_report_time > 10.0):
                try:
                    elapsed = current_time - start_time
                    await ctx.info(f" Query scanned {processed_count:,}/{total_to_scan:,} candidate events... ({elapsed:.1f}s)")
                    last_progress_report_time = current_time
                except Exception as progress_err:
                    logger.warning(f"Failed to send progress update during query: {progress_err}")

            if count >= limit: break # Stop if limit reached

            match = True # Assume match until a filter fails

            # --- Apply Remaining Filters ---
            # Skip indexed filters if already applied
            if candidate_indices is not None:
                if process_id_filter is not None and event_dict.get('pname_id') != process_id_filter: continue # Should not happen if index logic is correct
                if operation_id_filter is not None and event_dict.get('op_id') != operation_id_filter: continue # Should not happen

            # Apply non-indexed exact match filters
            if match and result_id_filter is not None and event_dict.get('res_id') != result_id_filter: match = False

            # Time Filter (using float timestamp) - apply to remaining candidates
            if match and (start_ts is not None or end_ts is not None):
                event_ts_float = event_dict.get('ts')
                if event_ts_float is None:
                    match = False
                else:
                    current_event_compare_val = event_ts_float
                    if is_start_time_only or is_end_time_only:
                        try:
                           event_dt_obj = datetime.fromtimestamp(event_ts_float, timezone.utc)
                           current_event_compare_val = (event_dt_obj.hour * 3600 + event_dt_obj.minute * 60 +
                                                        event_dt_obj.second + event_dt_obj.microsecond / 1e6)
                        except Exception:
                            match = False
                            logger.warning(f"Could not extract time part from event timestamp {event_ts_float}")

                    if match and start_ts is not None:
                        compare_filter_val = start_ts if (is_start_time_only or is_end_time_only) else start_ts
                        if current_event_compare_val < compare_filter_val: match = False
                    if match and end_ts is not None:
                        compare_filter_val = end_ts if (is_start_time_only or is_end_time_only) else end_ts
                        if current_event_compare_val > compare_filter_val: match = False


            # Contains / Regex / Stack filters require converting IDs back to strings
            if match and (filter_path_contains_lower or filter_process_contains_lower or path_regex or process_regex or detail_regex or filter_stack_module_path_lower):
                path_str = ""
                pname_str = ""
                detail_str = event_dict.get('detail') or ""

                if filter_path_contains_lower or path_regex:
                    path_str = get_string("path", event_dict.get('path_id')) or ""
                if filter_process_contains_lower or process_regex:
                    pname_str = get_string("process_name", event_dict.get('pname_id')) or ""

                if match and filter_path_contains_lower and filter_path_contains_lower not in path_str.lower(): match = False
                if match and filter_process_contains_lower and filter_process_contains_lower not in pname_str.lower(): match = False
                if match and path_regex and not path_regex.search(path_str): match = False
                if match and process_regex and not process_regex.search(pname_str): match = False
                if match and detail_regex and not detail_regex.search(detail_str): match = False

                if match and filter_stack_module_path_lower:
                    if not LOAD_STACK_TRACES: # Check if stacks were loaded
                        await ctx.warning("Stack trace filtering requested, but stack traces were not loaded (--no-stack-traces). Filter skipped.")
                        match = True # Don't filter out if stacks aren't available
                    else:
                        stack_list_optimized = event_dict.get('stack')
                        found_in_stack = False
                        if stack_list_optimized:
                            for frame_list in stack_list_optimized:
                                if len(frame_list) > 2 and frame_list[2] is not None:
                                    frame_path_str = get_string("stack_path", frame_list[2])
                                    if frame_path_str and filter_stack_module_path_lower in frame_path_str.lower():
                                        found_in_stack = True
                                        break
                        if not found_in_stack: match = False

            # --- Add to results if all filters passed ---
            if match:
                try:
                    ts_display = datetime.fromtimestamp(event_dict['ts'], timezone.utc).strftime(PROCMON_TIMESTAMP_FORMAT) if event_dict.get('ts') else None
                except Exception:
                    ts_display = "<Invalid Timestamp>"

                event_summary = {
                    'event_index': idx, # Use list index
                    'sequence_number': event_dict.get('seq'), # Will be None if missing in source
                    'timestamp': ts_display,
                    'process_name': get_string("process_name", event_dict.get('pname_id')),
                    'pid': event_dict.get('pid'),
                    'operation': get_string("operation", event_dict.get('op_id')),
                    'path': get_string("path", event_dict.get('path_id')),
                    'result': get_string("result", event_dict.get('res_id')),
                }
                filtered_event_summaries.append(event_summary)
                count += 1

        elapsed = time.time() - start_time
        await ctx.info(f"Query finished in {elapsed:.2f}s. Found {len(filtered_event_summaries)} matching events (limit {limit}).")
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
    Includes 'extra_data' field if unknown fields were captured during loading.

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
        # Validate index bounds using the actual length of LOADED_EVENTS
        num_events = len(LOADED_EVENTS)
        if not 0 <= event_index < num_events:
            # Correct the error message if num_events is 0
            upper_bound = num_events - 1 if num_events > 0 else -1
            await ctx.error(f"Invalid event index: {event_index}. Must be between 0 and {upper_bound}.")
            raise IndexError(f"Event index {event_index} is out of bounds.")

        event_dict = LOADED_EVENTS[event_index] # Get the optimized event dict

        # Convert optimized dict back to a more user-friendly format
        details: Dict[str, Any] = {}
        details['event_index'] = event_index
        details['sequence_number'] = event_dict.get('seq') # Will be None if missing in source
        details['pid'] = event_dict.get('pid')
        details['tid'] = event_dict.get('tid')
        details['parent_pid'] = event_dict.get('ppid') # Get ParentPID stored during optimization
        details['duration'] = event_dict.get('dur') # Duration stored as float
        details['detail'] = event_dict.get('detail') # Detail stored directly

        # Format timestamp
        ts_float = event_dict.get('ts')
        try:
            details['timestamp'] = datetime.fromtimestamp(ts_float, timezone.utc).strftime(PROCMON_TIMESTAMP_FORMAT) if ts_float else None
        except Exception:
             details['timestamp'] = "<Invalid Timestamp>"
        details['timestamp_unix'] = ts_float # Also include raw float timestamp

        # Convert IDs back to strings using helpers
        details['operation'] = get_string("operation", event_dict.get('op_id'))
        details['path'] = get_string("path", event_dict.get('path_id'))
        details['result'] = get_string("result", event_dict.get('res_id'))
        details['category'] = get_string("category", event_dict.get('cat_id'))
        details['process_name'] = get_string("process_name", event_dict.get('pname_id'))

        # *** ADDED: Include extra_data if present ***
        if 'extra_data' in event_dict:
            details['extra_data'] = event_dict['extra_data']

        # Add enriched process info by looking up process object via PID
        # This requires iterating the process list as it's keyed by ProcessIndex
        process_obj: Optional[ProcessInfo] = None
        pid_to_find = details.get('pid')
        if pid_to_find is not None and LOADED_PROCESSES:
            # Find the process object using PID.
            for proc_info in LOADED_PROCESSES.values():
                if proc_info.pid == pid_to_find:
                    process_obj = proc_info
                    break # Found it

        if process_obj:
            # Create a summary dict from the ProcessInfo dataclass
            proc_details_dict = dataclasses.asdict(process_obj)
            # Remove potentially redundant or internal fields if desired
            proc_details_dict.pop('process_index', None)
            proc_details_dict.pop('parent_process_index', None)
            details['process_details_summary'] = proc_details_dict
            # Ensure top-level fields are consistently populated from process obj if available
            details['user_sid'] = process_obj.owner # user_sid alias for owner
            details['is_64bit_process'] = process_obj.is_64bit
            # Overwrite parent_pid if available in process list (might be more reliable)
            if process_obj.parent_pid is not None: details['parent_pid'] = process_obj.parent_pid
            # Overwrite process_name if available (should match interned one)
            if process_obj.process_name is not None: details['process_name'] = process_obj.process_name
        else:
            # Simplified info if process not found in list (e.g., process terminated before list snapshot)
            details['process_details_summary'] = {"pid": details['pid'], "process_name": details['process_name'], "message": "Process details not found in <processlist>."}
            details['user_sid'] = None
            details['is_64bit_process'] = None
            # Keep parent_pid obtained from the event itself (or None) if process lookup failed

        # Note: We don't store all original fields in the optimized dict (e.g., completion_time, relative_time)
        # These fields are often absent or less useful in XML anyway
        details['completion_time'] = None
        details['relative_time'] = None


        await ctx.info(f"Successfully retrieved details for event index {event_index}.")
        return details

    except IndexError as e:
        # Logged and raised by the check above
        raise e
    except Exception as e:
        await ctx.error(f"Failed to get details for event {event_index}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving event details: {e}")

@tool_decorator
async def get_event_stack_trace(event_index: int, ctx: Context) -> List[Dict[str, Any]]:
    """
    Retrieves the detailed call stack trace for a specific event from the optimized in-memory data,
    referenced by its list index. Returns empty list if stack not loaded or not present.

    Args:
        event_index: The zero-based index of the event.

    Returns:
        A list of dictionaries representing stack frames ('depth', 'address', 'path', 'location').
        Returns an empty list if the event has no stack trace or if stacks were not loaded.
    """
    await ctx.info(f"Request received for stack trace of event index: {event_index}")
    if LOADED_EVENTS is None or not GLOBAL_INTERNERS:
        await ctx.error(f"Get stack trace failed: Event data or interners not loaded.")
        raise TypeError("Operation requires optimized event data to be loaded.")

    # Check if stack traces were loaded
    if not LOAD_STACK_TRACES:
        await ctx.warning("Stack traces were not loaded (--no-stack-traces). Returning empty list.")
        return []

    try:
        # Validate index bounds
        num_events = len(LOADED_EVENTS)
        if not 0 <= event_index < num_events:
            upper_bound = num_events - 1 if num_events > 0 else -1
            await ctx.error(f"Invalid event index: {event_index}. Must be between 0 and {upper_bound}.")
            raise IndexError(f"Event index {event_index} is out of bounds.")

        event_dict = LOADED_EVENTS[event_index]
        # Retrieve the list of optimized frames: [[depth, addr, path_id, loc_id], ...]
        stack_list_optimized = event_dict.get('stack') # Will be None if not present or not loaded

        detailed_stack = []
        if stack_list_optimized:
            for frame_data in stack_list_optimized:
                try:
                    # Ensure frame_data is a list/tuple with expected elements
                    if not isinstance(frame_data, (list, tuple)) or len(frame_data) < 4:
                         logger.warning(f"Malformed optimized stack frame data encountered for event index {event_index}: {frame_data}")
                         continue # Skip this malformed frame

                    # Reconstruct StackFrame dict by looking up interned strings
                    frame_dict = {
                        'depth': frame_data[0],
                        'address': frame_data[1], # Address stored directly as string
                        'path': get_string("stack_path", frame_data[2]),
                        'location': get_string("stack_location", frame_data[3])
                    }
                    detailed_stack.append(frame_dict)
                except IndexError:
                    # This shouldn't happen with the length check, but belt-and-suspenders
                    logger.warning(f"IndexError processing optimized stack frame for event index {event_index}: {frame_data}")
                    continue # Skip malformed frame
                except Exception as frame_e:
                     logger.warning(f"Unexpected error processing stack frame for event index {event_index}: {frame_e}", exc_info=False)
                     continue # Skip frame on other errors

        await ctx.info(f"Successfully retrieved stack trace (length: {len(detailed_stack)}) for event index {event_index}.")
        return detailed_stack

    except IndexError as e:
        # Logged and raised by the check above
        raise e
    except Exception as e:
        await ctx.error(f"Failed to get stack trace for event {event_index}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving event stack trace: {e}")

# --- Tools operating on LOADED_PROCESSES ---
@tool_decorator
async def list_processes(ctx: Context) -> List[Dict[str, Any]]:
    """ Lists summary info (pid, process_name, image_path, parent_pid) from the loaded process list. """
    await ctx.info(f"Request received to list processes from pre-loaded process list.")
    if LOADED_PROCESSES is None:
        await ctx.error(f"List processes failed: Process list not loaded.")
        raise TypeError("Operation requires an XML file's process list to be pre-loaded.")
    try:
        process_list = list(LOADED_PROCESSES.values()) # Get ProcessInfo objects
        process_summaries = []
        # Use properties defined in ProcessInfo for consistency
        summary_attributes = ['pid', 'process_name', 'image_path', 'parent_pid']
        for process_obj in process_list:
            summary = {attr: getattr(process_obj, attr, None) for attr in summary_attributes}
            if summary.get('pid') is None: continue # Skip if PID is missing somehow
            process_summaries.append(summary)
        # Sort by PID for better readability
        process_summaries.sort(key=lambda x: x.get('pid') or 0)
        await ctx.info(f"Generated {len(process_summaries)} process summaries.")
        return process_summaries
    except Exception as e:
        await ctx.error(f"Failed to list processes from loaded data: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error listing processes: {e}")

@tool_decorator
async def get_process_details(pid: int, ctx: Context) -> Dict[str, Any]:
    """ Retrieves detailed info for a specific PID from the loaded process list. """
    await ctx.info(f"Request received for details of PID: {pid} from loaded process list.")
    if LOADED_PROCESSES is None:
        await ctx.error(f"Get process details failed: Process list not loaded.")
        raise TypeError("Operation requires an XML file's process list to be pre-loaded.")
    try:
        process_obj: Optional[ProcessInfo] = None
        # Iterate through the values (ProcessInfo objects) of the loaded dictionary
        for proc in LOADED_PROCESSES.values():
            if proc.pid == pid:
                process_obj = proc
                break # Found the process
        if not process_obj:
            raise ValueError(f"Process with PID {pid} not found in pre-loaded list.")

        # Convert dataclass to dict for output
        details = dataclasses.asdict(process_obj)
        # Clean up internal/redundant fields that might confuse the user
        details.pop('process_index', None)
        details.pop('parent_process_index', None)
        # Add aliased properties for clarity if needed (already present via dataclass conversion)
        # details['pid'] = process_obj.pid # Already present
        # details['parent_pid'] = process_obj.parent_pid # Already present
        # details['user_sid'] = process_obj.user_sid # Already present as 'owner'
        details['modules_summary'] = "N/A (Module info not typically in XML process list)" # Clarify modules aren't present
        await ctx.info(f"Successfully retrieved details for PID {pid}.")
        return details
    except ValueError as e:
        await ctx.error(str(e))
        raise e # Re-raise specific error
    except Exception as e:
        await ctx.error(f"Failed to get details for PID {pid}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving process details: {e}")

@tool_decorator
async def get_metadata(ctx: Context) -> Dict[str, Any]:
    """ Retrieves metadata for the loaded XML file. """
    await ctx.info(f"Request received for metadata from XML file.")
    # Check that loading completed, even if event list is empty
    if LOADED_EVENTS is None or LOADED_PROCESSES is None or not LOADED_FILENAME:
        await ctx.error(f"Get metadata failed: Data not fully loaded.")
        raise TypeError("Operation requires file data to be pre-loaded.")
    try:
        metadata = {
            "loaded_filename": LOADED_FILENAME, "file_type": LOADED_FILE_TYPE,
            "compression": LOADED_COMPRESSION, "header_found": False, # XML doesn't have a PML header
            "message": "Standard OS/Header info N/A for XML format.",
            "os_version": None, "computer_name": None,
            "process_count_loaded": len(LOADED_PROCESSES),
            "event_count_loaded": len(LOADED_EVENTS) # Now available and correct
        }
        await ctx.info(f"Successfully retrieved metadata from {LOADED_FILENAME}.")
        return metadata
    except Exception as e:
        await ctx.error(f"Failed to get metadata: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving metadata: {e}")


# --- Analysis Tools (Operating on In-Memory Optimized Data) ---

@tool_decorator
async def count_events_by_process(ctx: Context) -> Dict[str, int]:
    """ Counts events per process name from the loaded in-memory data. """
    await ctx.info(f"Request received to count events by process name (in-memory).")
    if LOADED_EVENTS is None or not GLOBAL_INTERNERS:
        await ctx.error("Operation failed: Optimized event data not loaded.")
        raise TypeError("Operation requires optimized event data to be loaded.")

    # Handle case where there are no events
    if not LOADED_EVENTS:
        await ctx.info("Count events by process: No events loaded.")
        return {}

    try:
        event_counts = defaultdict(int)
        start_time = time.time()
        total_events = len(LOADED_EVENTS)
        last_progress_report_time = start_time

        for i, event_dict in enumerate(LOADED_EVENTS):
            # Progress reporting for potentially long loops on huge datasets
            current_time = time.time()
            if i > 0 and (i % (PROGRESS_REPORT_INTERVAL * 4) == 0 or (current_time - last_progress_report_time > 15.0)): # Report less often or every 15s
                elapsed = current_time - start_time
                try:
                    await ctx.info(f" Counting... processed {i:,}/{total_events:,} events ({elapsed:.1f}s)")
                    last_progress_report_time = current_time
                except Exception as progress_err:
                    logger.warning(f"Failed to send progress update during count: {progress_err}")

            # Lookup process name using the interned ID
            process_name = get_string("process_name", event_dict.get('pname_id')) or 'Unknown/Missing PID'
            event_counts[process_name] += 1

        elapsed = time.time() - start_time
        # Sort results by count descending for better presentation
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
    if LOADED_EVENTS is None or not GLOBAL_INTERNERS:
        await ctx.error("Operation failed: Optimized event data not loaded.")
        raise TypeError("Operation requires optimized event data to be loaded.")
    if not process_name_filter:
        await ctx.error("Process name filter cannot be empty."); raise ValueError("Process name filter is required.")

    # Handle case where there are no events
    if not LOADED_EVENTS:
        await ctx.info(f"Summarize operations for '{process_name_filter}': No events loaded.")
        return {}

    try:
        operation_counts = defaultdict(int)
        event_count_for_process = 0
        start_time = time.time()
        total_events = len(LOADED_EVENTS)
        last_progress_report_time = start_time

        # Get the target process ID only once using the interner (case-sensitive)
        target_pname_id = get_id("process_name", process_name_filter)
        if target_pname_id is None:
            # If the process name wasn't seen during load, it won't have an ID
            await ctx.warning(f"Process name '{process_name_filter}' not found in loaded data (check exact name/case). No events will match.")
            return {} # Return empty dict as no events can match

        # Use index if available
        indices_to_check = PID_INDEX.get(target_pname_id)
        if indices_to_check is None: # Process name existed but had 0 events (unlikely but possible)
             await ctx.warning(f"No events found matching process name '{process_name_filter}' (ID: {target_pname_id}).")
             return {}

        await ctx.info(f"Summarizing operations for {len(indices_to_check):,} events matching '{process_name_filter}'...")

        for i, idx in enumerate(indices_to_check):
            # Progress reporting
            current_time = time.time()
            if i > 0 and (i % (PROGRESS_REPORT_INTERVAL * 4) == 0 or (current_time - last_progress_report_time > 15.0)):
                elapsed = current_time - start_time
                try:
                    await ctx.info(f" Summarizing '{process_name_filter}'... processed {i:,}/{len(indices_to_check):,} matching events ({elapsed:.1f}s)")
                    last_progress_report_time = current_time
                except Exception as progress_err:
                    logger.warning(f"Failed to send progress update during summarize: {progress_err}")

            event_dict = LOADED_EVENTS[idx]
            event_count_for_process += 1 # Count events actually processed for this PID
            # Lookup operation string using the interned ID
            operation = get_string("operation", event_dict.get('op_id')) or 'Unknown'
            operation_counts[operation] += 1

        elapsed = time.time() - start_time
        # Sort results by count descending
        sorted_counts = dict(sorted(operation_counts.items(), key=lambda item: item[1], reverse=True))
        await ctx.info(f"Summarized {len(sorted_counts)} unique ops for '{process_name_filter}' ({event_count_for_process:,} events found) ({elapsed:.2f}s).")

        return sorted_counts

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
    grouped by either process name or operation type. Only includes events with a duration > 0.

    Args:
        group_by: 'process' (default) or 'operation'.

    Returns:
        Dictionary where keys are group names (process or operation) and values are
        dictionaries containing 'count', 'min_duration', 'max_duration', 'avg_duration',
        'total_duration'. Sorted by count descending.
    """
    await ctx.info(f"Request received to calculate timing statistics grouped by '{group_by}' (in-memory).")
    if group_by not in ["process", "operation"]:
        await ctx.error("Invalid group_by value. Must be 'process' or 'operation'."); raise ValueError("Invalid group_by value.")
    if LOADED_EVENTS is None or not GLOBAL_INTERNERS:
        await ctx.error("Operation failed: Optimized event data not loaded.")
        raise TypeError("Operation requires optimized event data to be loaded.")

    # Handle case where there are no events
    if not LOADED_EVENTS:
        await ctx.info(f"Get timing statistics grouped by '{group_by}': No events loaded.")
        return {}

    try:
        # Use defaultdict to store intermediate sums and counts
        # Structure: { group_key: {'min': float, 'max': float, 'sum': float, 'count': int} }
        stats = defaultdict(lambda: {'min': float('inf'), 'max': float('-inf'), 'sum': 0.0, 'count': 0})
        total_events = len(LOADED_EVENTS)
        start_time = time.time()
        events_with_duration = 0
        last_progress_report_time = start_time

        for i, event_dict in enumerate(LOADED_EVENTS):
            # Progress reporting
            current_time = time.time()
            if i > 0 and (i % (PROGRESS_REPORT_INTERVAL * 4) == 0 or (current_time - last_progress_report_time > 15.0)):
                elapsed = current_time - start_time
                try:
                    await ctx.info(f" Calculating stats... processed {i:,}/{total_events:,} events ({elapsed:.1f}s)")
                    last_progress_report_time = current_time
                except Exception as progress_err:
                    logger.warning(f"Failed to send progress update during timing stats: {progress_err}")

            # Get duration (stored as float)
            duration = event_dict.get('dur')
            # Only include events with a positive duration for statistics
            if duration is None or duration <= 0: continue
            events_with_duration += 1

            # Determine the grouping key based on user choice
            group_key_id = event_dict.get('pname_id') if group_by == "process" else event_dict.get('op_id')
            interner_name = "process_name" if group_by == "process" else "operation"
            # Lookup the string representation of the group key
            group_key = get_string(interner_name, group_key_id) or 'Unknown/Missing ID'

            # Update statistics for this group
            group_stats = stats[group_key]
            group_stats['count'] += 1
            group_stats['sum'] += duration
            if duration < group_stats['min']: group_stats['min'] = duration
            if duration > group_stats['max']: group_stats['max'] = duration

        # Calculate averages and format output into a list for sorting
        output_stats_list = []
        for key, data in stats.items():
            if data['count'] > 0: # Should always be true if duration > 0 check passed
                avg = data['sum'] / data['count']
                output_stats_list.append(
                    {
                    'group': key, # Keep group name for sorting
                    'count': data['count'],
                    'min_duration': data['min'] if data['min'] != float('inf') else None, # Handle case where min wasn't updated
                    'max_duration': data['max'] if data['max'] != float('-inf') else None, # Handle case where max wasn't updated
                    'avg_duration': avg,
                    'total_duration': data['sum']
                    }
                )

        # Sort results by count descending
        output_stats_list.sort(key=lambda x: x['count'], reverse=True)

        # Convert sorted list back to dict for final output, preserving order (Python 3.7+)
        final_output_stats = {item['group']: {k: v for k, v in item.items() if k != 'group'} for item in output_stats_list}


        elapsed = time.time() - start_time
        await ctx.info(f"Calculated timing statistics for {len(final_output_stats)} groups based on {events_with_duration:,} events with duration > 0 ({elapsed:.2f}s).")
        return final_output_stats

    except Exception as e:
        await ctx.error(f"Failed to calculate timing statistics: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error calculating timing statistics: {e}")

# --- *** NEW Analysis Tools *** ---

@tool_decorator
async def get_process_lifetime(pid: int, ctx: Context) -> Dict[str, Optional[float]]:
    """
    Finds the 'Process Create' and 'Process Exit' event timestamps for a given PID.

    Args:
        pid: The Process ID to query.

    Returns:
        A dictionary with 'create_timestamp' and 'exit_timestamp' (Unix float timestamp or None).
    """
    await ctx.info(f"Request received for lifetime of PID: {pid}")
    if LOADED_EVENTS is None or not GLOBAL_INTERNERS:
        await ctx.error("Operation failed: Event data not loaded.")
        raise TypeError("Operation requires event data to be loaded.")

    create_ts: Optional[float] = None
    exit_ts: Optional[float] = None

    # Get interned IDs for operations
    create_op_id = get_id("operation", OP_PROCESS_CREATE)
    exit_op_id = get_id("operation", OP_PROCESS_EXIT)

    if create_op_id is None: logger.warning(f"Operation '{OP_PROCESS_CREATE}' not found in interner.")
    if exit_op_id is None: logger.warning(f"Operation '{OP_PROCESS_EXIT}' not found in interner.")

    # Iterate through events to find the relevant ones
    # This assumes the event list is chronologically ordered (which it should be from iterparse)
    for event_dict in LOADED_EVENTS:
        if event_dict.get('pid') == pid:
            op_id = event_dict.get('op_id')
            if op_id == create_op_id and create_ts is None: # Find first create
                create_ts = event_dict.get('ts')
            elif op_id == exit_op_id: # Find last exit
                exit_ts = event_dict.get('ts')

            # Optimization: if both found, can potentially stop early, but finding *last* exit requires full scan
            # if create_ts is not None and exit_ts is not None: break

    result = {"create_timestamp": create_ts, "exit_timestamp": exit_ts}
    await ctx.info(f"Found lifetime for PID {pid}: {result}")
    return result

@tool_decorator
async def find_file_access(path_contains: str, limit: int = 100, *, ctx: Context) -> List[Dict[str, Any]]:
    """
    Finds events related to file system access where the path contains the given substring.

    Args:
        path_contains: Substring to search for in the event path (case-insensitive).
        limit: Maximum number of matching events to return.

    Returns:
        List of event summaries (index, timestamp, process, pid, operation, path, result).
    """
    await ctx.info(f"Request received to find file access containing: '{path_contains}' (limit={limit})")
    if LOADED_EVENTS is None or not GLOBAL_INTERNERS:
        await ctx.error("Operation failed: Event data not loaded.")
        raise TypeError("Operation requires event data to be loaded.")
    if not path_contains:
        await ctx.error("path_contains filter cannot be empty."); raise ValueError("path_contains filter is required.")

    found_events = []
    count = 0
    path_contains_lower = path_contains.lower()

    for idx, event_dict in enumerate(LOADED_EVENTS):
        if count >= limit: break

        path_id = event_dict.get('path_id')
        if path_id is not None:
            path_str = get_string("path", path_id)
            if path_str and path_contains_lower in path_str.lower():
                try:
                    ts_display = datetime.fromtimestamp(event_dict['ts'], timezone.utc).strftime(PROCMON_TIMESTAMP_FORMAT) if event_dict.get('ts') else None
                except Exception: ts_display = "<Invalid Timestamp>"

                summary = {
                    'event_index': idx,
                    'timestamp': ts_display,
                    'process_name': get_string("process_name", event_dict.get('pname_id')),
                    'pid': event_dict.get('pid'),
                    'operation': get_string("operation", event_dict.get('op_id')),
                    'path': path_str, # Already have the string
                    'result': get_string("result", event_dict.get('res_id')),
                }
                found_events.append(summary)
                count += 1

    await ctx.info(f"Found {len(found_events)} file access events matching '{path_contains}' (limit {limit}).")
    return found_events

@tool_decorator
async def find_network_connections(process_name: str, *, ctx: Context) -> List[str]:
    """
    Finds unique remote network endpoints (IP:port) accessed by a specific process.
    Looks for TCP Connect, TCP Send/Receive, UDP Send/Receive operations.

    Args:
        process_name: The exact name of the process (case-sensitive).

    Returns:
        A sorted list of unique remote endpoint strings (e.g., "192.168.1.100:443").
    """
    await ctx.info(f"Request received to find network connections for process: '{process_name}'")
    if LOADED_EVENTS is None or not GLOBAL_INTERNERS:
        await ctx.error("Operation failed: Event data not loaded.")
        raise TypeError("Operation requires event data to be loaded.")
    if not process_name:
        await ctx.error("process_name filter cannot be empty."); raise ValueError("process_name filter is required.")

    remote_endpoints = set()
    target_pname_id = get_id("process_name", process_name)
    network_op_ids = {get_id("operation", op) for op in NETWORK_OPERATIONS if get_id("operation", op) is not None}

    if target_pname_id is None:
        await ctx.warning(f"Process name '{process_name}' not found in loaded data. Returning empty list.")
        return []
    if not network_op_ids:
        await ctx.warning(f"Could not find standard network operations in interner. Returning empty list.")
        return []

    # Use PID index for efficiency
    indices_to_check = PID_INDEX.get(target_pname_id, [])
    if not indices_to_check:
         await ctx.info(f"No events found for process '{process_name}'.")
         return []

    await ctx.info(f"Scanning {len(indices_to_check):,} events for process '{process_name}' for network activity...")

    # Regex to extract remote endpoint (IP:port) from Path like "local:port -> remote:port"
    # Handles both IPv4 and IPv6 (within brackets)
    endpoint_regex = re.compile(r".* -> \[?([a-fA-F0-9:.]+)\]?:(\d+)")

    processed_count = 0
    start_time = time.time()
    last_progress_report_time = start_time

    for idx in indices_to_check:
        processed_count += 1
        event_dict = LOADED_EVENTS[idx]
        op_id = event_dict.get('op_id')

        if op_id in network_op_ids:
            path_str = get_string("path", event_dict.get('path_id'))
            if path_str:
                match = endpoint_regex.match(path_str)
                if match:
                    ip = match.group(1)
                    port = match.group(2)
                    remote_endpoints.add(f"{ip}:{port}")

        # Progress reporting
        current_time = time.time()
        if processed_count % 50000 == 0 or (current_time - last_progress_report_time > 10.0):
             elapsed = current_time - start_time
             try: await ctx.info(f" Network scan progress: {processed_count:,}/{len(indices_to_check):,} events checked ({elapsed:.1f}s)")
             except Exception: pass # Ignore errors sending progress
             last_progress_report_time = current_time


    sorted_endpoints = sorted(list(remote_endpoints))
    await ctx.info(f"Found {len(sorted_endpoints)} unique remote network endpoints for '{process_name}'.")
    return sorted_endpoints

# --- *** NEW Export Tool *** ---
@tool_decorator
async def export_query_results(
    output_file: str,
    output_format: str = 'csv', # 'csv' or 'json'
    # Filters (same as query_events)
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
    *,
    ctx: Context
) -> Dict[str, Any]:
    """
    Queries events using the specified filters and exports the full details
    of matching events to a file (CSV or JSON).

    Args:
        output_file: The name of the output file (relative to the allowed directory).
        output_format: The desired output format ('csv' or 'json', default 'csv').
        filter_*: Same filters as the 'query_events' tool. Limit is ignored.

    Returns:
        A dictionary indicating success, the output path, and the number of events exported.
    """
    await ctx.info(f"Request received to export events to '{output_file}' in {output_format} format.")
    if output_format.lower() not in ['csv', 'json']:
        raise ValueError("Invalid output_format. Must be 'csv' or 'json'.")

    # Validate output path securely within the allowed directory
    try:
        # Allow file creation, so check_exists=False
        # Base directory is implicitly ALLOWED_DIR_CONFIG from global scope
        abs_output_path = get_secure_path(output_file, check_exists=False)
        await ctx.info(f"Validated output path: {abs_output_path}")
    except (ValueError, PermissionError) as e:
        await ctx.error(f"Invalid or disallowed output file path: {e}")
        raise e

    # --- Reuse Query Logic (without limit) ---
    # Call query_events internally but get indices back instead of summaries
    # This avoids duplicating the complex filter logic.
    # We need to modify query_events slightly or create a helper.
    # For now, let's duplicate the filtering logic here for simplicity,
    # acknowledging this isn't ideal for maintenance.
    # TODO: Refactor filtering logic into a reusable (async) generator function.

    if LOADED_EVENTS is None or LOADED_PROCESSES is None or not GLOBAL_INTERNERS:
        await ctx.error(f"Export failed: Event data or interners not loaded.")
        raise TypeError("Operation requires optimized event data to be loaded.")

    if not LOADED_EVENTS:
         await ctx.info("Export finished: No events loaded in memory to export.")
         return {"success": True, "output_path": abs_output_path, "events_exported": 0}

    try:
        matching_indices = []
        start_time = time.time()

        # --- Filtering logic (mirrors query_events for now) ---
        path_regex = re.compile(filter_path_regex, re.IGNORECASE) if filter_path_regex else None
        process_regex = re.compile(filter_process_regex, re.IGNORECASE) if filter_process_regex else None
        detail_regex = re.compile(filter_detail_regex, re.IGNORECASE) if filter_detail_regex else None
        start_ts: Optional[float] = None
        end_ts: Optional[float] = None
        is_start_time_only = False
        is_end_time_only = False
        # (Time parsing logic - identical to query_events)
        try:
            if isinstance(filter_start_time, str):
                try:
                    parsed_time_obj = datetime.strptime(filter_start_time, PROCMON_TIMESTAMP_FORMAT).time()
                    start_ts = (parsed_time_obj.hour * 3600 + parsed_time_obj.minute * 60 +
                                parsed_time_obj.second + parsed_time_obj.microsecond / 1e6)
                    is_start_time_only = True
                except ValueError:
                    try: start_ts = float(filter_start_time)
                    except ValueError: raise ValueError(f"Invalid start_time format: '{filter_start_time}'.")
            elif isinstance(filter_start_time, (int, float)):
                start_ts = float(filter_start_time)
            if isinstance(filter_end_time, str):
                 try:
                    parsed_time_obj = datetime.strptime(filter_end_time, PROCMON_TIMESTAMP_FORMAT).time()
                    end_ts = (parsed_time_obj.hour * 3600 + parsed_time_obj.minute * 60 +
                              parsed_time_obj.second + parsed_time_obj.microsecond / 1e6)
                    is_end_time_only = True
                 except ValueError:
                    try: end_ts = float(filter_end_time)
                    except ValueError: raise ValueError(f"Invalid end_time format: '{filter_end_time}'.")
            elif isinstance(filter_end_time, (int, float)):
                end_ts = float(filter_end_time)
        except ValueError as e: await ctx.error(f"Invalid time format: {e}"); raise e

        process_id_filter = get_id("process_name", filter_process) if filter_process else None
        operation_id_filter = get_id("operation", filter_operation) if filter_operation else None
        result_id_filter = get_id("result", filter_result) if filter_result else None
        filter_path_contains_lower = filter_path_contains.lower() if filter_path_contains else None
        filter_process_contains_lower = filter_process_contains.lower() if filter_process_contains else None
        filter_stack_module_path_lower = filter_stack_module_path.lower() if filter_stack_module_path else None

        candidate_indices: Optional[Set[int]] = None
        if process_id_filter is not None: candidate_indices = set(PID_INDEX.get(process_id_filter, []))
        if operation_id_filter is not None:
            op_indices = set(OP_INDEX.get(operation_id_filter, []))
            if candidate_indices is None: candidate_indices = op_indices
            else: candidate_indices.intersection_update(op_indices)

        event_iterator = enumerate(LOADED_EVENTS) if candidate_indices is None else ((idx, LOADED_EVENTS[idx]) for idx in sorted(list(candidate_indices)))
        total_to_scan = len(LOADED_EVENTS) if candidate_indices is None else len(candidate_indices)
        processed_count = 0
        last_progress_report_time = start_time
        await ctx.info(f"Filtering {total_to_scan:,} events for export...")

        for idx, event_dict in event_iterator:
            processed_count += 1
            if processed_count % (PROGRESS_REPORT_INTERVAL * 2) == 0 or (time.time() - last_progress_report_time > 15.0):
                try: await ctx.info(f" Export filtering progress: {processed_count:,}/{total_to_scan:,}...")
                except Exception: pass
                last_progress_report_time = time.time()

            match = True
            # Apply non-indexed filters (or all filters if no index used)
            if candidate_indices is not None: # Skip already indexed filters
                 if process_id_filter is not None and event_dict.get('pname_id') != process_id_filter: continue
                 if operation_id_filter is not None and event_dict.get('op_id') != operation_id_filter: continue
            else: # Apply all filters if not using index
                 if process_id_filter is not None and event_dict.get('pname_id') != process_id_filter: match = False
                 if match and operation_id_filter is not None and event_dict.get('op_id') != operation_id_filter: match = False

            if match and result_id_filter is not None and event_dict.get('res_id') != result_id_filter: match = False
            # (Time filtering logic - identical to query_events)
            if match and (start_ts is not None or end_ts is not None):
                event_ts_float = event_dict.get('ts')
                if event_ts_float is None: match = False
                else:
                    current_event_compare_val = event_ts_float
                    if is_start_time_only or is_end_time_only:
                        try:
                           event_dt_obj = datetime.fromtimestamp(event_ts_float, timezone.utc)
                           current_event_compare_val = (event_dt_obj.hour * 3600 + event_dt_obj.minute * 60 +
                                                        event_dt_obj.second + event_dt_obj.microsecond / 1e6)
                        except Exception: match = False
                    if match and start_ts is not None:
                        compare_filter_val = start_ts if (is_start_time_only or is_end_time_only) else start_ts
                        if current_event_compare_val < compare_filter_val: match = False
                    if match and end_ts is not None:
                        compare_filter_val = end_ts if (is_start_time_only or is_end_time_only) else end_ts
                        if current_event_compare_val > compare_filter_val: match = False
            # (Contains/Regex/Stack filtering logic - identical to query_events)
            if match and (filter_path_contains_lower or filter_process_contains_lower or path_regex or process_regex or detail_regex or filter_stack_module_path_lower):
                path_str = get_string("path", event_dict.get('path_id')) or ""
                pname_str = get_string("process_name", event_dict.get('pname_id')) or ""
                detail_str = event_dict.get('detail') or ""
                if match and filter_path_contains_lower and filter_path_contains_lower not in path_str.lower(): match = False
                if match and filter_process_contains_lower and filter_process_contains_lower not in pname_str.lower(): match = False
                if match and path_regex and not path_regex.search(path_str): match = False
                if match and process_regex and not process_regex.search(pname_str): match = False
                if match and detail_regex and not detail_regex.search(detail_str): match = False
                if match and filter_stack_module_path_lower:
                    if not LOAD_STACK_TRACES: match = True # Don't filter if not loaded
                    else:
                        stack_list_optimized = event_dict.get('stack')
                        found_in_stack = False
                        if stack_list_optimized:
                            for frame_list in stack_list_optimized:
                                if len(frame_list) > 2 and frame_list[2] is not None:
                                    frame_path_str = get_string("stack_path", frame_list[2])
                                    if frame_path_str and filter_stack_module_path_lower in frame_path_str.lower():
                                        found_in_stack = True; break
                        if not found_in_stack: match = False
            # --- End Filtering ---

            if match:
                matching_indices.append(idx)

        filter_elapsed = time.time() - start_time
        await ctx.info(f"Filtering completed in {filter_elapsed:.2f}s. Found {len(matching_indices)} events to export.")

        # --- Exporting ---
        export_start_time = time.time()
        events_exported = 0
        if not matching_indices:
             await ctx.info("No matching events to export.")
             # Create empty file? Or just report 0 exported. Let's report 0.
             return {"success": True, "output_path": abs_output_path, "events_exported": 0}

        # Get full details for matching events
        events_to_export = []
        for i, event_idx in enumerate(matching_indices):
             if i % 10000 == 0 and i > 0: # Progress update during detail retrieval
                 try: await ctx.info(f" Export: Retrieving details for event {i:,}/{len(matching_indices):,}...")
                 except Exception: pass
             try:
                 # Use get_event_details logic but adapt it slightly
                 event_dict = LOADED_EVENTS[event_idx]
                 details = { # Manually build dict to control fields
                     'event_index': event_idx,
                     'sequence_number': event_dict.get('seq'),
                     'timestamp': datetime.fromtimestamp(event_dict['ts'], timezone.utc).strftime(PROCMON_TIMESTAMP_FORMAT) if event_dict.get('ts') else None,
                     'process_name': get_string("process_name", event_dict.get('pname_id')),
                     'pid': event_dict.get('pid'),
                     'tid': event_dict.get('tid'),
                     'operation': get_string("operation", event_dict.get('op_id')),
                     'path': get_string("path", event_dict.get('path_id')),
                     'result': get_string("result", event_dict.get('res_id')),
                     'detail': event_dict.get('detail'),
                     'duration': event_dict.get('dur'),
                     'category': get_string("category", event_dict.get('cat_id')),
                     'parent_pid': event_dict.get('ppid'),
                     # Add extra data if loaded and present
                     'extra_data': event_dict.get('extra_data') if LOAD_EXTRA_DATA else None,
                 }
                 # Add stack trace if loaded and present
                 if LOAD_STACK_TRACES and 'stack' in event_dict:
                     stack_list = []
                     for frame_data in event_dict['stack']:
                          stack_list.append({
                             'depth': frame_data[0], 'address': frame_data[1],
                             'path': get_string("stack_path", frame_data[2]),
                             'location': get_string("stack_location", frame_data[3])
                          })
                     details['stack_trace'] = stack_list # Use a different key to avoid conflict
                 else:
                     details['stack_trace'] = None

                 events_to_export.append(details)
             except Exception as detail_err:
                 await ctx.warning(f"Error retrieving details for event index {event_idx}: {detail_err}")
                 logger.debug(f"Detail retrieval error details:", exc_info=True)


        # Write to file
        if output_format.lower() == 'csv':
            if not events_to_export: # Handle empty list for CSV header
                 fieldnames = ['event_index', 'sequence_number', 'timestamp', 'process_name', 'pid', 'tid', 'operation', 'path', 'result', 'detail', 'duration', 'category', 'parent_pid', 'extra_data', 'stack_trace']
            else:
                 fieldnames = list(events_to_export[0].keys()) # Get headers from first event

            try:
                with open(abs_output_path, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                    writer.writeheader()
                    for row_dict in events_to_export:
                        # Convert complex types (like extra_data dict or stack list) to JSON strings for CSV
                        if isinstance(row_dict.get('extra_data'), dict):
                            row_dict['extra_data'] = json.dumps(row_dict['extra_data'])
                        if isinstance(row_dict.get('stack_trace'), list):
                            row_dict['stack_trace'] = json.dumps(row_dict['stack_trace'])
                        writer.writerow(row_dict)
                        events_exported += 1
            except IOError as e:
                await ctx.error(f"Error writing CSV file '{abs_output_path}': {e}")
                raise RuntimeError(f"Failed to write CSV file: {e}") from e

        elif output_format.lower() == 'json':
            try:
                with open(abs_output_path, 'w', encoding='utf-8') as jsonfile:
                    json.dump(events_to_export, jsonfile, indent=2) # Pretty print JSON
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
        description=f"MCP Server for analyzing Procmon XML files (.xml, .xml.gz/bz2/xz) using in-memory optimization.",
        epilog=f"Memory reporting requires 'psutil' library (`pip install psutil`)."
    )
    parser.add_argument("--allowed-dir", required=True, help="REQUIRED: Secure base directory containing Procmon XML files.")
    parser.add_argument("--load-file", required=True,
                        help="REQUIRED: XML file (.xml, .xml.gz/bz2/xz) relative to --allowed-dir to load and analyze.")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1", help="Host for MCP server (SSE transport), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8081, help="Port for MCP server (SSE transport), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"], help="MCP transport protocol, default: stdio")
    parser.add_argument("--debug", action='store_true', help="Enable debug logging.")
    parser.add_argument("--log-file", type=str, default=None, help="Optional: Path to a file to write logs to instead of console.")
    # --- Added Selective Loading Args ---
    parser.add_argument("--no-stack-traces", action='store_true', help="Do not parse or store stack traces to save memory.")
    parser.add_argument("--no-extra-data", action='store_true', help="Do not store unknown fields found within <event> tags.")

    args = parser.parse_args()

    # --- Set Global Flags from Args ---
    LOAD_STACK_TRACES = not args.no_stack_traces
    LOAD_EXTRA_DATA = not args.no_extra_data

    # --- Logging Configuration ---
    log_level = logging.DEBUG if args.debug else logging.INFO
    log_handlers = []

    # *** UPDATED Logging Setup ***
    if args.log_file:
        # Ensure the directory for the log file exists
        log_dir = os.path.dirname(args.log_file)
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir)
            except OSError as e:
                print(f"Error: Could not create directory for log file '{args.log_file}': {e}")
                exit(1)
        # Add file handler
        try:
            file_handler = logging.FileHandler(args.log_file, mode='w') # 'w' to overwrite each run
            file_handler.setLevel(log_level)
            file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
            log_handlers.append(file_handler)
            print(f"Logging to file: {args.log_file}") # Still print this to console
        except Exception as e:
             print(f"Error: Could not open log file '{args.log_file}' for writing: {e}")
             exit(1)
    else:
        # Add console handler (default behavior if no log file)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        log_handlers.append(console_handler)

    # Configure the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    # Remove existing default handlers (like the one from basicConfig)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    # Add our configured handlers
    for handler in log_handlers:
        root_logger.addHandler(handler)

    # Ensure our specific logger also respects the level
    logger.setLevel(log_level)
    # Configure MCP/Uvicorn loggers if possible
    try:
        logging.getLogger('mcp').setLevel(log_level)
        # Add our handlers to MCP logger too if desired, or let it propagate
        # for handler in log_handlers:
        #     logging.getLogger('mcp').addHandler(handler)
        # logging.getLogger('mcp').propagate = False # Prevent double logging if handlers added

        if args.transport == 'sse':
             logging.getLogger('uvicorn').setLevel(log_level)
             logging.getLogger('uvicorn.error').setLevel(log_level) # Ensure errors are logged
             logging.getLogger('uvicorn.access').setLevel(logging.WARNING if not args.debug else logging.DEBUG)
             # Optionally add file handler to uvicorn loggers too
             # for handler in log_handlers:
             #    logging.getLogger('uvicorn').addHandler(handler)
             #    logging.getLogger('uvicorn.error').addHandler(handler)
             #    logging.getLogger('uvicorn.access').addHandler(handler)
             # logging.getLogger('uvicorn').propagate = False
             # logging.getLogger('uvicorn.error').propagate = False
             # logging.getLogger('uvicorn.access').propagate = False

    except Exception:
        logger.debug("Could not configure MCP/Uvicorn loggers.", exc_info=True)
    logger.info(f"Logging level set to: {logging.getLevelName(log_level)}")
    if args.log_file:
        logger.info(f"Logging output directed to file: {args.log_file}")
    else:
        logger.info("Logging output directed to console.")

    # Log selective loading status
    logger.info(f"Selective loading: Stacks={LOAD_STACK_TRACES}, ExtraData={LOAD_EXTRA_DATA}")

    # --- Dependency Checks ---
    if not MCP_SDK_AVAILABLE:
        # Log critical error before exiting
        logger.critical("CRITICAL: Model Context Protocol SDK (modelcontextprotocol) is not installed.")
        logger.critical("Please install it: pip install modelcontextprotocol")
        exit(1)

    # --- Directory Validation ---
    if not os.path.isdir(args.allowed_dir):
        logger.critical(f"Error: Allowed directory does not exist or is not a directory: {args.allowed_dir}")
        exit(1)
    ALLOWED_DIR_CONFIG = os.path.abspath(args.allowed_dir)
    logger.info(f"Allowed Directory set to: {ALLOWED_DIR_CONFIG}")

    # --- Load File into Optimized In-Memory Structure ---
    try:
        logger.info(f"Attempting to load and optimize file: {args.load_file}")
        load_and_validate_file(ALLOWED_DIR_CONFIG, args.load_file)

        # Check if loading succeeded - LOADED_EVENTS should not be None
        if LOADED_EVENTS is None or LOADED_PROCESSES is None:
            logger.critical(f"File loading failed for '{args.load_file}'. Check logs above for errors. Exiting.")
            exit(1)
        else:
             logger.info(f"File '{args.load_file}' loaded successfully (Events: {len(LOADED_EVENTS):,}, Processes: {len(LOADED_PROCESSES)}).")

        # --- Memory Usage Reporting ---
        if PSUTIL_AVAILABLE:
            try:
                process = psutil.Process(os.getpid())
                mem_info = process.memory_info()
                rss_formatted = _format_bytes(mem_info.rss)
                vms_formatted = _format_bytes(mem_info.vms)
                logger.info(f"--- Post-Load Memory Usage (Process RSS): {rss_formatted} ---")
                if args.debug:
                    logger.debug(f"  Detailed Memory: RSS={rss_formatted}, VMS={vms_formatted}")
                    logger.debug(f"  Full psutil mem_info: {mem_info}")
            except Exception as mem_err:
                logger.warning(f"Could not retrieve process memory usage: {mem_err}")
        else:
            logger.info("Memory usage reporting skipped (psutil library not installed).")

        logger.info(f"Ready for MCP connections.")

    except (ValueError, PermissionError, FileNotFoundError, TypeError, IndexError) as e:
        logger.critical(f"Configuration or File Access Error loading '{args.load_file}': {e}")
        exit(1)
    except ET_impl.XMLSyntaxError as e:
         logger.critical(f"XML Syntax Error loading file ('{args.load_file}'): {e}")
         if args.debug: logger.exception("XML Syntax Error details:")
         exit(1)
    except RuntimeError as e:
         logger.critical(f"Runtime Error during file loading ('{args.load_file}'): {e}")
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
                mcp.settings.host = args.mcp_host
                mcp.settings.port = args.mcp_port
                # Pass log level name to MCP settings
                mcp_log_level_name = logging.getLevelName(log_level)
                mcp.settings.log_level = mcp_log_level_name.lower()
                logger.info(f"  MCP Host: {mcp.settings.host}")
                logger.info(f"  MCP Port: {mcp.settings.port}")
                logger.info(f"  MCP Log Level: {mcp.settings.log_level}")
            else:
                 logger.warning("MCP object lacks 'settings'; cannot configure SSE host/port/log level via arguments.")
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
        exit(1)

    # --- Post-Server Execution ---
    if not server_started and args.transport == "sse":
        logger.critical("SSE Server did not appear to start correctly.")
        exit(1)
    else:
         logger.info("Server execution finished.")
         exit(0) # Normal exit
