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
        async def info(self, msg): logger.info(f"(async mock ctx): {msg}")
        async def error(self, msg): logger.error(f"(async mock ctx): {msg}")
        async def warning(self, msg): logger.warning(f"(async mock ctx): {msg}")

# XML parser code is integrated
PROCMON_XML_PARSER_AVAILABLE = True

# --- XML Parser Data Structures ---
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

@dataclasses.dataclass
class ProcessInfo:
    """Represents information about a single process from the <processlist>."""
    process_index: Optional[int] = None
    process_id: Optional[int] = None
    parent_process_id: Optional[int] = None
    parent_process_index: Optional[int] = None
    authentication_id: Optional[str] = None
    create_time: Optional[str] = None
    finish_time: Optional[str] = None
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

@dataclasses.dataclass
class ProcmonEvent:
    """Represents a single event record parsed from Procmon XML data."""
    time_of_day: Optional[str] = None
    process_name: Optional[str] = None
    pid: Optional[int] = None
    operation: Optional[str] = None
    path: Optional[str] = None
    result: Optional[str] = None
    detail: Optional[str] = None
    category: Optional[str] = None
    duration: Optional[float] = None
    completion_time: Optional[str] = None
    relative_time: Optional[float] = None
    sequence_number: Optional[int] = None # Crucial for finding specific events
    process_index: Optional[int] = None
    stack: Optional[List[StackFrame]] = None
    tid: Optional[int] = None
    image_path: Optional[str] = None
    command_line: Optional[str] = None
    parent_pid: Optional[int] = None
    session_id: Optional[int] = None
    user: Optional[str] = None
    architecture: Optional[str] = None
    integrity: Optional[str] = None
    virtualized: Optional[bool] = None
    authentication_id: Optional[str] = None

    @property
    def timestamp(self): return self.time_of_day
    @property
    def user_sid(self): return self.user
    @property
    def is_64bit_process(self): return self.architecture == '64-bit' if self.architecture else None

    @staticmethod
    def _safe_find_text(elem: ET_impl.Element, tag: str) -> Optional[str]:
        child = elem.find(tag)
        return child.text.strip() if child is not None and child.text else None
    @staticmethod
    def _safe_get_attrib(elem: ET_impl.Element, attrib: str) -> Optional[str]:
        val = elem.get(attrib)
        return val.strip() if val else None
    @staticmethod
    def _safe_text_to_int(text: Optional[str]) -> Optional[int]:
        if text is None: return None
        text = text.strip()
        if text.isdigit() or (text.startswith('-') and text[1:].isdigit()):
            try: return int(text)
            except (ValueError, TypeError): return None
        else: return None
    @staticmethod
    def _safe_text_to_float(text: Optional[str]) -> Optional[float]:
        if text is None: return None
        try: return float(text.strip())
        except (ValueError, TypeError): return None

    @classmethod
    def from_xml_element(cls, elem: ET_impl.Element, processes: Dict[int, ProcessInfo]) -> 'ProcmonEvent':
        data: Dict[str, Any] = {}
        data['time_of_day'] = cls._safe_find_text(elem, 'Time_of_Day')
        data['process_name'] = cls._safe_find_text(elem, 'Process_Name')
        data['operation'] = cls._safe_find_text(elem, 'Operation')
        data['path'] = cls._safe_find_text(elem, 'Path')
        data['result'] = cls._safe_find_text(elem, 'Result')
        data['detail'] = cls._safe_find_text(elem, 'Detail')
        data['category'] = cls._safe_find_text(elem, 'Category')
        data['completion_time'] = cls._safe_find_text(elem, 'Completion_Time')
        data['pid'] = cls._safe_text_to_int(cls._safe_find_text(elem, 'PID'))
        data['duration'] = cls._safe_text_to_float(cls._safe_find_text(elem, 'Duration'))
        data['relative_time'] = cls._safe_text_to_float(cls._safe_find_text(elem, 'Relative_Time'))
        data['sequence_number'] = cls._safe_text_to_int(cls._safe_get_attrib(elem, 'SequenceNumber'))
        data['process_index'] = cls._safe_text_to_int(cls._safe_get_attrib(elem, 'ProcessIndex'))

        stack_elem = elem.find('stack')
        if stack_elem is not None:
            stack_frames: List[StackFrame] = []
            for frame_elem in stack_elem.findall('frame'):
                try: stack_frames.append(StackFrame.from_xml_element(frame_elem))
                except Exception as e: logger.warning(f"Failed to parse stack frame: {e}", exc_info=False)
            data['stack'] = stack_frames if stack_frames else None
        else: data['stack'] = None

        process_info = processes.get(data['process_index']) if data['process_index'] is not None else None
        if process_info:
            data['pid'] = process_info.process_id if process_info.process_id is not None else data['pid']
            data['process_name'] = process_info.process_name if process_info.process_name else data['process_name']
            data['image_path'] = process_info.image_path
            data['command_line'] = process_info.command_line
            data['parent_pid'] = process_info.parent_process_id
            data['user'] = process_info.owner
            data['architecture'] = '64-bit' if process_info.is_64bit else ('32-bit' if process_info.is_64bit is False else None)
            data['integrity'] = process_info.integrity
            data['virtualized'] = process_info.is_virtualized
            data['authentication_id'] = process_info.authentication_id
        else:
            data['image_path'],data['command_line'],data['parent_pid'],data['user'] = None,None,None,None
            data['architecture'],data['integrity'],data['virtualized'],data['authentication_id'] = None,None,None,None

        data['tid'] = None
        if data['detail']:
            detail_parts = data['detail'].split(',')
            for part in detail_parts:
                part = part.strip()
                if part.lower().startswith('tid:'):
                    try: data['tid'] = int(part.split(':')[1].strip()); break
                    except (IndexError, ValueError, TypeError): data['tid'] = None
        data['session_id'] = None
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

def _parse_xml_stream(source_stream: IO[bytes], parse_events: bool = True) -> Tuple[Optional[Iterator[ProcmonEvent]], Dict[int, ProcessInfo]]:
    """
    Internal helper function to parse XML from a byte stream using iterparse (lxml preferred).

    Parses the <processlist> first to build a dictionary for enrichment.
    Optionally yields <event> elements via a generator based on `parse_events` flag.

    Args:
        source_stream: A readable binary stream providing the XML content.
        parse_events: If True, yields events. If False, stops after parsing processes.

    Returns:
        A tuple containing:
          - An iterator yielding ProcmonEvent objects (or None if parse_events is False).
          - A dictionary mapping process index to ProcessInfo objects parsed from <processlist>.

    Raises:
        ET_impl.XMLSyntaxError: If the XML is malformed.
        ValueError: If the root <procmon> tag is missing or structure is invalid.
    """
    processes_dict: Dict[int, ProcessInfo] = {}
    parsing_stage = "seeking_procmon"
    processlist_parsed = False
    eventlist_entered = False
    tags_of_interest = ('process', 'event', 'processlist', 'eventlist', 'procmon')
    context = ET_impl.iterparse(source_stream, events=('end',), tag=tags_of_interest)

    def event_generator() -> Iterator[ProcmonEvent]:
        nonlocal parsing_stage, eventlist_entered
        event_count = 0
        try:
            for event_type, elem in context:
                if elem.tag == 'event':
                    if not processlist_parsed: logger.warning("Encountered <event> before <processlist> fully parsed.")
                    try:
                        yield ProcmonEvent.from_xml_element(elem, processes_dict)
                        event_count += 1
                        # Reduce logging frequency for streaming
                        if event_count % 250000 == 0: logger.info(f"Streamed {event_count} events...")
                    except Exception as e: logger.warning(f"Failed to parse <event> element: {e}", exc_info=False)
                    _clear_elem(elem)
                elif elem.tag == 'eventlist':
                    logger.info(f"Finished streaming <eventlist>.")
                    parsing_stage = "done"; _clear_elem(elem)
                elif elem.tag == 'procmon':
                    logger.debug("Reached end of <procmon> during event generation.")
                    parsing_stage = "done"; break
                elif elem.tag in tags_of_interest: _clear_elem(elem)
            logger.info(f"Total events successfully streamed: {event_count}")
        except ET_impl.XMLSyntaxError as e: logger.error(f"XML Parse Error during event stream: {e}"); raise
        except Exception as e: logger.error(f"Unexpected error during event stream: {e}", exc_info=True); raise

    try:
        for event_type, elem in context:
            if parsing_stage == "seeking_procmon": parsing_stage = "seeking_processlist"
            if parsing_stage == "seeking_processlist":
                if elem.tag == 'process': parsing_stage = "parsing_processlist" # Fallthrough
                elif elem.tag == 'processlist': processlist_parsed = True; parsing_stage = "seeking_eventlist"; _clear_elem(elem); break # Break to start events if requested
                elif elem.tag == 'eventlist': logger.warning("Found <eventlist> before <processlist>."); parsing_stage = "seeking_eventlist"; eventlist_entered = True; _clear_elem(elem); break
                elif elem.tag == 'event': logger.warning("Found <event> before <processlist>."); parsing_stage = "seeking_eventlist"; eventlist_entered = True; break
            if parsing_stage == "parsing_processlist":
                if elem.tag == 'process':
                    try:
                        proc_info = ProcessInfo.from_xml_element(elem)
                        if proc_info.process_index is not None and proc_info.process_index >= 0: processes_dict[proc_info.process_index] = proc_info
                        else: logger.warning(f"Parsed process element with invalid index.")
                    except Exception as e: logger.warning(f"Failed to parse <process> element: {e}", exc_info=False)
                    _clear_elem(elem)
                elif elem.tag == 'processlist':
                    logger.info(f"Finished parsing <processlist>. Found {len(processes_dict)} processes.")
                    processlist_parsed = True; parsing_stage = "seeking_eventlist"; _clear_elem(elem); break # Break to start events if requested
            if elem.tag == 'procmon': logger.debug("Reached end of <procmon> during process phase."); parsing_stage = "done"; break

        # Decide what to return based on parse_events flag and final state
        if parse_events and (parsing_stage == "seeking_eventlist" or parsing_stage == "generating_events"):
            return event_generator(), processes_dict
        elif parse_events and parsing_stage == "done" and not eventlist_entered:
             logger.info("No <eventlist> found/processed."); return iter([]), processes_dict # Return empty iterator
        elif not parse_events:
             logger.info("Stopped parsing after process list as requested.")
             return None, processes_dict # Return None for iterator
        else: # Should not happen
             logger.warning(f"XML parsing ended unexpectedly: {parsing_stage}."); return None, processes_dict

    except ET_impl.XMLSyntaxError as e: logger.error(f"XML Parse Error during initial processing: {e}"); raise
    except Exception as e: logger.error(f"Unexpected error during initial XML processing: {e}", exc_info=True); raise

def stream_procmon_events(file_path: str, compression: Optional[str]) -> Iterator[Tuple[ProcmonEvent, Dict[int, ProcessInfo]]]:
    """
    Opens a Procmon XML file (plain or compressed) and yields events one by one.
    Parses the process list first and includes it with each yielded event for context.

    Args:
        file_path: Absolute path to the XML file.
        compression: Compression type ('gz', 'bz2', 'xz', or None).

    Yields:
        Tuple[ProcmonEvent, Dict[int, ProcessInfo]]: The event and the full process dictionary.

    Raises:
        FileNotFoundError, ValueError, RuntimeError, ET_impl.XMLSyntaxError
    """
    open_func: Any = open
    if compression == 'gz': open_func = gzip.open
    elif compression == 'bz2': open_func = bz2.open
    elif compression == 'xz': open_func = lzma.open

    comp_str = f" ({compression} compressed)" if compression else ""
    logger.info(f"Streaming events from{comp_str} XML file: {file_path}")

    try:
        with open_func(file_path, "rb") as f_stream:
            # Use parse_events=True to get the event generator
            event_iterator, processes_dict = _parse_xml_stream(f_stream, parse_events=True)
            if event_iterator is None: # Should not happen if parse_events=True
                 logger.error("Failed to get event iterator from _parse_xml_stream")
                 return # Return empty iterator

            # Yield each event along with the *same* processes_dict
            for event in event_iterator:
                yield event, processes_dict # Yield event and the *complete* process map

    except Exception as e:
        logger.error(f"Error streaming events from {file_path}: {e}", exc_info=True)
        # Re-raise specific errors if needed, otherwise wrap
        if isinstance(e, (FileNotFoundError, ValueError, ET_impl.XMLSyntaxError)):
            raise
        else:
            raise RuntimeError(f"Failed to stream events from '{file_path}'") from e


# --- Global State ---
ALLOWED_DIR_CONFIG: Optional[str] = None
LOADED_FILENAME: Optional[str] = None
LOADED_FILE_TYPE: Optional[str] = None # Should always be 'xml' if loaded
LOADED_COMPRESSION: Optional[str] = None # Store compression type
LOADED_PROCESSES: Optional[Dict[int, ProcessInfo]] = None # Store only processes

# --- Setup MCP ---
if MCP_SDK_AVAILABLE:
    mcp = FastMCP(
        "ProcmonXmlTool",
        description="A tool to analyze a specific, pre-loaded Procmon XML log file (plain or compressed) via streaming."
    )
else:
    mcp = MockMCP(
         "ProcmonXmlTool (Mock)",
         description="Mock Tool: Analyzes pre-loaded Procmon XML files via streaming."
    )

# --- Security Helper (Updated) ---
def get_secure_path(filename: str) -> str:
    """
    Validates filename relative to ALLOWED_FILE_DIR and returns full path if safe.
    Relies on abspath and commonpath for security, allowing formats like '.\file.xml'.
    """
    if not ALLOWED_DIR_CONFIG:
        raise RuntimeError("Internal Error: Allowed directory configuration is missing.")
    if not filename:
        raise ValueError("Filename cannot be empty.")
    # Prevent absolute paths explicitly passed by the user
    if os.path.isabs(filename):
         raise ValueError("Invalid filename format: Absolute paths are not allowed.")

    # Construct the path using the allowed directory and the relative filename
    # os.path.join handles separators correctly
    full_path = os.path.join(ALLOWED_DIR_CONFIG, filename)

    # Normalize both the allowed directory and the constructed path
    normalized_allowed_dir = os.path.abspath(ALLOWED_DIR_CONFIG)
    normalized_full_path = os.path.abspath(full_path)

    logger.debug(f"Checking path: {normalized_full_path} against allowed: {normalized_allowed_dir}")

    # Use commonpath to ensure the resulting path is within the allowed directory
    # This handles '..' and other relative path components safely.
    common_prefix = os.path.commonpath([normalized_allowed_dir, normalized_full_path])
    if common_prefix != normalized_allowed_dir:
          raise PermissionError(f"Access denied: File '{filename}' resolves outside the allowed directory ('{normalized_allowed_dir}'). Resolved path: '{normalized_full_path}'")

    # Final checks
    if not os.path.exists(normalized_full_path):
        raise FileNotFoundError(f"File not found: {filename} (resolves to {normalized_full_path})")
    if not os.path.isfile(normalized_full_path):
        raise ValueError(f"Path exists but is not a file: {filename} (resolves to {normalized_full_path})")

    logger.debug(f"Path validated: {normalized_full_path}")
    return normalized_full_path # Return the absolute, validated path


# --- Loading Helper (Loads ONLY processes) ---
def load_and_validate_file(allowed_dir: str, filename_relative: str) -> Tuple[Dict[int, ProcessInfo], str, Optional[str]]:
    """
    Validates XML file path, determines compression, parses and returns ONLY the process list.
    Stores filename and compression type globally for later streaming by tools.

    Returns:
        Tuple containing:
            - Dictionary of ProcessInfo objects keyed by process_index.
            - File type ('xml').
            - Compression type (str or None).

    Raises:
        FileNotFoundError, ValueError, PermissionError, RuntimeError, ET_impl.XMLSyntaxError
    """
    global LOADED_FILENAME, LOADED_FILE_TYPE, LOADED_COMPRESSION, LOADED_PROCESSES

    # Use the updated get_secure_path which returns absolute path
    # We still need the relative filename for storing globally
    abs_full_path = get_secure_path(filename_relative)
    fname_lower = filename_relative.lower() # Use relative name for extension checks
    file_type: str = "xml"
    compression: Optional[str] = None

    # Determine compression type based on relative filename
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

    try:
        open_func: Any = open
        if compression == 'gz': open_func = gzip.open
        elif compression == 'bz2': open_func = bz2.open
        elif compression == 'xz': open_func = lzma.open

        comp_str = f" ({compression} compressed)" if compression else ""
        logger.info(f"Validating and parsing process list from{comp_str} XML file: {abs_full_path}")

        with open_func(abs_full_path, "rb") as f_stream: # Use absolute path here
             # Use parse_events=False to only get processes
             _, processes_dict = _parse_xml_stream(f_stream, parse_events=False)
             if processes_dict is None:
                  processes_dict = {}
                  logger.error("Failed to parse process dictionary.")
                  # raise RuntimeError("Failed to parse process information from file.") # Optionally make this fatal

        # Store globally for tools to access
        LOADED_FILENAME = filename_relative # Store original relative name
        LOADED_FILE_TYPE = file_type
        LOADED_COMPRESSION = compression
        LOADED_PROCESSES = processes_dict # Store the parsed processes

        logger.info(f"Successfully parsed process list: {len(processes_dict)} processes found.")

    except ET_impl.XMLSyntaxError as e:
        logger.error(f"XML Syntax Error processing file {filename_relative}: {e}", exc_info=True)
        raise RuntimeError(f"Failed to parse XML file '{filename_relative}': Invalid XML.") from e
    except Exception as e:
         logger.error(f"Error during initial processing of file {filename_relative}: {e}", exc_info=True)
         LOADED_FILENAME = None; LOADED_FILE_TYPE = None; LOADED_COMPRESSION = None; LOADED_PROCESSES = None
         raise RuntimeError(f"Failed to load or parse file '{filename_relative}': {e}") from e

    end_time = time.time()
    logger.info(f"File validation and process list parsing took {end_time - start_time:.2f} seconds.")
    return processes_dict, file_type, compression


# --- Helper to Safely Get Attributes ---
# (Implementation remains the same as previous version, focused on XML dataclasses)
def safe_get_attributes(obj: Any, attributes: List[str]) -> Dict[str, Any]:
    result = {}
    if obj is None: return {attr: None for attr in attributes}
    for attr_lower in attributes:
        value = None; found = False
        if hasattr(obj, attr_lower):
            try: value = getattr(obj, attr_lower); found = True
            except Exception: pass
        if not found:
            possible_names = [ attr_lower.capitalize(), attr_lower.title().replace("_", ""), f"{attr_lower.replace('_', ' ').title().replace(' ', '')}", ]
            if attr_lower == "pid": possible_names.append("ProcessId")
            if attr_lower == "parent_pid": possible_names.append("ParentProcessId")
            if attr_lower == "timestamp": possible_names.append("Time_of_Day")
            if attr_lower == "user_sid": possible_names.append("Owner")
            if attr_lower == "is_64bit_process": possible_names.append("is_64bit")
            if attr_lower == "stack": possible_names.append("stacktrace") # Allow getting raw stack obj if needed
            possible_names = list(dict.fromkeys(possible_names))
            for name_attempt in possible_names:
                 if hasattr(obj, name_attempt):
                     try: value = getattr(obj, name_attempt); found = True; break
                     except Exception: pass
        if isinstance(value, (bytes, bytearray)):
            try: result[attr_lower] = value.decode('utf-8', errors='replace')
            except Exception: result[attr_lower] = repr(value)
        elif attr_lower == 'stack' and isinstance(value, list) and value and isinstance(value[0], StackFrame):
             result[attr_lower] = value # Return list of StackFrame objects
        elif value is not None and not isinstance(value, (str, int, float, bool, list, dict)):
             result[attr_lower] = str(value)
        else: result[attr_lower] = value
    return result

# --- Helper to get absolute path for streaming ---
def _get_stream_file_path() -> str:
    """Gets the absolute path of the globally loaded file for streaming."""
    if not LOADED_FILENAME or not ALLOWED_DIR_CONFIG:
         raise RuntimeError("File path information not loaded globally.")
    try:
        # Re-run security check using the stored relative name to get abs path
        abs_path = get_secure_path(LOADED_FILENAME)
        return abs_path
    except Exception as e:
        raise RuntimeError(f"Could not resolve secure path for streaming: {e}") from e


# --- MCP Tools (Refactored for Streaming) ---
tool_decorator = mcp.tool() if MCP_SDK_AVAILABLE else lambda func: func

@tool_decorator
async def get_loaded_file_summary(ctx: Context) -> Dict[str, Any]:
    """
    Returns a basic summary of the pre-loaded Procmon XML file (based on process list).
    """
    await ctx.info(f"Request received for summary of pre-loaded file.")
    # Check if process list was loaded
    if not LOADED_PROCESSES or not LOADED_FILENAME or not LOADED_FILE_TYPE:
        await ctx.error("No Procmon XML file process list was pre-loaded via --load-file.")
        raise RuntimeError("Operation failed: No Procmon file process data is loaded.")
    if LOADED_FILE_TYPE != 'xml': # Should be redundant now
        await ctx.error(f"Loaded file type is '{LOADED_FILE_TYPE}', not 'xml'.")
        raise RuntimeError(f"Operation failed: Expected XML file type.")

    summary = {
        "loaded_filename": LOADED_FILENAME,
        "file_type": LOADED_FILE_TYPE,
        "compression": LOADED_COMPRESSION,
        "process_count": len(LOADED_PROCESSES),
        "event_count": "N/A (Streamed)", # Indicate events are not pre-counted
        "os_version": "N/A (XML)",
        "computer_name": "N/A (XML)",
        "is_64bit_os": None
    }
    try:
        # Could potentially derive some info from process list if needed
        await ctx.info(f"Successfully generated summary for {LOADED_FILENAME}.")
        return summary
    except Exception as e:
        await ctx.error(f"Error generating summary for {LOADED_FILENAME}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error generating summary: {e}")

@tool_decorator
async def query_events(
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
    Queries events by streaming the pre-loaded XML file, returning summaries.
    Use 'get_event_details' and 'get_event_stack_trace' with the event's 'sequence_number' for more info.

    Args:
        filter_process: Optional exact process name (case-insensitive).
        filter_operation: Optional operation name (case-insensitive).
        filter_result: Optional result string or hex '0x...' code.
        filter_path_contains: Optional string contained in the path (case-insensitive).
        filter_process_contains: Optional string contained in the process name (case-insensitive).
        limit: Maximum number of event summaries to return.

    Returns:
        List of dictionaries, each summarizing a matching event including 'sequence_number'.
    """
    await ctx.info(f"Request received to query event summaries via streaming. Filters: Process='{filter_process}', Op='{filter_operation}', Result='{filter_result}', PathContains='{filter_path_contains}', ProcessContains='{filter_process_contains}', Limit={limit}")
    if not LOADED_FILENAME or LOADED_FILE_TYPE != 'xml':
        await ctx.error(f"Query failed: No XML file is loaded or file type is incorrect ({LOADED_FILE_TYPE}).")
        raise TypeError("Operation requires an XML file to be pre-loaded.")
    if LOADED_PROCESSES is None: # Check if processes were loaded
         await ctx.warning("Process list not loaded; event enrichment might be incomplete.")
         # Allow to proceed, but enrichment in ProcmonEvent.from_xml_element will use empty dict

    try:
        abs_path = _get_stream_file_path()
        filtered_event_summaries = []
        count = 0

        # Pre-process filters (same as before)
        filter_result_lower_str = None; filter_result_int = None; is_hex_filter = False
        if filter_result:
            filter_result_lower = filter_result.lower()
            if filter_result_lower.startswith("0x"):
                try: filter_result_int = int(filter_result_lower, 16); is_hex_filter = True
                except ValueError: filter_result_lower_str = filter_result_lower
            else: filter_result_lower_str = filter_result_lower
        filter_process_lower = filter_process.lower() if filter_process else None
        filter_operation_lower = filter_operation.lower() if filter_operation else None
        filter_path_contains_lower = filter_path_contains.lower() if filter_path_contains else None
        filter_process_contains_lower = filter_process_contains.lower() if filter_process_contains else None

        # Stream events
        for event, _ in stream_procmon_events(abs_path, LOADED_COMPRESSION): # Ignore processes dict yielded
            if count >= limit:
                logger.debug(f"Query limit ({limit}) reached during streaming.")
                break

            # Apply filters directly on the streamed event object
            # Use safe_get_attributes for consistent access
            event_attrs = safe_get_attributes(event, ['process_name', 'operation', 'result', 'path', 'pid', 'timestamp', 'sequence_number'])
            process_name = event_attrs.get('process_name', '') or ''
            operation = event_attrs.get('operation', '') or ''
            result_val = event_attrs.get('result', '')
            path = event_attrs.get('path', '') or ''

            match = True
            if filter_process_lower is not None and process_name.lower() != filter_process_lower: match = False
            if match and filter_operation_lower is not None and operation.lower() != filter_operation_lower: match = False
            if match and filter_result is not None:
                # Apply result filter logic (same as before)
                if is_hex_filter:
                    event_result_int = None
                    if isinstance(result_val, int): event_result_int = result_val
                    elif isinstance(result_val, str):
                         if result_val.lower().startswith("0x"):
                              try: event_result_int = int(result_val, 16)
                              except ValueError: pass
                         elif result_val.isdigit() or (result_val.startswith('-') and result_val[1:].isdigit()):
                              try: event_result_int = int(result_val)
                              except ValueError: pass
                    if event_result_int is None or event_result_int != filter_result_int: match = False
                else:
                    if str(result_val).lower() != filter_result_lower_str: match = False
            if match and filter_path_contains_lower is not None and filter_path_contains_lower not in path.lower(): match = False
            if match and filter_process_contains_lower is not None and filter_process_contains_lower not in process_name.lower(): match = False

            if match:
                 # Create summary dict
                 event_summary = {
                     'sequence_number': event_attrs.get('sequence_number'), # Use sequence number instead of index
                     'timestamp': str(event_attrs.get('timestamp')),
                     'process_name': process_name,
                     'pid': event_attrs.get('pid'),
                     'operation': operation,
                     'path': path,
                     'result': result_val,
                 }
                 filtered_event_summaries.append(event_summary)
                 count += 1

        await ctx.info(f"Found {len(filtered_event_summaries)} matching event summaries via streaming {LOADED_FILENAME}.")
        return filtered_event_summaries

    except Exception as e:
        await ctx.error(f"Failed to query XML file {LOADED_FILENAME} via streaming: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error querying XML file via streaming: {e}")

@tool_decorator
async def get_event_details(sequence_number: int, ctx: Context) -> Dict[str, Any]:
    """
    Retrieves detailed properties for a specific event by its SequenceNumber
    by streaming the loaded XML file.

    Args:
        sequence_number: The SequenceNumber of the event to retrieve.

    Returns:
        A dictionary containing available properties of the specified event. Includes enriched process info.
        Raises ValueError if the sequence number is not found.
    """
    await ctx.info(f"Request received for details of event sequence number: {sequence_number}")
    if not LOADED_FILENAME or LOADED_FILE_TYPE != 'xml':
        await ctx.error(f"Get details failed: No XML file is loaded or file type incorrect.")
        raise TypeError("Operation requires an XML file to be pre-loaded.")
    if LOADED_PROCESSES is None:
         await ctx.warning("Process list not loaded; event enrichment might be incomplete.")

    try:
        abs_path = _get_stream_file_path()
        found_event: Optional[ProcmonEvent] = None

        await ctx.info(f"Streaming file {LOADED_FILENAME} to find sequence number {sequence_number}...")
        start_stream_time = time.time()
        processed_count = 0

        # Stream events to find the matching sequence number
        for event, _ in stream_procmon_events(abs_path, LOADED_COMPRESSION):
            processed_count += 1
            # Ensure sequence_number is compared as int
            event_seq_num = getattr(event, 'sequence_number', None)
            if event_seq_num is not None and event_seq_num == sequence_number:
                found_event = event
                break # Stop streaming once found
            # Log progress occasionally for long searches
            if processed_count % 500000 == 0:
                 await ctx.info(f" Scanned {processed_count} events...")


        end_stream_time = time.time()
        logger.info(f"Scan for sequence number {sequence_number} took {end_stream_time - start_stream_time:.2f} seconds, scanned {processed_count} events.")

        if not found_event:
            await ctx.error(f"Event with SequenceNumber {sequence_number} not found in {LOADED_FILENAME}.")
            raise ValueError(f"Event with SequenceNumber {sequence_number} not found.")

        # Get details from the found event object
        event_attributes = [
            'timestamp', 'pid', 'tid', 'parent_pid', 'operation', 'path', 'result', 'duration',
            'detail', 'category', 'user_sid', 'session_id', 'authentication_id',
            'is_64bit_process', 'process_name', 'image_path', 'command_line', 'architecture',
            'integrity', 'virtualized', 'sequence_number', 'relative_time', 'completion_time',
            'stack' # Get raw stack for stack trace tool
        ]
        details = safe_get_attributes(found_event, event_attributes)
        details['sequence_number'] = sequence_number # Ensure it's there

        # Create process summary
        process_summary_fields = ['pid', 'process_name', 'image_path', 'parent_pid', 'command_line', 'user_sid', 'is_64bit_process', 'architecture', 'integrity', 'virtualized']
        details['process_details_summary'] = {k: details.get(k) for k in process_summary_fields if k in details and details[k] is not None}

        # Remove raw stack object from general details
        if 'stack' in details: del details['stack']

        # Ensure key fields are present
        for key in ['pid', 'process_name', 'operation', 'path', 'result', 'timestamp']:
             if key not in details: details[key] = None

        await ctx.info(f"Successfully retrieved details for event sequence number {sequence_number}.")
        return details

    except ValueError as e: # Catch specific ValueError for not found
         raise e
    except Exception as e:
        await ctx.error(f"Failed to get details for event sequence {sequence_number} in {LOADED_FILENAME}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving event details via streaming: {e}")

@tool_decorator
async def get_event_stack_trace(sequence_number: int, ctx: Context) -> List[Dict[str, Any]]:
    """
    Retrieves the detailed call stack trace for a specific event by its SequenceNumber
    by streaming the loaded XML file.

    Args:
        sequence_number: The SequenceNumber of the event.

    Returns:
        A list of dictionaries, each representing a stack frame ('depth', 'address', 'path', 'location').
        Empty list if no stack trace or event not found.
    """
    await ctx.info(f"Request received for stack trace of event sequence number: {sequence_number}")
    if not LOADED_FILENAME or LOADED_FILE_TYPE != 'xml':
        await ctx.error(f"Get stack trace failed: No XML file is loaded or file type incorrect.")
        raise TypeError("Operation requires an XML file to be pre-loaded.")

    try:
        abs_path = _get_stream_file_path()
        found_event: Optional[ProcmonEvent] = None

        await ctx.info(f"Streaming file {LOADED_FILENAME} to find sequence number {sequence_number} for stack trace...")
        start_stream_time = time.time()
        processed_count = 0

        # Stream events to find the matching sequence number
        for event, _ in stream_procmon_events(abs_path, LOADED_COMPRESSION):
            processed_count += 1
            # Ensure sequence_number is compared as int
            event_seq_num = getattr(event, 'sequence_number', None)
            if event_seq_num is not None and event_seq_num == sequence_number:
                found_event = event
                break
            if processed_count % 500000 == 0: await ctx.info(f" Scanned {processed_count} events...")

        end_stream_time = time.time()
        logger.info(f"Scan for sequence number {sequence_number} took {end_stream_time - start_stream_time:.2f} seconds, scanned {processed_count} events.")

        detailed_stack = []
        if found_event:
            stack_frames_raw = getattr(found_event, 'stack', None)
            if isinstance(stack_frames_raw, list):
                for frame in stack_frames_raw:
                    if isinstance(frame, StackFrame):
                        detailed_stack.append(frame.to_dict())
                    else: logger.warning(f"Non-StackFrame object in stack for event {sequence_number}: {frame}")
            elif stack_frames_raw is not None:
                 logger.warning(f"Stack trace for event {sequence_number} is not a list: {type(stack_frames_raw)}")
        else:
             await ctx.warning(f"Event with SequenceNumber {sequence_number} not found, cannot retrieve stack trace.")
             # Return empty list if event not found

        await ctx.info(f"Successfully retrieved stack trace (length: {len(detailed_stack)}) for event sequence number {sequence_number}.")
        logger.debug(f"Detailed stack trace for event {sequence_number}: {detailed_stack}")
        return detailed_stack

    except Exception as e:
        await ctx.error(f"Failed to get stack trace for event sequence {sequence_number} in {LOADED_FILENAME}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving event stack trace via streaming: {e}")

@tool_decorator
async def list_processes(ctx: Context) -> List[Dict[str, Any]]:
    """
    Lists summary information (pid, process_name, image_path) for all unique processes
    found in the pre-parsed process list from the loaded XML file.

    Returns:
        A list of dictionaries, each summarizing a unique process.
    """
    await ctx.info(f"Request received to list processes from pre-loaded process list.")
    if LOADED_PROCESSES is None or not LOADED_FILENAME or LOADED_FILE_TYPE != 'xml':
        await ctx.error(f"List processes failed: Process list not loaded or file type incorrect.")
        raise TypeError("Operation requires an XML file's process list to be pre-loaded.")

    try:
        process_list = list(LOADED_PROCESSES.values()) # Get list of ProcessInfo objects
        logger.debug(f"Listing {len(process_list)} processes from loaded data.")
        process_summaries = []
        summary_attributes = ['pid', 'process_name', 'image_path']

        for process_obj in process_list:
            summary = safe_get_attributes(process_obj, summary_attributes)
            if summary.get('pid') is None:
                logger.warning(f"Process object missing PID in loaded list: {process_obj}")
                continue
            for attr in summary_attributes:
                 if attr not in summary: summary[attr] = None
            process_summaries.append(summary)

        await ctx.info(f"Generated {len(process_summaries)} process summaries from {LOADED_FILENAME}.")
        return process_summaries
    except Exception as e:
        await ctx.error(f"Failed to list processes from loaded data: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error listing processes: {e}")

@tool_decorator
async def get_process_details(pid: int, ctx: Context) -> Dict[str, Any]:
    """
    Retrieves detailed information for a specific process (by PID) from the pre-parsed
    process list loaded from the XML file.

    Args: pid: The Process ID.
    Returns: Dictionary containing detailed properties. Error if PID not found in loaded list.
    """
    await ctx.info(f"Request received for details of PID: {pid} from loaded process list.")
    if LOADED_PROCESSES is None or not LOADED_FILENAME or LOADED_FILE_TYPE != 'xml':
        await ctx.error(f"Get process details failed: Process list not loaded or file type incorrect.")
        raise TypeError("Operation requires an XML file's process list to be pre-loaded.")

    try:
        process_obj: Optional[ProcessInfo] = None
        # Efficient lookup now that LOADED_PROCESSES is keyed by process_index
        # We need to iterate to find by PID
        for proc in LOADED_PROCESSES.values():
            if proc.pid == pid:
                process_obj = proc
                break

        logger.debug(f"Looking for PID {pid} in loaded process list ({len(LOADED_PROCESSES)} items). Found: {process_obj is not None}")

        if not process_obj:
            await ctx.error(f"Process with PID {pid} not found in the loaded process list from {LOADED_FILENAME}.")
            raise ValueError(f"Process with PID {pid} not found in pre-loaded list.")

        details = dataclasses.asdict(process_obj)
        details['pid'] = process_obj.pid
        details['parent_pid'] = process_obj.parent_pid
        details['user_sid'] = process_obj.user_sid
        details['is_64bit_process'] = process_obj.is_64bit
        for key in ['pid', 'parent_pid', 'process_name', 'image_path', 'command_line']:
            if key not in details: details[key] = None
        if 'parent_process_index' in details: del details['parent_process_index']
        details['modules_summary'] = None # No modules in XML

        await ctx.info(f"Successfully retrieved details for PID {pid} from loaded list.")
        return details

    except ValueError as e: raise e # Re-raise not found error
    except Exception as e:
        await ctx.error(f"Failed to get details for PID {pid} from loaded list: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving process details: {e}")

@tool_decorator
async def get_metadata(ctx: Context) -> Dict[str, Any]:
    """ Retrieves metadata for the loaded XML file (primarily process count). """
    await ctx.info(f"Request received for metadata from XML file.")
    if LOADED_PROCESSES is None or not LOADED_FILENAME or LOADED_FILE_TYPE != 'xml':
        await ctx.error(f"Get metadata failed: Process list not loaded or file type incorrect.")
        raise TypeError("Operation requires an XML file's process list to be pre-loaded.")

    try:
        metadata = {
             "loaded_filename": LOADED_FILENAME, "file_type": LOADED_FILE_TYPE,
             "compression": LOADED_COMPRESSION, "header_found": False,
             "message": "Header info N/A for XML. Event count requires streaming.",
             "os_version": None, "computer_name": None,
             "process_count_loaded": len(LOADED_PROCESSES),
             "event_count_loaded": "N/A (Streamed)"
        }
        await ctx.info(f"Successfully retrieved metadata from {LOADED_FILENAME}.")
        logger.debug(f"File metadata retrieved: {metadata}")
        return metadata
    except Exception as e:
        await ctx.error(f"Failed to get metadata from {LOADED_FILENAME}: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error retrieving metadata: {e}")

# --- Analysis Tools (Streaming) ---

@tool_decorator
async def count_events_by_process(ctx: Context) -> Dict[str, int]:
    """ Counts events per process name by streaming the loaded XML file. """
    await ctx.info(f"Request received to count events by process name via streaming.")
    if not LOADED_FILENAME or LOADED_FILE_TYPE != 'xml':
        await ctx.error("Operation failed: No XML file loaded.")
        raise TypeError("Operation requires an XML file to be pre-loaded.")

    try:
        abs_path = _get_stream_file_path()
        event_counts = defaultdict(int)
        total_events = 0

        for event, _ in stream_procmon_events(abs_path, LOADED_COMPRESSION):
            total_events += 1
            process_name = safe_get_attributes(event, ['process_name']).get('process_name', 'Unknown') or 'Unknown'
            event_counts[process_name] += 1
            if total_events % 500000 == 0: await ctx.info(f" Counted {total_events} events...")


        await ctx.info(f"Counted {total_events} total events for {len(event_counts)} processes in {LOADED_FILENAME}.")
        logger.debug(f"Event counts by process: {dict(event_counts)}")
        return dict(event_counts)
    except Exception as e:
        await ctx.error(f"Failed to count events by process via streaming: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error counting events by process: {e}")

@tool_decorator
async def summarize_operations_by_process(process_name_filter: str, ctx: Context) -> Dict[str, int]:
    """ Counts operations for a specific process name (case-sensitive) by streaming the XML file. """
    await ctx.info(f"Request to summarize operations for process: {process_name_filter} via streaming.")
    if not LOADED_FILENAME or LOADED_FILE_TYPE != 'xml':
        await ctx.error("Operation failed: No XML file loaded.")
        raise TypeError("Operation requires an XML file to be pre-loaded.")
    if not process_name_filter:
        await ctx.error("Process name filter cannot be empty."); raise ValueError("Process name filter is required.")

    try:
        abs_path = _get_stream_file_path()
        operation_counts = defaultdict(int)
        event_count_for_process = 0

        for event, _ in stream_procmon_events(abs_path, LOADED_COMPRESSION):
            process_name = safe_get_attributes(event, ['process_name']).get('process_name', '') or ''
            if process_name == process_name_filter: # Case-sensitive match
                event_count_for_process += 1
                operation = safe_get_attributes(event, ['operation']).get('operation', 'Unknown') or 'Unknown'
                operation_counts[operation] += 1
                if event_count_for_process % 100000 == 0: await ctx.info(f" Found {event_count_for_process} events for '{process_name_filter}'...")


        await ctx.info(f"Summarized {len(operation_counts)} ops for '{process_name_filter}' ({event_count_for_process} events) in {LOADED_FILENAME}.")
        if event_count_for_process == 0: await ctx.warning(f"No events found for process name '{process_name_filter}'.")
        return dict(operation_counts)
    except Exception as e:
        await ctx.error(f"Failed to summarize operations for '{process_name_filter}' via streaming: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error summarizing operations: {e}")

@tool_decorator
async def find_events_by_result(result_filter: str, limit: int = 50, *, ctx: Context) -> List[Dict[str, Any]]:
    """ Finds event summaries matching a result value (string/hex) by streaming the XML file. """
    await ctx.info(f"Request received to find events by result: '{result_filter}', Limit={limit} via streaming.")
    if not LOADED_FILENAME or LOADED_FILE_TYPE != 'xml':
        await ctx.error("Operation failed: No XML file loaded.")
        raise TypeError("Operation requires an XML file to be pre-loaded.")
    if not result_filter:
        await ctx.error("Result filter cannot be empty."); raise ValueError("Result filter is required.")

    try:
        abs_path = _get_stream_file_path()
        filtered_event_summaries = []
        count = 0

        # Pre-process filter
        filter_result_lower_str=None; filter_result_int=None; is_hex_filter=False
        if result_filter.lower().startswith("0x"):
            try: filter_result_int=int(result_filter,16); is_hex_filter=True
            except ValueError: filter_result_lower_str=result_filter.lower()
        else: filter_result_lower_str=result_filter.lower()

        for event, _ in stream_procmon_events(abs_path, LOADED_COMPRESSION):
            if count >= limit: break

            result_val = safe_get_attributes(event, ['result']).get('result')
            match = False
            # Apply result filter logic
            if is_hex_filter:
                event_result_int=None
                if isinstance(result_val,int): event_result_int=result_val
                elif isinstance(result_val,str):
                    if result_val.lower().startswith("0x"):
                        try: event_result_int=int(result_val,16)
                        except ValueError: pass
                    elif result_val.isdigit() or (result_val.startswith('-') and result_val[1:].isdigit()):
                        try: event_result_int=int(result_val)
                        except ValueError: pass
                if event_result_int is not None and event_result_int == filter_result_int: match=True
            elif filter_result_lower_str is not None:
                if str(result_val).lower() == filter_result_lower_str: match=True

            if match:
                # Create summary
                event_attrs = safe_get_attributes(event, ['timestamp', 'pid', 'process_name', 'operation', 'path', 'sequence_number'])
                event_summary={'sequence_number':event_attrs.get('sequence_number'), 'timestamp':str(event_attrs.get('timestamp')),'process_name':event_attrs.get('process_name','')or'','pid':event_attrs.get('pid'),'operation':event_attrs.get('operation',''),'path':event_attrs.get('path',''),'result':result_val}
                filtered_event_summaries.append(event_summary)
                count+=1

        await ctx.info(f"Found {len(filtered_event_summaries)} events matching result '{result_filter}' via streaming {LOADED_FILENAME}.")
        return filtered_event_summaries
    except Exception as e:
        await ctx.error(f"Failed to find events by result '{result_filter}' via streaming: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error finding events by result: {e}")

@tool_decorator
async def get_process_tree(ctx: Context) -> Dict[int, Dict[str, Any]]:
    """ Constructs the process tree from the pre-loaded process list. """
    await ctx.info(f"Request received to get process tree from loaded list.")
    if LOADED_PROCESSES is None or not LOADED_FILENAME or LOADED_FILE_TYPE != 'xml':
        await ctx.error("Operation failed: Process list not loaded or file type incorrect.")
        raise TypeError("Operation requires an XML file's process list to be pre-loaded.")

    try:
        # --- Tree building logic remains the same (uses LOADED_PROCESSES) ---
        process_list = list(LOADED_PROCESSES.values())
        if not process_list: await ctx.warning("No process info available for tree."); return {}
        process_map:Dict[int,Dict[str,Any]]={}; all_pids=set()
        for p_obj in process_list:
            pid=p_obj.pid # Access directly
            if pid is not None: process_map[pid]={'obj':p_obj,'children':[]}; all_pids.add(pid)
            else: logger.warning(f"Skipping process object without PID: {p_obj}")
        roots=[]
        for pid,p_data in process_map.items():
            parent_pid=p_data['obj'].parent_pid # Access directly
            if parent_pid is not None and parent_pid in all_pids:
                if parent_pid!=pid:
                    if parent_pid in process_map: process_map[parent_pid]['children'].append(pid)
                    else: logger.warning(f"PID {pid} parent {parent_pid} not in map."); roots.append(pid)
                else: logger.warning(f"PID {pid} is own parent."); roots.append(pid)
            else: roots.append(pid)
        roots=sorted(list(dict.fromkeys(roots)))

        def build_tree_node(pid_to_build:int)->Optional[Dict[str,Any]]:
            p_data=process_map.get(pid_to_build)
            if not p_data: return None
            p_obj = p_data['obj']
            node={'pid':pid_to_build,'process_name':p_obj.process_name or 'Unknown','image_path':p_obj.image_path}
            child_pids=sorted(p_data.get('children',[]))
            if child_pids:
                node['children']={}
                for child_pid in child_pids:
                    child_node=build_tree_node(child_pid)
                    if child_node: node['children'][child_pid]=child_node
            return node

        process_tree_output={}
        for root_pid in roots:
            root_node=build_tree_node(root_pid)
            if root_node: process_tree_output[root_pid]=root_node
        await ctx.info(f"Constructed process tree with {len(roots)} root(s) from loaded list.")
        return process_tree_output
    except Exception as e:
        await ctx.error(f"Failed to build process tree from loaded list: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error building process tree: {e}")


# --- Main Execution Block ---
if __name__ == "__main__":
    if not MCP_SDK_AVAILABLE:
        print("Error: Model Context Protocol SDK (modelcontextprotocol) is not installed.")
        exit(1)

    parser = argparse.ArgumentParser(description="MCP Server for analyzing Procmon XML files (.xml, .xml.gz/bz2/xz) via streaming.")
    parser.add_argument("--allowed-dir", required=True, help="REQUIRED: Secure base directory containing Procmon XML files.")
    parser.add_argument("--load-file", required=True, # Make load-file required for streaming
                        help="REQUIRED: XML file (.xml, .xml.gz/bz2/xz) relative to --allowed-dir (no subdirs) to analyze.")
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

    # Load only processes at startup
    try:
        logger.info(f"Attempting to validate and load process list from: {args.load_file}")
        # load_and_validate_file now stores processes globally and returns them too
        loaded_procs, file_type, compression = load_and_validate_file(ALLOWED_DIR_CONFIG, args.load_file)

        if file_type != 'xml' or loaded_procs is None: # Check if loading succeeded
             logger.critical(f"Initial file processing failed for '{args.load_file}'. Check logs.")
             exit(1)

        logger.info(f"Successfully validated file and loaded {len(loaded_procs)} processes for: {args.load_file}")
        if args.debug:
             logger.debug(f"XML Load Summary: Processes={len(loaded_procs)}, Compression={compression}, Events=Streamed")

    except (ValueError, PermissionError, FileNotFoundError, TypeError, IndexError) as e:
        logger.critical(f"Error during initial file processing ('{args.load_file}'): {e}")
        exit(1)
    except ET_impl.XMLSyntaxError as e:
         logger.critical(f"XML Syntax Error during initial file processing ('{args.load_file}'): {e}")
         exit(1)
    except RuntimeError as e:
         logger.critical(f"Runtime Error during initial file processing ('{args.load_file}'): {e}")
         exit(1)
    except Exception as e:
        logger.critical(f"An unexpected error occurred during initial file processing ('{args.load_file}'): {e}", exc_info=args.debug)
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
