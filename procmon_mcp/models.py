"""Data structure classes for ProcmonMCP."""
import dataclasses
import logging
from collections import defaultdict
from typing import List, Dict, Any, Optional

from .compat import ET_impl
from .helpers import find_text_func

logger = logging.getLogger(__name__)


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
        return self.id_to_str[id_val]

    def lookup_id(self, s: Optional[str]) -> Optional[int]:
        """Looks up an ID from its string. Does NOT add new strings."""
        if s is None:
            return None
        return self.str_to_id.get(s)


@dataclasses.dataclass
class StackFrame:
    """Represents a single frame in a call stack parsed from a <frame> element."""
    depth: Optional[int] = None
    address: Optional[str] = None
    path: Optional[str] = None
    location: Optional[str] = None

    @classmethod
    def from_xml_element(cls, elem: ET_impl.Element) -> 'StackFrame':
        """Parses a <frame> XML element into a StackFrame object, ignoring namespaces."""
        depth_text = find_text_func(elem, 'depth')
        try:
            depth = int(depth_text) if depth_text and depth_text.isdigit() else None
        except (ValueError, TypeError):
            depth = None
        address = find_text_func(elem, 'address')
        path = find_text_func(elem, 'path')
        location = find_text_func(elem, 'location')
        return cls(depth=depth, address=address, path=path, location=location)

    def to_dict(self) -> Dict[str, Any]:
        """Convert StackFrame to dictionary for tool output."""
        return dataclasses.asdict(self)

    def to_optimized_list(self, path_interner: 'StringInterner', location_interner: 'StringInterner') -> list:
        """Converts StackFrame to a more compact list representation for storage using interners."""
        return [
            self.depth,
            self.address,
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
    def pid(self):
        return self.process_id

    @property
    def parent_pid(self):
        return self.parent_process_id

    @property
    def user_sid(self):
        return self.owner

    @staticmethod
    def _safe_text_to_int(text: Optional[str]) -> Optional[int]:
        """Safely converts text (decimal or hex '0x...') to int, returning None on failure."""
        if text is None:
            return None
        text = text.strip()
        if not text:
            return None
        try:
            if text.startswith(('0x', '0X')):
                return int(text, 16)
            else:
                return int(text)
        except (ValueError, TypeError):
            logger.debug(f"Failed to convert text '{text}' to int.")
            return None

    @staticmethod
    def _safe_text_to_bool(text: Optional[str]) -> Optional[bool]:
        """Safely converts text ('1' or '0') to bool, returning None otherwise."""
        if text:
            text = text.strip()
            if text == '1':
                return True
            if text == '0':
                return False
        return None

    @classmethod
    def from_xml_element(cls, elem: ET_impl.Element) -> 'ProcessInfo':
        """Parses a <process> XML element into a ProcessInfo object, ignoring namespaces."""
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


@dataclasses.dataclass
class ProcmonLogData:
    """Holds the loaded and optimized data from a Procmon XML file."""
    # Configuration
    loaded_filename: Optional[str] = None
    loaded_compression: Optional[str] = None
    load_stack_traces: bool = True
    load_extra_data: bool = True
    # True when this object was deserialized from the on-disk cache rather than
    # parsed from XML this run. Not part of the cached payload's identity.
    loaded_from_cache: bool = False

    # Loaded Data
    processes_by_index: Dict[int, ProcessInfo] = dataclasses.field(default_factory=dict)
    processes_by_pid: Dict[int, ProcessInfo] = dataclasses.field(default_factory=dict)
    events: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    interners: Dict[str, StringInterner] = dataclasses.field(default_factory=dict)

    # Indices
    pname_id_index: Dict[int, List[int]] = dataclasses.field(default_factory=lambda: defaultdict(list))
    op_id_index: Dict[int, List[int]] = dataclasses.field(default_factory=lambda: defaultdict(list))
    pid_index: Dict[int, List[int]] = dataclasses.field(default_factory=lambda: defaultdict(list))
    path_id_index: Dict[int, List[int]] = dataclasses.field(default_factory=lambda: defaultdict(list))

    def get_string(self, interner_key: str, id_val: Optional[int]) -> Optional[str]:
        """Looks up a string from its ID using the stored interners."""
        if id_val is None:
            return None
        interner = self.interners.get(interner_key)
        if interner:
            return interner.get_str(id_val)
        logger.warning(f"Interner '{interner_key}' not found during string lookup.")
        return f"<Unknown Interner:{interner_key}_ID:{id_val}>"

    def get_id(self, interner_key: str, s: Optional[str]) -> Optional[int]:
        """Looks up an ID from its string using the stored interners. Does NOT add new strings."""
        if s is None:
            return None
        interner = self.interners.get(interner_key)
        if interner:
            return interner.lookup_id(s)
        logger.warning(f"Interner '{interner_key}' not found during ID lookup.")
        return None

    def is_loaded(self) -> bool:
        """Checks if data appears to be loaded."""
        return self.events is not None and self.loaded_filename is not None
