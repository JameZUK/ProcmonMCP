"""XML helper functions, regex utilities, timestamp parsing, and formatting."""
import re
import logging
from datetime import datetime, timezone, time as dt_time
from typing import Optional

from .compat import ET_impl
from .constants import PROCMON_TIMESTAMP_FORMAT, BASE_DATE, MAX_REGEX_LEN

logger = logging.getLogger(__name__)


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


# --- XML Helper Functions ---
def _strip_namespace(tag: str) -> str:
    """Helper to remove namespace from tag string if present."""
    if '}' in tag:
        try:
            return tag.split('}', 1)[1]
        except IndexError:
            return tag
    return tag


def _find_child_ignore_ns(elem: ET_impl.Element, tag_name: str) -> Optional[ET_impl.Element]:
    """Finds the first direct child element with the given tag name, ignoring namespaces."""
    for child_elem in elem:
        child_tag = child_elem.tag
        if '}' in child_tag:
            try:
                child_tag_stripped = child_tag.split('}', 1)[1]
            except IndexError:
                child_tag_stripped = child_tag
        else:
            child_tag_stripped = child_tag

        if child_tag_stripped == tag_name:
            return child_elem
    return None


def _find_text_ignore_ns(elem: ET_impl.Element, tag_name: str) -> Optional[str]:
    """Finds the text of the first direct child element with the given tag name, ignoring namespaces."""
    child = _find_child_ignore_ns(elem, tag_name)
    return child.text.strip() if child is not None and child.text else None


# Always use the faster iteration-based text finder (profiling showed XPath was a bottleneck)
find_text_func = _find_text_ignore_ns


def _clear_elem(elem: ET_impl.Element):
    """Helper to clear element memory using lxml/ET specific methods."""
    elem.clear()


# --- Timestamp Parsing ---
def _parse_timestamp_str(ts_str: Optional[str]) -> Optional[float]:
    """
    Parses HH:MM:SS.ffffff[f...] string to a UTC float timestamp relative to BASE_DATE.
    Handles arbitrary digits in fractional seconds by truncating to 6.

    WARNING: This function does NOT handle midnight rollovers by itself.
    The main loading function contains inline logic to handle rollovers.
    This function is used for time-only filter parsing in _iter_filtered_event_indices.
    """
    if ts_str is None:
        return None
    try:
        parts = ts_str.split('.', 1)
        time_part = parts[0]
        if len(parts) > 1:
            fractional_part = parts[1][:6].ljust(6, '0')
        else:
            fractional_part = "000000"
        ts_str_corrected = f"{time_part}.{fractional_part}"
        parsed_time: dt_time = datetime.strptime(ts_str_corrected, PROCMON_TIMESTAMP_FORMAT).time()
        full_dt = datetime.combine(BASE_DATE.date(), parsed_time, tzinfo=timezone.utc)
        return full_dt.timestamp()
    except (ValueError, TypeError, IndexError) as e:
        logger.warning(f"Could not parse timestamp string '{ts_str}': {e}")
        return None


# --- Network Endpoint Parsing ---
# Procmon renders network Path fields as "<local> -> <remote>", where an
# endpoint is "host:port", "ipv4:port", or "[ipv6]:port". The host class covers
# IPv4/IPv6 literals as well as DNS hostnames (letters, digits, dot, hyphen).
_ENDPOINT_REGEX = re.compile(r".* -> \[?([A-Za-z0-9._:\-]+)\]?:(\d+)")


def parse_network_endpoint(path_str: Optional[str]) -> Optional[str]:
    """Extracts the remote 'host:port' endpoint from a Procmon network Path field.

    Returns None if the path does not contain a recognisable remote endpoint.
    """
    if not path_str:
        return None
    match = _ENDPOINT_REGEX.match(path_str)
    if not match:
        return None
    return f"{match.group(1)}:{match.group(2)}"


# --- Byte Formatting ---
def _format_bytes(bytes_val: int) -> str:
    """Formats bytes into a human-readable string (KB, MB, GB)."""
    if bytes_val < 1024:
        return f"{bytes_val} Bytes"
    elif bytes_val < 1024**2:
        return f"{bytes_val / 1024:.2f} KB"
    elif bytes_val < 1024**3:
        return f"{bytes_val / (1024**2):.2f} MB"
    else:
        return f"{bytes_val / (1024**3):.2f} GB"
