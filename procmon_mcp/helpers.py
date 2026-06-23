"""XML helper functions, regex utilities, timestamp parsing, and formatting."""
import re
import logging
import ipaddress
from datetime import datetime, timezone, time as dt_time
from typing import Optional, Dict, Any

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


def repair_mojibake(s: Optional[str]) -> Optional[str]:
    """Repairs text double-encoded by Procmon's XML export.

    Procmon exports non-ASCII names by taking the real UTF-8 bytes, treating each
    byte as Latin-1, and UTF-8-encoding again. The result decodes to mojibake
    (e.g. the bytes for ``温度スイッチ.exe`` come through as ``æ¸©åº¦…``). Undo it by
    re-encoding the string as Latin-1 (recovering the original bytes) and decoding
    those as UTF-8.

    This is conservative: it only repairs strings whose every codepoint is in the
    Latin-1 range AND whose Latin-1 bytes form valid (multi-byte) UTF-8 — the exact
    fingerprint of the double-encoding. Pure-ASCII text and correctly-stored names
    (e.g. ``café.exe``, whose ``é`` is not valid standalone UTF-8) are returned
    unchanged.
    """
    if not s or s.isascii():
        return s
    try:
        repaired = s.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return s
    return repaired if repaired != s else s


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
# The port may be numeric (443) OR a resolved service name (domain, https),
# which Procmon emits for well-known ports unless "Show resolved network
# addresses" is disabled.
_ENDPOINT_REGEX = re.compile(r".* -> \[?([A-Za-z0-9._:\-]+)\]?:([A-Za-z0-9\-]+)$")


def _host_is_ip(host: str) -> bool:
    """True if `host` is a literal IPv4/IPv6 address rather than a hostname."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def parse_network_endpoint_parts(path_str: Optional[str]) -> Optional[Dict[str, Any]]:
    """Parses a Procmon network Path field into structured remote-endpoint parts.

    Returns a dict with keys ``endpoint`` (``host:port``), ``host``, ``port``,
    ``ip`` (set when the host is a literal IP, else None), and ``hostname`` (set
    when the host is a DNS name, else None). Returns None when the path has no
    recognisable remote endpoint.
    """
    if not path_str:
        return None
    match = _ENDPOINT_REGEX.match(path_str)
    if not match:
        return None
    host, port = match.group(1), match.group(2)
    is_ip = _host_is_ip(host)
    return {
        "endpoint": f"{host}:{port}",
        "host": host,
        "port": port,
        "ip": host if is_ip else None,
        "hostname": None if is_ip else host,
    }


def parse_network_endpoint(path_str: Optional[str]) -> Optional[str]:
    """Extracts the remote 'host:port' endpoint from a Procmon network Path field.

    Returns None if the path does not contain a recognisable remote endpoint.
    """
    parts = parse_network_endpoint_parts(path_str)
    return parts["endpoint"] if parts else None


# Procmon network operations encode a direction in their name.
def network_direction(operation: Optional[str]) -> Optional[str]:
    """Infers the connection direction ('connect'/'send'/'receive') from an op name."""
    if not operation:
        return None
    op = operation.lower()
    if "connect" in op:
        return "connect"
    if "send" in op:
        return "send"
    if "receive" in op:
        return "receive"
    if "accept" in op:
        return "accept"
    if "disconnect" in op:
        return "disconnect"
    return None


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
