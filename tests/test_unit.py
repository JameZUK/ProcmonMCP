"""Unit tests for ProcmonMCP core components."""
import sys
import os
import re
import pytest
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

# Add parent directory to path so we can import the package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import procmon_mcp

# --- StringInterner Tests ---

class TestStringInterner:
    def test_get_id_returns_int_for_new_string(self):
        si = procmon_mcp.StringInterner()
        result = si.get_id("hello")
        assert isinstance(result, int)
        assert result == 0

    def test_get_id_returns_same_id_for_same_string(self):
        si = procmon_mcp.StringInterner()
        id1 = si.get_id("hello")
        id2 = si.get_id("hello")
        assert id1 == id2

    def test_get_id_returns_different_ids_for_different_strings(self):
        si = procmon_mcp.StringInterner()
        id1 = si.get_id("hello")
        id2 = si.get_id("world")
        assert id1 != id2

    def test_get_id_returns_none_for_none(self):
        si = procmon_mcp.StringInterner()
        assert si.get_id(None) is None

    def test_get_str_returns_original_string(self):
        si = procmon_mcp.StringInterner()
        id_val = si.get_id("test_string")
        assert si.get_str(id_val) == "test_string"

    def test_get_str_returns_none_for_none(self):
        si = procmon_mcp.StringInterner()
        assert si.get_str(None) is None

    def test_get_str_returns_none_for_invalid_id(self):
        si = procmon_mcp.StringInterner()
        si.get_id("hello")
        assert si.get_str(999) is None
        assert si.get_str(-1) is None

    def test_lookup_id_finds_existing(self):
        si = procmon_mcp.StringInterner()
        id_val = si.get_id("existing")
        assert si.lookup_id("existing") == id_val

    def test_lookup_id_returns_none_for_missing(self):
        si = procmon_mcp.StringInterner()
        assert si.lookup_id("nonexistent") is None

    def test_lookup_id_returns_none_for_none(self):
        si = procmon_mcp.StringInterner()
        assert si.lookup_id(None) is None

    def test_lookup_id_does_not_add_string(self):
        si = procmon_mcp.StringInterner()
        si.lookup_id("should_not_add")
        assert si.next_id == 0

    def test_sequential_ids(self):
        si = procmon_mcp.StringInterner()
        assert si.get_id("a") == 0
        assert si.get_id("b") == 1
        assert si.get_id("c") == 2
        assert si.next_id == 3

    def test_empty_string(self):
        si = procmon_mcp.StringInterner()
        id_val = si.get_id("")
        assert id_val == 0
        assert si.get_str(id_val) == ""


# --- _strip_namespace Tests ---

class TestStripNamespace:
    def test_strips_namespace(self):
        assert procmon_mcp._strip_namespace("{http://example.com}tag") == "tag"

    def test_no_namespace(self):
        assert procmon_mcp._strip_namespace("tag") == "tag"

    def test_empty_namespace(self):
        assert procmon_mcp._strip_namespace("{}tag") == "tag"

    def test_complex_namespace(self):
        assert procmon_mcp._strip_namespace("{urn:schemas:procmon}event") == "event"

    def test_empty_string(self):
        assert procmon_mcp._strip_namespace("") == ""


# --- _find_text_ignore_ns Tests ---

class TestFindTextIgnoreNs:
    def test_finds_text_no_namespace(self):
        root = ET.fromstring("<root><child>value</child></root>")
        assert procmon_mcp._find_text_ignore_ns(root, "child") == "value"

    def test_finds_text_with_namespace(self):
        root = ET.fromstring('<root xmlns:ns="http://test">'
                             '<ns:child>value</ns:child></root>')
        assert procmon_mcp._find_text_ignore_ns(root, "child") == "value"

    def test_returns_none_for_missing(self):
        root = ET.fromstring("<root><other>value</other></root>")
        assert procmon_mcp._find_text_ignore_ns(root, "missing") is None

    def test_returns_none_for_empty_text(self):
        root = ET.fromstring("<root><child></child></root>")
        assert procmon_mcp._find_text_ignore_ns(root, "child") is None

    def test_strips_whitespace(self):
        root = ET.fromstring("<root><child>  value  </child></root>")
        assert procmon_mcp._find_text_ignore_ns(root, "child") == "value"


# --- _parse_timestamp_str Tests ---

class TestParseTimestampStr:
    def test_valid_timestamp(self):
        result = procmon_mcp._parse_timestamp_str("12:30:45.123456")
        assert result is not None
        assert isinstance(result, float)

    def test_none_input(self):
        assert procmon_mcp._parse_timestamp_str(None) is None

    def test_invalid_format(self):
        assert procmon_mcp._parse_timestamp_str("not_a_time") is None

    def test_truncates_extra_fractional_digits(self):
        # Procmon can produce >6 fractional digits
        result = procmon_mcp._parse_timestamp_str("12:30:45.1234567890")
        assert result is not None

    def test_pads_short_fractional(self):
        result = procmon_mcp._parse_timestamp_str("12:30:45.12")
        assert result is not None

    def test_no_fractional(self):
        result = procmon_mcp._parse_timestamp_str("12:30:45")
        assert result is not None

    def test_midnight(self):
        result = procmon_mcp._parse_timestamp_str("00:00:00.000000")
        assert result is not None

    def test_end_of_day(self):
        result = procmon_mcp._parse_timestamp_str("23:59:59.999999")
        assert result is not None

    def test_monotonically_increasing(self):
        t1 = procmon_mcp._parse_timestamp_str("10:00:00.000000")
        t2 = procmon_mcp._parse_timestamp_str("10:00:01.000000")
        assert t2 > t1


# --- ProcessInfo Safe Conversion Tests ---

class TestProcessInfoSafeConversions:
    def test_safe_text_to_int_decimal(self):
        assert procmon_mcp.ProcessInfo._safe_text_to_int("42") == 42

    def test_safe_text_to_int_hex(self):
        assert procmon_mcp.ProcessInfo._safe_text_to_int("0xFF") == 255

    def test_safe_text_to_int_hex_upper(self):
        assert procmon_mcp.ProcessInfo._safe_text_to_int("0XFF") == 255

    def test_safe_text_to_int_none(self):
        assert procmon_mcp.ProcessInfo._safe_text_to_int(None) is None

    def test_safe_text_to_int_empty(self):
        assert procmon_mcp.ProcessInfo._safe_text_to_int("") is None

    def test_safe_text_to_int_whitespace(self):
        assert procmon_mcp.ProcessInfo._safe_text_to_int("  42  ") == 42

    def test_safe_text_to_int_invalid(self):
        assert procmon_mcp.ProcessInfo._safe_text_to_int("abc") is None

    def test_safe_text_to_bool_true(self):
        assert procmon_mcp.ProcessInfo._safe_text_to_bool("1") is True

    def test_safe_text_to_bool_false(self):
        assert procmon_mcp.ProcessInfo._safe_text_to_bool("0") is False

    def test_safe_text_to_bool_none(self):
        assert procmon_mcp.ProcessInfo._safe_text_to_bool(None) is None

    def test_safe_text_to_bool_other(self):
        assert procmon_mcp.ProcessInfo._safe_text_to_bool("yes") is None

    def test_safe_text_to_bool_empty(self):
        assert procmon_mcp.ProcessInfo._safe_text_to_bool("") is None

    def test_safe_text_to_bool_whitespace(self):
        assert procmon_mcp.ProcessInfo._safe_text_to_bool(" 1 ") is True


# --- _compile_safe_regex Tests ---

class TestCompileSafeRegex:
    def test_none_returns_none(self):
        assert procmon_mcp._compile_safe_regex(None, "test") is None

    def test_valid_pattern_compiles(self):
        result = procmon_mcp._compile_safe_regex("foo.*bar", "test")
        assert isinstance(result, re.Pattern)

    def test_case_insensitive(self):
        regex = procmon_mcp._compile_safe_regex("hello", "test")
        assert regex.search("HELLO") is not None

    def test_exceeds_max_length_raises(self):
        long_pattern = "a" * (procmon_mcp.MAX_REGEX_LEN + 1)
        with pytest.raises(ValueError, match="exceeds maximum length"):
            procmon_mcp._compile_safe_regex(long_pattern, "test_field")

    def test_at_max_length_ok(self):
        pattern = "a" * procmon_mcp.MAX_REGEX_LEN
        result = procmon_mcp._compile_safe_regex(pattern, "test")
        assert isinstance(result, re.Pattern)

    def test_invalid_regex_raises(self):
        with pytest.raises(re.error):
            procmon_mcp._compile_safe_regex("[invalid", "test")


# --- _format_bytes Tests ---

class TestFormatBytes:
    def test_bytes(self):
        assert "Bytes" in procmon_mcp._format_bytes(500)

    def test_kilobytes(self):
        assert "KB" in procmon_mcp._format_bytes(2048)

    def test_megabytes(self):
        assert "MB" in procmon_mcp._format_bytes(2 * 1024 * 1024)

    def test_gigabytes(self):
        assert "GB" in procmon_mcp._format_bytes(2 * 1024 * 1024 * 1024)

    def test_zero(self):
        assert "0 Bytes" == procmon_mcp._format_bytes(0)


# --- StackFrame Tests ---

class TestStackFrame:
    def test_from_xml_element(self):
        xml = "<frame><depth>0</depth><address>0x7FF</address><path>ntdll.dll</path><location>NtCreateFile+0x14</location></frame>"
        elem = ET.fromstring(xml)
        frame = procmon_mcp.StackFrame.from_xml_element(elem)
        assert frame.depth == 0
        assert frame.address == "0x7FF"
        assert frame.path == "ntdll.dll"
        assert frame.location == "NtCreateFile+0x14"

    def test_from_xml_element_missing_fields(self):
        xml = "<frame><depth>1</depth></frame>"
        elem = ET.fromstring(xml)
        frame = procmon_mcp.StackFrame.from_xml_element(elem)
        assert frame.depth == 1
        assert frame.address is None
        assert frame.path is None
        assert frame.location is None

    def test_to_dict(self):
        frame = procmon_mcp.StackFrame(depth=0, address="0x1", path="test.dll", location="func+0x0")
        d = frame.to_dict()
        assert d['depth'] == 0
        assert d['path'] == "test.dll"

    def test_to_optimized_list(self):
        path_interner = procmon_mcp.StringInterner()
        loc_interner = procmon_mcp.StringInterner()
        frame = procmon_mcp.StackFrame(depth=0, address="0x1", path="test.dll", location="func")
        opt = frame.to_optimized_list(path_interner, loc_interner)
        assert len(opt) == 4
        assert opt[0] == 0  # depth
        assert opt[1] == "0x1"  # address (kept as string)
        assert isinstance(opt[2], int)  # path_id
        assert isinstance(opt[3], int)  # location_id


# --- ProcessInfo.from_xml_element Tests ---

class TestProcessInfoFromXml:
    def test_basic_process(self):
        xml = """<process>
            <ProcessIndex>0</ProcessIndex>
            <ProcessId>1234</ProcessId>
            <ParentProcessId>4</ParentProcessId>
            <ProcessName>test.exe</ProcessName>
            <ImagePath>C:\\test.exe</ImagePath>
            <CommandLine>"C:\\test.exe" --flag</CommandLine>
            <Owner>SYSTEM</Owner>
            <Is64bit>1</Is64bit>
            <Integrity>High</Integrity>
        </process>"""
        elem = ET.fromstring(xml)
        proc = procmon_mcp.ProcessInfo.from_xml_element(elem)
        assert proc.process_id == 1234
        assert proc.parent_process_id == 4
        assert proc.process_name == "test.exe"
        assert proc.image_path == "C:\\test.exe"
        assert proc.owner == "SYSTEM"
        assert proc.is_64bit is True
        assert proc.integrity == "High"

    def test_properties(self):
        proc = procmon_mcp.ProcessInfo(process_id=100, parent_process_id=1, owner="S-1-5-18")
        assert proc.pid == 100
        assert proc.parent_pid == 1
        assert proc.user_sid == "S-1-5-18"


# --- ProcmonLogData Tests ---

class TestProcmonLogData:
    def test_is_loaded_false_when_empty(self):
        log_data = procmon_mcp.ProcmonLogData()
        assert log_data.is_loaded() is False

    def test_is_loaded_true_when_populated(self):
        log_data = procmon_mcp.ProcmonLogData()
        log_data.events = [{}]
        log_data.loaded_filename = "test.xml"
        log_data.processes_by_index = {0: procmon_mcp.ProcessInfo()}
        assert log_data.is_loaded() is True

    def test_get_string_with_interner(self):
        log_data = procmon_mcp.ProcmonLogData()
        interner = procmon_mcp.StringInterner()
        id_val = interner.get_id("test_value")
        log_data.interners["test_key"] = interner
        assert log_data.get_string("test_key", id_val) == "test_value"

    def test_get_string_invalid_key(self):
        log_data = procmon_mcp.ProcmonLogData()
        # Returns a fallback string when the interner key is unknown
        result = log_data.get_string("nonexistent", 0)
        assert "Unknown Interner" in result

    def test_get_id_with_interner(self):
        log_data = procmon_mcp.ProcmonLogData()
        interner = procmon_mcp.StringInterner()
        interner.get_id("hello")
        log_data.interners["test_key"] = interner
        assert log_data.get_id("test_key", "hello") == 0

    def test_get_id_nonexistent_string(self):
        log_data = procmon_mcp.ProcmonLogData()
        interner = procmon_mcp.StringInterner()
        log_data.interners["test_key"] = interner
        assert log_data.get_id("test_key", "missing") is None

    def test_default_indices_are_defaultdicts(self):
        log_data = procmon_mcp.ProcmonLogData()
        # All indices should support defaultdict behavior
        log_data.pname_id_index[0].append(1)
        log_data.op_id_index[0].append(2)
        log_data.pid_index[100].append(3)
        log_data.path_id_index[5].append(4)
        assert log_data.pname_id_index[0] == [1]
        assert log_data.op_id_index[0] == [2]
        assert log_data.pid_index[100] == [3]
        assert log_data.path_id_index[5] == [4]

    def test_pid_index_stores_event_indices(self):
        log_data = procmon_mcp.ProcmonLogData()
        # Simulate indexing events by PID
        log_data.pid_index[1234].append(0)
        log_data.pid_index[1234].append(5)
        log_data.pid_index[1234].append(10)
        log_data.pid_index[5678].append(3)
        assert log_data.pid_index[1234] == [0, 5, 10]
        assert log_data.pid_index[5678] == [3]
        assert log_data.pid_index.get(9999, []) == []

    def test_path_id_index_stores_event_indices(self):
        log_data = procmon_mcp.ProcmonLogData()
        log_data.path_id_index[0].append(1)
        log_data.path_id_index[0].append(2)
        log_data.path_id_index[1].append(3)
        assert log_data.path_id_index[0] == [1, 2]
        assert log_data.path_id_index[1] == [3]

    def test_pid_index_set_intersection(self):
        """Test the pattern used by get_process_lifetime: intersecting PID index with op index."""
        log_data = procmon_mcp.ProcmonLogData()
        # PID 100 has events at indices 0, 1, 5, 10
        log_data.pid_index[100] = [0, 1, 5, 10]
        # "Process Create" operation has events at indices 0, 3, 7
        log_data.op_id_index[42] = [0, 3, 7]
        # Intersection should find event 0
        pid_set = set(log_data.pid_index.get(100, []))
        create_indices = log_data.op_id_index.get(42, [])
        found = None
        for idx in create_indices:
            if idx in pid_set:
                found = idx
                break
        assert found == 0

    def test_path_id_index_substring_search(self):
        """Test the pattern used by find_file_access: searching unique paths then collecting indices."""
        log_data = procmon_mcp.ProcmonLogData()
        interner = procmon_mcp.StringInterner()
        # Intern some paths
        id_sys32 = interner.get_id("C:\\Windows\\System32\\ntdll.dll")
        id_sys32b = interner.get_id("C:\\Windows\\System32\\kernel32.dll")
        id_temp = interner.get_id("C:\\Users\\temp\\file.txt")
        log_data.interners["path"] = interner
        # Index events
        log_data.path_id_index[id_sys32] = [0, 5, 10]
        log_data.path_id_index[id_sys32b] = [2, 7]
        log_data.path_id_index[id_temp] = [1, 3]
        # Find paths matching "system32" (case-insensitive)
        search = "system32"
        matching = []
        for path_id, indices in log_data.path_id_index.items():
            path_str = log_data.get_string("path", path_id)
            if path_str and search.lower() in path_str.lower():
                matching.extend(indices)
        matching.sort()
        assert matching == [0, 2, 5, 7, 10]
