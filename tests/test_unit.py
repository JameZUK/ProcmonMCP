"""Unit tests for ProcmonMCP core components."""
import sys
import os
import re
import asyncio
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


# --- Config Module Tests ---

class TestConfig:
    def test_load_config_returns_defaults_when_no_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr("procmon_mcp.config.CONFIG_FILE", str(tmp_path / "nonexistent.json"))
        from procmon_mcp.config import load_config
        config = load_config()
        assert config["last_file"] is None
        assert config["no_stack_traces"] is False
        assert config["no_extra_data"] is False

    def test_save_and_load_config_roundtrip(self, tmp_path, monkeypatch):
        config_file = str(tmp_path / "config.json")
        monkeypatch.setattr("procmon_mcp.config.CONFIG_DIR", str(tmp_path))
        monkeypatch.setattr("procmon_mcp.config.CONFIG_FILE", config_file)
        from procmon_mcp.config import save_config, load_config
        save_config({"last_file": "/tmp/test.xml", "no_stack_traces": True, "no_extra_data": False})
        loaded = load_config()
        assert loaded["last_file"] == "/tmp/test.xml"
        assert loaded["no_stack_traces"] is True
        assert loaded["no_extra_data"] is False

    def test_set_and_get_last_file(self, tmp_path, monkeypatch):
        config_file = str(tmp_path / "config.json")
        monkeypatch.setattr("procmon_mcp.config.CONFIG_DIR", str(tmp_path))
        monkeypatch.setattr("procmon_mcp.config.CONFIG_FILE", config_file)
        from procmon_mcp.config import set_last_file, get_last_file
        set_last_file("/home/user/capture.xml.gz")
        assert get_last_file() == "/home/user/capture.xml.gz"

    def test_load_config_handles_corrupt_json(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.json"
        config_file.write_text("not valid json {{{")
        monkeypatch.setattr("procmon_mcp.config.CONFIG_FILE", str(config_file))
        from procmon_mcp.config import load_config
        config = load_config()
        # Should return defaults without crashing
        assert config["last_file"] is None

    def test_load_config_ignores_unknown_keys(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.json"
        config_file.write_text('{"last_file": "/tmp/x.xml", "unknown_key": 42}')
        monkeypatch.setattr("procmon_mcp.config.CONFIG_FILE", str(config_file))
        from procmon_mcp.config import load_config
        config = load_config()
        assert config["last_file"] == "/tmp/x.xml"
        assert "unknown_key" not in config


# --- Network Endpoint Parsing Tests ---

class TestParseNetworkEndpoint:
    def test_ipv4(self):
        assert procmon_mcp.parse_network_endpoint(
            "test.exe:1234 -> 93.184.216.34:443") == "93.184.216.34:443"

    def test_ipv6_bracketed(self):
        assert procmon_mcp.parse_network_endpoint(
            "test.exe -> [fe80::1]:443") == "fe80::1:443"

    def test_hostname(self):
        assert procmon_mcp.parse_network_endpoint(
            "host:5000 -> example-host.local:8080") == "example-host.local:8080"

    def test_no_arrow_returns_none(self):
        assert procmon_mcp.parse_network_endpoint("C:\\Windows\\file.dll") is None

    def test_none_returns_none(self):
        assert procmon_mcp.parse_network_endpoint(None) is None

    def test_empty_returns_none(self):
        assert procmon_mcp.parse_network_endpoint("") is None

    def test_missing_port_returns_none(self):
        assert procmon_mcp.parse_network_endpoint("a -> 10.0.0.1") is None

    def test_service_name_port_dns(self):
        # Procmon resolves well-known ports to service names (e.g. 53 -> domain).
        assert procmon_mcp.parse_network_endpoint(
            "DESKTOP-VQV04L8.localdomain:59075 -> 192.168.249.2:domain") == "192.168.249.2:domain"

    def test_service_name_port_https(self):
        assert procmon_mcp.parse_network_endpoint(
            "PC:1 -> server.corp:https") == "server.corp:https"

    def test_service_name_port_hyphenated(self):
        assert procmon_mcp.parse_network_endpoint(
            "PC:1 -> 10.0.0.5:microsoft-ds") == "10.0.0.5:microsoft-ds"

    def test_ipv6_with_service_name_port(self):
        assert procmon_mcp.parse_network_endpoint(
            "a:1 -> [2001:db8::1]:https") == "2001:db8::1:https"


# --- Parser Integration Tests ---

def _write_capture(path, n_events, with_stack=True):
    """Write a synthetic Procmon XML capture with n_events events.

    The file is intentionally large enough that <event> elements span
    iterparse read-buffer boundaries, which is the condition that previously
    caused events to be silently dropped or have null fields.
    """
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>\n<procmon>\n<processlist>\n',
        '<process><ProcessIndex>0</ProcessIndex><ProcessId>1234</ProcessId>'
        '<ParentProcessId>4</ParentProcessId><ProcessName>test.exe</ProcessName>'
        '<ImagePath>C:\\test.exe</ImagePath></process>\n',
        '</processlist>\n<eventlist>\n',
    ]
    for i in range(n_events):
        stack = ''
        if with_stack:
            stack = ('<stack><frame><depth>0</depth><address>0x%x</address>'
                     '<path>ntdll.dll</path><location>Nt+0x%x</location></frame></stack>' % (i, i))
        parts.append(
            '<event><ProcessIndex>0</ProcessIndex>'
            '<Time_of_Day>12:00:%02d.000000</Time_of_Day>'
            '<PID>1234</PID><Operation>CreateFile</Operation>'
            '<Path>C:\\Windows\\System32\\file_%d.dll</Path><Result>SUCCESS</Result>'
            '<Process_Name>test.exe</Process_Name>%s</event>\n' % (i % 60, i, stack)
        )
    parts.append('</eventlist>\n</procmon>\n')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(''.join(parts))


class TestParserIntegration:
    def test_small_capture_parses_all_fields(self, tmp_path):
        from procmon_mcp.parser import load_procmon_xml
        from procmon_mcp.constants import IK_OPERATION, IK_PATH, IK_RESULT, IK_PROCESS_NAME
        path = str(tmp_path / "small.xml")
        _write_capture(path, 3)
        data = load_procmon_xml(path, load_stack=True, load_extra=True)
        assert len(data.events) == 3
        assert len(data.processes_by_index) == 1
        e = data.events[0]
        assert e['pid'] == 1234
        assert data.get_string(IK_OPERATION, e['op_id']) == "CreateFile"
        assert data.get_string(IK_RESULT, e['res_id']) == "SUCCESS"
        assert data.get_string(IK_PROCESS_NAME, e['pname_id']) == "test.exe"
        assert "System32" in data.get_string(IK_PATH, e['path_id'])

    def test_large_capture_drops_no_events(self, tmp_path):
        """Regression: events spanning read-buffer boundaries must not be lost.

        Previously, reading child fields on the iterparse 'start' event silently
        dropped events (and nulled later fields like Path/Result) whenever a
        buffer boundary fell inside an <event>.
        """
        from procmon_mcp.parser import load_procmon_xml
        n = 20000
        path = str(tmp_path / "large.xml")
        _write_capture(path, n, with_stack=True)
        data = load_procmon_xml(path, load_stack=True, load_extra=True)
        assert len(data.events) == n
        # No event may have a missing core field.
        for e in data.events:
            assert e.get('pid') is not None
            assert e.get('op_id') is not None
            assert e.get('path_id') is not None
            assert e.get('res_id') is not None
            assert e.get('pname_id') is not None
        # Every event carried a stack frame; all must be present.
        assert sum(1 for e in data.events if 'stack' in e) == n

    def test_large_capture_no_stack_flag(self, tmp_path):
        from procmon_mcp.parser import load_procmon_xml
        n = 20000
        path = str(tmp_path / "large_nostack.xml")
        _write_capture(path, n, with_stack=True)
        data = load_procmon_xml(path, load_stack=False, load_extra=False)
        assert len(data.events) == n
        assert all('stack' not in e for e in data.events)

    def test_indices_cover_all_events(self, tmp_path):
        from procmon_mcp.parser import load_procmon_xml
        n = 5000
        path = str(tmp_path / "idx.xml")
        _write_capture(path, n, with_stack=False)
        data = load_procmon_xml(path, load_stack=False, load_extra=False)
        # Every event index should appear exactly once in the PID index.
        assert sum(len(v) for v in data.pid_index.values()) == n
        assert sum(len(v) for v in data.pname_id_index.values()) == n


# --- Exact-Match Filter Tests ---

class _DummyContext:
    """Minimal MCP Context stand-in for driving tools/filters in tests.

    Intentionally self-contained rather than imported from procmon_mcp.compat:
    when the real MCP SDK is installed, compat.Context is the SDK Context, whose
    info()/error() raise outside an active request. The tool code only needs
    awaitable info/error/warning that record nothing.
    """
    def __init__(self):
        self.messages = []

    async def info(self, msg):
        self.messages.append(("info", msg))

    async def error(self, msg):
        self.messages.append(("error", msg))

    async def warning(self, msg):
        self.messages.append(("warning", msg))


def _collect_filtered(log_data, **filters):
    """Drain the async filter iterator into a list of event indices."""

    async def _run():
        ctx = _DummyContext()
        out = []
        async for idx in procmon_mcp._iter_filtered_event_indices(
                log_data=log_data, ctx=ctx, **filters):
            out.append(idx)
        return out

    return asyncio.run(_run())


class TestFilterExactMatch:
    """Synthetic capture: N identical CreateFile / SUCCESS / test.exe events."""

    def _load(self, tmp_path, n=10):
        from procmon_mcp.parser import load_procmon_xml
        path = str(tmp_path / "filt.xml")
        _write_capture(path, n, with_stack=False)
        return load_procmon_xml(path, load_stack=False, load_extra=False)

    def test_present_operation_matches_all(self, tmp_path):
        data = self._load(tmp_path)
        assert len(_collect_filtered(data, filter_operation="CreateFile")) == 10

    def test_present_result_matches_all(self, tmp_path):
        data = self._load(tmp_path)
        assert len(_collect_filtered(data, filter_result="SUCCESS")) == 10

    def test_present_process_matches_all(self, tmp_path):
        data = self._load(tmp_path)
        assert len(_collect_filtered(data, filter_process="test.exe")) == 10

    def test_absent_operation_matches_none(self, tmp_path):
        # Regression: an absent exact-match value must yield 0, not every event.
        data = self._load(tmp_path)
        assert _collect_filtered(data, filter_operation="RegSetValue") == []

    def test_absent_result_matches_none(self, tmp_path):
        data = self._load(tmp_path)
        assert _collect_filtered(data, filter_result="ACCESS DENIED") == []

    def test_absent_process_matches_none(self, tmp_path):
        data = self._load(tmp_path)
        assert _collect_filtered(data, filter_process="nonexistent.exe") == []

    def test_absent_value_does_not_leak_with_other_filters(self, tmp_path):
        # Combining a present operation with an absent result still yields 0.
        data = self._load(tmp_path)
        res = _collect_filtered(data, filter_operation="CreateFile",
                                filter_result="ACCESS DENIED")
        assert res == []
