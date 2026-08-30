# -*- coding: utf-8 -*-
"""Integration test client for ProcmonMCP with assertions and pass/fail tracking."""
import asyncio
import json
import argparse
import logging
import sys
from typing import Any, Dict, List, Optional, Union

# --- Configure Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Import MCP Client library ---
try:
    from mcp import ClientSession, types
    from mcp.client.sse import sse_client
    logger.info("MCP SDK components imported successfully.")
    HAS_STREAMABLE_HTTP = False
    try:
        # SDK v2 dropped the unseparated `streamablehttp_client` spelling; the
        # `streamable_http_client` name it kept is also present in recent v1
        # releases, so prefer it and fall back for older v1 SDKs.
        try:
            from mcp.client.streamable_http import streamable_http_client
        except ImportError:
            from mcp.client.streamable_http import (
                streamablehttp_client as streamable_http_client,
            )
        HAS_STREAMABLE_HTTP = True
        logger.info("Streamable HTTP client available.")
    except ImportError:
        logger.info("Streamable HTTP client not available (older SDK version).")
except ImportError as e:
    logger.critical(f"MCP SDK import failed: {e}")
    logger.critical("Please ensure the MCP Python SDK is installed correctly.")
    sys.exit(1)


# --- Test Results Tracker ---
class TestResults:
    """Tracks pass/fail counts and messages for integration tests."""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors: List[str] = []

    def record_pass(self, test_name: str, detail: str = ""):
        self.passed += 1
        msg = f"  PASS: {test_name}"
        if detail:
            msg += f" ({detail})"
        print(msg)

    def record_fail(self, test_name: str, detail: str = ""):
        self.failed += 1
        msg = f"  FAIL: {test_name}"
        if detail:
            msg += f" - {detail}"
        print(msg)
        self.errors.append(f"{test_name}: {detail}")

    def assert_is_dict(self, test_name: str, value: Any, required_keys: Optional[List[str]] = None) -> bool:
        if not isinstance(value, dict):
            self.record_fail(test_name, f"Expected dict, got {type(value).__name__}")
            return False
        if required_keys:
            missing = [k for k in required_keys if k not in value]
            if missing:
                self.record_fail(test_name, f"Missing keys: {missing}")
                return False
        self.record_pass(test_name)
        return True

    def assert_is_list(self, test_name: str, value: Any, min_length: int = 0) -> bool:
        if not isinstance(value, list):
            self.record_fail(test_name, f"Expected list, got {type(value).__name__}")
            return False
        if len(value) < min_length:
            self.record_fail(test_name, f"Expected at least {min_length} items, got {len(value)}")
            return False
        self.record_pass(test_name)
        return True

    def assert_positive_int(self, test_name: str, value: Any) -> bool:
        if not isinstance(value, int) or value <= 0:
            self.record_fail(test_name, f"Expected positive int, got {value!r}")
            return False
        self.record_pass(test_name)
        return True

    def assert_true(self, test_name: str, condition: bool, detail: str = "") -> bool:
        if condition:
            self.record_pass(test_name, detail)
            return True
        self.record_fail(test_name, detail)
        return False

    def print_summary(self):
        total = self.passed + self.failed
        print(f"\n{'='*50}")
        print(f"Integration Test Summary: {self.passed}/{total} passed, {self.failed} failed")
        if self.errors:
            print(f"\nFailures:")
            for err in self.errors:
                print(f"  - {err}")
        print(f"{'='*50}")


# --- Helper Function to Extract and Parse JSON Result ---
def extract_json_from_result(raw_result: Any, expect_list: bool = False) -> Optional[Union[Dict, List]]:
    """Extracts and parses JSON from MCP tool result."""
    try:
        if not hasattr(raw_result, 'content') or not isinstance(raw_result.content, list):
            logger.warning(f"Unexpected result structure: {raw_result}")
            return None
        if not raw_result.content:
            return [] if expect_list else {}

        if expect_list and len(raw_result.content) > 1:
            parsed_list = []
            for i, item in enumerate(raw_result.content):
                if hasattr(item, 'text') and isinstance(item.text, str):
                    try:
                        parsed_list.append(json.loads(item.text))
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse JSON from list item {i}: {e}")
                else:
                    logger.warning(f"List item {i} has unexpected structure: {item}")
            return parsed_list

        elif len(raw_result.content) >= 1:
            item = raw_result.content[0]
            if hasattr(item, 'text') and isinstance(item.text, str):
                parsed_data = json.loads(item.text)
                return parsed_data
            else:
                logger.warning(f"Result content item 0 has unexpected structure: {item}")
                return None

        return None
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON from result text: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error extracting/parsing result: {e}", exc_info=True)
        return None


# --- Tool Testing Function ---
async def test_tools_with_session(session: ClientSession):
    """Runs tool tests with assertions."""
    logger.info("Starting tool test sequence...")
    results = TestResults()

    test_data = {
        "pid_to_test": 4,
        "pid_to_test_alt": None,
        "process_name_to_test": "svchost.exe",
        "event_index_to_test": None,
    }

    # Initialize session
    try:
        if hasattr(session, 'initialize'):
            await session.initialize()
            logger.info("Session initialized.")
    except Exception as e:
        logger.error(f"Error during session initialization: {e}", exc_info=True)

    # 0. get_status
    print(f"\n--- Testing: get_status ---")
    try:
        raw = await session.call_tool("get_status", arguments={})
        parsed = extract_json_from_result(raw)
        if results.assert_is_dict("get_status: returns dict", parsed,
                                  required_keys=["file_loaded", "message", "available_actions"]):
            results.assert_true("get_status: file_loaded is bool",
                                isinstance(parsed.get("file_loaded"), bool))
            results.assert_is_list("get_status: available_actions is list",
                                   parsed.get("available_actions"), min_length=1)
    except Exception as e:
        results.record_fail("get_status: call succeeded", str(e))

    # 1. get_loaded_file_summary
    print(f"\n--- Testing: get_loaded_file_summary ---")
    try:
        raw = await session.call_tool("get_loaded_file_summary", arguments={})
        parsed = extract_json_from_result(raw)
        if results.assert_is_dict("summary: returns dict", parsed,
                                  required_keys=["loaded_filename", "event_count", "process_count"]):
            results.assert_positive_int("summary: event_count > 0", parsed.get("event_count", 0))
            results.assert_positive_int("summary: process_count > 0", parsed.get("process_count", 0))
            results.assert_is_dict("summary: has index_stats", parsed.get("index_stats"),
                                   required_keys=["pname_indexed_count", "op_indexed_count",
                                                   "pid_indexed_count", "path_indexed_count"])
            results.assert_is_dict("summary: has interner_stats", parsed.get("interner_stats"))
            results.assert_is_dict("summary: has selective_loading", parsed.get("selective_loading"),
                                   required_keys=["stack_traces", "extra_data"])
    except Exception as e:
        results.record_fail("summary: call succeeded", str(e))

    # 2. get_metadata
    print(f"\n--- Testing: get_metadata ---")
    try:
        raw = await session.call_tool("get_metadata", arguments={})
        parsed = extract_json_from_result(raw)
        if results.assert_is_dict("metadata: returns dict", parsed,
                                  required_keys=["loaded_filename", "event_count_loaded", "process_count_loaded"]):
            results.assert_positive_int("metadata: event_count_loaded > 0", parsed.get("event_count_loaded", 0))
    except Exception as e:
        results.record_fail("metadata: call succeeded", str(e))

    # 3. list_processes
    print(f"\n--- Testing: list_processes ---")
    process_list = None
    try:
        raw = await session.call_tool("list_processes", arguments={})
        parsed = extract_json_from_result(raw, expect_list=True)
        if results.assert_is_list("list_processes: returns list", parsed, min_length=1):
            process_list = parsed
            first = parsed[0]
            results.assert_is_dict("list_processes: first item is dict with pid",
                                   first, required_keys=["pid", "process_name"])
            # All entries should have pid
            all_have_pid = all(isinstance(p.get("pid"), int) for p in parsed)
            results.assert_true("list_processes: all entries have int pid", all_have_pid)
            # Find alt PID
            for proc in parsed:
                pid = proc.get("pid")
                if pid is not None and pid != test_data["pid_to_test"]:
                    test_data["pid_to_test_alt"] = pid
                    break
    except Exception as e:
        results.record_fail("list_processes: call succeeded", str(e))

    # 4. get_process_details
    pids_to_check = [test_data["pid_to_test"]]
    if test_data["pid_to_test_alt"] is not None:
        pids_to_check.append(test_data["pid_to_test_alt"])
    print(f"\n--- Testing: get_process_details ---")
    for pid_val in pids_to_check:
        try:
            raw = await session.call_tool("get_process_details", arguments={"pid": pid_val})
            parsed = extract_json_from_result(raw)
            if results.assert_is_dict(f"process_details(pid={pid_val}): returns dict", parsed):
                results.assert_true(f"process_details(pid={pid_val}): has process_id",
                                    parsed.get("process_id") == pid_val,
                                    f"expected {pid_val}, got {parsed.get('process_id')}")
        except Exception as e:
            results.record_fail(f"process_details(pid={pid_val}): call succeeded", str(e))

    # 5. query_events (no filters)
    print(f"\n--- Testing: query_events ---")
    try:
        raw = await session.call_tool("query_events", arguments={"limit": 5})
        parsed = extract_json_from_result(raw, expect_list=True)
        if results.assert_is_list("query_events(no filter): returns list", parsed, min_length=1):
            first = parsed[0]
            results.assert_is_dict("query_events: first item has required keys", first,
                                   required_keys=["event_index", "timestamp", "process_name", "pid", "operation"])
            idx = first.get("event_index")
            if isinstance(idx, int):
                test_data["event_index_to_test"] = idx
            results.assert_true("query_events(limit=5): at most 5 results",
                                len(parsed) <= 5, f"got {len(parsed)}")
    except Exception as e:
        results.record_fail("query_events(no filter): call succeeded", str(e))

    # query_events with process filter
    process_filter = test_data["process_name_to_test"]
    try:
        raw = await session.call_tool("query_events",
                                      arguments={"filter_process": process_filter, "limit": 5})
        parsed = extract_json_from_result(raw, expect_list=True)
        if results.assert_is_list(f"query_events(process={process_filter}): returns list", parsed):
            if parsed:
                all_match = all(e.get("process_name") == process_filter for e in parsed)
                results.assert_true(f"query_events(process={process_filter}): all match filter",
                                    all_match, "some events don't match process filter")
    except Exception as e:
        results.record_fail(f"query_events(process={process_filter}): call succeeded", str(e))

    # query_events with operation filter
    op_filter = "RegQueryKey"
    try:
        raw = await session.call_tool("query_events",
                                      arguments={"filter_operation": op_filter, "limit": 5})
        parsed = extract_json_from_result(raw, expect_list=True)
        if results.assert_is_list(f"query_events(op={op_filter}): returns list", parsed):
            if parsed:
                all_match = all(e.get("operation") == op_filter for e in parsed)
                results.assert_true(f"query_events(op={op_filter}): all match filter",
                                    all_match, "some events don't match operation filter")
    except Exception as e:
        results.record_fail(f"query_events(op={op_filter}): call succeeded", str(e))

    # query_events with path_contains filter
    path_filter = "Software\\Microsoft"
    try:
        raw = await session.call_tool("query_events",
                                      arguments={"filter_path_contains": path_filter, "limit": 5})
        parsed = extract_json_from_result(raw, expect_list=True)
        if results.assert_is_list(f"query_events(path_contains): returns list", parsed):
            if parsed:
                all_match = all(path_filter.lower() in (e.get("path") or "").lower() for e in parsed)
                results.assert_true(f"query_events(path_contains): all paths contain '{path_filter}'",
                                    all_match, "some paths don't contain the filter substring")
    except Exception as e:
        results.record_fail(f"query_events(path_contains): call succeeded", str(e))

    # 6. get_event_details
    print(f"\n--- Testing: get_event_details ---")
    event_idx = test_data["event_index_to_test"]
    if event_idx is not None:
        try:
            raw = await session.call_tool("get_event_details", arguments={"event_index": event_idx})
            parsed = extract_json_from_result(raw)
            if results.assert_is_dict(f"event_details(idx={event_idx}): returns dict", parsed,
                                      required_keys=["event_index", "timestamp", "process_name", "pid", "operation"]):
                results.assert_true(f"event_details: event_index matches",
                                    parsed.get("event_index") == event_idx,
                                    f"expected {event_idx}, got {parsed.get('event_index')}")
        except Exception as e:
            results.record_fail(f"event_details(idx={event_idx}): call succeeded", str(e))
    else:
        results.record_fail("event_details: skipped", "no event_index available")

    # 7. get_event_stack_trace
    print(f"\n--- Testing: get_event_stack_trace ---")
    if event_idx is not None:
        try:
            raw = await session.call_tool("get_event_stack_trace", arguments={"event_index": event_idx})
            parsed = extract_json_from_result(raw, expect_list=True)
            if results.assert_is_list(f"stack_trace(idx={event_idx}): returns list", parsed):
                if parsed:
                    results.assert_is_dict("stack_trace: first frame has keys",
                                           parsed[0], required_keys=["depth", "address", "path", "location"])
        except Exception as e:
            results.record_fail(f"stack_trace(idx={event_idx}): call succeeded", str(e))
    else:
        results.record_fail("stack_trace: skipped", "no event_index available")

    # 8. count_events_by_process
    print(f"\n--- Testing: count_events_by_process ---")
    try:
        raw = await session.call_tool("count_events_by_process", arguments={})
        parsed = extract_json_from_result(raw)
        if results.assert_is_dict("count_by_process: returns dict", parsed):
            results.assert_true("count_by_process: has entries",
                                len(parsed) > 0, f"got {len(parsed)} entries")
            all_int_values = all(isinstance(v, int) and v > 0 for v in parsed.values())
            results.assert_true("count_by_process: all values are positive ints", all_int_values)
    except Exception as e:
        results.record_fail("count_by_process: call succeeded", str(e))

    # 9. summarize_operations_by_process
    print(f"\n--- Testing: summarize_operations_by_process ---")
    try:
        raw = await session.call_tool("summarize_operations_by_process",
                                      arguments={"process_name_filter": process_filter})
        parsed = extract_json_from_result(raw)
        if results.assert_is_dict(f"ops_by_process({process_filter}): returns dict", parsed):
            if parsed:
                all_int_values = all(isinstance(v, int) and v > 0 for v in parsed.values())
                results.assert_true(f"ops_by_process({process_filter}): all values positive ints", all_int_values)
    except Exception as e:
        results.record_fail(f"ops_by_process({process_filter}): call succeeded", str(e))

    # 10. get_timing_statistics
    print(f"\n--- Testing: get_timing_statistics ---")
    for group_by in ["process", "operation"]:
        try:
            raw = await session.call_tool("get_timing_statistics",
                                          arguments={"group_by": group_by})
            parsed = extract_json_from_result(raw)
            if results.assert_is_dict(f"timing_stats(group={group_by}): returns dict", parsed):
                if parsed:
                    first_key = next(iter(parsed))
                    first_val = parsed[first_key]
                    results.assert_is_dict(f"timing_stats(group={group_by}): first value has stats",
                                           first_val, required_keys=["count", "min_duration", "max_duration",
                                                                     "avg_duration", "total_duration"])
        except Exception as e:
            results.record_fail(f"timing_stats(group={group_by}): call succeeded", str(e))

    # 11. get_process_lifetime
    print(f"\n--- Testing: get_process_lifetime ---")
    for pid_val in pids_to_check:
        try:
            raw = await session.call_tool("get_process_lifetime", arguments={"pid": pid_val})
            parsed = extract_json_from_result(raw)
            results.assert_is_dict(f"lifetime(pid={pid_val}): returns dict", parsed,
                                   required_keys=["create_timestamp", "exit_timestamp"])
        except Exception as e:
            results.record_fail(f"lifetime(pid={pid_val}): call succeeded", str(e))

    # 12. find_file_access
    print(f"\n--- Testing: find_file_access ---")
    fa_path = "windows\\system32"
    try:
        raw = await session.call_tool("find_file_access",
                                      arguments={"path_contains": fa_path, "limit": 5})
        parsed = extract_json_from_result(raw, expect_list=True)
        if results.assert_is_list(f"file_access('{fa_path}'): returns list", parsed):
            if parsed:
                results.assert_is_dict("file_access: first item has keys", parsed[0],
                                       required_keys=["event_index", "path", "operation"])
                all_match = all(fa_path.lower() in (e.get("path") or "").lower() for e in parsed)
                results.assert_true(f"file_access: all paths contain '{fa_path}'",
                                    all_match, "some paths don't contain the filter")
                results.assert_true("file_access(limit=5): at most 5 results",
                                    len(parsed) <= 5, f"got {len(parsed)}")
    except Exception as e:
        results.record_fail(f"file_access('{fa_path}'): call succeeded", str(e))

    # 13. find_network_connections
    print(f"\n--- Testing: find_network_connections ---")
    try:
        raw = await session.call_tool("find_network_connections",
                                      arguments={"process_name": process_filter})
        parsed = extract_json_from_result(raw, expect_list=True)
        results.assert_is_list(f"network({process_filter}): returns list", parsed)
    except Exception as e:
        results.record_fail(f"network({process_filter}): call succeeded", str(e))

    # 14. export_query_results
    print(f"\n--- Testing: export_query_results ---")
    for fmt in ["csv", "json"]:
        output_file = f"mcp_test_export.{fmt}"
        try:
            raw = await session.call_tool("export_query_results",
                                          arguments={"output_file": output_file,
                                                     "output_format": fmt,
                                                     "filter_operation": "RegQueryValue",
                                                     "filter_result": "SUCCESS"})
            parsed = extract_json_from_result(raw)
            if results.assert_is_dict(f"export({fmt}): returns dict", parsed,
                                      required_keys=["success", "output_path", "events_exported"]):
                results.assert_true(f"export({fmt}): success is True",
                                    parsed.get("success") is True,
                                    f"got {parsed.get('success')}")
        except Exception as e:
            results.record_fail(f"export({fmt}): call succeeded", str(e))

    # Print summary and exit with appropriate code
    results.print_summary()
    return results.failed == 0


# --- Main Execution Function ---
async def main(host: str, port: int, transport: str):
    """Sets up connection and runs tests."""
    all_passed = False
    try:
        if transport == "stdio":
            logger.error("Testing via stdio from this script is not directly supported.")
            logger.error("Please run the server with SSE or streamable-http for client testing.")
            sys.exit(1)

        elif transport == "streamable-http":
            if not HAS_STREAMABLE_HTTP:
                logger.error("Streamable HTTP client not available. Upgrade MCP SDK: pip install 'mcp[cli]>=2'")
                sys.exit(1)
            url = f"http://{host}:{port}/mcp"
            logger.info(f"Connecting via Streamable HTTP to: {url}...")

            async with streamable_http_client(url) as streams:
                logger.info("Streamable HTTP client connected.")
                read_stream, write_stream = streams[0], streams[1]
                async with ClientSession(read_stream, write_stream) as session:
                    logger.info("ClientSession created. Running tests...")
                    all_passed = await test_tools_with_session(session)

        elif transport == "sse":
            sse_url = f"http://{host}:{port}/sse"
            logger.info(f"Connecting via SSE (deprecated) to: {sse_url}...")

            async with sse_client(sse_url) as streams:
                logger.info("SSE client connected.")
                read_stream, write_stream = streams
                async with ClientSession(read_stream, write_stream) as session:
                    logger.info("ClientSession created. Running tests...")
                    all_passed = await test_tools_with_session(session)

    except ConnectionRefusedError:
        logger.error(f"Connection refused. Is the MCP server running at {host}:{port}?")
    except Exception as e:
        logger.error(f"Error during connection or testing: {e}", exc_info=True)

    if not all_passed:
        sys.exit(1)


# --- Script Entry Point ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Integration test client for ProcmonMCP with assertion-based pass/fail tracking.")
    parser.add_argument("--host", type=str, default="127.0.0.1",
                        help="Host where the MCP server is running (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8081,
                        help="Port where the MCP server is running (default: 8081)")
    parser.add_argument("--transport", type=str, default="streamable-http",
                        choices=["stdio", "sse", "streamable-http"],
                        help="MCP transport (default: streamable-http)")

    args = parser.parse_args()
    asyncio.run(main(args.host, args.port, args.transport))
