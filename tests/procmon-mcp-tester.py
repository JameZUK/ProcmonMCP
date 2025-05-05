# -*- coding: utf-8 -*-
import asyncio
import json
import argparse
import logging
from typing import Any, Dict, List, Optional, Union
import sys
from urllib.parse import urlparse # To validate URL scheme

# --- Configure Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Import MCP Client library ---
# Assumes SDK from https://github.com/modelcontextprotocol/python-sdk is installed
# If these imports fail, the script will raise an ImportError and exit.
try:
    from mcp import ClientSession, types # Core session and types
    from mcp.client.sse import sse_client # Specific transport client for SSE
    logger.info("MCP SDK components imported successfully.")
except ImportError as e:
    logger.critical(f"MCP SDK import failed: {e}")
    logger.critical("Please ensure the MCP Python SDK is installed correctly.")
    logger.critical("Install using: pip install git+https://github.com/modelcontextprotocol/python-sdk.git")
    sys.exit(1) # Exit if SDK cannot be imported

# --- Helper Function to Extract and Parse JSON Result ---
def extract_json_from_result(raw_result: Any, expect_list: bool = False) -> Optional[Union[Dict, List]]:
    """
    Extracts the JSON string(s) from the MCP tool result object and parses it.

    Handles cases where:
    - content[0].text contains a single JSON object/list.
    - content is empty.
    - content contains multiple items, each with a JSON object in .text (if expect_list is True).

    Args:
        raw_result: The raw result object from session.call_tool.
        expect_list: If True, attempts to parse multiple content items into a list.

    Returns:
        The parsed Python object (dict or list), or None if parsing fails or structure is unexpected.
    """
    try:
        # Check the basic structure of the result object
        if not hasattr(raw_result, 'content') or not isinstance(raw_result.content, list):
            logger.warning(f"Unexpected result structure: 'content' attribute missing or not a list: {raw_result}")
            return None

        # Handle empty content list
        if not raw_result.content:
            logger.debug("Result content list is empty.")
            # Return empty list/dict based on expectation
            return [] if expect_list else {}

        # If expecting a list AND there are multiple content items, parse each
        if expect_list and len(raw_result.content) > 1:
            parsed_list = []
            for i, item in enumerate(raw_result.content):
                if hasattr(item, 'text') and isinstance(item.text, str):
                    try:
                        parsed_item = json.loads(item.text)
                        parsed_list.append(parsed_item)
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse JSON from list item {i}: {e}")
                        logger.debug(f"Raw text content of item {i}: {item.text}")
                        # Skip this item
                else:
                     logger.warning(f"List item {i} has unexpected structure: {item}")
            return parsed_list # Return list of successfully parsed items

        # Handle single content item (or first item if list not expected explicitly)
        elif len(raw_result.content) >= 1:
             item = raw_result.content[0]
             if hasattr(item, 'text') and isinstance(item.text, str):
                 json_string = item.text
                 parsed_data = json.loads(json_string)
                 # Optional: Warn if a list was expected but got something else
                 if expect_list and not isinstance(parsed_data, list):
                      logger.warning(f"Expected a list result, but parsed single item is type {type(parsed_data)}.")
                 return parsed_data
             else:
                 logger.warning(f"Result content item 0 has unexpected structure: {item}")
                 return None
        else:
             # Should be caught by the initial empty check
             logger.warning("Result content list was unexpectedly empty after initial check.")
             return None

    except json.JSONDecodeError as e:
        # Log specific JSON error and the content that failed
        logger.error(f"Failed to parse JSON from result text: {e}")
        json_text_content = "<N/A>"
        if hasattr(raw_result, 'content') and raw_result.content and hasattr(raw_result.content[0], 'text'):
            json_text_content = raw_result.content[0].text
        logger.debug(f"Raw text content leading to JSON error: {json_text_content}")
        return None
    except AttributeError as e:
        logger.error(f"Attribute error accessing result content: {e}")
        logger.debug(f"Raw result object: {raw_result}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error extracting/parsing result: {e}", exc_info=True)
        return None


# --- Helper Function for Printing Results ---
def print_result(tool_name: str, params: Dict[str, Any], parsed_result: Optional[Union[Dict, List]], raw_result: Any = None):
    """Formats and prints the results of a tool call clearly."""
    print(f"\n{'='*15} Testing Tool: {tool_name} {'='*15}")
    if params:
        print("Parameters:")
        try: print(json.dumps(params, indent=2))
        except TypeError: print(str(params)) # Fallback for non-serializable params
    else: print("Parameters: None")
    print("-" * (32 + len(tool_name))) # Separator line
    print("Result (Parsed JSON):")
    if isinstance(parsed_result, (dict, list)):
        # Pretty print the parsed JSON
        try: print(json.dumps(parsed_result, indent=2, default=str))
        except Exception as e: logger.warning(f"Could not JSON serialize parsed result for {tool_name}: {e}"); print(parsed_result)
    elif parsed_result is None:
        print("None (or failed to parse/empty content)") # Clarify potential reason
        # Log the raw result if parsing failed or content was empty for debugging
        if raw_result:
             logger.debug(f"Raw result object for {tool_name} when parsed result was None: {raw_result}")
    else: # Should not happen if extract_json_from_result works correctly
        print(parsed_result)
    print(f"{'='*15} End Test: {tool_name} {'='*15}\n")

# --- Tool Testing Function ---
async def test_tools_with_session(session: ClientSession): # Expecting a ClientSession instance
    """Runs the sequence of tool tests using the provided ClientSession object."""
    logger.info("Starting tool test sequence...")

    # Dictionary to store intermediate results for chaining tests
    test_data = {
        "pid_to_test": 4, # Default PID to test (System process)
        "pid_to_test_alt": None, # Will try to find another PID from list_processes
        "process_name_to_test": "svchost.exe", # Common process name to test
        "event_index_to_test": None # Will try to get an index from query_events
    }

    # --- Tool Test Sequence ---
    # Use session.call_tool("tool_name", arguments={...})

    # 0. Initialize (Optional but good practice according to example)
    tool_name = "session.initialize"
    try:
        if hasattr(session, 'initialize'):
             logger.info("Calling session.initialize()...")
             await session.initialize()
             logger.info("Session initialized.")
        else:
             logger.info("Session object does not have an initialize method, skipping.")
    except Exception as e:
        logger.error(f"Error during session initialization: {e}", exc_info=True)

    # 1. get_loaded_file_summary
    tool_name = "get_loaded_file_summary"
    try:
        params = {}
        raw_result = await session.call_tool(tool_name, arguments=params)
        parsed_result = extract_json_from_result(raw_result) # Expect dict
        print_result(tool_name, params, parsed_result, raw_result)
    except Exception as e: logger.error(f"Error calling {tool_name}: {e}", exc_info=True); print_result(tool_name, params, f"ERROR: {e}")

    # 2. get_metadata
    tool_name = "get_metadata"
    try:
        params = {}
        raw_result = await session.call_tool(tool_name, arguments=params)
        parsed_result = extract_json_from_result(raw_result) # Expect dict
        print_result(tool_name, params, parsed_result, raw_result)
    except Exception as e: logger.error(f"Error calling {tool_name}: {e}", exc_info=True); print_result(tool_name, params, f"ERROR: {e}")

    # 3. list_processes
    tool_name = "list_processes"
    process_list_result: Optional[List[Dict]] = None
    try:
        params = {}
        raw_result = await session.call_tool(tool_name, arguments=params)
        # Tell helper to expect a list, potentially from multiple content items
        parsed_result = extract_json_from_result(raw_result, expect_list=True)
        if isinstance(parsed_result, list):
             process_list_result = parsed_result
        else:
             logger.error(f"{tool_name} did not return a list as expected (parsed type: {type(parsed_result)}).")
             process_list_result = None

        print_result(tool_name, params, process_list_result, raw_result)
        # Check process_list_result is not None before len()
        if process_list_result and len(process_list_result) > 1:
            for proc in process_list_result:
                pid = proc.get("pid")
                if pid is not None and pid != test_data["pid_to_test"]:
                    test_data["pid_to_test_alt"] = pid
                    logger.info(f"Found alternative PID for testing: {test_data['pid_to_test_alt']}")
                    break
    except Exception as e: logger.error(f"Error calling {tool_name}: {e}", exc_info=True); print_result(tool_name, params, f"ERROR: {e}")

    # 4. get_process_details
    pids_to_check = [test_data["pid_to_test"]]
    if test_data["pid_to_test_alt"] is not None: pids_to_check.append(test_data["pid_to_test_alt"])
    for pid_val in pids_to_check:
         tool_name_display = f"get_process_details (PID: {pid_val})"
         tool_name_call = "get_process_details"
         try:
             params = {"pid": pid_val}
             raw_result = await session.call_tool(tool_name_call, arguments=params)
             parsed_result = extract_json_from_result(raw_result) # Expect dict
             print_result(tool_name_display, params, parsed_result, raw_result)
         except Exception as e: logger.error(f"Error calling {tool_name_call} for PID {pid_val}: {e}", exc_info=True); print_result(tool_name_display, params, f"ERROR: {e}")

    # 5. query_events
    query_results_parsed: Optional[List[Dict]] = None
    tool_name_call = "query_events"
    tool_name_display = "query_events (no filters)"
    try:
        params = {"limit": 5}
        raw_result = await session.call_tool(tool_name_call, arguments=params)
        parsed_result = extract_json_from_result(raw_result, expect_list=True) # Expect list
        if isinstance(parsed_result, list):
             query_results_parsed = parsed_result
        else:
             logger.error(f"{tool_name_call} did not return a list as expected (parsed type: {type(parsed_result)}).")
             query_results_parsed = None

        print_result(tool_name_display, params, query_results_parsed, raw_result)
        # Check query_results_parsed is not None before len()
        if query_results_parsed and len(query_results_parsed) > 0:
            idx_val = query_results_parsed[0].get("event_index")
            if isinstance(idx_val, int): test_data["event_index_to_test"] = idx_val; logger.info(f"Found event index for testing: {test_data['event_index_to_test']}")
            else: logger.warning(f"First query result missing valid 'event_index': {query_results_parsed[0]}")
        elif query_results_parsed is not None: # It's an empty list
             logger.info(f"{tool_name_display} returned an empty list.")
        # else: parsing failed, error already logged by extract_json_from_result

    except Exception as e: logger.error(f"Error calling {tool_name_call}: {e}", exc_info=True); print_result(tool_name_display, params, f"ERROR: {e}")

    # Other query_events scenarios (apply same parsing logic)
    process_filter = test_data["process_name_to_test"]
    tool_name_display = f"query_events (filter_process='{process_filter}')"
    try: params = {"filter_process": process_filter, "limit": 5}; raw_result = await session.call_tool(tool_name_call, arguments=params); parsed_result = extract_json_from_result(raw_result, expect_list=True); print_result(tool_name_display, params, parsed_result, raw_result)
    except Exception as e: logger.error(f"Error calling {tool_name_call}: {e}", exc_info=True); print_result(tool_name_display, params, f"ERROR: {e}")
    op_filter = "RegQueryKey"; tool_name_display = f"query_events (filter_operation='{op_filter}')"
    try: params = {"filter_operation": op_filter, "limit": 5}; raw_result = await session.call_tool(tool_name_call, arguments=params); parsed_result = extract_json_from_result(raw_result, expect_list=True); print_result(tool_name_display, params, parsed_result, raw_result)
    except Exception as e: logger.error(f"Error calling {tool_name_call}: {e}", exc_info=True); print_result(tool_name_display, params, f"ERROR: {e}")
    res_filter = "SUCCESS"; tool_name_display = f"query_events (filter_result='{res_filter}')"
    try: params = {"filter_result": res_filter, "limit": 5}; raw_result = await session.call_tool(tool_name_call, arguments=params); parsed_result = extract_json_from_result(raw_result, expect_list=True); print_result(tool_name_display, params, parsed_result, raw_result)
    except Exception as e: logger.error(f"Error calling {tool_name_call}: {e}", exc_info=True); print_result(tool_name_display, params, f"ERROR: {e}")
    path_filter = "Software\\Microsoft"; tool_name_display = f"query_events (filter_path_contains='{path_filter}')"
    try: params = {"filter_path_contains": path_filter, "limit": 5}; raw_result = await session.call_tool(tool_name_call, arguments=params); parsed_result = extract_json_from_result(raw_result, expect_list=True); print_result(tool_name_display, params, parsed_result, raw_result)
    except Exception as e: logger.error(f"Error calling {tool_name_call}: {e}", exc_info=True); print_result(tool_name_display, params, f"ERROR: {e}")
    tool_name_display = "query_events (combined filters)"
    try: params = {"filter_process": process_filter, "filter_operation": op_filter, "filter_result": res_filter, "limit": 5}; raw_result = await session.call_tool(tool_name_call, arguments=params); parsed_result = extract_json_from_result(raw_result, expect_list=True); print_result(tool_name_display, params, parsed_result, raw_result)
    except Exception as e: logger.error(f"Error calling {tool_name_call}: {e}", exc_info=True); print_result(tool_name_display, params, f"ERROR: {e}")

    # 6. get_event_details
    event_idx = test_data["event_index_to_test"]
    tool_name_display = f"get_event_details (index={event_idx})"
    tool_name_call = "get_event_details"
    if event_idx is not None:
        try: params = {"event_index": event_idx}; raw_result = await session.call_tool(tool_name_call, arguments=params); parsed_result = extract_json_from_result(raw_result); print_result(tool_name_display, params, parsed_result, raw_result)
        except Exception as e: logger.error(f"Error calling {tool_name_call}: {e}", exc_info=True); print_result(tool_name_display, params, f"ERROR: {e}")
    else: logger.warning(f"Skipping {tool_name_display} test: No valid event_index found."); print_result(tool_name_display, {}, None) # Pass None for parsed_result

    # 7. get_event_stack_trace
    tool_name_display = f"get_event_stack_trace (index={event_idx})"
    tool_name_call = "get_event_stack_trace"
    if event_idx is not None:
        try:
            params = {"event_index": event_idx}; raw_result = await session.call_tool(tool_name_call, arguments=params); parsed_result = extract_json_from_result(raw_result, expect_list=True); print_result(tool_name_display, params, parsed_result, raw_result) # Expect list
            if isinstance(parsed_result, list) and not parsed_result: print("  (Note: Result is empty. This is expected if stacks were not loaded via --no-stack-traces on the server, or if this specific event had no stack).")
        except Exception as e: logger.error(f"Error calling {tool_name_call}: {e}", exc_info=True); print_result(tool_name_display, params, f"ERROR: {e}")
    else: logger.warning(f"Skipping {tool_name_display} test: No valid event_index found."); print_result(tool_name_display, {}, None)

    # 8. count_events_by_process
    tool_name = "count_events_by_process"
    try: params = {}; raw_result = await session.call_tool(tool_name, arguments=params); parsed_result = extract_json_from_result(raw_result); print_result(tool_name, params, parsed_result, raw_result) # Expect dict
    except Exception as e: logger.error(f"Error calling {tool_name}: {e}", exc_info=True); print_result(tool_name, {}, f"ERROR: {e}")

    # 9. summarize_operations_by_process
    process_filter = test_data["process_name_to_test"]
    tool_name_display = f"summarize_operations_by_process (process='{process_filter}')"
    tool_name_call = "summarize_operations_by_process"
    try: params = {"process_name_filter": process_filter}; raw_result = await session.call_tool(tool_name_call, arguments=params); parsed_result = extract_json_from_result(raw_result); print_result(tool_name_display, params, parsed_result, raw_result) # Expect dict
    except Exception as e: logger.error(f"Error calling {tool_name_call}: {e}", exc_info=True); print_result(tool_name_display, params, f"ERROR: {e}")

    # 10. get_timing_statistics
    tool_name_call = "get_timing_statistics"
    tool_name_display = "get_timing_statistics (group_by='process')"
    try: params = {"group_by": "process"}; raw_result = await session.call_tool(tool_name_call, arguments=params); parsed_result = extract_json_from_result(raw_result); print_result(tool_name_display, params, parsed_result, raw_result) # Expect dict
    except Exception as e: logger.error(f"Error calling {tool_name_call}: {e}", exc_info=True); print_result(tool_name_display, params, f"ERROR: {e}")
    tool_name_display = "get_timing_statistics (group_by='operation')"
    try: params = {"group_by": "operation"}; raw_result = await session.call_tool(tool_name_call, arguments=params); parsed_result = extract_json_from_result(raw_result); print_result(tool_name_display, params, parsed_result, raw_result) # Expect dict
    except Exception as e: logger.error(f"Error calling {tool_name_call}: {e}", exc_info=True); print_result(tool_name_display, params, f"ERROR: {e}")

    # 11. get_process_lifetime
    tool_name_call = "get_process_lifetime"
    for pid_val in pids_to_check:
         tool_name_display = f"get_process_lifetime (PID: {pid_val})"
         try: params = {"pid": pid_val}; raw_result = await session.call_tool(tool_name_call, arguments=params); parsed_result = extract_json_from_result(raw_result); print_result(tool_name_display, params, parsed_result, raw_result) # Expect dict
         except Exception as e: logger.error(f"Error calling {tool_name_call} for PID {pid_val}: {e}", exc_info=True); print_result(tool_name_display, params, f"ERROR: {e}")

    # 12. find_file_access
    path_filter = "windows\\system32"
    tool_name_display = f"find_file_access (path_contains='{path_filter}')"
    tool_name_call = "find_file_access"
    try: params = {"path_contains": path_filter, "limit": 5}; raw_result = await session.call_tool(tool_name_call, arguments=params); parsed_result = extract_json_from_result(raw_result, expect_list=True); print_result(tool_name_display, params, parsed_result, raw_result) # Expect list
    except Exception as e: logger.error(f"Error calling {tool_name_call}: {e}", exc_info=True); print_result(tool_name_display, params, f"ERROR: {e}")

    # 13. find_network_connections
    process_filter = test_data["process_name_to_test"]
    tool_name_display = f"find_network_connections (process='{process_filter}')"
    tool_name_call = "find_network_connections"
    try: params = {"process_name": process_filter}; raw_result = await session.call_tool(tool_name_call, arguments=params); parsed_result = extract_json_from_result(raw_result, expect_list=True); print_result(tool_name_display, params, parsed_result, raw_result) # Expect list
    except Exception as e: logger.error(f"Error calling {tool_name_call}: {e}", exc_info=True); print_result(tool_name_display, params, f"ERROR: {e}")

    # 14. export_query_results
    tool_name_call = "export_query_results"
    tool_name_display = "export_query_results (to CSV)"
    try:
        output_filename_csv = "mcp_test_export.csv"; params = {"output_file": output_filename_csv, "output_format": "csv", "filter_operation": "RegQueryValue", "filter_result": "SUCCESS"}
        raw_result = await session.call_tool(tool_name_call, arguments=params)
        parsed_result = extract_json_from_result(raw_result) # Expect dict
        print_result(tool_name_display, params, parsed_result, raw_result)
        # Check parsed_result for success
        if isinstance(parsed_result, dict) and parsed_result.get("success"):
            logger.info(f"CSV Export test reported success. File generated: {parsed_result.get('output_path')}")
        else:
            logger.error(f"CSV Export test failed or did not report success. Parsed Result: {parsed_result}")
    except Exception as e: logger.error(f"Error calling {tool_name_call} for CSV: {e}", exc_info=True); print_result(tool_name_display, params, f"ERROR: {e}")

    tool_name_display = "export_query_results (to JSON)"
    try:
        output_filename_json = "mcp_test_export.json"; params = {"output_file": output_filename_json, "output_format": "json", "filter_operation": "RegCloseKey"}
        raw_result = await session.call_tool(tool_name_call, arguments=params)
        parsed_result = extract_json_from_result(raw_result) # Expect dict
        print_result(tool_name_display, params, parsed_result, raw_result)
        # Check parsed_result for success
        if isinstance(parsed_result, dict) and parsed_result.get("success"):
            logger.info(f"JSON Export test reported success. File generated: {parsed_result.get('output_path')}")
        else:
             logger.error(f"JSON Export test failed or did not report success. Parsed Result: {parsed_result}")
    except Exception as e: logger.error(f"Error calling {tool_name_call} for JSON: {e}", exc_info=True); print_result(tool_name_display, params, f"ERROR: {e}")

    logger.info("All tests completed.")


# --- Main Execution Function ---
async def main(host: str, port: int, transport: str):
    """Sets up connection and runs tests."""

    # --- Connection Logic ---
    try:
        if transport == "stdio":
            logger.error("Testing via stdio from this script is not directly supported.")
            logger.error("Please run the server with stdio and interact manually, or use SSE for client testing.")
            return # Exit if stdio requested

        elif transport == "sse":
            # Construct the SSE endpoint URL
            sse_url = f"http://{host}:{port}/sse"
            logger.info(f"Attempting to connect via SSE to MCP server endpoint: {sse_url}...")

            # Use sse_client to get read/write streams
            async with sse_client(sse_url) as streams:
                logger.info("SSE client connected. Creating ClientSession...")
                read_stream, write_stream = streams
                # Use ClientSession with the obtained streams
                async with ClientSession(read_stream, write_stream) as session:
                    logger.info("ClientSession created. Running tool tests...")
                    await test_tools_with_session(session) # Pass the ClientSession instance

    except ConnectionRefusedError:
        logger.error(f"Connection refused. Is the MCP server running at {host}:{port} and accepting SSE connections at /sse?")
    except ImportError:
         # This case should ideally be caught at the top, but included for safety
         logger.critical("MCP SDK is required but not found. Cannot run tests.")
         logger.critical("Install using: pip install git+https://github.com/modelcontextprotocol/python-sdk.git")
         sys.exit(1)
    except Exception as e:
        logger.error(f"An error occurred during connection or testing: {e}", exc_info=True)


# --- Script Entry Point ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simplified Test client for the Procmon XML MCP Tool (using ClientSession).")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host where the MCP server is running (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8081, help="Port where the MCP server is running (default: 8081)")
    parser.add_argument("--transport", type=str, default="sse", choices=["stdio", "sse"],
                        help="MCP transport expected by the server (default: sse). Only SSE connection is attempted by this client.")

    args = parser.parse_args()

    # Run the main async function
    asyncio.run(main(args.host, args.port, args.transport))
