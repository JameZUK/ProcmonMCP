"""MCP tool definitions for ProcmonMCP."""
import re
import os
import csv
import json
import time
import logging
import dataclasses
from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from .compat import Context, PSUTIL_AVAILABLE
from .constants import (
    PROCMON_TIMESTAMP_FORMAT, PROGRESS_REPORT_INTERVAL, PROGRESS_REPORT_SECONDS,
    OP_PROCESS_CREATE, OP_PROCESS_EXIT, NETWORK_OPERATIONS,
    IK_PROCESS_NAME, IK_OPERATION, IK_PATH, IK_RESULT, IK_CATEGORY,
    IK_STACK_PATH, IK_STACK_LOCATION,
)
from . import server
from .server import tool_decorator, _check_loaded
from .filters import _iter_filtered_event_indices
from .formatters import _get_formatted_event_details
from .helpers import _format_bytes, parse_network_endpoint_parts, network_direction

logger = logging.getLogger(__name__)


# ---- Lifecycle tools (load_file, get_status) ----

@tool_decorator
async def get_status(ctx: Context) -> Dict[str, Any]:
    """
    Returns the current status of the ProcmonMCP server.
    Shows whether a file is loaded, loading progress, and available actions.
    Call this tool first to understand the current state before using other tools.
    """
    await ctx.info("[get_status] Checking server state...")
    try:
        status: Dict[str, Any] = {
            "file_loaded": False,
            "loading_in_progress": server.LOADING_IN_PROGRESS,
        }

        if server.LOADING_IN_PROGRESS:
            status["message"] = "A file is currently being loaded. Please wait for loading to complete."
            status["available_actions"] = ["get_status (to check progress)"]
        elif server.LOADED_DATA and server.LOADED_DATA.is_loaded():
            status["file_loaded"] = True
            status["loaded_filename"] = server.LOADED_DATA.loaded_filename
            status["event_count"] = len(server.LOADED_DATA.events)
            status["process_count"] = len(server.LOADED_DATA.processes_by_index)
            status["compression"] = server.LOADED_DATA.loaded_compression
            status["message"] = f"File '{server.LOADED_DATA.loaded_filename}' is loaded and ready for analysis."
            status["available_actions"] = [
                "All analysis tools (query_events, list_processes, etc.)",
                "load_file (to load a different file)",
            ]

            # Memory usage
            if PSUTIL_AVAILABLE:
                try:
                    import psutil
                    process = psutil.Process(os.getpid())
                    mem_info = process.memory_info()
                    status["memory_usage_rss"] = _format_bytes(mem_info.rss)
                except Exception:
                    pass
        else:
            # Check config for last-used file
            from .config import get_last_file
            last_file = get_last_file()
            status["message"] = "No file loaded. Use the 'load_file' tool to open a Procmon XML file."
            status["available_actions"] = ["load_file"]
            if last_file:
                status["last_used_file"] = last_file
                status["hint"] = f"Your last loaded file was: {last_file}"

        await ctx.info(f"[get_status] Completed. Loaded: {status['file_loaded']}")
        return status

    except Exception as e:
        await ctx.error(f"[get_status] Failed: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error checking status: {e}")


@tool_decorator
async def load_file(
    file_path: str,
    no_stack_traces: bool = False,
    no_extra_data: bool = False,
    no_cache: bool = False,
    *,
    ctx: Context,
) -> Dict[str, Any]:
    """
    Loads a Procmon XML file for analysis. Supports .xml, .xml.gz, .xml.bz2, and .xml.xz formats.
    This replaces any previously loaded data.

    Provides progress feedback during loading via MCP notifications.

    Loading an unchanged file that was parsed before (with the same options) is
    served from an on-disk cache and is near-instant; the response's 'from_cache'
    field indicates whether the cache was used.

    Args:
        file_path: Absolute or relative path to the Procmon XML file.
        no_stack_traces: If True, skip loading stack traces (saves memory for large files).
        no_extra_data: If True, skip loading extra/unknown event fields (saves memory).
        no_cache: If True, bypass the parsed-capture cache (always re-parse, and refresh the cache).
    """
    from .parser import load_procmon_xml
    from .config import set_last_file

    await ctx.info(f"[load_file] Starting load for: {file_path}")

    if server.LOADING_IN_PROGRESS:
        await ctx.error("[load_file] A file is already being loaded. Please wait.")
        raise RuntimeError("A file load is already in progress.")

    # Validate path
    abs_path = os.path.abspath(file_path)
    if not os.path.exists(abs_path):
        await ctx.error(f"[load_file] File not found: {abs_path}")
        raise FileNotFoundError(f"File not found: {abs_path}")
    if not os.path.isfile(abs_path):
        await ctx.error(f"[load_file] Path is not a file: {abs_path}")
        raise ValueError(f"Path is not a file: {abs_path}")

    load_stacks = not no_stack_traces
    load_extra = not no_extra_data

    server.LOADING_IN_PROGRESS = True
    try:
        await ctx.info(f"[load_file] Loading '{os.path.basename(abs_path)}' "
                       f"(stacks={'yes' if load_stacks else 'no'}, extra={'yes' if load_extra else 'no'})...")

        start_time = time.time()
        new_data = load_procmon_xml(abs_path, load_stacks, load_extra, use_cache=not no_cache)

        if not new_data or not new_data.is_loaded():
            await ctx.error("[load_file] File loading failed. Check server logs for details.")
            raise RuntimeError(f"Failed to load file: {abs_path}")

        elapsed = time.time() - start_time

        # Replace global data
        server.LOADED_DATA = new_data

        # Save to config
        set_last_file(abs_path)

        from_cache = bool(getattr(new_data, "loaded_from_cache", False))
        source = "cache" if from_cache else "XML parse"
        result = {
            "success": True,
            "loaded_filename": new_data.loaded_filename,
            "event_count": len(new_data.events),
            "process_count": len(new_data.processes_by_index),
            "compression": new_data.loaded_compression,
            "load_time_seconds": round(elapsed, 2),
            "from_cache": from_cache,
            "stack_traces_loaded": load_stacks,
            "extra_data_loaded": load_extra,
            "index_stats": {
                "pname_indexed_count": len(new_data.pname_id_index),
                "op_indexed_count": len(new_data.op_id_index),
                "pid_indexed_count": len(new_data.pid_index),
                "path_indexed_count": len(new_data.path_id_index),
            },
            "message": f"Successfully loaded {len(new_data.events):,} events and "
                       f"{len(new_data.processes_by_index)} processes from "
                       f"'{new_data.loaded_filename}' in {elapsed:.1f}s (via {source}).",
        }

        # Memory usage
        if PSUTIL_AVAILABLE:
            try:
                import psutil
                process = psutil.Process(os.getpid())
                mem_info = process.memory_info()
                result["memory_usage_rss"] = _format_bytes(mem_info.rss)
            except Exception:
                pass

        await ctx.info(f"[load_file] Completed. {result['message']}")
        return result

    except (FileNotFoundError, ValueError):
        raise
    except Exception as e:
        await ctx.error(f"[load_file] Failed: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Error loading file: {e}")
    finally:
        server.LOADING_IN_PROGRESS = False


@tool_decorator
async def clear_cache(ctx: Context) -> Dict[str, Any]:
    """
    Removes all on-disk parsed-capture caches.

    The cache stores previously parsed captures so reloading an unchanged file is
    near-instant. Use this to reclaim disk space or to force a clean re-parse of
    every file. Does not affect the currently loaded data.
    """
    from . import cache
    await ctx.info("[clear_cache] Clearing parsed-capture cache...")
    try:
        removed = cache.clear()
        await ctx.info(f"[clear_cache] Removed {removed} cached capture(s) from {cache.CACHE_DIR}.")
        return {"success": True, "removed": removed, "cache_dir": cache.CACHE_DIR}
    except Exception as e:
        await ctx.error(f"[clear_cache] Failed: {e}")
        logger.debug("Exception details:", exc_info=True)
        raise RuntimeError(f"Internal error clearing cache: {e}")


# ---- Analysis tools ----

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
            "pid_indexed_count": len(log_data.pid_index),
            "path_indexed_count": len(log_data.path_id_index),
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
    filter_process: Optional[str] = None, filter_operation: Optional[str] = None,
    filter_result: Optional[str] = None, filter_path_contains: Optional[str] = None,
    filter_process_contains: Optional[str] = None, filter_start_time: Optional[Any] = None,
    filter_end_time: Optional[Any] = None, filter_path_regex: Optional[str] = None,
    filter_process_regex: Optional[str] = None, filter_detail_regex: Optional[str] = None,
    filter_stack_module_path: Optional[str] = None,
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
    filters_applied = {k: v for k, v in locals().items() if k.startswith('filter_') and v is not None}
    if filters_applied:
        logger.debug(f"Filters Applied: {filters_applied}")

    if not log_data.events:
        await ctx.info("[query_events] Completed. No events loaded.")
        return []
    filtered_event_summaries = []
    count = 0
    query_start_time = time.time()

    try:
        event_indices_iterator = _iter_filtered_event_indices(
            log_data=log_data, ctx=ctx,
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
                break

            event_dict = log_data.events[idx]
            try:
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

    except (ValueError, TypeError, RuntimeError, re.error) as e:
        # These are already meaningful client-facing errors (bad filter input,
        # invalid regex, or an internal error surfaced by the filter iterator);
        # re-raise as-is rather than double-wrapping.
        await ctx.error(f"[query_events] Failed: {e}")
        logger.debug("Query exception details:", exc_info=True)
        raise


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

        for pname_id, event_indices in log_data.pname_id_index.items():
            name = log_data.get_string(IK_PROCESS_NAME, pname_id) or 'Unknown/Missing'
            event_counts[name] = len(event_indices)

        elapsed = time.time() - start_time
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

        target_pname_id = log_data.get_id(IK_PROCESS_NAME, process_name_filter)
        if target_pname_id is None:
            await ctx.warning(f"[summarize_operations_by_process] Process name '{process_name_filter}' not found in loaded data.")
            return {}

        indices_to_check = log_data.pname_id_index.get(target_pname_id)
        if not indices_to_check:
            await ctx.warning(f"No events found matching process name '{process_name_filter}'.")
            return {}

        await ctx.info(f"[summarize_operations_by_process] Scanning {len(indices_to_check):,} events for '{process_name_filter}'...")
        last_progress_report_time = start_time

        for i, idx in enumerate(indices_to_check):
            current_time = time.time()
            if i > 0 and (i % (PROGRESS_REPORT_INTERVAL * 4) == 0 or (current_time - last_progress_report_time > PROGRESS_REPORT_SECONDS)):
                elapsed = current_time - start_time
                try:
                    await ctx.info(f"[summarize_operations_by_process] Processed {i:,}/{len(indices_to_check):,} events ({elapsed:.1f}s)")
                except Exception as progress_err:
                    logger.warning(f"Failed to send progress update during summarize: {progress_err}")
                last_progress_report_time = current_time

            event_dict = log_data.events[idx]
            event_count_for_process += 1
            operation = log_data.get_string(IK_OPERATION, event_dict.get('op_id')) or 'Unknown'
            operation_counts[operation] += 1

        elapsed = time.time() - start_time
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
        stats = defaultdict(lambda: {'min': float('inf'), 'max': float('-inf'), 'sum': 0.0, 'count': 0})
        total_events = len(log_data.events)
        start_time = time.time()
        events_with_duration = 0
        last_progress_report_time = start_time

        for i, event_dict in enumerate(log_data.events):
            current_time = time.time()
            if i > 0 and (i % (PROGRESS_REPORT_INTERVAL * 4) == 0 or (current_time - last_progress_report_time > PROGRESS_REPORT_SECONDS)):
                elapsed = current_time - start_time
                try:
                    await ctx.info(f"[get_timing_statistics] Processed {i:,}/{total_events:,} events ({elapsed:.1f}s)")
                except Exception as progress_err:
                    logger.warning(f"Failed to send progress update during timing stats: {progress_err}")
                last_progress_report_time = current_time

            duration = event_dict.get('dur')
            if duration is None or not isinstance(duration, (float, int)) or duration <= 0:
                if duration is not None and logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Event {i} has invalid duration for stats: '{duration}' (Type: {type(duration)})")
                continue
            events_with_duration += 1
            if events_with_duration == 1 and logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"Event {i} has first valid duration for stats: {duration}")

            group_key_id = event_dict.get('pname_id') if group_by == "process" else event_dict.get('op_id')
            interner_name = IK_PROCESS_NAME if group_by == "process" else IK_OPERATION
            group_key = log_data.get_string(interner_name, group_key_id) or 'Unknown/Missing'

            group_stats = stats[group_key]
            group_stats['count'] += 1
            group_stats['sum'] += duration
            if duration < group_stats['min']:
                group_stats['min'] = duration
            if duration > group_stats['max']:
                group_stats['max'] = duration

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

        output_stats_list.sort(key=lambda x: x['count'], reverse=True)
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
    create_op_id = log_data.get_id(IK_OPERATION, OP_PROCESS_CREATE)
    exit_op_id = log_data.get_id(IK_OPERATION, OP_PROCESS_EXIT)

    if pid not in log_data.processes_by_pid:
        await ctx.warning(f"[get_process_lifetime] PID {pid} not found in initial process list. It might have started/exited before the list snapshot.")

    # Use PID index intersected with operation indices for fast lookup
    pid_event_set = set(log_data.pid_index.get(pid, []))
    if not pid_event_set:
        await ctx.info(f"[get_process_lifetime] No events found for PID {pid}.")
        result = {"create_timestamp": create_ts, "exit_timestamp": exit_ts}
        await ctx.info(f"[get_process_lifetime] PID {pid}: {result}")
        return result

    if create_op_id is not None:
        create_indices = log_data.op_id_index.get(create_op_id, [])
        for idx in create_indices:
            if idx in pid_event_set:
                create_ts = log_data.events[idx].get('ts')
                break

    if exit_op_id is not None:
        exit_indices = log_data.op_id_index.get(exit_op_id, [])
        for idx in reversed(exit_indices):
            if idx in pid_event_set:
                exit_ts = log_data.events[idx].get('ts')
                break

    result = {"create_timestamp": create_ts, "exit_timestamp": exit_ts}
    await ctx.info(f"[get_process_lifetime] PID {pid}: {result}")
    return result


@tool_decorator
async def find_file_access(path_contains: str, limit: int = 100, *, ctx: Context) -> List[Dict[str, Any]]:
    """
    Finds events related to file system access where the event's 'Path' field contains the given substring (case-insensitive).
    Returns a list of event summaries (up to the specified limit) for matching events.
    Each summary includes index, timestamp, process, PID, operation, path, and result.
    Uses path_id_index to check unique paths first (O(unique_paths)) instead of scanning all events.
    """
    log_data = await _check_loaded(ctx, "find_file_access")
    await ctx.info(f"[find_file_access] Starting for path containing: '{path_contains}' (limit={limit})")
    if not path_contains:
        await ctx.error("[find_file_access] path_contains filter cannot be empty.")
        raise ValueError("path_contains filter is required.")
    found_events = []
    count = 0
    path_contains_lower = path_contains.lower()

    # Phase 1: Find all path_ids whose string contains the substring
    # This is O(unique_paths) instead of O(total_events)
    matching_path_ids = []
    for path_id, event_indices in log_data.path_id_index.items():
        path_str = log_data.get_string(IK_PATH, path_id)
        if path_str and path_contains_lower in path_str.lower():
            matching_path_ids.append((path_id, path_str, event_indices))

    if not matching_path_ids:
        await ctx.info(f"[find_file_access] No paths matching '{path_contains}' found in {len(log_data.path_id_index)} unique paths.")
        return []

    await ctx.info(f"[find_file_access] Found {len(matching_path_ids)} matching unique paths out of {len(log_data.path_id_index)}.")

    # Phase 2: Collect events from matching paths, sorted by event index
    # Merge-sort approach: collect all candidate indices, sort, then take up to limit
    candidate_indices = []
    for _, _, event_indices in matching_path_ids:
        candidate_indices.extend(event_indices)
    candidate_indices.sort()

    # Phase 3: Build summaries up to limit
    for idx in candidate_indices:
        if count >= limit:
            break
        event_dict = log_data.events[idx]
        path_id = event_dict.get('path_id')
        # Find the cached path_str for this path_id
        path_str = log_data.get_string(IK_PATH, path_id)
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


def _format_ts(ts: Optional[float]) -> Optional[str]:
    """Formats a Unix timestamp as a Procmon time-of-day string, or None."""
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime(PROCMON_TIMESTAMP_FORMAT)
    except (ValueError, OverflowError, OSError):
        return None


def _network_op_ids(log_data) -> set:
    """Returns the set of interned operation IDs for known network operations."""
    return {
        oid for oid in (log_data.get_id(IK_OPERATION, op) for op in NETWORK_OPERATIONS)
        if oid is not None
    }


def _aggregate_network(log_data, indices, network_op_ids: set, group_by_process: bool) -> List[Dict[str, Any]]:
    """Aggregates network events (by index) into enriched remote-endpoint records.

    Each record carries the endpoint (host:port), split host/ip/hostname/port,
    the operations and inferred directions seen, the distinct results, an event
    count, and first/last-seen timestamps. When ``group_by_process`` is True the
    grouping key is (process_name, pid, endpoint); otherwise it is the endpoint
    alone (capture-wide rollup), with a process list/count attached.
    """
    agg: Dict[Any, Dict[str, Any]] = {}
    for idx in indices:
        event_dict = log_data.events[idx]
        if event_dict.get('op_id') not in network_op_ids:
            continue
        parts = parse_network_endpoint_parts(log_data.get_string(IK_PATH, event_dict.get('path_id')))
        if not parts:
            continue
        pname = log_data.get_string(IK_PROCESS_NAME, event_dict.get('pname_id'))
        pid = event_dict.get('pid')
        operation = log_data.get_string(IK_OPERATION, event_dict.get('op_id'))
        result = log_data.get_string(IK_RESULT, event_dict.get('res_id'))
        ts = event_dict.get('ts')
        endpoint = parts['endpoint']
        key = (pname, pid, endpoint) if group_by_process else endpoint

        rec = agg.get(key)
        if rec is None:
            rec = {
                'endpoint': endpoint, 'host': parts['host'], 'port': parts['port'],
                'ip': parts['ip'], 'hostname': parts['hostname'], 'count': 0,
                '_ops': set(), '_dirs': set(), '_results': set(),
                '_first': ts, '_last': ts, '_procs': set(),
            }
            if group_by_process:
                rec['process_name'] = pname
                rec['pid'] = pid
            agg[key] = rec

        rec['count'] += 1
        if operation:
            rec['_ops'].add(operation)
        direction = network_direction(operation)
        if direction:
            rec['_dirs'].add(direction)
        if result:
            rec['_results'].add(result)
        if pname is not None or pid is not None:
            rec['_procs'].add((pname, pid))
        if ts is not None:
            if rec['_first'] is None or ts < rec['_first']:
                rec['_first'] = ts
            if rec['_last'] is None or ts > rec['_last']:
                rec['_last'] = ts

    records: List[Dict[str, Any]] = []
    for rec in agg.values():
        first = rec.pop('_first')
        last = rec.pop('_last')
        rec['operations'] = sorted(rec.pop('_ops'))
        rec['directions'] = sorted(rec.pop('_dirs'))
        rec['results'] = sorted(rec.pop('_results'))
        procs = rec.pop('_procs')
        rec['first_seen_unix'] = first
        rec['last_seen_unix'] = last
        rec['first_seen'] = _format_ts(first)
        rec['last_seen'] = _format_ts(last)
        if not group_by_process:
            rec['process_count'] = len(procs)
            rec['processes'] = sorted(
                f"{name} (PID {p})" if p is not None else str(name)
                for name, p in procs if name is not None or p is not None
            )
        records.append(rec)
    return records


@tool_decorator
async def find_network_connections(process_name: str, *, ctx: Context) -> List[Dict[str, Any]]:
    """
    Finds remote network endpoints accessed by a specific process, with enrichment.
    Uses a case-sensitive, exact match for the process name.

    Scans the process's network operations (TCP/UDP Connect/Send/Receive) and returns
    one record per unique (PID, endpoint), each containing: endpoint (host:port), host,
    ip, hostname, port, the operations and inferred directions (connect/send/receive)
    seen, distinct results, an event count, and first/last-seen timestamps.
    Records are sorted by event count (descending). Returns an empty list if the process
    has no recognised network endpoints.
    """
    log_data = await _check_loaded(ctx, "find_network_connections")
    await ctx.info(f"[find_network_connections] Starting for process: '{process_name}'")
    if not process_name:
        await ctx.error("[find_network_connections] process_name filter cannot be empty.")
        raise ValueError("process_name filter is required.")

    target_pname_id = log_data.get_id(IK_PROCESS_NAME, process_name)
    network_op_ids = _network_op_ids(log_data)

    if target_pname_id is None:
        await ctx.warning(f"[find_network_connections] Process name '{process_name}' not found in loaded data.")
        return []
    if not network_op_ids:
        await ctx.warning(f"[find_network_connections] No standard network operations found in interner.")
        return []

    indices_to_check = log_data.pname_id_index.get(target_pname_id, [])
    if not indices_to_check:
        await ctx.info(f"[find_network_connections] No events found for process '{process_name}'.")
        return []

    await ctx.info(f"[find_network_connections] Scanning {len(indices_to_check):,} events for '{process_name}'...")
    records = _aggregate_network(log_data, indices_to_check, network_op_ids, group_by_process=True)
    records.sort(key=lambda r: (-r['count'], str(r['endpoint']), r.get('pid') or 0))
    await ctx.info(f"[find_network_connections] Completed. {len(records)} unique endpoints for '{process_name}'.")
    return records


@tool_decorator
async def export_query_results(
    output_file: str,
    output_format: str = 'csv',
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
    SECURITY: Output files are restricted to the script's current working
    directory or subdirectories. Absolute paths or paths with '..' are denied.

    Filter Notes:
    - Exact match filters (filter_process, filter_operation, filter_result) use case-sensitive matching on the full string.
    - Contains filters (filter_path_contains, filter_process_contains, filter_stack_module_path) perform case-insensitive substring checks.
    - Regex filters (filter_path_regex, filter_process_regex, filter_detail_regex) use Python's 're' module with IGNORECASE.
    - Time filters (filter_start_time, filter_end_time) accept Unix timestamps (float/int) or time strings ("HH:MM:SS.ffffff").
    """
    await ctx.info(f"[export_query_results] Starting export to '{output_file}' ({output_format})...")
    if output_format.lower() not in ['csv', 'json']:
        raise ValueError("Invalid output_format. Must be 'csv' or 'json'.")
    if not output_file:
        raise ValueError("Output file name cannot be empty.")

    # Ensure data is loaded before validating paths or creating directories.
    log_data = await _check_loaded(ctx, "export_query_results")

    # Path validation (hardened)
    try:
        allowed_dir = os.path.abspath(os.getcwd())
        abs_output_path = os.path.abspath(os.path.join(allowed_dir, output_file))

        if os.path.commonpath([abs_output_path, allowed_dir]) != allowed_dir:
            await ctx.error(f"[export_query_results] Path traversal denied: '{abs_output_path}' is outside allowed directory '{allowed_dir}'.")
            raise ValueError(f"Invalid output path. Must be relative and inside the directory: {allowed_dir}")

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

    if not log_data.events:
        await ctx.info("[export_query_results] Completed. No events loaded to export.")
        return {"success": True, "output_path": abs_output_path, "events_exported": 0}
    events_to_export = []
    events_exported = 0
    export_start_time = time.time()

    try:
        await ctx.info("[export_query_results] Filtering events...")
        event_indices_iterator = _iter_filtered_event_indices(
            log_data=log_data, ctx=ctx,
            filter_process=filter_process, filter_operation=filter_operation,
            filter_result=filter_result, filter_path_contains=filter_path_contains,
            filter_process_contains=filter_process_contains, filter_start_time=filter_start_time,
            filter_end_time=filter_end_time, filter_path_regex=filter_path_regex,
            filter_process_regex=filter_process_regex, filter_detail_regex=filter_detail_regex,
            filter_stack_module_path=filter_stack_module_path
        )

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
                try:
                    await ctx.info(f"[export_query_results] Retrieved details for {indices_processed:,} events...")
                except Exception:
                    pass

        await ctx.info(f"[export_query_results] Retrieved {len(events_to_export)} event details in {time.time() - detail_retrieval_start:.2f}s.")

        if not events_to_export:
            await ctx.info("[export_query_results] No matching events to export.")
            if output_format.lower() == 'csv':
                try:
                    with open(abs_output_path, 'w', newline='', encoding='utf-8') as csvfile:
                        fieldnames = ['event_index', 'sequence_number', 'timestamp', 'process_name', 'pid', 'tid', 'operation', 'path', 'result', 'detail', 'duration', 'category', 'parent_pid', 'extra_data', 'stack_trace', 'user_sid', 'is_64bit_process', 'process_details_summary']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                        writer.writeheader()
                    await ctx.info(f"Created empty CSV file with headers: {abs_output_path}")
                except IOError as e:
                    await ctx.error(f"Error writing empty CSV file '{abs_output_path}': {e}")
            return {"success": True, "output_path": abs_output_path, "events_exported": 0}

        if output_format.lower() == 'csv':
            fieldnames = list(events_to_export[0].keys())
            try:
                with open(abs_output_path, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                    writer.writeheader()
                    for row_dict in events_to_export:
                        csv_row = dict(row_dict)
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


@tool_decorator
async def list_network_connections(limit: int = 200, *, ctx: Context) -> List[Dict[str, Any]]:
    """
    Lists network connections across ALL processes in the loaded capture, enriched.

    Scans every network operation (TCP/UDP Connect/Send/Receive) and returns one record
    per unique (process_name, PID, endpoint), ranked by event count (descending) so the
    busiest connections appear first. Each record includes: process_name, pid, endpoint
    (host:port), host, ip, hostname, port, the operations and inferred directions
    (connect/send/receive), distinct results, an event count, and first/last-seen
    timestamps. At most `limit` records are returned (the top ones by count). Use this for
    triage, then drill into a process with find_network_connections or rank remote
    endpoints with get_network_top_talkers.
    """
    log_data = await _check_loaded(ctx, "list_network_connections")
    await ctx.info("[list_network_connections] Scanning all network events...")

    network_op_ids = _network_op_ids(log_data)
    if not network_op_ids:
        await ctx.warning("[list_network_connections] No network operations found in interner.")
        return []

    # Gather only network-event indices via op_id_index, so this is O(network events)
    # rather than O(total events).
    candidate_indices: List[int] = []
    for op_id in network_op_ids:
        candidate_indices.extend(log_data.op_id_index.get(op_id, []))

    records = _aggregate_network(log_data, candidate_indices, network_op_ids, group_by_process=True)
    records.sort(key=lambda r: (-r['count'], str(r.get('process_name')), str(r['endpoint'])))

    total = len(records)
    if total > limit:
        await ctx.warning(f"[list_network_connections] {total} records; returning top {limit} by event count.")
        records = records[:limit]
    await ctx.info(f"[list_network_connections] Completed. {len(records)} of {total} unique connections.")
    return records


@tool_decorator
async def get_network_top_talkers(limit: int = 50, *, ctx: Context) -> List[Dict[str, Any]]:
    """
    Ranks unique remote endpoints across the WHOLE capture by network-event count.

    Aggregates all network operations (TCP/UDP Connect/Send/Receive) by remote endpoint
    (ignoring which process), returning up to `limit` endpoints sorted by event count
    (descending). Each record includes: endpoint (host:port), host, ip, hostname, port,
    an event count, the number of distinct processes that touched it (process_count) and
    their names (processes), the operations and inferred directions seen, distinct
    results, and first/last-seen timestamps.
    """
    log_data = await _check_loaded(ctx, "get_network_top_talkers")
    await ctx.info("[get_network_top_talkers] Ranking remote endpoints...")

    network_op_ids = _network_op_ids(log_data)
    if not network_op_ids:
        await ctx.warning("[get_network_top_talkers] No network operations found in interner.")
        return []

    candidate_indices: List[int] = []
    for op_id in network_op_ids:
        candidate_indices.extend(log_data.op_id_index.get(op_id, []))

    records = _aggregate_network(log_data, candidate_indices, network_op_ids, group_by_process=False)
    records.sort(key=lambda r: (-r['count'], str(r['endpoint'])))

    total = len(records)
    if total > limit:
        records = records[:limit]
    await ctx.info(f"[get_network_top_talkers] Completed. Top {len(records)} of {total} unique endpoints.")
    return records
