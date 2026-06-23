"""Event filtering engine for ProcmonMCP."""
import re
import time
import logging
from datetime import datetime, timezone
from typing import Optional, Any, Tuple, Set, AsyncIterator

from .compat import Context
from .constants import (
    PROCMON_TIMESTAMP_FORMAT, PROGRESS_REPORT_INTERVAL, PROGRESS_REPORT_SECONDS,
    MAX_FILTER_STR_LEN,
    IK_PROCESS_NAME, IK_OPERATION, IK_PATH, IK_RESULT, IK_STACK_PATH,
)
from .helpers import _compile_safe_regex
from .models import ProcmonLogData

logger = logging.getLogger(__name__)


async def _iter_filtered_event_indices(
    log_data: ProcmonLogData,
    ctx: Context,
    # Filters
    filter_process: Optional[str] = None,
    filter_pid: Optional[int] = None,
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
) -> AsyncIterator[int]:
    """
    Asynchronously iterates through event indices, applying filters.
    Uses indices for Process Name and Operation if applicable.

    Yields:
        Integer indices of events matching all filters.
    """
    if not log_data or not log_data.is_loaded():
        await ctx.error("Filtering failed: Log data not loaded.")
        return
    if not log_data.events:
        await ctx.info("Filtering: No events loaded.")
        return

    try:
        start_time = time.time()

        # Validate string filter lengths
        for param_name, param_val in [
            ("filter_path_contains", filter_path_contains),
            ("filter_process_contains", filter_process_contains),
            ("filter_stack_module_path", filter_stack_module_path),
        ]:
            if param_val and len(param_val) > MAX_FILTER_STR_LEN:
                await ctx.error(f"Filter '{param_name}' exceeds maximum length of {MAX_FILTER_STR_LEN}.")
                raise ValueError(f"Filter '{param_name}' exceeds maximum length of {MAX_FILTER_STR_LEN}.")

        # Pre-compile regex with safety checks
        path_regex_obj = _compile_safe_regex(filter_path_regex, "filter_path_regex")
        process_regex_obj = _compile_safe_regex(filter_process_regex, "filter_process_regex")
        detail_regex_obj = _compile_safe_regex(filter_detail_regex, "filter_detail_regex")
        start_ts: Optional[float] = None
        end_ts: Optional[float] = None
        is_start_time_only = False
        is_end_time_only = False

        # Parse time filters
        def parse_time_filter(time_filter_val: Any) -> Tuple[Optional[float], bool]:
            ts_val = None
            is_time_only = False
            if isinstance(time_filter_val, str):
                try:
                    parsed_time_obj = datetime.strptime(time_filter_val, PROCMON_TIMESTAMP_FORMAT).time()
                    ts_val = (parsed_time_obj.hour * 3600 + parsed_time_obj.minute * 60 +
                              parsed_time_obj.second + parsed_time_obj.microsecond / 1e6)
                    is_time_only = True
                    logger.info(f"Using time-only string filter for: {time_filter_val}")
                except ValueError:
                    try:
                        ts_val = float(time_filter_val)
                    except ValueError:
                        raise ValueError(f"Invalid time string format: '{time_filter_val}'. Use HH:MM:SS.ffffff or Unix timestamp.")
            elif isinstance(time_filter_val, (int, float)):
                ts_val = float(time_filter_val)
            return ts_val, is_time_only

        try:
            if filter_start_time is not None:
                start_ts, is_start_time_only = parse_time_filter(filter_start_time)
            if filter_end_time is not None:
                end_ts, is_end_time_only = parse_time_filter(filter_end_time)
            if (is_start_time_only and end_ts is not None and not is_end_time_only) or \
               (is_end_time_only and start_ts is not None and not is_start_time_only):
                logger.warning("Mixing time-only string filters and full timestamps might lead to unexpected results.")
        except ValueError as e:
            await ctx.error(f"Invalid time filter: {e}")
            raise e

        # Get interned IDs for exact match filters. A filter that was supplied
        # but whose value is absent from the interner can match nothing, so we
        # return immediately rather than silently dropping the filter (which
        # would wrongly return every event).
        if filter_process:
            process_id_filter = log_data.get_id(IK_PROCESS_NAME, filter_process)
            if process_id_filter is None:
                await ctx.info(f"Filter: process '{filter_process}' not present in loaded data; no matches.")
                return
        else:
            process_id_filter = None

        if filter_operation:
            operation_id_filter = log_data.get_id(IK_OPERATION, filter_operation)
            if operation_id_filter is None:
                await ctx.info(f"Filter: operation '{filter_operation}' not present in loaded data; no matches.")
                return
        else:
            operation_id_filter = None

        if filter_result:
            result_id_filter = log_data.get_id(IK_RESULT, filter_result)
            if result_id_filter is None:
                await ctx.info(f"Filter: result '{filter_result}' not present in loaded data; no matches.")
                return
        else:
            result_id_filter = None

        # Prepare case-insensitive substring filters
        filter_path_contains_lower = filter_path_contains.lower() if filter_path_contains else None
        filter_process_contains_lower = filter_process_contains.lower() if filter_process_contains else None
        filter_stack_module_path_lower = filter_stack_module_path.lower() if filter_stack_module_path else None

        # Determine initial candidate set using indices
        candidate_indices: Optional[Set[int]] = None
        index_used = False
        if process_id_filter is not None:
            pid_indices = set(log_data.pname_id_index.get(process_id_filter, []))
            candidate_indices = pid_indices
            index_used = True
            if not candidate_indices:
                await ctx.info(f"Filter Index: No events match Process filter '{filter_process}'.")
                return
        if operation_id_filter is not None:
            op_indices = set(log_data.op_id_index.get(operation_id_filter, []))
            if candidate_indices is None:
                candidate_indices = op_indices
            else:
                candidate_indices.intersection_update(op_indices)
            index_used = True
            if not candidate_indices:
                await ctx.info(f"Filter Index: No events match Operation filter '{filter_operation}'.")
                return
        if filter_pid is not None:
            this_pid_indices = set(log_data.pid_index.get(filter_pid, []))
            if candidate_indices is None:
                candidate_indices = this_pid_indices
            else:
                candidate_indices.intersection_update(this_pid_indices)
            index_used = True
            if not candidate_indices:
                await ctx.info(f"Filter Index: No events match PID filter {filter_pid}.")
                return

        # Determine iterator and total scan count
        if index_used and candidate_indices is not None:
            logger.info(f"Using index. Filtering {len(candidate_indices):,} candidate events.")
            indices_to_check = sorted(list(candidate_indices))
            total_to_scan = len(indices_to_check)
        else:
            logger.info("No index applicable or used. Filtering all events.")
            indices_to_check = range(len(log_data.events))
            total_to_scan = len(log_data.events)

        processed_count = 0
        last_progress_report_time = start_time

        # Main filtering loop
        for idx in indices_to_check:
            event_dict = log_data.events[idx]
            processed_count += 1

            # Progress reporting
            current_time = time.time()
            report_interval = max(10000, total_to_scan // 20) if total_to_scan > 0 else 10000
            if processed_count % report_interval == 0 or (current_time - last_progress_report_time > PROGRESS_REPORT_SECONDS):
                try:
                    await ctx.info(f" Filter scanned {processed_count:,}/{total_to_scan:,} candidate events... ({current_time - start_time:.1f}s)")
                except Exception as progress_err:
                    logger.warning(f"Failed to send progress update during filter: {progress_err}")
                last_progress_report_time = current_time

            # Apply filters sequentially (fail fast)
            if not index_used:
                if process_id_filter is not None and event_dict.get('pname_id') != process_id_filter:
                    continue
                if operation_id_filter is not None and event_dict.get('op_id') != operation_id_filter:
                    continue

            if result_id_filter is not None and event_dict.get('res_id') != result_id_filter:
                continue

            # Time filter
            event_ts_float = event_dict.get('ts')
            if event_ts_float is None:
                continue
            if start_ts is not None or end_ts is not None:
                current_event_compare_val = event_ts_float
                if is_start_time_only or is_end_time_only:
                    try:
                        event_dt_obj = datetime.fromtimestamp(event_ts_float, timezone.utc)
                        current_event_compare_val = (event_dt_obj.hour * 3600 + event_dt_obj.minute * 60 +
                                                     event_dt_obj.second + event_dt_obj.microsecond / 1e6)
                    except Exception:
                        continue

                if start_ts is not None and current_event_compare_val < start_ts:
                    continue
                if end_ts is not None and current_event_compare_val > end_ts:
                    continue

            # String contains/regex/stack filters
            if filter_path_contains_lower or filter_process_contains_lower or path_regex_obj or process_regex_obj or detail_regex_obj or filter_stack_module_path_lower:
                if filter_path_contains_lower or path_regex_obj:
                    path_str = log_data.get_string(IK_PATH, event_dict.get('path_id')) or ""
                    if filter_path_contains_lower and filter_path_contains_lower not in path_str.lower():
                        continue
                    if path_regex_obj and not path_regex_obj.search(path_str):
                        continue

                if filter_process_contains_lower or process_regex_obj:
                    pname_str = log_data.get_string(IK_PROCESS_NAME, event_dict.get('pname_id')) or ""
                    if filter_process_contains_lower and filter_process_contains_lower not in pname_str.lower():
                        continue
                    if process_regex_obj and not process_regex_obj.search(pname_str):
                        continue

                if detail_regex_obj:
                    detail_str = event_dict.get('detail') or ""
                    if not detail_regex_obj.search(detail_str):
                        continue

                if filter_stack_module_path_lower:
                    if not log_data.load_stack_traces:
                        continue
                    stack_list_optimized = event_dict.get('stack')
                    if not stack_list_optimized:
                        continue
                    found_in_stack = False
                    for frame_list in stack_list_optimized:
                        if len(frame_list) > 2 and frame_list[2] is not None:
                            frame_path_str = log_data.get_string(IK_STACK_PATH, frame_list[2])
                            if frame_path_str and filter_stack_module_path_lower in frame_path_str.lower():
                                found_in_stack = True
                                break
                    if not found_in_stack:
                        continue

            yield idx

        filter_elapsed = time.time() - start_time
        logger.info(f"Filtering completed in {filter_elapsed:.2f}s.")

    except re.error as e:
        await ctx.error(f"Invalid Regex pattern provided: {e}")
        raise ValueError(f"Invalid regex pattern: {e}") from e
    except Exception as e:
        await ctx.error(f"Failed during event filtering: {e}")
        logger.debug("Filtering exception details:", exc_info=True)
        raise RuntimeError(f"Internal error filtering events: {e}")
