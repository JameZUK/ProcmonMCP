"""Event detail formatting for ProcmonMCP."""
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from .constants import (
    PROCMON_TIMESTAMP_FORMAT,
    IK_PROCESS_NAME, IK_OPERATION, IK_PATH, IK_RESULT, IK_CATEGORY,
    IK_STACK_PATH, IK_STACK_LOCATION,
)
from .models import ProcmonLogData

logger = logging.getLogger(__name__)


def _get_formatted_event_details(log_data: ProcmonLogData, event_index: int) -> Optional[Dict[str, Any]]:
    """
    Retrieves and formats the full details for a single event by its index.
    Handles string lookups, timestamp formatting, and process enrichment.
    Returns None if index is invalid.
    """
    if not log_data or not log_data.is_loaded() or not (0 <= event_index < len(log_data.events)):
        logger.error(f"Invalid request for event details: Index {event_index} out of bounds or data not loaded.")
        return None

    event_dict = log_data.events[event_index]
    details: Dict[str, Any] = {}

    try:
        # Basic fields
        details['event_index'] = event_index
        details['sequence_number'] = event_dict.get('seq')
        details['pid'] = event_dict.get('pid')
        details['tid'] = event_dict.get('tid')
        details['parent_pid'] = event_dict.get('ppid')
        details['duration'] = event_dict.get('dur')
        details['detail'] = event_dict.get('detail')

        # Format timestamp
        ts_float = event_dict.get('ts')
        details['timestamp_unix'] = ts_float
        try:
            details['timestamp'] = datetime.fromtimestamp(ts_float, timezone.utc).strftime(PROCMON_TIMESTAMP_FORMAT) if ts_float else None
        except Exception:
            details['timestamp'] = "<Invalid Timestamp>"

        # Lookup interned strings
        details['operation'] = log_data.get_string(IK_OPERATION, event_dict.get('op_id'))
        details['path'] = log_data.get_string(IK_PATH, event_dict.get('path_id'))
        details['result'] = log_data.get_string(IK_RESULT, event_dict.get('res_id'))
        details['category'] = log_data.get_string(IK_CATEGORY, event_dict.get('cat_id'))
        details['process_name'] = log_data.get_string(IK_PROCESS_NAME, event_dict.get('pname_id'))

        # Extra data (if loaded)
        details['extra_data'] = event_dict.get('extra_data') if log_data.load_extra_data else None

        # Stack trace (if loaded)
        details['stack_trace'] = None
        if log_data.load_stack_traces and 'stack' in event_dict:
            stack_list = []
            for frame_data in event_dict['stack']:
                try:
                    if isinstance(frame_data, (list, tuple)) and len(frame_data) >= 4:
                        stack_list.append({
                            'depth': frame_data[0],
                            'address': frame_data[1],
                            'path': log_data.get_string(IK_STACK_PATH, frame_data[2]),
                            'location': log_data.get_string(IK_STACK_LOCATION, frame_data[3])
                        })
                    else:
                        logger.warning(f"Malformed optimized stack frame data encountered for event index {event_index}: {frame_data}")
                except (IndexError, TypeError):
                    logger.warning(f"Error processing stack frame data in event {event_index}: {frame_data}")
            details['stack_trace'] = stack_list

        # Enriched process info
        process_obj = log_data.processes_by_pid.get(details.get('pid')) if details.get('pid') is not None else None
        if process_obj:
            proc_details_dict = process_obj.to_dict()
            proc_details_dict.pop('process_index', None)
            proc_details_dict.pop('parent_process_index', None)
            details['process_details_summary'] = proc_details_dict
            details['user_sid'] = process_obj.owner
            details['is_64bit_process'] = process_obj.is_64bit
            if process_obj.parent_pid is not None:
                details['parent_pid'] = process_obj.parent_pid
            if process_obj.process_name is not None:
                details['process_name'] = process_obj.process_name
        else:
            details['process_details_summary'] = {"pid": details['pid'], "process_name": details['process_name'], "message": "Process details not found in <processlist>."}
            details['user_sid'] = None
            details['is_64bit_process'] = None

        # Placeholder fields
        details['completion_time'] = None
        details['relative_time'] = None

        return details

    except Exception as e:
        logger.error(f"Error formatting details for event {event_index}: {e}", exc_info=True)
        return None
