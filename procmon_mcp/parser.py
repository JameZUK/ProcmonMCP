"""XML parsing logic for Procmon XML files."""
import os
import io
import time
import gzip
import bz2
import lzma
import logging
import contextlib
from datetime import datetime, timezone, timedelta, time as dt_time
from typing import Dict, Any, Optional, Iterator, IO

from .compat import ET_impl, LXML_AVAILABLE
from .constants import (
    PROCMON_TIMESTAMP_FORMAT, PROGRESS_REPORT_INTERVAL, PROGRESS_REPORT_SECONDS,
    BASE_DATE, ROLLOVER_THRESHOLD_SECONDS,
    OP_PROCESS_CREATE, OP_PROCESS_EXIT, NETWORK_OPERATIONS,
    IK_PROCESS_NAME, IK_OPERATION, IK_PATH, IK_RESULT, IK_CATEGORY,
    IK_STACK_PATH, IK_STACK_LOCATION,
)
from .helpers import find_text_func, _strip_namespace, _find_child_ignore_ns, _clear_elem, _format_bytes
from .models import StringInterner, StackFrame, ProcessInfo, ProcmonLogData

logger = logging.getLogger(__name__)


def _parse_xml_processes_only(source_stream: IO[bytes]) -> Dict[int, ProcessInfo]:
    """
    Parses only the <processlist> from the XML stream and returns the process dictionary
    keyed by ProcessIndex. Stops parsing after the </processlist> tag. Ignores namespaces.
    """
    processes_dict: Dict[int, ProcessInfo] = {}
    parsing_stage = "seeking_procmon"
    tags_of_interest = ('process', 'processlist', 'procmon')
    start_time = time.time()
    process_element_count = 0

    try:
        if LXML_AVAILABLE:
            context = ET_impl.iterparse(source_stream, events=('end',), tag=tags_of_interest)
        else:
            context = ET_impl.iterparse(source_stream, events=('end',))
        logger.info("Starting Pass 1: Parsing process list...")
    except Exception as e:
        logger.error(f"Unexpected error initializing XML parser for process list: {e}", exc_info=True)
        raise RuntimeError("Failed to initialize XML parser for process list") from e

    try:
        for event_type, elem in context:
            tag = _strip_namespace(elem.tag)

            if parsing_stage == "seeking_procmon":
                if tag == 'procmon':
                    logger.warning("Found end of procmon before processlist.")
                    break
                parsing_stage = "seeking_processlist"
                # Fall through intentionally: first non-procmon element
                # may be the processlist or a process element itself.

            if parsing_stage == "seeking_processlist":
                if tag == 'process':
                    parsing_stage = "parsing_processlist"
                    # Fall through intentionally: process the first
                    # <process> element immediately below.
                elif tag == 'processlist':
                    logger.info("Found empty <processlist>.")
                    _clear_elem(elem)
                    break
                else:
                    continue  # Skip unrelated elements while seeking

            if parsing_stage == "parsing_processlist":
                if tag == 'process':
                    process_element_count += 1
                    try:
                        proc_info = ProcessInfo.from_xml_element(elem)
                        if proc_info.process_index is not None and proc_info.process_index >= 0:
                            processes_dict[proc_info.process_index] = proc_info
                        else:
                            logger.warning(f"Parsed process element missing or invalid ProcessIndex.")
                    except Exception as e:
                        logger.warning(f"Failed to parse <process> element: {e}", exc_info=False)
                    _clear_elem(elem)
                    if process_element_count % 500 == 0:
                        elapsed = time.time() - start_time
                        logger.info(f"  [Pass 1] Parsed {process_element_count:,} process elements... ({elapsed:.1f}s)")
                elif tag == 'processlist':
                    logger.debug(f"Finished parsing <processlist> tag.")
                    _clear_elem(elem)
                    break

            if tag == 'procmon':
                logger.warning("Reached end of <procmon> while parsing processes.")
                break

    except ET_impl.XMLSyntaxError as e:
        logger.error(f"XML Parse Error during process parsing: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during process parsing: {e}", exc_info=True)
        raise

    elapsed = time.time() - start_time
    logger.info(f"Finished Pass 1: Found {len(processes_dict)} unique processes from {process_element_count:,} elements ({elapsed:.2f}s).")
    return processes_dict


def _parse_xml_stream_for_loading(
    source_stream: IO[bytes],
    interners: Dict[str, StringInterner],
    processes: Dict[int, ProcessInfo],
    load_stack: bool,
    load_extra: bool,
    raw_file_stream: Optional[IO[bytes]] = None,
    total_size: Optional[int] = None
) -> Iterator[Dict[str, Any]]:
    """
    Internal helper optimized for initial loading into memory. Parses <event> elements
    directly into optimized dictionaries using interners, and yields them.

    NOTE: This function contains stateful logic to handle timestamp rollovers (e.g., spanning midnight).
    """
    parsing_stage = "seeking_eventlist"
    try:
        # Only <event> (processed at end), plus the section/root markers used by
        # the state machine. Stack <frame> elements are read from each event's
        # fully-parsed subtree, so they don't need to trigger iterparse events.
        tags_of_interest = ('event', 'eventlist', 'procmon')
        if LXML_AVAILABLE:
            context = ET_impl.iterparse(source_stream, events=('start', 'end'), tag=tags_of_interest)
        else:
            context = ET_impl.iterparse(source_stream, events=('start', 'end'))
        logger.info("Starting Pass 2: Parsing and optimizing events...")
    except Exception as e:
        logger.error(f"Unexpected error initializing XML parser for event loading: {e}", exc_info=True)
        raise RuntimeError("Failed to initialize XML parser for events") from e

    event_count = 0
    yielded_count = 0
    skipped_count = 0
    start_time = time.time()
    last_report_time = start_time

    # State for timestamp midnight rollover
    current_processing_date = BASE_DATE.date()
    last_parsed_time: Optional[dt_time] = None

    try:
        for event_type, elem in context:
            tag = _strip_namespace(elem.tag)

            if parsing_stage == "seeking_eventlist":
                if event_type == 'start' and tag == 'eventlist':
                    logger.debug("Entered <eventlist> (start event).")
                    parsing_stage = "parsing_events"
                elif event_type == 'end' and tag == 'procmon':
                    logger.warning("Reached end of <procmon> before finding <eventlist>.")
                    break
                elif event_type == 'end':
                    _clear_elem(elem)
                continue

            elif parsing_stage == "parsing_events":
                # Process each <event> only on its 'end' event. iterparse does
                # NOT guarantee that an element's children/text are populated on
                # the 'start' event (they are only complete by 'end'), so reading
                # child fields early silently drops or corrupts events whenever a
                # read-buffer boundary falls inside an <event>.
                if event_type == 'end' and tag == 'event':
                    event_count += 1
                    try:
                        pid_str = find_text_func(elem, 'PID')
                        ts_str = find_text_func(elem, 'Time_of_Day')
                        pid = ProcessInfo._safe_text_to_int(pid_str)

                        # Inline timestamp parsing with midnight rollover handling
                        ts_float: Optional[float] = None
                        if ts_str:
                            try:
                                parts = ts_str.split('.', 1)
                                time_part = parts[0]
                                if len(parts) > 1:
                                    fractional_part = parts[1][:6].ljust(6, '0')
                                else:
                                    fractional_part = "000000"
                                ts_str_corrected = f"{time_part}.{fractional_part}"
                                parsed_time_obj = datetime.strptime(ts_str_corrected, PROCMON_TIMESTAMP_FORMAT).time()

                                # Check for midnight rollover with threshold
                                if last_parsed_time and parsed_time_obj < last_parsed_time:
                                    last_seconds = (last_parsed_time.hour * 3600 + last_parsed_time.minute * 60 +
                                                    last_parsed_time.second + last_parsed_time.microsecond / 1e6)
                                    new_seconds = (parsed_time_obj.hour * 3600 + parsed_time_obj.minute * 60 +
                                                   parsed_time_obj.second + parsed_time_obj.microsecond / 1e6)
                                    time_gap = last_seconds - new_seconds
                                    if time_gap > ROLLOVER_THRESHOLD_SECONDS:
                                        current_processing_date += timedelta(days=1)
                                        logger.info(f"Midnight rollover detected at event #{event_count} "
                                                     f"(gap: {time_gap:.1f}s). Advancing date to {current_processing_date}.")
                                    else:
                                        logger.debug(f"Out-of-order timestamp at event #{event_count} "
                                                      f"(gap: {time_gap:.1f}s < threshold). No rollover.")

                                full_dt = datetime.combine(current_processing_date, parsed_time_obj, tzinfo=timezone.utc)
                                ts_float = full_dt.timestamp()
                                last_parsed_time = parsed_time_obj

                            except (ValueError, TypeError, IndexError) as e:
                                logger.warning(f"Could not parse timestamp string '{ts_str}': {e}")

                        # Validate required fields before building the event
                        if pid is None or ts_float is None:
                            skipped_count += 1
                            if logger.isEnabledFor(logging.DEBUG):
                                skip_reason = ""
                                if pid is None:
                                    skip_reason += f"Missing/invalid PID ('{pid_str}'). "
                                if ts_float is None:
                                    skip_reason += f"Missing/invalid Time_of_Day ('{ts_str}'). "
                                logger.warning(f"Skipping event #{event_count}: {skip_reason.strip()}")
                                try:
                                    event_xml_str = ET_impl.tostring(elem, encoding='unicode', method='xml')
                                    logger.debug(f"  Skipped Event XML:\n{event_xml_str[:1500]}...")
                                except Exception as log_e:
                                    logger.debug(f"  Could not serialize skipped event #{event_count} to string: {log_e}")
                            _clear_elem(elem)
                            continue

                        opt_event: Dict[str, Any] = {
                            'pid': pid,
                            'ts': ts_float,
                            'seq': ProcessInfo._safe_text_to_int(find_text_func(elem, 'SequenceNumber')),
                            'tid': ProcessInfo._safe_text_to_int(find_text_func(elem, 'ThreadId')),
                            'ppid': ProcessInfo._safe_text_to_int(find_text_func(elem, 'ParentPID')),
                            'detail': find_text_func(elem, 'Detail'),
                            'dur': None,
                        }
                        duration_text = find_text_func(elem, 'Duration')
                        if duration_text:
                            try:
                                opt_event['dur'] = float(duration_text)
                            except (ValueError, TypeError):
                                pass

                        # Process name fallback logic
                        process_name_str = find_text_func(elem, 'Process_Name')
                        if process_name_str is None:
                            process_index = ProcessInfo._safe_text_to_int(find_text_func(elem, 'ProcessIndex'))
                            if process_index is not None:
                                proc_info = processes.get(process_index)
                                if proc_info:
                                    process_name_str = proc_info.process_name
                                    if opt_event.get('ppid') is None:
                                        opt_event['ppid'] = proc_info.parent_pid
                                else:
                                    logger.warning(f"Event #{event_count} has ProcessIndex {process_index} but process info not found.")

                        # String interning
                        opt_event['pname_id'] = interners[IK_PROCESS_NAME].get_id(process_name_str)
                        opt_event['op_id'] = interners[IK_OPERATION].get_id(find_text_func(elem, 'Operation'))
                        opt_event['path_id'] = interners[IK_PATH].get_id(find_text_func(elem, 'Path'))
                        opt_event['res_id'] = interners[IK_RESULT].get_id(find_text_func(elem, 'Result'))
                        opt_event['cat_id'] = interners[IK_CATEGORY].get_id(find_text_func(elem, 'Category'))

                        # Stack frames (read from the fully-parsed <stack> child)
                        if load_stack:
                            stack_elem = _find_child_ignore_ns(elem, 'stack')
                            if stack_elem is not None:
                                stack_frames = []
                                for child in stack_elem:
                                    if _strip_namespace(child.tag) != 'frame':
                                        continue
                                    try:
                                        frame_obj = StackFrame.from_xml_element(child)
                                        stack_frames.append(frame_obj.to_optimized_list(
                                            interners[IK_STACK_PATH], interners[IK_STACK_LOCATION]
                                        ))
                                    except Exception as frame_e:
                                        logger.warning(f"Failed to parse/optimize stack frame for event #{event_count}: {frame_e}", exc_info=False)
                                if stack_frames:
                                    opt_event['stack'] = stack_frames

                        # Handle extra data (if enabled)
                        if load_extra:
                            extra_data_dict = {}
                            known_event_tags = {
                                'SequenceNumber', 'ProcessIndex', 'PID', 'ThreadId', 'ParentPID',
                                'Time_of_Day', 'Operation', 'Path', 'Result', 'Detail', 'Duration',
                                'Category', 'Process_Name', 'stack'
                            }
                            for child in elem:
                                child_tag_orig = child.tag
                                child_tag_clean = _strip_namespace(child_tag_orig)
                                if child_tag_clean not in known_event_tags:
                                    tag_text = child.text.strip() if child.text else None
                                    if tag_text is not None:
                                        extra_data_dict[child_tag_orig] = tag_text
                            if extra_data_dict:
                                opt_event['extra_data'] = extra_data_dict

                        yield opt_event
                        yielded_count += 1

                        # Progress reporting
                        current_time = time.time()
                        if yielded_count % PROGRESS_REPORT_INTERVAL == 0 or (current_time - last_report_time) > PROGRESS_REPORT_SECONDS:
                            elapsed_total = current_time - start_time
                            rate = yielded_count / elapsed_total if elapsed_total > 0 else 0
                            percent_str = ""
                            if raw_file_stream and total_size is not None and total_size > 0:
                                try:
                                    current_pos = raw_file_stream.tell()
                                    percent = (current_pos / total_size) * 100
                                    percent_str = f" ({percent:.1f}%)"
                                except (OSError, AttributeError, TypeError, io.UnsupportedOperation) as tell_err:
                                    logger.debug(f"Could not get raw stream position for progress: {tell_err}")
                            logger.info(f"  [Pass 2] Yielded {yielded_count:,} events{percent_str}... ({elapsed_total:.1f}s | {rate:,.0f} events/sec)")
                            last_report_time = current_time

                    except Exception as event_parse_err:
                        logger.warning(f"Error parsing event #{event_count}: {event_parse_err}", exc_info=True)
                    finally:
                        _clear_elem(elem)

                elif event_type == 'end' and tag == 'eventlist':
                    logger.debug("Reached end of <eventlist>.")
                    _clear_elem(elem)

        elapsed = time.time() - start_time
        logger.info(f"Finished Pass 2: Processed {event_count:,} <event> elements, yielded {yielded_count:,}, skipped {skipped_count:,} ({elapsed:.2f}s).")

    except ET_impl.XMLSyntaxError as e:
        logger.error(f"XML Parse Error during event loading stream: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during event loading stream: {e}", exc_info=True)
        raise


def load_procmon_xml(filename_abs: str, load_stack: bool, load_extra: bool) -> ProcmonLogData:
    """
    Loads XML file: Parses processes, then streams events, converting them
    to an optimized in-memory format using string interning. Stores results
    in a ProcmonLogData object. Builds indices.
    """
    if not os.path.exists(filename_abs):
        raise FileNotFoundError(f"Input file not found: {filename_abs}")
    if not os.path.isfile(filename_abs):
        raise ValueError(f"Input path is not a file: {filename_abs}")

    log_data = ProcmonLogData(
        load_stack_traces=load_stack,
        load_extra_data=load_extra,
        loaded_filename=os.path.basename(filename_abs)
    )

    fname_lower = filename_abs.lower()
    compression: Optional[str] = None
    open_func: Any = open
    file_mode = "rb"

    if fname_lower.endswith(".xml"):
        compression = None
    elif fname_lower.endswith((".gz", ".xml.gz")):
        compression = 'gz'
        open_func = gzip.open
    elif fname_lower.endswith((".bz2", ".xml.bz2")):
        compression = 'bz2'
        open_func = bz2.open
    elif fname_lower.endswith((".xz", ".xml.xz")):
        compression = 'xz'
        open_func = lzma.open
    else:
        logger.warning(f"File extension not recognized for compression type: {filename_abs}. Assuming plain XML.")

    log_data.loaded_compression = compression
    overall_start_time = time.time()

    total_file_size: Optional[int] = None
    try:
        total_file_size = os.path.getsize(filename_abs)
        logger.info(f"Total input file size: {_format_bytes(total_file_size)}")
    except OSError as e:
        logger.warning(f"Could not get file size for progress reporting: {e}")

    # Initialize interners
    log_data.interners = {
        IK_PROCESS_NAME: StringInterner(),
        IK_OPERATION: StringInterner(),
        IK_PATH: StringInterner(),
        IK_RESULT: StringInterner(),
        IK_CATEGORY: StringInterner(),
        IK_STACK_PATH: StringInterner(),
        IK_STACK_LOCATION: StringInterner(),
    }
    # Pre-intern known operation strings
    log_data.interners[IK_OPERATION].get_id(OP_PROCESS_CREATE)
    log_data.interners[IK_OPERATION].get_id(OP_PROCESS_EXIT)
    for op in NETWORK_OPERATIONS:
        log_data.interners[IK_OPERATION].get_id(op)

    try:
        comp_str = f" ({compression} compressed)" if compression else ""
        logger.info(f"Loading and optimizing{comp_str} XML file: {filename_abs}")

        raw_f = None
        try:
            raw_f = open(filename_abs, "rb")

            # Pass 1: Parse Processes Only
            with open_func(filename_abs, file_mode) as f_stream_pass1:
                log_data.processes_by_index = _parse_xml_processes_only(f_stream_pass1)
                if log_data.processes_by_index is None:
                    log_data.processes_by_index = {}

            # Build PID -> ProcessInfo Map
            pid_map_start_time = time.time()
            for proc_info in log_data.processes_by_index.values():
                if proc_info.pid is not None:
                    if proc_info.pid in log_data.processes_by_pid:
                        logger.warning(f"Duplicate PID {proc_info.pid} encountered in process list. Using the last entry found (ProcessIndex: {proc_info.process_index}).")
                    log_data.processes_by_pid[proc_info.pid] = proc_info
            logger.info(f"Built PID-to-ProcessInfo map for {len(log_data.processes_by_pid)} unique PIDs in {time.time() - pid_map_start_time:.2f}s.")

            # Pass 2: Parse Events and Optimize
            if compression is not None:
                stream_context = open_func(raw_f, file_mode)
            else:
                stream_context = contextlib.nullcontext(raw_f)

            with stream_context as f_stream_pass2:
                event_iterator = _parse_xml_stream_for_loading(
                    f_stream_pass2, log_data.interners, log_data.processes_by_index,
                    load_stack=log_data.load_stack_traces,
                    load_extra=log_data.load_extra_data,
                    raw_file_stream=raw_f,
                    total_size=total_file_size
                )

                logger.info("[Loader] Starting consumption of event iterator and building indices...")
                temp_event_list = []
                consumed_count = 0
                indexing_start_time = time.time()
                try:
                    for idx, opt_event in enumerate(event_iterator):
                        temp_event_list.append(opt_event)
                        consumed_count += 1

                        pname_id = opt_event.get('pname_id')
                        op_id = opt_event.get('op_id')
                        pid = opt_event.get('pid')
                        path_id = opt_event.get('path_id')
                        if pname_id is not None:
                            log_data.pname_id_index[pname_id].append(idx)
                        if op_id is not None:
                            log_data.op_id_index[op_id].append(idx)
                        if pid is not None:
                            log_data.pid_index[pid].append(idx)
                        if path_id is not None:
                            log_data.path_id_index[path_id].append(idx)

                except Exception as consume_err:
                    logger.error(f"[Loader] Error during iterator consumption/indexing after {consumed_count} events: {consume_err}", exc_info=True)
                finally:
                    logger.info(f"[Loader] Finished consuming event iterator. Total events consumed: {consumed_count}. Final list length: {len(temp_event_list)}. Indexing time: {time.time() - indexing_start_time:.2f}s")

                log_data.events = temp_event_list

        finally:
            if raw_f:
                raw_f.close()

        # Final Summary
        overall_end_time = time.time()
        logger.info(f"--- Loading Summary ---")
        logger.info(f" Successfully loaded and optimized {len(log_data.events):,} events from {log_data.loaded_filename}.")
        logger.info(f" Found {len(log_data.processes_by_index)} unique processes (by index).")
        logger.info(f" Built PName index for {len(log_data.pname_id_index)} names, OP index for {len(log_data.op_id_index)} operations, PID index for {len(log_data.pid_index)} PIDs, Path index for {len(log_data.path_id_index)} paths.")
        logger.info(f" Total loading and optimization time: {overall_end_time - overall_start_time:.2f} seconds.")
        if logger.isEnabledFor(logging.DEBUG):
            for name, interner in log_data.interners.items():
                logger.debug(f"  Interner '{name}': {interner.next_id:,} unique strings.")

        return log_data

    except (FileNotFoundError, ValueError) as e:
        logger.error(f"File error: {e}")
        raise
    except ET_impl.XMLSyntaxError as e:
        logger.error(f"XML Syntax Error in {filename_abs}: {e}")
        raise RuntimeError(f"Invalid XML: {e}") from e
    except OSError as e:
        logger.error(f"File read/decompression error for {filename_abs}: {e}")
        raise RuntimeError(f"File read/decompression failed for '{filename_abs}'.") from e
    except Exception as e:
        logger.error(f"Error loading/optimizing file {filename_abs}: {e}", exc_info=True)
        raise RuntimeError(f"Failed to load/optimize file: {e}") from e
