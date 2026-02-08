"""CLI entry point and argument parsing for ProcmonMCP."""
import sys
import os
import io
import logging
import argparse
import cProfile
import pstats

from .compat import MCP_SDK_AVAILABLE, PSUTIL_AVAILABLE
from .constants import LOG_FORMAT
from .helpers import _format_bytes
from .parser import load_procmon_xml
from . import server
from . import tools  # noqa: F401 - force tool registration

logger = logging.getLogger(__name__)


def main_execution(args):
    """Encapsulates the main loading and server run logic for profiling."""
    load_stacks = not args.no_stack_traces
    load_extra = not args.no_extra_data

    try:
        input_file_path = os.path.abspath(args.input_file)
        logger.info(f"Attempting to load and optimize file: {input_file_path}")

        server.LOADED_DATA = load_procmon_xml(input_file_path, load_stacks, load_extra)

        if not server.LOADED_DATA or not server.LOADED_DATA.is_loaded():
            logger.critical(f"File loading failed for '{input_file_path}'. Check logs above for errors. Exiting.")
            sys.exit(1)
        else:
            logger.info(f"File '{server.LOADED_DATA.loaded_filename}' loaded successfully (Events: {len(server.LOADED_DATA.events):,}, Processes: {len(server.LOADED_DATA.processes_by_index)}).")

        # Memory usage reporting
        if PSUTIL_AVAILABLE:
            try:
                import psutil
                process = psutil.Process(os.getpid())
                mem_info = process.memory_info()
                rss_formatted = _format_bytes(mem_info.rss)
                vms_formatted = _format_bytes(mem_info.vms)
                logger.info(f"--- Post-Load Memory Usage (Process RSS): {rss_formatted} ---")
                if args.debug:
                    logger.debug(f"  Detailed Memory: RSS={rss_formatted}, VMS={vms_formatted}")
            except Exception as mem_err:
                logger.warning(f"Could not retrieve process memory usage: {mem_err}")
        else:
            logger.info("Memory usage reporting skipped (psutil library not installed).")

        logger.info(f"Ready for MCP connections.")

    except (ValueError, FileNotFoundError, TypeError, IndexError, RuntimeError) as e:
        logger.critical(f"Error loading file '{args.input_file}': {e}")
        if args.debug:
            logger.exception("Loading error details:")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"An unexpected error occurred during file loading ('{args.input_file}'): {e}", exc_info=args.debug)
        sys.exit(1)

    # Start MCP Server
    server_started = False
    try:
        if args.transport == "sse":
            if hasattr(server.mcp, 'settings'):
                logger.info("Configuring MCP for SSE transport...")
                server.mcp.settings.host = args.mcp_host
                server.mcp.settings.port = args.mcp_port
                log_level = logging.DEBUG if args.debug else logging.INFO
                mcp_log_level_name = logging.getLevelName(log_level)
                server.mcp.settings.log_level = mcp_log_level_name.lower()
                logger.info(f"  MCP Host: {server.mcp.settings.host}, Port: {server.mcp.settings.port}, Log Level: {server.mcp.settings.log_level}")
            else:
                logger.warning("MCP object lacks 'settings'; cannot configure SSE via arguments.")
            logger.info(f"Starting MCP server with SSE transport on http://{args.mcp_host}:{args.mcp_port}")
            server.mcp.run(transport="sse")
            server_started = True
        else:
            logger.info("Starting MCP server with STDIO transport...")
            server.mcp.run(transport="stdio")
            server_started = True
    except KeyboardInterrupt:
        logger.info("Server stopped by user (KeyboardInterrupt).")
    except Exception as e:
        logger.critical(f"Failed during server startup or execution: {e}", exc_info=args.debug)
        sys.exit(1)

    if not server_started and args.transport == "sse":
        logger.critical("SSE Server did not appear to start correctly.")
        sys.exit(1)
    else:
        logger.info("Server execution finished.")


def main():
    """Main entry point: parse arguments and run the server."""
    parser = argparse.ArgumentParser(
        description="MCP Server for analyzing Procmon XML files (.xml, .gz/bz2/xz) using in-memory optimization.",
        epilog="Memory reporting requires 'psutil' library (`pip install psutil`). Profiling requires '--profile' flag."
    )
    parser.add_argument("--input-file", required=True,
                        help="REQUIRED: Path to the Procmon XML file (.xml, .gz/bz2/xz) to load and analyze.")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1", help="Host for MCP server (SSE transport), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8081, help="Port for MCP server (SSE transport), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"], help="MCP transport protocol, default: stdio")
    parser.add_argument("--debug", action='store_true', help="Enable debug logging.")
    parser.add_argument("--log-file", type=str, default=None, help="Optional: Path to a file to write logs to instead of console.")
    parser.add_argument("--no-stack-traces", action='store_true', help="Do not parse or store stack traces to save memory.")
    parser.add_argument("--no-extra-data", action='store_true', help="Do not store unknown fields found within <event> tags.")
    parser.add_argument("--profile", action='store_true', help="Enable profiling and print stats on exit.")
    parser.add_argument("--profile-output", type=str, default="procmon_profile.prof", help="Output file for profiling data (used with --profile).")
    parser.add_argument("--profile-sort", type=str, default="cumulative", help="Sort key for profile stats (e.g., cumulative, tottime, calls).")
    parser.add_argument("--profile-lines", type=int, default=50, help="Number of lines to print in profile stats.")

    args = parser.parse_args()

    # Logging configuration
    log_level = logging.DEBUG if args.debug else logging.INFO
    log_handlers = []
    if args.log_file:
        log_dir = os.path.dirname(args.log_file)
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir)
            except OSError as e:
                print(f"Error: Could not create directory for log file '{args.log_file}': {e}")
                sys.exit(1)
        try:
            file_handler = logging.FileHandler(args.log_file, mode='w')
            file_handler.setLevel(log_level)
            file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
            log_handlers.append(file_handler)
            print(f"Logging to file: {args.log_file}")
        except Exception as e:
            print(f"Error: Could not open log file '{args.log_file}': {e}")
            sys.exit(1)
    else:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        log_handlers.append(console_handler)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    for handler in log_handlers:
        root_logger.addHandler(handler)
    logger.setLevel(log_level)

    try:
        logging.getLogger('mcp').setLevel(log_level)
        if args.transport == 'sse':
            logging.getLogger('uvicorn').setLevel(log_level)
            logging.getLogger('uvicorn.error').setLevel(log_level)
            logging.getLogger('uvicorn.access').setLevel(logging.WARNING if not args.debug else logging.DEBUG)
    except Exception:
        logger.debug("Could not configure MCP/Uvicorn loggers.", exc_info=True)
    logger.info(f"Logging level set to: {logging.getLevelName(log_level)}")
    logger.info(f"Selective loading: Stacks={not args.no_stack_traces}, ExtraData={not args.no_extra_data}")

    # Dependency checks
    if not MCP_SDK_AVAILABLE:
        logger.critical("CRITICAL: Model Context Protocol SDK (mcp[cli]) is not installed.")
        logger.critical("Please install it: pip install \"mcp[cli]\"")
        sys.exit(1)

    # Profiling setup
    if args.profile:
        logger.info(f"Profiling enabled. Outputting stats to console (sorted by '{args.profile_sort}') and saving raw data to '{args.profile_output}'.")
        profiler = cProfile.Profile()
        profiler.enable()

        try:
            main_execution(args)
        finally:
            profiler.disable()
            logger.info(f"Profiling finished. Saving raw data to '{args.profile_output}'...")
            profiler.dump_stats(args.profile_output)

            s = io.StringIO()
            sortby = args.profile_sort
            ps = pstats.Stats(profiler, stream=s).sort_stats(sortby)
            ps.print_stats(args.profile_lines)
            logger.info(f"\n--- Profiling Stats (Top {args.profile_lines}, sorted by {sortby}) ---\n{s.getvalue()}")
            logger.info(f"--- End Profiling Stats ---")
    else:
        main_execution(args)

    sys.exit(0)
