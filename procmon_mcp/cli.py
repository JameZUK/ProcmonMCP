"""CLI entry point and argument parsing for ProcmonMCP."""
import sys
import os
import io
import logging
import argparse
import cProfile
import pstats
import warnings

from .compat import MCP_SDK_AVAILABLE, PSUTIL_AVAILABLE
from .constants import LOG_FORMAT
from .helpers import _format_bytes
from .parser import load_procmon_xml
from .config import load_config, save_config, set_last_file
from . import server
from . import tools  # noqa: F401 - force tool registration

logger = logging.getLogger(__name__)


def main_execution(args):
    """Encapsulates the main loading and server run logic for profiling."""
    load_stacks = not args.no_stack_traces
    load_extra = not args.no_extra_data

    # Persist preferences to config for next run
    config = load_config()
    config["no_stack_traces"] = args.no_stack_traces
    config["no_extra_data"] = args.no_extra_data
    save_config(config)

    # If an input file was specified, pre-load it at startup
    if args.input_file:
        try:
            input_file_path = os.path.abspath(args.input_file)
            logger.info(f"Attempting to load and optimise file: {input_file_path}")

            server.LOADED_DATA = load_procmon_xml(input_file_path, load_stacks, load_extra,
                                                  use_cache=not args.no_cache)

            if not server.LOADED_DATA or not server.LOADED_DATA.is_loaded():
                logger.critical(f"File loading failed for '{input_file_path}'. Check logs above for errors. Exiting.")
                sys.exit(1)
            else:
                logger.info(f"File '{server.LOADED_DATA.loaded_filename}' loaded successfully "
                            f"(Events: {len(server.LOADED_DATA.events):,}, "
                            f"Processes: {len(server.LOADED_DATA.processes_by_index)}).")

            # Save as last-used file
            set_last_file(input_file_path)

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

        except (ValueError, FileNotFoundError, TypeError, IndexError, RuntimeError) as e:
            logger.critical(f"Error loading file '{args.input_file}': {e}")
            if args.debug:
                logger.exception("Loading error details:")
            sys.exit(1)
        except Exception as e:
            logger.critical(f"An unexpected error occurred during file loading ('{args.input_file}'): {e}",
                            exc_info=args.debug)
            sys.exit(1)
    else:
        logger.info("No input file specified. Server will start without data loaded.")
        logger.info("Use the 'load_file' tool from your MCP client to open a Procmon XML file.")

    logger.info("Ready for MCP connections.")

    # Start MCP Server
    transport = args.transport
    server_started = False
    try:
        if transport == "sse":
            warnings.warn(
                "SSE transport is deprecated since MCP spec 2025-03-26. "
                "Please migrate to 'streamable-http' or 'stdio'.",
                DeprecationWarning,
                stacklevel=1,
            )
            if hasattr(server.mcp, 'settings'):
                logger.info("Configuring MCP for SSE transport (deprecated)...")
                server.mcp.settings.host = args.mcp_host
                server.mcp.settings.port = args.mcp_port
                log_level = logging.DEBUG if args.debug else logging.INFO
                mcp_log_level_name = logging.getLevelName(log_level)
                server.mcp.settings.log_level = mcp_log_level_name.lower()
                logger.info(f"  MCP Host: {server.mcp.settings.host}, Port: {server.mcp.settings.port}")
            else:
                logger.warning("MCP object lacks 'settings'; cannot configure SSE via arguments.")
            logger.info(f"Starting MCP server with SSE transport on http://{args.mcp_host}:{args.mcp_port}")
            server.mcp.run(transport="sse")
            server_started = True

        elif transport == "streamable-http":
            logger.info(f"Starting MCP server with Streamable HTTP transport on "
                        f"http://{args.mcp_host}:{args.mcp_port}/mcp")
            server.mcp.run(transport="streamable-http", host=args.mcp_host, port=args.mcp_port)
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

    if not server_started and transport in ("sse", "streamable-http"):
        logger.critical(f"{transport} server did not appear to start correctly.")
        sys.exit(1)
    else:
        logger.info("Server execution finished.")


def main():
    """Main entry point: parse arguments and run the server."""
    parser = argparse.ArgumentParser(
        description="ProcmonMCP - MCP server for analysing Procmon XML files (.xml, .gz/bz2/xz) "
                    "using in-memory optimisation.",
        epilog="Memory reporting requires 'psutil' (`pip install psutil`). "
               "Profiling requires '--profile' flag."
    )
    parser.add_argument("--input-file", required=False, default=None,
                        help="Path to a Procmon XML file (.xml, .gz/bz2/xz) to pre-load at startup. "
                             "If omitted, the server starts without data; use the 'load_file' MCP tool to open a file.")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host for MCP server (HTTP transports), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8081,
                        help="Port for MCP server (HTTP transports), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio",
                        choices=["stdio", "sse", "streamable-http"],
                        help="MCP transport protocol, default: stdio. "
                             "Note: SSE is deprecated; use 'streamable-http' for network access.")
    parser.add_argument("--debug", action='store_true', help="Enable debug logging.")
    parser.add_argument("--log-file", type=str, default=None,
                        help="Optional: Path to a file to write logs to instead of console.")
    parser.add_argument("--no-stack-traces", action='store_true',
                        help="Do not parse or store stack traces to save memory.")
    parser.add_argument("--no-extra-data", action='store_true',
                        help="Do not store unknown fields found within <event> tags.")
    parser.add_argument("--no-cache", action='store_true',
                        help="Bypass the parsed-capture cache (always re-parse, and refresh the cache).")
    parser.add_argument("--clear-cache", action='store_true',
                        help="Remove all cached parsed captures, then exit.")
    parser.add_argument("--profile", action='store_true',
                        help="Enable profiling and print stats on exit.")
    parser.add_argument("--profile-output", type=str, default="procmon_profile.prof",
                        help="Output file for profiling data (used with --profile).")
    parser.add_argument("--profile-sort", type=str, default="cumulative",
                        help="Sort key for profile stats (e.g., cumulative, tottime, calls).")
    parser.add_argument("--profile-lines", type=int, default=50,
                        help="Number of lines to print in profile stats.")

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
        if args.transport in ('sse', 'streamable-http'):
            logging.getLogger('uvicorn').setLevel(log_level)
            logging.getLogger('uvicorn.error').setLevel(log_level)
            logging.getLogger('uvicorn.access').setLevel(logging.WARNING if not args.debug else logging.DEBUG)
    except Exception:
        logger.debug("Could not configure MCP/Uvicorn loggers.", exc_info=True)
    logger.info(f"Logging level set to: {logging.getLevelName(log_level)}")
    logger.info(f"Selective loading: Stacks={not args.no_stack_traces}, ExtraData={not args.no_extra_data}")

    # Clear cache and exit, if requested.
    if args.clear_cache:
        from . import cache
        removed = cache.clear()
        logger.info(f"Removed {removed} cached capture(s) from {cache.CACHE_DIR}.")
        sys.exit(0)

    # Dependency checks
    if not MCP_SDK_AVAILABLE:
        logger.critical("CRITICAL: Model Context Protocol SDK (mcp[cli]) is not installed.")
        logger.critical("Please install it: pip install \"mcp[cli]\"")
        sys.exit(1)

    # Profiling setup
    if args.profile:
        logger.info(f"Profiling enabled. Outputting stats to console (sorted by '{args.profile_sort}') "
                     f"and saving raw data to '{args.profile_output}'.")
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
            logger.info("--- End Profiling Stats ---")
    else:
        main_execution(args)

    sys.exit(0)
