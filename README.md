# ProcmonMCP

ProcmonMCP is a Model Context Protocol server designed to allow LLMs to autonomously analyze **Procmon XML log files**. It exposes numerous functionalities to MCP clients.

## Overview

This project provides a Model Context Protocol (MCP) server that parses and analyzes **Process Monitor (Procmon) XML log files (`.xml`, `.xml.gz`, `.xml.bz2`, `.xml.xz`)**. It allows Large Language Models (LLMs) connected via MCP clients (like Cline) to investigate system activity captured in these logs.

By pre-loading a specific Procmon XML file at startup, this server optimizes the data for in-memory analysis using **string interning**. It then exposes various tools enabling the LLM to query events, inspect process details, view metadata, and perform basic analysis on the loaded log data.

This project was inspired by the approach taken in the [GhidraMCP project](https://github.com/LaurieWired/GhidraMCP).

**WARNING:** Process Monitor logs can contain sensitive system information. Exposing this data via an API carries significant security risks. Ensure the `--allowed-dir` restricts access appropriately and only run this server in trusted environments.

## Features

* Load a specific Procmon **XML** file (`.xml` or compressed `.xml.gz`/`.bz2`/`.xz`) at startup.
* **Optimizes** loaded data using in-memory string interning for reduced memory footprint and faster querying on repetitive data.
* Provide MCP tools for LLMs to:
    * Query event summaries with filtering capabilities (process name/contains, operation, result, path contains/regex, detail regex, timestamp, stack module path).
    * Retrieve detailed information for specific events by index.
    * Get stack traces (module path, location, address) for specific events.
    * List unique processes found in the log's process list section.
    * Get detailed information for specific processes by PID from the process list.
    * Retrieve basic metadata about the loaded file.
    * Perform basic analysis (count events by process, summarize operations by process, calculate timing statistics).
* Uses `lxml` for faster XML parsing if available, with fallback to standard library `xml.etree.ElementTree`.
* Supports `stdio` and `sse` MCP transport protocols.
* Debug logging option (`--debug`).

## Installation

1.  **Prerequisites:**
    * Python 3.x (developed with 3.10+ in mind).
    * `pip` (Python package installer).

2.  **Clone the Repository (Optional):**
    ```bash
    git clone https://github.com/JameZUK/ProcmonMCP
    cd ProcmonMCP
    ```

3.  **Install Dependencies:**
    ```bash
    # lxml is highly recommended for performance
    pip install "mcp[cli]" lxml
    ```
    *(If you choose not to install `lxml`, the script will use the slower built-in XML parser).*

## Usage

The server requires specifying a directory containing the Procmon XML files and the specific file to pre-load for analysis.

**Command-Line Arguments:**

* `--allowed-dir <path>`: **(Required)** The secure base directory containing Procmon XML files. Access is restricted to this directory.
* `--load-file <filename>`: **(Required)** The specific XML filename (e.g., `my_log.xml`, `capture.xml.gz`, relative to `--allowed-dir`) to pre-load and analyze.
* `--transport <stdio|sse>`: (Optional) Transport protocol for MCP. Default: `stdio`.
* `--mcp-host <ip>`: (Optional) Host address for the MCP server (only used for `sse` transport). Default: `127.0.0.1`.
* `--mcp-port <port>`: (Optional) Port for the MCP server (only used for `sse` transport). Default: `8081`.
* `--debug`: (Optional) Enable verbose debug logging.

**Examples:**

* **Run with STDIO, loading a compressed XML file:**
    ```bash
    python procmon-mcp.py --allowed-dir /path/to/secure/logs --load-file my_capture.xml.gz
    ```

* **Run with SSE on port 8082, loading an uncompressed XML file, with debug logging:**
    ```bash
    python procmon-mcp.py --allowed-dir C:\procmon_files --load-file trace_log.xml --transport sse --mcp-port 8082 --debug
    ```

## Available MCP Tools

Once the server is running with a loaded file and connected to an MCP client, the following tools are available:

* `get_loaded_file_summary()`: Returns basic summary (filename, type, compression, counts, interner stats) of the loaded file.
* `query_events(...)`: Queries events with various filters (see docstring/code for all filters like `filter_process`, `filter_path_contains`, `filter_start_time`, `filter_path_regex`, `filter_stack_module_path`, etc.) and returns a list of event summaries including their index.
* `get_event_details(event_index)`: Gets detailed properties for a specific event by its index.
* `get_event_stack_trace(event_index)`: Gets the stack trace (list of frames with address, path, location) for a specific event by index.
* `list_processes()`: Lists summaries (PID, Name, Path) of unique processes found in the file's process list section.
* `get_process_details(pid)`: Gets detailed properties for a specific process by PID from the file's process list section.
* `Youtube()`: Retrieves basic metadata about the loaded file (filename, type, counts).
* `count_events_by_process()`: Counts events per process name across all loaded events.
* `summarize_operations_by_process(process_name_filter)`: Counts operations for a specific process name (case-sensitive).
* `get_timing_statistics(group_by)`: Calculates event duration statistics, grouped by 'process' (default) or 'operation'.

*(Refer to the tool docstrings within the script or use the client's `tools/list` command for detailed argument descriptions.)*

## Example LLM Prompts for Malware Analysis

*(Assuming a relevant Procmon XML file is loaded)*

1.  **Initial Triage:**
    * "Get the summary of the loaded file."
    * "List the unique processes found in the log."
    * "Count the events per process." (Identify high-activity processes)
    * "Calculate timing statistics grouped by process." (Identify processes with long-duration events)

2.  **Investigating a Suspicious Process (e.g., `malware.exe` with PID 1234):**
    * "Get details for process PID 1234." (Check command line, parent PID, image path)
    * "Summarize operations for process `malware.exe`." (See what it mainly does - file access, registry, network?)
    * "Query events where filter_process is `malware.exe` and filter_operation is `RegSetValue`, limit 10." (Check registry writes)
    * "Query events where filter_process is `malware.exe` and filter_operation is `WriteFile`, limit 20." (Check file writes)
    * "Query events where filter_process is `malware.exe` and filter_operation contains `TCP` or filter_operation contains `UDP`, limit 20." (Check network activity - requires `procmon-parser` capability or specific XML operations)
    * "Query events where filter_process_contains is `malware` and filter_detail_regex is `some_pattern_in_details`, limit 5." (Use regex on the Detail column)

3.  **Looking for Persistence:**
    * "Query events where filter_operation is `RegSetValue` and filter_path_contains is `CurrentVersion\\Run`, limit 20."
    * "Query events where filter_operation is `RegCreateKey` and filter_path_contains is `Services`, limit 20."
    * "Query events where filter_operation is `CreateFile` and filter_path_contains is `StartUp`, limit 10." (Check common persistence locations)

4.  **Troubleshooting Errors / Evasion:**
    * "Query events where filter_result is `ACCESS DENIED`, limit 10."
    * "Query events where filter_result is `NAME NOT FOUND`, limit 10."
    * "Query events where filter_result is `PATH NOT FOUND`, limit 10."
    * "Query events where filter_result is `0xc0000022`, limit 5." (Use hex codes for results if needed)
    * (After finding an interesting error event at index 55): "Get details for event 55."
    * (If details suggest a code issue): "Get stack trace for event 55."

## Limitations

* **Single File:** The tool loads and analyzes only *one* file specified at startup. Analyzing a different file requires restarting the server.
* **Memory Usage:** While optimized, loading extremely large XML files (millions of events, especially with highly unique string data in paths/details/stacks) can still consume significant RAM.
* **Loading Time:** Parsing and optimizing large XML files, especially compressed ones, can take time during startup.
* **Filter Performance:** Querying is generally fast for filters using interned IDs (process, operation, result). Filters requiring string comparisons (`_contains`), regular expressions (`_regex`), or stack inspection (`filter_stack_module_path`) are slower as they require more processing per event. The stack filter is particularly intensive.
* **XML Structure:** Relies on the standard Procmon XML export structure. Malformed or non-standard XML files will likely cause parsing errors.
* **Stack Traces:** Stack trace information (module paths, locations) depends entirely on what Procmon resolved and included in the XML export.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.
