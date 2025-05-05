# ProcmonMCP

ProcmonMCP is a Model Context Protocol server designed to allow LLMs to autonomously analyze **Procmon XML log files**. It exposes numerous functionalities to MCP clients.

## Overview

This project provides a Model Context Protocol (MCP) server that parses and analyzes **Process Monitor (Procmon) XML log files (`.xml`, `.xml.gz`, `.xml.bz2`, `.xml.xz`)**. It allows Large Language Models (LLMs) connected via MCP clients (like Cline) to investigate system activity captured in these logs.

By pre-loading a specific Procmon XML file specified via the `--input-file` argument at startup, this server optimizes the data for in-memory analysis using **string interning** and other techniques. It then exposes various tools enabling the LLM to query events, inspect process details, view metadata, export results, and perform basic analysis on the loaded log data.

This project was inspired by the approach taken in the [GhidraMCP project](https://github.com/LaurieWired/GhidraMCP).

**⚠ VERY IMPORTANT SECURITY WARNING ⚠**

* Process Monitor logs can contain extremely sensitive system information (keystrokes, passwords in command lines, file contents, network traffic details, etc.).
* This script loads **any file path** provided via the `--input-file` argument that the user running the script has read permissions for. There is **NO** directory sandboxing.
* Exposing Procmon data via an API (like the MCP server) carries **significant security risks**. Malicious actors could potentially request sensitive information from the loaded log file.
* **Only run this server in highly trusted environments.**
* **NEVER run this server with Procmon logs captured from systems containing sensitive production or personal data unless you fully understand and accept the risks.**
* **Carefully review the logs you intend to load for sensitive information BEFORE using this tool.**

## Features

* Load a specific Procmon **XML** file (`.xml` or compressed `.xml.gz`/`.bz2`/`.xz`) using the `--input-file` path at startup.
* **Optimizes** loaded data using in-memory string interning for reduced memory footprint and faster querying on repetitive data.
* Provides **progress reporting** during the potentially long loading phase.
* Provide MCP tools for LLMs to:
    * Query event summaries with filtering capabilities (process name/contains, operation, result, path contains/regex, detail regex, timestamp, stack module path).
    * Retrieve detailed information for specific events by index.
    * Get stack traces (module path, location, address) for specific events (if loaded).
    * List unique processes found in the log's process list section.
    * Get detailed information for specific processes by PID from the process list.
    * Retrieve basic metadata about the loaded file.
    * Perform basic analysis (count events by process, summarize operations by process, calculate timing statistics, find network connections, find file access).
    * Export filtered event results to CSV or JSON files.
* Uses `lxml` for faster XML parsing if available, with fallback to standard library `xml.etree.ElementTree`.
* Supports `stdio` and `sse` MCP transport protocols.
* Optional flags to skip loading stack traces (`--no-stack-traces`) or extra unknown event fields (`--no-extra-data`) to save memory.
* Debug logging option (`--debug`).
* Memory usage reporting if `psutil` is installed.

## Installation

1.  **Prerequisites:**
    * Python 3.x (developed with 3.10+ in mind).
    * `pip` (Python package installer).

2.  **Clone the Repository (Optional):**
    ```bash
    git clone [https://github.com/JameZUK/ProcmonMCP](https://github.com/JameZUK/ProcmonMCP)
    cd ProcmonMCP
    ```
    *(Or just download the Python script)*

3.  **Install Dependencies:**
    ```bash
    # modelcontextprotocol is required
    # lxml is highly recommended for performance
    # psutil is optional for memory reporting
    pip install modelcontextprotocol lxml psutil
    ```
    *(If you choose not to install `lxml`, the script will use the slower built-in XML parser. If you don't install `psutil`, memory usage won't be reported after loading.)*

## Usage

The server requires specifying the path to the Procmon XML file to pre-load for analysis.

**Command-Line Arguments:**

* `--input-file <path>`: **(Required)** The full path to the Procmon XML file (.xml, .gz, .bz2, .xz) to load and analyze. The script must have read permissions for this file.
* `--transport <stdio|sse>`: (Optional) Transport protocol for MCP. Default: `stdio`.
* `--mcp-host <ip>`: (Optional) Host address for the MCP server (only used for `sse` transport). Default: `127.0.0.1`.
* `--mcp-port <port>`: (Optional) Port for the MCP server (only used for `sse` transport). Default: `8081`.
* `--debug`: (Optional) Enable verbose debug logging.
* `--log-file <path>`: (Optional) Path to a file to write logs to instead of the console.
* `--no-stack-traces`: (Optional) Do not parse or store stack traces (saves memory).
* `--no-extra-data`: (Optional) Do not store unknown fields found within `<event>` tags (saves memory).

**Examples:**

* **Run with STDIO, loading a compressed XML file:**
    ```bash
    python procmon-mcp.py --input-file /path/to/logs/my_capture.xml.gz
    ```

* **Run with SSE on port 8082, loading an uncompressed XML file, with debug logging, and skipping stacks:**
    ```bash
    python procmon-mcp.py --input-file C:\procmon_files\trace_log.xml --transport sse --mcp-port 8082 --debug --no-stack-traces
    ```

## Available MCP Tools

Once the server is running with a loaded file and connected to an MCP client, the following tools are available:

* `get_loaded_file_summary()`: Returns basic summary (filename, type, compression, counts, interner stats, selective loading flags) of the loaded file.
* `query_events(...)`: Queries events with various filters (see docstring/code for all filters like `filter_process`, `filter_path_contains`, `filter_start_time`, `filter_path_regex`, `filter_stack_module_path`, etc.) and returns a list of event summaries including their index. Use the `limit` parameter (default 50).
* `get_event_details(event_index)`: Gets detailed properties for a specific event by its index (returned by `query_events`).
* `get_event_stack_trace(event_index)`: Gets the stack trace (list of frames with address, path, location) for a specific event by index (only works if `--no-stack-traces` was **not** used).
* `list_processes()`: Lists summaries (PID, Name, ImagePath, ParentPID) of unique processes found in the file's process list section.
* `get_process_details(pid)`: Gets detailed properties for a specific process by PID from the file's process list section.
* `get_metadata()`: Retrieves basic metadata about the loaded file (filename, type, counts). **(Corrected)**
* `count_events_by_process()`: Counts events per process name across all loaded events.
* `summarize_operations_by_process(process_name_filter)`: Counts operations for a specific process name (case-sensitive match).
* `get_timing_statistics(group_by)`: Calculates event duration statistics, grouped by 'process' (default) or 'operation'.
* `get_process_lifetime(pid)`: Finds the 'Process Create' and 'Process Exit' event timestamps (unix float) for a given PID by scanning events.
* `find_file_access(path_contains, limit=100)`: Finds file system events where the path contains the given substring (case-insensitive).
* `find_network_connections(process_name)`: Finds unique remote network endpoints (IP:port) accessed by a specific process name (case-sensitive match).
* `export_query_results(...)`: Queries events using the same filters as `query_events` and exports the full details of **all** matching events to a specified file (CSV or JSON). Useful for offline analysis.

*(Refer to the tool docstrings within the script or use the client's `tools/list` command for detailed argument descriptions.)*

## Example LLM Prompts for Malware Analysis

*(Assuming a relevant Procmon XML file is loaded)*

1.  **Initial Triage:**
    * "Get the summary of the loaded file."
    * "List the unique processes found in the log."
    * "Count the events per process." (Identify high-activity processes)
    * "Calculate timing statistics grouped by process." (Identify processes with long-duration events)

2.  **Investigating a Suspicious Process (e.g., `suspicious.exe` with PID 4568):**
    * "Get details for process PID 4568." (Check command line, parent PID, image path)
    * "Summarize operations for process `suspicious.exe`." (See what it mainly does - file access, registry, network?)
    * "Query events where filter_process is `suspicious.exe` and filter_operation is `RegSetValue`, limit 10." (Check registry writes)
    * "Query events where filter_process is `suspicious.exe` and filter_operation is `WriteFile`, limit 20." (Check file writes)
    * "Find network connections for process `suspicious.exe`."
    * "Query events where filter_process_contains is `suspicious` and filter_detail_regex is `some_pattern_in_details`, limit 5." (Use regex on the Detail column)
    * "Find file access containing `temp\\suspicious_data`, limit 50."

3.  **Looking for Persistence:**
    * "Query events where filter_operation is `RegSetValue` and filter_path_contains is `CurrentVersion\\Run`, limit 20."
    * "Query events where filter_operation is `RegCreateKey` and filter_path_contains is `Services`, limit 20."
    * "Query events where filter_operation is `CreateFile` and filter_path_contains is `StartUp`, limit 10." (Check common persistence locations)

4.  **Troubleshooting Errors / Evasion:**
    * "Query events where filter_result is `ACCESS DENIED`, limit 10."
    * "Query events where filter_result is `NAME NOT FOUND`, limit 10."
    * "Query events where filter_result is `PATH NOT FOUND`, limit 10."
    * "Query events where filter_result is `0xc0000022`, limit 5." (Use hex codes for results if needed)
    * (After finding an interesting error event at index 987): "Get details for event 987."
    * (If details suggest a code issue and stacks were loaded): "Get stack trace for event 987."

5.  **Exporting Data:**
    * "Export query results to `suspicious_reg_writes.csv` where filter_process is `suspicious.exe` and filter_operation contains `RegSet`."
    * "Export query results to `network_activity.json` in json format where filter_operation contains `TCP` or filter_operation contains `UDP`."

## Limitations

* **Single File:** The tool loads and analyzes only *one* file specified via `--input-file` at startup. Analyzing a different file requires restarting the server.
* **Memory Usage:** While optimized with interning, loading extremely large XML files (millions of events, especially with highly unique string data or if stack traces are loaded) can still consume significant RAM. Use `--no-stack-traces` and `--no-extra-data` for very large files.
* **Loading Time:** Parsing and optimizing large XML files, especially compressed ones, can take considerable time during startup (though faster than previously). Progress is reported to the console.
* **Filter Performance:** Querying is generally fast for filters using interned IDs (process, operation, result). Filters requiring string comparisons (`_contains`), regular expressions (`_regex`), or stack inspection (`filter_stack_module_path`) are slower as they require more processing per event. The stack filter is particularly intensive. Indexing helps significantly for process name and operation filters.
* **XML Structure:** Relies on the standard Procmon XML export structure. Malformed or non-standard XML files will likely cause parsing errors.
* **Stack Traces:** Stack trace information (module paths, locations) depends entirely on what Procmon resolved and included in the XML export, and requires running Procmon with symbols configured correctly. Stacks are only loaded if `--no-stack-traces` is **not** used.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.
