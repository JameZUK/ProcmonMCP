ProcmonMCP is an Model Context Protocol server for allowing LLMs to autonomously analyse procmon logs. It exposes numerous functionality to MCP clients.

## Overview

This project provides a Model Context Protocol (MCP) server that acts as an interface to the `eronnen/procmon-parser` library. It allows Large Language Models (LLMs) connected via MCP clients (like Cline) to analyze Process Monitor (Procmon) log files (`.pml`) and configuration files (`.pmc`).

By pre-loading a specific Procmon file at startup, this server exposes various tools enabling the LLM to query events, inspect process details, view metadata, analyze results, and understand process relationships within the log data.

This project was inspired by the approach taken in the [GhidraMCP project](https://github.com/LaurieWired/GhidraMCP).

**Core Library:** [eronnen/procmon-parser](https://github.com/eronnen/procmon-parser)

**WARNING:** Process Monitor logs can contain sensitive system information. Exposing this data via an API carries significant security risks. Ensure the `--allowed-dir` restricts access appropriately and only run this server in trusted environments.

## Features

* Load a specific `.pml` or `.pmc` file at startup.
* Provide MCP tools for LLMs to:
    * Query event summaries with filtering capabilities (process name, operation, result, path).
    * Retrieve detailed information for specific events by index.
    * Get stack traces (as raw addresses) for specific events.
    * List unique processes found in the log.
    * Get detailed information for specific processes by PID.
    * Retrieve log metadata (header information, if available).
    * Perform basic analysis (count events by process, summarize operations, find events by result code, get process tree).
* Supports `stdio` and `sse` MCP transport protocols.
* Debug logging option (`--debug`).

## Installation

1.  **Prerequisites:**
    * Python 3.10 or higher.
    * `pip` (Python package installer).

2.  **Clone the Repository (Optional):**
    ```bash
    git clone [https://github.com/JameZUK/ProcmonMCP](https://github.com/JameZUK/ProcmonMCP)
    cd ProcmonMCP
    ```

3.  **Install Dependencies:**
    ```bash
    pip install "modelcontextprotocol>=1.2.0,<2" procmon-parser
    ```
    *(Note: `uvicorn` is also used for the SSE transport and will be installed by `modelcontextprotocol` if needed, or install manually: `pip install uvicorn`)*

## Usage

The server requires specifying a directory containing the Procmon files and optionally pre-loading a specific file for analysis.

**Command-Line Arguments:**

* `--allowed-dir <path>`: **(Required)** The secure base directory containing Procmon files. Access is restricted to this directory.
* `--load-file <filename>`: (Optional) The specific PML or PMC filename (relative to `--allowed-dir`) to pre-load and analyze. If not provided, tools operating on loaded data will fail.
* `--transport <stdio|sse>`: (Optional) Transport protocol for MCP. Default: `stdio`.
* `--mcp-host <ip>`: (Optional) Host address for the MCP server (only used for `sse` transport). Default: `127.0.0.1`.
* `--mcp-port <port>`: (Optional) Port for the MCP server (only used for `sse` transport). Default: `8081`.
* `--debug`: (Optional) Enable verbose debug logging.

**Examples:**

* **Run with STDIO, loading a PML file:**
    ```bash
    python procmon-mcp.py --allowed-dir /path/to/secure/logs --load-file my_capture.pml
    ```

* **Run with SSE on port 8082, loading a PMC file, with debug logging:**
    ```bash
    python procmon-mcp.py --allowed-dir C:\procmon_files --load-file config.pmc --transport sse --mcp-port 8082 --debug
    ```

## Available MCP Tools

Once the server is running and connected to an MCP client, the following tools are available:

* `get_loaded_file_summary()`: Returns basic summary (filename, type, counts) of the loaded file.
* `query_loaded_pml_events(...)`: Queries events with filters (process name/contains, operation, result, path contains) and returns a list of event summaries including their index. *Requires PML.*
* `get_pml_event_details(event_index)`: Gets detailed properties for a specific event by its index. *Requires PML.*
* `get_pml_event_stack_trace(event_index)`: Gets the stack trace (list of hex addresses) for a specific event by index. *Requires PML.*
* `list_pml_processes()`: Lists summaries (PID, Name, Path) of unique processes found in the log. *Requires PML.*
* `get_pml_process_details(pid)`: Gets detailed properties for a specific process by PID. *Requires PML.*
* `get_pml_metadata()`: Retrieves metadata from the PML header (OS, computer name, etc.), if available. *Requires PML.*
* `get_loaded_pmc_rules()`: Returns filter rules from a loaded PMC file. *Requires PMC.*
* `count_events_by_process()`: Counts events per process name. *Requires PML.*
* `summarize_operations_by_process(process_name_filter)`: Counts operations for a specific process name (case-sensitive). *Requires PML.*
* `find_events_by_result(result_filter, limit)`: Finds event summaries matching a specific result string (e.g., "SUCCESS") or hex code (e.g., "0xc0000022"). *Requires PML.*
* `get_process_tree()`: Constructs and returns the process parent-child hierarchy. *Requires PML.*

*(Refer to the tool docstrings within the script or use the client's `tools/list` command for detailed argument descriptions.)*

## Example LLM Prompts for Malware Analysis

*(Assuming a relevant PML file is loaded)*

1.  **Initial Triage:**
    * "Get the summary of the loaded file."
    * "List the unique processes found in the log."
    * "Count the events per process." (Identify high-activity processes)
    * "Get the process tree." (Understand parent-child relationships)

2.  **Investigating a Suspicious Process (e.g., `malware.exe` with PID 1234):**
    * "Get details for process PID 1234." (Check command line, parent PID)
    * "Summarize operations for process `malware.exe`." (See what it mainly does - file access, registry, network?)
    * "Query events where filter_process is `malware.exe` and filter_operation is `RegSetValue`, limit 10." (Check registry writes)
    * "Query events where filter_process is `malware.exe` and filter_operation is `WriteFile`, limit 20." (Check file writes)
    * "Query events where filter_process is `malware.exe` and filter_operation contains `TCP` or `UDP`, limit 20." (Check network activity)

3.  **Looking for Persistence:**
    * "Query events where filter_operation is `RegSetValue` and filter_path_contains is `CurrentVersion\\Run`, limit 20."
    * "Query events where filter_operation is `RegSetValue` and filter_path_contains is `Services`, limit 20."
    * "Query events where filter_operation is `CreateFile` and filter_path_contains is `StartUp`, limit 10."

4.  **Troubleshooting Errors / Evasion:**
    * "Find events with result `ACCESS DENIED`, limit 10." (Note: Might need to use the numeric code, e.g., `0xc0000022`)
    * "Find events with result `NAME NOT FOUND`, limit 10."
    * "Find events with result `PATH NOT FOUND`, limit 10."
    * (After finding an interesting error event at index 55): "Get details for event 55."
    * (If details suggest a code issue): "Get stack trace for event 55."

## Limitations

* **Header Access:** Extracting PML header information is currently unreliable.
* **Performance:** Loading and processing very large PML files can be memory and time-intensive as all events/processes are read into memory on startup.
* **Attribute Names:** Relies on common attribute naming conventions (`pid`, `process_name`, `stacktrace`, etc.) within the `procmon-parser` objects. Unusual naming might cause data retrieval issues.
* **Result Filtering:** String filtering for results only works if the PML stores results as strings. Numeric codes (decimal or hex `0x...`) should be used if results are stored numerically.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.
