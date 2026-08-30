# ProcmonMCP

ProcmonMCP is a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that allows LLMs to autonomously analyse **Process Monitor (Procmon) XML log files**. It exposes a comprehensive set of analysis tools to any MCP-compatible client, including Claude Code, Claude Desktop, Cline, and others.

As seen on [REMnux](https://docs.remnux.org/discover-the-tools/use+artificial+intelligence#procmonmcp)

## Overview

Process Monitor captures detailed system activity — file access, registry operations, network connections, process creation, and more. ProcmonMCP parses these XML logs into an optimised in-memory representation and exposes them as MCP tools, enabling an LLM to investigate system behaviour without manual data wrangling.

Key capabilities:
- **Load files at runtime** — no need to restart the server to analyse a different capture
- **Parsed-capture cache** — reloading an unchanged file is near-instant (parsing is skipped)
- **String interning** for reduced memory footprint on large logs
- **Indexed lookups** by process name, operation, PID, and file path for fast filtering
- **Multiple transport protocols** — stdio (recommended), Streamable HTTP, and SSE (deprecated)
- **Progress feedback** during file loading via MCP notifications

This project was inspired by the approach taken in [GhidraMCP](https://github.com/LaurieWired/GhidraMCP).

> **Security Warning**
>
> Process Monitor logs can contain extremely sensitive system information (keystrokes, passwords in command lines, file contents, network traffic details, etc.).
>
> - This tool loads **any file path** that the user running the script has read permissions for. There is **no** directory sandboxing.
> - **Only run this server in trusted environments.**
> - **Never run this server with Procmon logs captured from systems containing sensitive production or personal data unless you fully understand and accept the risks.**
> - **Review the logs you intend to load for sensitive information before using this tool.**

## Installation

### Prerequisites

- Python 3.10 or newer (required by the MCP SDK; developed and tested with 3.10-3.13)
- `pip` (Python package installer)

### Install from source

```bash
git clone https://github.com/JameZUK/ProcmonMCP
cd ProcmonMCP
pip install -r requirements.txt
```

Or install the package itself (provides a `procmon-mcp` console script):

```bash
pip install .            # core only (mcp[cli])
pip install ".[all]"     # core + optional lxml and psutil
pip install -e ".[dev]"  # editable install with test tooling
```

### Dependencies

| Package | Required | Purpose |
|---------|----------|---------|
| `mcp[cli]>=2.0.0` | Yes | MCP SDK with CLI tools and Streamable HTTP support |
| `lxml>=4.9.0` | Recommended | Faster XML parsing (falls back to stdlib `ElementTree` if absent) |
| `psutil>=5.9.0` | Optional | Memory usage reporting after file loading |
| `google-re2` | Optional | Linear-time, ReDoS-safe engine for user filter regexes (`pip install ".[re2]"`; falls back to stdlib `re`) |

Install all at once:
```bash
pip install "mcp[cli]>=2.0.0" lxml psutil
```

> **MCP SDK v2:** the SDK renamed `FastMCP` to `MCPServer` and moved it to
> `mcp.server.mcpserver` in v2. ProcmonMCP targets v2, and still runs against
> `mcp<2` via a compatibility fallback. If you previously installed with an
> unpinned `mcp[cli]` and saw *"the MCP SDK could not be loaded"*, upgrade with
> `pip install --upgrade "mcp[cli]>=2"`.

## Quick Start with Claude Code

The recommended way to use ProcmonMCP is via **stdio** transport with Claude Code. The server starts without any file loaded — you (or the LLM) can then use the `load_file` tool to open a Procmon capture.

### Option 1: Add via Claude Code CLI

```bash
# Add ProcmonMCP as a stdio server (user-wide)
claude mcp add procmon --scope user -- python -m procmon_mcp

# Or with a file pre-loaded at startup
claude mcp add procmon --scope user -- python -m procmon_mcp --input-file /path/to/capture.xml.gz

# Or scoped to the current project only
claude mcp add procmon --scope project -- python -m procmon_mcp
```

### Option 2: Add via JSON

```bash
claude mcp add-json procmon '{
  "type": "stdio",
  "command": "python",
  "args": ["-m", "procmon_mcp"]
}'
```

### Option 3: Edit configuration files directly

Claude Code reads MCP server configuration from these locations:

| Scope | File | Description |
|-------|------|-------------|
| Project (shared, version-controlled) | `.mcp.json` in project root | Shared with the team |
| Project (personal) | `.claude/settings.local.json` | Your local overrides |
| User (global) | `~/.claude.json` | Available across all projects |

Example `.mcp.json` for a shared project:

```json
{
  "mcpServers": {
    "procmon": {
      "type": "stdio",
      "command": "python",
      "args": ["-m", "procmon_mcp"]
    }
  }
}
```

Example with a pre-loaded file and options:

```json
{
  "mcpServers": {
    "procmon": {
      "type": "stdio",
      "command": "python",
      "args": [
        "-m", "procmon_mcp",
        "--input-file", "/path/to/capture.xml.gz",
        "--no-stack-traces"
      ]
    }
  }
}
```

### Option 4: Streamable HTTP transport

For network access or multi-client scenarios, use Streamable HTTP:

```bash
# Add as an HTTP server (start the server separately first)
claude mcp add --transport http procmon http://127.0.0.1:8081/mcp
```

Then start the server:
```bash
python -m procmon_mcp --transport streamable-http --mcp-port 8081
```

### Verify the connection

Once configured, verify that Claude Code can see ProcmonMCP:

```bash
claude mcp list
```

Inside a Claude Code session, you can also type `/mcp` to check the status of connected servers.

## Usage

### Typical workflow

1. **Start the server** (Claude Code does this automatically for stdio servers)
2. **Check status**: The LLM calls `get_status` to see if a file is loaded
3. **Load a file**: The LLM calls `load_file` with a path to a Procmon XML capture
4. **Analyse**: The LLM uses the analysis tools to investigate the log data

### Command-line arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--input-file <path>` | *(none)* | Pre-load a Procmon XML file at startup. If omitted, use `load_file` from the MCP client. |
| `--transport <mode>` | `stdio` | Transport protocol: `stdio`, `streamable-http`, or `sse` (deprecated). |
| `--mcp-host <ip>` | `127.0.0.1` | Host address (HTTP transports only). |
| `--mcp-port <port>` | `8081` | Port number (HTTP transports only). |
| `--no-stack-traces` | off | Skip loading stack traces to save memory. |
| `--no-extra-data` | off | Skip loading unknown/extra event fields to save memory. |
| `--no-cache` | off | Bypass the parsed-capture cache (always re-parse, and refresh the cache). |
| `--clear-cache` | off | Remove all cached parsed captures, then exit. |
| `--debug` | off | Enable verbose debug logging. |
| `--log-file <path>` | *(console)* | Write logs to a file instead of the console. |
| `--profile` | off | Enable cProfile profiling (for development). |

### Examples

**Start with stdio (no file pre-loaded — use `load_file` from the client):**
```bash
python -m procmon_mcp
```

**Pre-load a compressed XML file:**
```bash
python -m procmon_mcp --input-file /path/to/capture.xml.gz
```

**Start with Streamable HTTP on a custom port:**
```bash
python -m procmon_mcp --transport streamable-http --mcp-port 9000
```

**Skip stack traces for a very large file:**
```bash
python -m procmon_mcp --input-file /path/to/huge_capture.xml --no-stack-traces --no-extra-data
```

## Transport Protocols

| Transport | Use case | Status |
|-----------|----------|--------|
| **stdio** | Local use with Claude Code, Claude Desktop, etc. | **Recommended** |
| **streamable-http** | Network access, multiple clients, remote deployment | Supported |
| **sse** | Legacy MCP clients that do not yet support Streamable HTTP | **Deprecated** (MCP spec 2025-03-26) |

### stdio (recommended)

The simplest and most reliable transport. Claude Code spawns the server as a child process and communicates over stdin/stdout. No network configuration required.

### Streamable HTTP

Uses a single HTTP endpoint (`/mcp`) for all communication. Supports session management, optional SSE streaming for long-running operations, and is designed for scalability.

```bash
python -m procmon_mcp --transport streamable-http --mcp-host 0.0.0.0 --mcp-port 8081
```

The server will be available at `http://<host>:<port>/mcp`.

### SSE (deprecated)

> **Deprecated since MCP specification 2025-03-26.** SSE is retained for backwards compatibility but will be removed in a future release. Please migrate to `streamable-http` or `stdio`.

```bash
python -m procmon_mcp --transport sse --mcp-port 8081
```

## User Configuration

ProcmonMCP stores user preferences in `~/.procmonmcp/config.json`. This file is created automatically and remembers:

- The last loaded file path (shown as a hint in `get_status` when no file is loaded)
- Loading preferences (`no_stack_traces`, `no_extra_data`)

No API keys or authentication tokens are required — ProcmonMCP is a purely local analysis tool.

### Parsed-capture cache

Parsing a large capture is expensive (tens of seconds to minutes). After a successful
parse, ProcmonMCP serializes the optimised in-memory representation (events, interners,
indices, process tables) to `~/.procmonmcp/cache/`, keyed on the source file's path,
size, and modification time plus the load options. Reloading the same unchanged file is
then served from the cache and is near-instant — in practice a 20s parse drops to well
under a second.

- The cache is invalidated automatically when the file changes (mtime/size) or when the
  cache format version changes. Different `no_stack_traces`/`no_extra_data` options are
  cached separately.
- Bypass it with `--no-cache` (CLI) or `no_cache: true` (the `load_file` tool); the
  `from_cache` field in the load response indicates whether the cache was used.
- Clear it with `--clear-cache` (CLI) or the `clear_cache` tool. The cache is
  size-bounded with LRU eviction (default 5 GiB; override with the
  `PROCMONMCP_CACHE_MAX_BYTES` environment variable).
- **Security:** cache files are serialized with Python's `pickle` and are read back only
  from your user-owned `~/.procmonmcp/cache` directory (only this tool's own output is
  ever deserialized). Do not point the cache at a location other users can write to.

## Available MCP Tools

### Lifecycle Tools

| Tool | Description |
|------|-------------|
| `get_status()` | Returns the current server state — whether a file is loaded, loading progress, memory usage, and available actions. **Call this first.** |
| `load_file(file_path, no_stack_traces?, no_extra_data?, no_cache?)` | Loads a Procmon XML file (.xml, .gz, .bz2, .xz) for analysis. Uses the parsed-capture cache for near-instant reloads (`from_cache` in the response says whether it was used). Set `no_cache: true` to bypass the cache. Provides progress feedback. Replaces any previously loaded data. |
| `close_file()` | Closes (unloads) the currently loaded capture and frees its memory. Analysis tools are unavailable until another file is opened with `load_file`. Does not remove the on-disk cache. |
| `clear_cache()` | Removes all on-disk parsed-capture caches. Reclaims disk space and forces a clean re-parse on the next load. Does not affect currently loaded data. |

### Data Retrieval Tools

| Tool | Description |
|------|-------------|
| `get_loaded_file_summary()` | Returns a detailed summary of the loaded file — filename, counts, compression, index stats, interner stats, and selective loading flags. |
| `get_metadata()` | Returns basic metadata (filename, type, event/process counts). |
| `list_processes()` | Lists unique processes (PID, name, image path, parent PID) from the process list section. |
| `get_process_details(pid)` | Returns detailed properties for a specific process by PID. |
| `query_events(...)` | Queries events with flexible filters — by process, **PID** (`filter_pid`), operation, result, path (contains/regex), detail (regex), timestamp range, and stack module path. Returns event summaries with index. |
| `get_event_details(event_index)` | Returns all properties for a specific event by its index. |
| `get_event_stack_trace(event_index)` | Returns the call stack for a specific event (module path, location, address). |

### Analysis Tools

| Tool | Description |
|------|-------------|
| `count_events_by_process()` | Counts events per process name. |
| `summarize_operations_by_process(process_name_filter)` | Counts operations for a specific process. |
| `get_timing_statistics(group_by)` | Calculates duration statistics grouped by process or operation. |
| `get_process_lifetime(pid)` | Finds the Process Create and Process Exit timestamps for a given PID. |
| `find_file_access(path_contains, limit?)` | Finds file system events matching a path substring (case-insensitive). |
| `find_network_connections(process_name)` | Returns enriched records for the remote endpoints a process accessed: endpoint, host/ip/hostname/port, operations, inferred directions (connect/send/receive), results, event count, and first/last-seen timestamps — ranked by count. |
| `list_network_connections(limit?)` | Capture-wide network triage: one enriched record per (process, PID, endpoint) across all processes, ranked by event count. |
| `get_network_top_talkers(limit?)` | Ranks unique remote endpoints across the whole capture by event count, with the count of distinct processes (and their names) that touched each. |

### Export Tools

| Tool | Description |
|------|-------------|
| `export_query_results(...)` | Exports filtered events to CSV or JSON file. Uses the same filters as `query_events`. |

## MCP Clients

ProcmonMCP works with any MCP-compatible client. Below are setup instructions for popular clients.

### Claude Code (recommended)

See the [Quick Start with Claude Code](#quick-start-with-claude-code) section above.

### Claude Desktop

Add the following to your Claude Desktop configuration file:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "procmon": {
      "command": "python",
      "args": ["-m", "procmon_mcp"]
    }
  }
}
```

### Cline

For Cline with Streamable HTTP transport, first start the server:

```bash
python -m procmon_mcp --transport streamable-http --mcp-port 8081
```

Then in Cline, select MCP Servers and add:
- **Server Name:** ProcmonMCP
- **Server URL:** `http://127.0.0.1:8081/mcp`

## Example LLM Prompts for Malware Analysis

*(Assuming a Procmon XML file is loaded)*

### Initial Triage

- "Get the summary of the loaded file."
- "List the unique processes found in the log."
- "Count the events per process." *(Identify high-activity processes)*
- "Calculate timing statistics grouped by process." *(Identify long-duration events)*

### Investigating a Suspicious Process

- "Get details for process PID 4568." *(Check command line, parent PID, image path)*
- "Summarise operations for process `suspicious.exe`."
- "Query events where filter_process is `suspicious.exe` and filter_operation is `RegSetValue`, limit 10."
- "Find network connections for process `suspicious.exe`." *(Enriched: directions, results, counts, first/last-seen)*
- "List network connections across the whole capture." *(Capture-wide triage, busiest first)*
- "Show the network top talkers." *(Rank remote endpoints by event count)*
- "Find file access containing `temp\\suspicious_data`, limit 50."

### Looking for Persistence

- "Query events where filter_operation is `RegSetValue` and filter_path_contains is `CurrentVersion\\Run`, limit 20."
- "Query events where filter_operation is `CreateFile` and filter_path_contains is `StartUp`, limit 10."

### Troubleshooting Errors

- "Query events where filter_result is `ACCESS DENIED`, limit 10."
- "Query events where filter_result is `NAME NOT FOUND`, limit 10."
- "Get details for event 987."
- "Get stack trace for event 987."

### Exporting Data

- "Export query results to `suspicious_reg_writes.csv` where filter_process is `suspicious.exe` and filter_operation contains `RegSet`."
- "Export query results to `network_activity.json` in json format."

## Performance and Indexing

ProcmonMCP builds four indices during file loading for fast filtered lookups:

| Index | Used by | Complexity |
|-------|---------|------------|
| Process name (interned ID) | `query_events`, `count_events_by_process` | O(1) lookup |
| Operation (interned ID) | `query_events`, `summarize_operations_by_process` | O(1) lookup |
| PID | `query_events` (`filter_pid`), `get_process_lifetime` | O(1) lookup with set intersection |
| File path (interned ID) | `find_file_access` | O(unique_paths) substring scan |

For filters not backed by an index (e.g., regex, path contains, stack module path), ProcmonMCP falls back to a linear scan of all events. Use indexed filters first to narrow results, then apply more expensive filters.

## Limitations

- **Memory usage**: Whilst optimised with string interning, loading extremely large XML files (millions of events with stack traces) can consume significant RAM. Use `--no-stack-traces` and `--no-extra-data` for very large files.
- **Loading time**: Parsing and optimising large XML files takes time, particularly compressed ones. Progress is reported during loading. Reloading an unchanged file is near-instant thanks to the [parsed-capture cache](#parsed-capture-cache); only the first parse pays the full cost.
- **XML structure**: Relies on the standard Procmon XML export structure. Malformed or non-standard XML will likely cause parsing errors.
- **Non-ASCII names**: Procmon's XML export double-encodes non-ASCII process/path names (e.g. Japanese filenames). ProcmonMCP detects and repairs this on load so names are readable and matchable by their true value; if a process name is still awkward to type exactly, filter by `filter_pid` instead.
- **Stack traces**: Stack trace quality depends on what Procmon resolved and included in the XML export. Requires running Procmon with symbols configured correctly.
- **Single file at a time**: Only one file can be loaded at any given time. Loading a new file replaces the previous data.

## Changelog

Notable changes are recorded in [CHANGELOG.md](CHANGELOG.md).

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues on [GitHub](https://github.com/JameZUK/ProcmonMCP).

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
