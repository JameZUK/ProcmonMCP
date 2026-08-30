# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-08-30

### Fixed
- **Support MCP SDK v2, which renamed `FastMCP` to `MCPServer`.** (#33)
  The dependency was pinned only as `mcp[cli]>=1.8.0`, so a fresh install
  resolved to mcp 2.x, where `mcp.server.fastmcp` no longer exists. `compat.py`
  caught the resulting `ImportError`, fell back to mock objects, and the CLI
  exited claiming the SDK was *"not installed"* when it was — just a version it
  could not use. The SDK import is now tried v2-first
  (`from mcp.server.mcpserver import MCPServer, Context`), falling back to the
  v1 `FastMCP` path for environments pinned to `mcp<2`.
- **Host and port were silently dropped on the HTTP transports under v2.**
  v2 removed `host`/`port` from `mcp.settings`, so the old assignment raised
  `ValueError: "Settings" object has no field "host"`; the existing
  `hasattr(mcp, 'settings')` guard did not catch it, because `.settings` still
  exists and only lost those two fields. Host and port are now passed as
  `run()` keyword arguments on v2 and set on `settings` on v1.
- **`requires-python` corrected to `>=3.10`.** It claimed `>=3.7`, but every
  supported MCP SDK — v1 from 1.8.0 onward, and all of v2 — already requires
  3.10 or newer.
- **The startup failure message now distinguishes an absent SDK from an
  unusable one**, reporting which import was attempted rather than telling
  users to install a package they already have.

### Changed
- **`mcp[cli]>=2.0.0`** is now the declared dependency (was `>=1.8.0`). The v1
  code path is retained as a compatibility fallback, not a supported
  configuration; `compat.MCP_SDK_V2` reports which API is live.
- **`compat` exports `MCPServer`**, with `FastMCP` kept as an alias so
  `from procmon_mcp import FastMCP` keeps working.
- **The server now advertises its own version** (`procmon-mcp`'s, e.g. `0.4.0`)
  to clients on v2, which defaults the field to an empty string. v1's `FastMCP`
  has no such parameter and continues to report the SDK's version.
- **The manual test client (`tests/procmon-mcp-tester.py`) works on both
  majors:** v2 dropped the `streamablehttp_client` spelling, so the client now
  prefers `streamable_http_client` (present in both) and falls back for older
  v1 SDKs.
- **CI `sdk-smoke` runs against both SDK majors** (`mcp[cli]>=2` and
  `mcp[cli]<2`) and now asserts the SDK was actually detected and that all
  tools registered — the previous job would have passed while the server
  silently degraded to mock objects.

## [0.4.0] - 2026-06-23

Reliability/efficiency/stability hardening pass (code review).

### Fixed
- **A mid-stream parse error no longer reports success or caches a truncated
  capture.** `load_procmon_xml` now raises on incomplete consumption and skips
  the cache write, instead of returning partial events and persisting them. (#23)
- **stdlib (no-lxml) error handling:** the parser caught `ET_impl.XMLSyntaxError`,
  which does not exist on `xml.etree.ElementTree` (it has `ParseError`) — on
  malformed XML this raised `AttributeError` and masked the real error. A
  backend-correct `compat.XMLSyntaxError` alias is now used.

### Changed
- **Loading runs off the event loop** (`asyncio.to_thread`), so the server stays
  responsive during a long parse on the HTTP/SSE transports. (#24)
- **Parsed-capture cache is size-bounded** with LRU eviction (default 5 GiB,
  override via `PROCMONMCP_CACHE_MAX_BYTES`); cache hits refresh recency. (#25)
- **`export_query_results` streams rows to disk** instead of buffering every
  matching event in memory, so exports are bounded-memory on large captures. (#26)
- **User filter regexes use Google RE2 when available** (linear-time, ReDoS-safe),
  falling back to stdlib `re` with the existing length cap. Install via the
  optional `re2` extra. (#27)
- **`find_file_access`** lazily heap-merges per-path index lists and stops at
  `limit` instead of collecting and sorting every match. (#28)
- Hot scan loops read the wall clock only periodically (`CLOCK_CHECK_INTERVAL`)
  rather than every event. (#29)
- Event-detail formatting uses a shallow `ProcessInfo.to_dict()` instead of
  `dataclasses.asdict()` (no deep recursion per row). (#30)
- Minor: factored the duplicated HTTP transport-settings block in the CLI;
  pre-intern `Process Start`.

## [0.3.1] - 2026-06-23

### Added
- **`filter_pid`** on `query_events` and `export_query_results` — select a single
  process by its numeric PID (index-backed). Useful when a process name is hard to
  type exactly, e.g. non-ASCII names. (#21)

### Fixed
- **Non-ASCII process/path names** were unreadable mojibake (e.g.
  `æ¸©åº¦ã¹ã¤ãã.exe` instead of `温度スイッチ.exe`) and couldn't be matched by
  `filter_process`. Procmon's XML export double-encodes such text (UTF-8 bytes →
  Latin-1 → UTF-8); the parser now repairs this on load for process names, paths,
  image paths, command lines, owners, descriptions, and event detail. The repair
  is conservative (only strings with the exact double-encoding fingerprint are
  touched; ASCII and correctly-stored names are unchanged). The parsed-capture
  cache version was bumped so existing caches re-parse. (#21)

### Added
- **`close_file`** tool — closes (unloads) the currently loaded capture and frees
  its memory, so a client can explicitly release a file before opening another or
  leave the server idle. Analysis tools refuse until another file is loaded; the
  on-disk cache is left intact. `get_status` now lists `close_file` as an
  available action while a file is loaded.

## [0.2.2] - 2026-06-23

### Fixed
- `--transport streamable-http` crashed immediately with
  `FastMCP.run() got an unexpected keyword argument 'host'`. The MCP SDK's
  `run()` signature is `run(transport, mount_path)`; host and port belong on
  `mcp.settings`. The Streamable HTTP branch now configures host/port/log level
  via `settings` (matching the SSE branch) before calling `run()`. `stdio`
  (the default) was unaffected. (#17)

## [0.2.1] - 2026-06-23

### Fixed
- `get_process_lifetime` returned `create_timestamp: null` for processes that
  started during the capture. Procmon records a process's own start as a
  `Process Start` event (with that PID), whereas `Process Create` is logged by
  the parent (with the parent's PID), so matching only `Process Create` against
  the requested PID never found the process's own creation. The tool now
  considers both operations and uses the earliest, so a process's own
  `Process Start` is used when present. (#14)

## [0.2.0] - 2026-06-23

### Added
- **Parsed-capture cache** so reloading an unchanged file is near-instant — the
  optimised in-memory structures are serialized to `~/.procmonmcp/cache/`, keyed
  on the file's path/size/mtime, the load options, and a cache-version stamp.
  Measured 29×–146× faster reloads on real captures. Adds the `clear_cache`
  tool, a `no_cache` option (and `from_cache` in the response) on `load_file`,
  and `--no-cache` / `--clear-cache` CLI flags. (#8)
- **`list_network_connections`** — capture-wide network triage across all
  processes. (#7)
- **`get_network_top_talkers`** — ranks unique remote endpoints across the whole
  capture by event count, with the distinct-process count per endpoint. (#9)
- **Enriched network records** for `find_network_connections` /
  `list_network_connections`: split host/ip/hostname/port, operations, inferred
  directions (connect/send/receive), distinct results, event count, and
  first/last-seen timestamps. (#9)
- **Packaging**: `pyproject.toml` with a `procmon-mcp` console script and
  `lxml` / `psutil` / `all` / `dev` optional extras; MIT `LICENSE`. (#4)
- **CI**: GitHub Actions running the test suite on Python 3.10–3.13 with and
  without lxml, plus an `sdk-smoke` job that installs the real MCP SDK and
  imports the server. (#4, #6)
- Substantially expanded unit tests (78 → 123), including a large-capture parser
  regression, exact-match filter coverage, network-tool tests, and cache tests.

### Changed
- **BREAKING:** `find_network_connections` now returns enriched structured
  records (`List[dict]`) ranked by event count, instead of a bare list of
  `host:port` strings. (#9)
- Network endpoint parsing now accepts resolved **service-name ports**
  (`domain`, `https`, …) and DNS hostnames, not just numeric ports. (#10)
- `requirements.txt` now lists only `mcp[cli]` as required; `lxml` and `psutil`
  are documented as optional, matching the code's graceful fallbacks. (#4)

### Fixed
- **Critical:** event fields were read on the iterparse `start` event, which is
  not guaranteed to have the element's children populated. On large captures
  this silently dropped events or nulled `Operation`/`Path`/`Result` whenever an
  event spanned a read-buffer boundary. Fields are now read on the `end` event.
  (#4)
- Exact-match filters (`filter_process` / `filter_operation` / `filter_result`)
  returned **all** events instead of zero when the supplied value was absent from
  the capture. (#4)
- Server failed to import on current MCP SDKs because it passed `description=`
  to `FastMCP`, which expects `instructions=`. (#5)
- `query_events` no longer double-wraps already-meaningful errors;
  `export_query_results` verifies a file is loaded before validating paths or
  creating directories. (#4)

### Security
- Cache files are serialized with Python's `pickle` module and are read back
  only from the user-owned `~/.procmonmcp/cache` directory (only this tool's own
  output is deserialized). Documented in the README; do not point the cache at a
  location other users can write to. (#8)

## [0.1.0]

- Initial modular `procmon_mcp` package: two-pass streaming XML parser with
  string interning and process/operation/PID/path indices; MCP tools for
  querying events, inspecting processes, timing/operation summaries, file and
  network lookups, and CSV/JSON export; stdio / Streamable HTTP / SSE
  transports; runtime `load_file`; and `~/.procmonmcp/config.json` preferences.
