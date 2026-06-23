# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
