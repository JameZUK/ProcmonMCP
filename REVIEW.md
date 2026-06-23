# ProcmonMCP — Project Review

> This review reflects the modular `procmon_mcp` package (post-refactor). An
> earlier review of the original single-file `procmon-mcp.py` has been
> superseded; its findings were either addressed by the package split or are
> tracked below.

## Summary

ProcmonMCP is a Model Context Protocol (MCP) server that lets an LLM analyse
Process Monitor (Procmon) XML captures. The codebase is split into focused
modules (`compat`, `constants`, `helpers`, `models`, `parser`, `filters`,
`formatters`, `server`, `tools`, `cli`, `config`) with string interning and four
indices (process name, operation, PID, path) for fast lookups, graceful
fallbacks (lxml → stdlib ElementTree, optional psutil/MCP SDK), and a unit-test
suite. It is functional and demonstrates solid domain knowledge of both MCP and
Procmon analysis.

---

## Findings addressed in this pass

### Critical — silent event loss/corruption on large files (fixed)

`parser._parse_xml_stream_for_loading` previously extracted every event field on
the iterparse **`start`** event of `<event>`. `iterparse` does not guarantee an
element's children/text are populated at `start` (only at `end`), so whenever a
read-buffer boundary fell inside an `<event>`, that event was silently dropped
or kept with null `Operation`/`Path`/`Result`. Reproduced on a 20,000-event
capture: ~0.5% of events were lost and dozens more were corrupted, in both the
lxml and stdlib paths.

**Fix:** all field extraction (including stack frames, read from the event's
fully-parsed `<stack>` subtree) now happens on the `<event>` **end** event —
matching how Pass 1 already parses `<process>` elements. A regression test
(`TestParserIntegration`) loads a 20,000-event capture and asserts zero drops,
zero null core fields, and complete stacks, under both XML backends.

### Medium

- **`requirements.txt` vs docs (fixed):** the file pinned `lxml` and `psutil`
  as hard requirements while the README/`compat.py` treat them as optional. It
  now lists only `mcp[cli]` as required and documents the optional extras.
- **Packaging metadata (fixed):** added `pyproject.toml` (setuptools) with a
  `procmon-mcp` console script and `lxml`/`psutil`/`all`/`dev` optional extras.
  Added a `LICENSE` (MIT) and a CI workflow that runs the tests on Python
  3.10–3.13 with and without lxml.

### Low

- **`query_events` exception handling (fixed):** removed a redundant
  `isinstance` re-check that double-wrapped `RuntimeError`s; meaningful errors
  are now re-raised as-is.
- **`export_query_results` ordering (fixed):** it now verifies a file is loaded
  *before* validating the output path and creating directories.
- **`find_network_connections` endpoint parsing (fixed):** the inline regex
  matched only IP/hex hosts despite a docstring promising "Hostname:port". It is
  now a tested helper (`helpers.parse_network_endpoint`) covering IPv4, bracketed
  IPv6, and DNS hostnames.

---

## Notes / possible future work

- **Global mutable state:** `server.LOADED_DATA` / `LOADING_IN_PROGRESS` are
  module-level globals. A single async load guard makes this safe in practice,
  but a server-context object would ease testing and multi-instance use.
- **Single file at a time:** loading a new capture replaces the previous one.
  Documented and intentional.
- **ReDoS:** user-supplied regex filters are length-capped (`MAX_REGEX_LEN`) but
  not time-bounded. A pathological pattern over millions of events could still
  be slow; a `re2`/timeout wrapper would harden this.
- **Network/SSE transport:** HTTP/SSE transports are unauthenticated. The README
  warns to run only in trusted environments; a shared-secret option would help
  for networked deployments.
- **Midnight rollover:** date advancement uses a 1-hour out-of-order threshold,
  which is reasonable but still heuristic for unusual captures.

## Testing

`pytest -q` — unit tests cover `StringInterner`, XML helpers, timestamp parsing,
`ProcessInfo`, `ProcmonLogData`, config, network-endpoint parsing, and full
parser integration (including the large-file regression). All pass under both
lxml and the stdlib ElementTree fallback.
