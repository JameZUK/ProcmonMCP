#!/usr/bin/env python3
"""
ProcmonMCP - MCP server for analyzing Process Monitor XML log files.

This is a thin wrapper for backward compatibility.
The actual implementation lives in the procmon_mcp package.

Usage: python procmon-mcp.py --input-file <path_to_xml>
"""
from procmon_mcp.cli import main

if __name__ == "__main__":
    main()
