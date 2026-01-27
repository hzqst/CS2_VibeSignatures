"""
Search for CNetworkTransmitComponent::StateChanged string in IDA Pro
This script is meant to be used with ida-pro-mcp tools
"""

# The string we're searching for
SEARCH_STRING = "CNetworkTransmitComponent::StateChanged(%s) @%s:%d"

print(f"Searching for string: {SEARCH_STRING}")
print("=" * 80)

# Instructions for manual execution via MCP:
print("\nTo search for this string in IDA Pro, use the following MCP tool calls:")
print("\n1. First, search for the string:")
print(f"""
ida-pro-mcp.search_string with parameter:
{{
  "search": "{SEARCH_STRING}"
}}
""")

print("\n2. Once found, get cross-references to the string address")
print("""
ida-pro-mcp.get_xrefs with parameter:
{
  "addr": "<address_of_string_from_step_1>"
}
""")

print("\n3. For each xref, decompile the function to see usage context")
print("""
ida-pro-mcp.decompile with parameter:
{
  "addr": "<function_address_from_xrefs>"
}
""")
