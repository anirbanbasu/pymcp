from typing import Any, ClassVar, Dict, List

from fastmcp import FastMCP


class MCPMixin:
    """
    A mixin class to register tools, resources, and prompts with a FastMCP instance.
    """

    # Each entry is a dict, must include "fn" (method name),
    # rest is arbitrary metadata relevant to FastMCP.
    tools: ClassVar[List[Dict[str, Any]]] = []
    # Each entry is a dict, must include "fn" (method name) and "uri",
    # rest is arbitrary metadata relevant to FastMCP.
    resources: ClassVar[List[Dict[str, Any]]] = []
    # Each entry is a dict, must include "fn" (method name),
    # rest is arbitrary metadata relevant to FastMCP.
    prompts: ClassVar[List[Dict[str, Any]]] = []

    def register_features(self, mcp: FastMCP) -> FastMCP:
        """
        Register tools, resources, and prompts with the given FastMCP instance.

        Args:
            mcp (FastMCP): The FastMCP instance to register features with.

        Returns:
            FastMCP: The FastMCP instance with registered features.
        """
        # Register tools
        for tool in self.tools:
            assert "fn" in tool, "Tool metadata must include the 'fn' key."
            fn_name = tool.pop("fn")
            fn = getattr(self, fn_name)
            mcp.tool(fn, **tool)  # pass remaining metadata as kwargs

        # Register resources
        for res in self.resources:
            assert "fn" in res and "uri" in res, (
                "Resource metadata must include 'fn' and 'uri' keys."
            )
            fn_name = res.pop("fn")
            uri = res.pop("uri")
            fn = getattr(self, fn_name)
            mcp.resource(uri, **res)(fn)

        # Register prompts
        for pr in self.prompts:
            assert "fn" in pr, "Prompt metadata must include the 'fn' key."
            fn_name = pr.pop("fn")
            fn = getattr(self, fn_name)
            mcp.prompt(fn, **pr)

        return mcp
