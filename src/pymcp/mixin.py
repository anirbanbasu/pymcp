from typing import Any, ClassVar, Dict, List

from fastmcp import FastMCP
from fastmcp.tools.tool import ToolResult
import copy

from importlib.metadata import metadata as importlib_metadata

from pymcp import PACKAGE_NAME


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
            tool_copy = copy.deepcopy(tool)
            fn_name = tool_copy.pop("fn")
            fn = getattr(self, fn_name)
            mcp.tool(**tool_copy)(fn)  # pass remaining metadata as kwargs
        # Register resources
        for res in self.resources:
            assert "fn" in res and "uri" in res, (
                "Resource metadata must include 'fn' and 'uri' keys."
            )
            res_copy = copy.deepcopy(res)
            fn_name = res_copy.pop("fn")
            uri = res_copy.pop("uri")
            fn = getattr(self, fn_name)
            mcp.resource(uri, **res_copy)(fn)
        # Register prompts
        for pr in self.prompts:
            assert "fn" in pr, "Prompt metadata must include the 'fn' key."
            pr_copy = copy.deepcopy(pr)
            fn_name = pr_copy.pop("fn")
            fn = getattr(self, fn_name)
            mcp.prompt(**pr_copy)(fn)

        return mcp

    def get_tool_result(
        self, result: Any, metadata: Dict[str, Any] | None = None
    ) -> ToolResult:
        if metadata is None:
            metadata = {}
        _package_metadata = importlib_metadata(PACKAGE_NAME)
        metadata["_package_metadata"] = {
            "name": _package_metadata["name"],
            "version": _package_metadata["version"],
        }
        return ToolResult(structured_content={"result": result}, meta=metadata)
