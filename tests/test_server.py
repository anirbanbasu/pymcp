import asyncio
from fastmcp import Client
from mcp.types import TextContent
import pytest

from pymcp.server import app as target_mcp_server, Base64EncodedBinaryDataResponse


@pytest.fixture(scope="module", autouse=True)
def mcp_client():
    """
    Fixture to create a client for the MCP server.
    """
    mcp_client = Client(
        transport=target_mcp_server,
        timeout=60,
    )
    return mcp_client


class TestMCPServer:
    async def call_tool(self, tool_name: str, mcp_client: Client, **kwargs):
        """
        Helper method to call a tool on the MCP server.
        """
        async with mcp_client:
            result = await mcp_client.call_tool(tool_name, arguments=kwargs)
            await mcp_client.close()
        for r in result:
            # Log experimental metadata from TextContent responses
            if isinstance(r, TextContent) and hasattr(r, "meta"):
                print(f"{tool_name} response metadata: {r.meta}")
        return result

    async def read_resource(self, resource_name: str, mcp_client: Client):
        """
        Helper method to load a resource from the MCP server.
        """
        async with mcp_client:
            result = await mcp_client.read_resource(resource_name)
            await mcp_client.close()
        return result

    def test_resource_logo(self, mcp_client: Client):
        """
        Test to read the logo resource from the MCP server.
        """
        results = asyncio.run(self.read_resource("data://logo", mcp_client))
        assert len(results) == 1, "Expected one result for the logo resource."
        result = results[0]
        assert hasattr(result, "text"), (
            "Expected the result to have a 'text' attribute containing the response."
        )
        encoded_response = Base64EncodedBinaryDataResponse.model_validate_json(
            result.text
        )
        assert hasattr(encoded_response, "hash"), (
            "Expected the response to have a 'hash' attribute."
        )
        assert hasattr(encoded_response, "hash_algorithm"), (
            "Expected the response to have a 'hash_algorithm' attribute."
        )
        assert (
            encoded_response.hash
            == "6414b58d9e44336c2629846172ec5c4008477a9c94fa572d3419c723a8b30eb4c0e2909b151fa13420aaa6a2596555b29834ac9b2baab38919c87dada7a6ef14"
        ), "Obtained hash does not match the expected hash."
        assert encoded_response.hash_algorithm == "sha3_512", (
            f"Expected hash algorithm is sha3_512. Got {encoded_response.hash_algorithm}."
        )

    def test_permutations(self, mcp_client: Client):
        """
        Test to call the permutations tool on the MCP server.
        """
        results = asyncio.run(self.call_tool("permutations", mcp_client, n=16, k=8))
        assert len(results) == 1, "Expected one result for the permutations tool."
        result = results[0]
        assert hasattr(result, "text"), (
            "Expected the result to have a 'text' attribute containing the response."
        )
        assert result.text.isdigit(), "Expected the response to be a number."
        assert int(result.text) == 518918400, (
            f"Expected 518918400 permutations for n=16, k=5. Obtained {result.text}."
        )
