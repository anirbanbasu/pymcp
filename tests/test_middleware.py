import asyncio
import logging
import string

import pytest
from fastmcp import Client, FastMCP

from pymcp.middleware import ResponseMetadataMiddleware, StripUnknownArgumentsMiddleware
from pymcp.server import PyMCP

logger = logging.getLogger(__name__)


class TestStripUnknownArgumentsMiddleware:
    """Dedicated test class for the StripUnknownArgumentsMiddleware."""

    @pytest.fixture(scope="class")
    @classmethod
    def mcp_server(cls):
        """Fixture to create an MCP server instance with the middleware."""
        server = FastMCP()
        mcp_obj = PyMCP()
        server_with_features = mcp_obj.register_features(server)
        server_with_features.add_middleware(StripUnknownArgumentsMiddleware())
        return server_with_features

    @pytest.fixture(scope="class", autouse=True)
    @classmethod
    def mcp_client(cls, mcp_server):
        """Fixture to create a client for the MCP server."""
        mcp_client = Client(transport=mcp_server, timeout=60)
        return mcp_client

    async def call_tool(self, tool_name: str, mcp_client: Client, **kwargs):
        """Helper method to call a tool on the MCP server."""
        async with mcp_client:
            result = await mcp_client.call_tool(tool_name, arguments=kwargs)
            await mcp_client.close()
        return result

    def test_strip_unknown_arguments(self, mcp_client: Client, caplog):
        """Test that unknown arguments are stripped from tool calls and logged."""
        tool_name = "greet"
        valid_name = "Test User"
        unknown_arg_value = "This should be stripped"

        with caplog.at_level(logging.INFO):
            results = asyncio.run(
                self.call_tool(
                    tool_name,
                    mcp_client,
                    name=valid_name,
                    unknown_argument=unknown_arg_value,
                )
            )

        # Verify the tool call succeeded with valid argument
        assert hasattr(results, "content"), "Expected results to have 'content' attribute"
        assert hasattr(results, "structured_content"), "Expected results to have 'structured_content' attribute"
        assert "result" in results.structured_content, "Expected 'structured_content' to have 'result' key"

        # Verify the greeting contains the valid name (proving valid args passed through)
        greeting = results.structured_content["result"]
        assert valid_name in greeting, f"Expected greeting to contain '{valid_name}'"

        # Verify logging occurred for unknown arguments
        assert any("Unknown arguments for tool 'greet'" in record.message for record in caplog.records), (
            "Expected logging of unknown arguments"
        )

        # Verify the unknown argument was identified in the logs
        assert any("unknown_argument" in record.message for record in caplog.records), (
            "Expected 'unknown_argument' to be logged as unknown"
        )

    def test_all_arguments_unknown(self, mcp_client: Client, caplog):
        """Test behavior when all provided arguments are unknown."""
        tool_name = "greet"

        with caplog.at_level(logging.INFO):
            results = asyncio.run(
                self.call_tool(
                    tool_name,
                    mcp_client,
                    completely_unknown_arg="value1",
                    another_unknown_arg="value2",
                )
            )

        # Verify the tool call still succeeds (using defaults)
        assert hasattr(results, "content"), "Expected results to have 'content' attribute"
        assert hasattr(results, "structured_content"), "Expected results to have 'structured_content' attribute"
        assert "result" in results.structured_content, "Expected 'structured_content' to have 'result' key"

        # Verify default greeting (no name provided)
        greeting = results.structured_content["result"]
        assert "World" in greeting, "Expected default greeting with 'World'"

        # Verify logging occurred
        assert any("Unknown arguments for tool 'greet'" in record.message for record in caplog.records), (
            "Expected logging of unknown arguments"
        )

    def test_no_arguments_provided(self, mcp_client: Client, caplog):
        """Test that middleware handles tools called with no arguments correctly."""
        tool_name = "greet"

        with caplog.at_level(logging.INFO):
            results = asyncio.run(self.call_tool(tool_name, mcp_client))

        # Verify the tool call succeeds
        assert hasattr(results, "content"), "Expected results to have 'content' attribute"
        assert hasattr(results, "structured_content"), "Expected results to have 'structured_content' attribute"

        # Verify no middleware logging for this case (no args to strip)
        middleware_logs = [record for record in caplog.records if "Unknown arguments" in record.message]
        assert len(middleware_logs) == 0, "Expected no middleware logging when no arguments provided"

    def test_only_valid_arguments(self, mcp_client: Client, caplog):
        """Test that middleware doesn't interfere when only valid arguments are provided."""
        tool_name = "greet"
        valid_name = "Valid User"

        with caplog.at_level(logging.INFO):
            results = asyncio.run(self.call_tool(tool_name, mcp_client, name=valid_name))

        # Verify the tool call succeeds with the valid argument
        assert hasattr(results, "content"), "Expected results to have 'content' attribute"
        greeting = results.structured_content["result"]
        assert valid_name in greeting, f"Expected greeting to contain '{valid_name}'"

        # Verify no unknown argument logging
        unknown_arg_logs = [record for record in caplog.records if "Unknown arguments" in record.message]
        assert len(unknown_arg_logs) == 0, "Expected no unknown argument logging for valid args only"

    def test_mixed_valid_and_unknown_arguments(self, mcp_client: Client, caplog):
        """Test middleware behavior with a mix of valid and unknown arguments."""
        tool_name = "greet"
        valid_name = "Mixed Test"

        with caplog.at_level(logging.INFO):
            results = asyncio.run(
                self.call_tool(
                    tool_name,
                    mcp_client,
                    name=valid_name,
                    unknown1="value1",
                    unknown2={"key": "value2"},
                    unknown3=3.14,
                )
            )

        # Verify valid argument was used
        greeting = results.structured_content["result"]
        assert valid_name in greeting, f"Expected greeting to contain '{valid_name}'"

        # Verify multiple unknown arguments are logged
        unknown_logs = [record for record in caplog.records if "Unknown arguments for tool 'greet'" in record.message]
        assert len(unknown_logs) > 0, "Expected logging for unknown arguments"

        # Verify all three unknown arguments are mentioned
        log_messages = " ".join([record.message for record in caplog.records])
        assert "unknown1" in log_messages, "Expected 'unknown1' in logs"
        assert "unknown2" in log_messages, "Expected 'unknown2' in logs"
        assert "unknown3" in log_messages, "Expected 'unknown3' in logs"


class TestResponseMetadataMiddleware:
    """Dedicated test class for the ResponseMetadataMiddleware."""

    @pytest.fixture(scope="class")
    @classmethod
    def mcp_server(cls):
        """Fixture to create an MCP server instance with the middleware."""
        server = FastMCP()
        mcp_obj = PyMCP()
        server_with_features = mcp_obj.register_features(server)
        server_with_features.add_middleware(ResponseMetadataMiddleware())
        return server_with_features

    @pytest.fixture(scope="class", autouse=True)
    @classmethod
    def mcp_client(cls, mcp_server):
        """Fixture to create a client for the MCP server."""
        mcp_client = Client(transport=mcp_server, timeout=60)
        return mcp_client

    async def call_tool(self, tool_name: str, mcp_client: Client, **kwargs):
        """Helper method to call a tool on the MCP server."""
        async with mcp_client:
            result = await mcp_client.call_tool(tool_name, arguments=kwargs)
            await mcp_client.close()
        return result

    def test_call_for_package_metadata(self, mcp_client: Client, caplog):
        """Test that metadata is added to tool responses and appropriate logging occurs."""
        tool_name = "greet"
        valid_name = "Test User"

        with caplog.at_level(logging.DEBUG):
            results = asyncio.run(
                self.call_tool(
                    tool_name,
                    mcp_client,
                    name=valid_name,
                )
            )

        # Verify the tool call succeeded with valid argument
        assert hasattr(results, "content"), "Expected results to have 'content' attribute"
        assert hasattr(results, "structured_content"), "Expected results to have 'structured_content' attribute"
        assert "result" in results.structured_content, "Expected 'structured_content' to have 'result' key"

        # Verify the greeting contains the valid name (proving valid args passed through)
        greeting = results.structured_content["result"]
        assert valid_name in greeting, f"Expected greeting to contain '{valid_name}'"

        assert getattr(results, "meta", None) is not None, "Expected results to have a valid 'meta' attribute"
        assert ResponseMetadataMiddleware.PACKAGE_METADATA_KEY in results.meta, (
            f"Expected '{ResponseMetadataMiddleware.PACKAGE_METADATA_KEY}' in meta"
        )
        assert ResponseMetadataMiddleware.TIMING_METADATA_KEY in results.meta, (
            f"Expected '{ResponseMetadataMiddleware.TIMING_METADATA_KEY}' in meta"
        )
        assert "name" in results.meta[ResponseMetadataMiddleware.PACKAGE_METADATA_KEY], (
            "Expected 'name' in package metadata"
        )
        assert "version" in results.meta[ResponseMetadataMiddleware.PACKAGE_METADATA_KEY], (
            "Expected 'version' in package metadata"
        )
        assert results.meta[ResponseMetadataMiddleware.PACKAGE_METADATA_KEY]["name"] == "pymcp-template"
        assert "tool_execution_time_ms" in results.meta[ResponseMetadataMiddleware.TIMING_METADATA_KEY], (
            "Expected 'tool_execution_time_ms' in timing metadata"
        )
        assert isinstance(
            results.meta[ResponseMetadataMiddleware.TIMING_METADATA_KEY]["tool_execution_time_ms"], float
        ), "Expected 'tool_execution_time_ms' to be a float"

        # Verify logging occurred for metadata addition
        assert any("Added package metadata to tool response" in record.message for record in caplog.records), (
            "Expected debug logging of package metadata addition"
        )

    def test_call_tool_no_response(self, mcp_client: Client, caplog):
        """Test that the middleware passes up exceptions."""
        tool_name = "permutations"

        with caplog.at_level(logging.DEBUG):
            try:
                results = asyncio.run(
                    self.call_tool(
                        tool_name,
                        mcp_client,
                        n=5,
                        k=6,  # k > n to force exception
                    )
                )
            except Exception as e:
                logger.error(f"Exception during tool call. {e}", exc_info=True)
                results = None

        # Verify the tool call returns None because an exception was raised (k > n is invalid)
        assert results is None, "Expected results to be None because of exception in tool"

        # Verify error logging occurred
        assert any(
            record.levelno == logging.ERROR and "cannot be greater" in record.message for record in caplog.records
        ), "Expected error logging due to exception in tool call"

        assert any("failed after" in record.message for record in caplog.records), (
            "Expected warning logging of operation failure"
        )

        # Verify no logging occurred for metadata addition since result is None
        assert not any("Added package metadata to tool response" in record.message for record in caplog.records), (
            "Did not expect debug logging of package metadata addition when exceptions occur"
        )

    def test_call_tool_with_specific_metadata(self, mcp_client: Client, caplog):
        """Test that existing metadata is preserved and package metadata is added."""
        tool_name = "generate_password"
        expected_password_length = 12

        with caplog.at_level(logging.DEBUG):
            results = asyncio.run(
                self.call_tool(
                    tool_name,
                    mcp_client,
                    use_special_chars=True,
                    length=expected_password_length,
                )
            )

        # Verify the tool call succeeded with valid argument
        assert hasattr(results, "content"), "Expected results to have 'content' attribute"
        assert hasattr(results, "structured_content"), "Expected results to have 'structured_content' attribute"
        assert "result" in results.structured_content, "Expected 'structured_content' to have 'result' key"

        # Verify the generated password has the expected length
        generated_password = results.structured_content["result"]
        assert len(generated_password) == expected_password_length, (
            f"Expected generated password to be of length {expected_password_length}, got {len(generated_password)}"
        )

        assert getattr(results, "meta", None) is not None, "Expected results to have a valid 'meta' attribute"
        assert ResponseMetadataMiddleware.PACKAGE_METADATA_KEY in results.meta, (
            f"Expected '{ResponseMetadataMiddleware.PACKAGE_METADATA_KEY}' in meta"
        )
        assert ResponseMetadataMiddleware.TIMING_METADATA_KEY in results.meta, (
            f"Expected '{ResponseMetadataMiddleware.TIMING_METADATA_KEY}' in meta"
        )
        assert "name" in results.meta[ResponseMetadataMiddleware.PACKAGE_METADATA_KEY], (
            "Expected 'name' in package metadata"
        )
        assert "version" in results.meta[ResponseMetadataMiddleware.PACKAGE_METADATA_KEY], (
            "Expected 'version' in package metadata"
        )
        assert results.meta[ResponseMetadataMiddleware.PACKAGE_METADATA_KEY]["name"] == "pymcp-template"
        assert "tool_execution_time_ms" in results.meta[ResponseMetadataMiddleware.TIMING_METADATA_KEY], (
            "Expected 'tool_execution_time_ms' in timing metadata"
        )
        assert isinstance(
            results.meta[ResponseMetadataMiddleware.TIMING_METADATA_KEY]["tool_execution_time_ms"], float
        ), "Expected 'tool_execution_time_ms' to be a float"

        # Verify tool specific metadata is still present and values make sense
        assert "length_satisfied" in results.meta[tool_name], (
            "Expected tool specific metadata key 'length_satisfied' to be present"
        )
        assert results.meta[tool_name]["length_satisfied"] is True, (
            "Expected 'length_satisfied' to be True since password matches requested length"
        )
        assert "generation_attempts" in results.meta[tool_name], (
            "Expected tool specific metadata key 'generation_attempts' to be present"
        )
        assert results.meta[tool_name]["generation_attempts"] >= 1, (
            "Expected 'generation_attempts' to be at least 1"
        )
        assert "character_set" in results.meta[tool_name], (
            "Expected tool specific metadata key 'character_set' to be present"
        )
        assert isinstance(results.meta[tool_name]["character_set"], str), (
            "Expected 'character_set' to be a string"
        )
        # Verify character_set contains expected character types when use_special_chars=True
        # The character_set should be the pool of available characters for password generation
        character_set = results.meta[tool_name]["character_set"]
        assert any(c in character_set for c in string.ascii_lowercase), (
            "Expected character_set to contain lowercase letters"
        )
        assert any(c in character_set for c in string.ascii_uppercase), (
            "Expected character_set to contain uppercase letters"
        )
        assert any(c in character_set for c in string.digits), (
            "Expected character_set to contain digits"
        )
        assert any(c in character_set for c in string.punctuation), (
            "Expected character_set to contain punctuation when use_special_chars=True"
        )

        # Verify logging occurred for metadata addition
        assert any("Added package metadata to tool response" in record.message for record in caplog.records), (
            "Expected debug logging of package metadata addition"
        )
