import asyncio
from datetime import datetime
import logging
import math
import random
import json
import re
import string
import uuid
from fastmcp.exceptions import ToolError
from fastmcp import Client, FastMCP
import pytest
from fastmcp.prompts.prompt import TextContent
from mcp.shared.context import RequestContext
from fastmcp.client.sampling import SamplingMessage, SamplingParams
from fastmcp.client.elicitation import ElicitRequestParams, ElicitResult

from pymcp.data_model.response_models import Base64EncodedBinaryDataResponse
from pymcp.server import PyMCP


from pymcp.server import (
    package_version,
)

logger = logging.getLogger(__name__)


class TestMCPServer:
    @classmethod
    async def random_llm_sampling_handler(
        cls,
        messages: list[SamplingMessage],
        params: SamplingParams,
        context: RequestContext,
    ) -> str:
        # Since we do not have a language model at our disposal, ignore all the paramers and generate a unique ID.
        logger.info(f"Received LLM sampling request: {messages[-1].content.text}")
        return str(uuid.uuid4())

    @classmethod
    async def random_elicitation_handler(
        cls,
        message: str,
        response_type: type,
        params: ElicitRequestParams,
        context: RequestContext,
    ) -> ElicitResult:
        # Since we are in the midst of a test, ignore all the paramers and generate a random response.
        logger.info(f"Received elicitation request: {message}")
        return response_type(value=random.uniform(0.0, 2.0))

    @pytest.fixture(scope="class", autouse=True)
    @classmethod
    def mcp_server(cls):
        """
        Fixture to register features in an MCP server.
        """
        server = FastMCP()
        mcp_obj = PyMCP()
        server_with_features = mcp_obj.register_features(server)
        return server_with_features

    @pytest.fixture(scope="class", autouse=True)
    @classmethod
    def mcp_client(cls, mcp_server):
        """
        Fixture to create a client for the MCP server.
        """
        mcp_client = Client(
            transport=mcp_server,
            timeout=60,
            sampling_handler=TestMCPServer.random_llm_sampling_handler,
            elicitation_handler=TestMCPServer.random_elicitation_handler,
        )
        return mcp_client

    async def call_tool(self, tool_name: str, mcp_client: Client, **kwargs):
        """
        Helper method to call a tool on the MCP server.
        """
        async with mcp_client:
            result = await mcp_client.call_tool(tool_name, arguments=kwargs)
            await mcp_client.close()
        return result

    async def read_resource(self, resource_name: str, mcp_client: Client):
        """
        Helper method to load a resource from the MCP server.
        """
        async with mcp_client:
            result = await mcp_client.read_resource(resource_name)
            await mcp_client.close()
        return result

    async def get_prompt(self, prompt_name: str, mcp_client: Client, **kwargs):
        """
        Helper method to get a prompt from the MCP server.
        """
        async with mcp_client:
            result = await mcp_client.get_prompt(prompt_name, arguments=kwargs)
            await mcp_client.close()
        return result

    def test_resource_logo(self, mcp_client: Client):
        """
        Test to read the logo resource from the MCP server.
        """
        resource_uri = "data://logo"
        resource_name = "resource_logo"

        results = asyncio.run(self.read_resource(resource_uri, mcp_client))
        assert len(results) == 1, (
            f"Expected one result for the {resource_name} resource."
        )
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

    def test_resource_logo_svg(self, mcp_client: Client):
        """
        Test to read the logo_svg resource from the MCP server.
        """
        resource_uri = "data://logo_svg"
        resource_name = "resource_logo_svg"
        results = asyncio.run(self.read_resource(resource_uri, mcp_client))
        assert len(results) == 1, (
            f"Expected one result for the {resource_name} resource."
        )
        result = results[0]
        assert hasattr(result, "text"), (
            "Expected the result to have a 'text' attribute containing the response."
        )
        svg_pattern = (
            r"(?:<\?xml\b[^>]*>[^<]*)?(?:<!--.*?-->[^<]*)*(?:<svg|<!DOCTYPE svg)\b"
        )
        svg_regexp = re.compile(svg_pattern, re.DOTALL | re.IGNORECASE)
        assert svg_regexp.match(result.text), (
            "Expected the response to be a valid SVG document."
        )

    def test_resource_modulo10(self, mcp_client: Client):
        """
        Test to read the modulo10 resource from the MCP server.
        """
        resource_uri = "data://modulo10/{number}"
        resource_name = "resource_modulo10"
        # Try the odd one first using 127. Expect a ❼ (U+277C)
        odd_number = 127
        results_odd = asyncio.run(
            self.read_resource(
                resource_uri.format(number=odd_number),
                mcp_client,
            )
        )
        assert len(results_odd) == 1, (
            f"Expected one result for the {resource_name} resource."
        )
        result_odd = results_odd[0]
        assert hasattr(result_odd, "text"), (
            "Expected the result to have a 'text' attribute containing the response."
        )
        assert result_odd.text == "❼", (
            f"Expected the response to be the Unicode character ❼ as modulo 10 of {odd_number}."
        )

        # Try the even one first using 64. Expect a ④ (U+2463)
        even_number = 64
        results_even = asyncio.run(
            self.read_resource(
                resource_uri.format(number=even_number),
                mcp_client,
            )
        )
        assert len(results_even) == 1, (
            f"Expected one result for the {resource_name} resource."
        )
        result_even = results_even[0]
        assert hasattr(result_even, "text"), (
            "Expected the result to have a 'text' attribute containing the response."
        )
        assert result_even.text == "④", (
            f"Expected the response to be the Unicode character ④ as a modulo 10 of {even_number}."
        )

    def test_prompt_code_prompt(self, mcp_client: Client):
        """
        Test to call the code_prompt on the MCP server.
        """
        prompt_name = "code_prompt"
        response = asyncio.run(
            self.get_prompt(
                prompt_name,
                mcp_client,
                task="Generate the number sequence for the Collatz conjecture starting with a given number.",
            )
        )
        assert hasattr(response, "messages"), (
            "Expected the response to have a 'messages' attribute containing the prompt."
        )
        assert len(response.messages) == 1, "Expected one message in the response."
        result = response.messages[0]
        assert hasattr(result, "content"), (
            "Expected the message to have a 'content' attribute."
        )
        assert isinstance(result.content, TextContent), (
            "Expected the content to be of type TextContent."
        )

        assert hasattr(result.content, "text"), (
            "Expected the content to have a 'text' attribute containing the response text."
        )
        pattern = r"""Write a Python code snippet to perform the following task:\n\s+\[TASK\]\n\s+(.+)\n\s+\[/TASK\]\n\s+The code should be well-commented and follow best practices.\n\s+Make sure to include necessary imports and handle any exceptions that may arise."""
        match = re.match(pattern, result.content.text)
        assert match, (
            f"Expected the response to be a code snippet in a specific format. The obtained response does not match the expected format: {result.content.text}"
        )

    def test_tool_greet(self, mcp_client: Client):
        """
        Test to call the greet tool on the MCP server.
        """
        tool_name = "greet"
        name_to_be_greeted = "Sherlock Holmes"
        results = asyncio.run(
            self.call_tool(
                tool_name,
                mcp_client,
                name=name_to_be_greeted,
            )
        )
        assert hasattr(results, "content"), (
            "Expected the results to have a 'content' attribute."
        )
        assert len(results.content) == 1, (
            f"Expected one result for the {tool_name} tool."
        )
        result = results.content[0]
        assert hasattr(result, "text"), (
            "Expected the result to have a 'text' attribute containing the response."
        )
        pattern = r"Hello(,?) (.+)! Welcome to the pymcp-template (\d+\.\d+\.\d+(\.?[a-zA-Z]+\.?\d+)?) server! The current date time in UTC is ([\d\-T:.+]+)."
        match = re.match(pattern, result.text)
        assert match, (
            f"Expected the response to be a greeting in a specific format. The obtained response does not match the expected format: {result.text}"
        )
        name = match.group(2)  # Extracted name
        assert name == name_to_be_greeted if name_to_be_greeted else "World", (
            f"Expected the name in the greeting to be '{name_to_be_greeted}', but got '{name}'."
        )
        version = match.group(3)  # Extracted version
        assert version == package_version, (
            f"Expected the version in the greeting to be '{package_version}', but got '{version}'."
        )
        datetime_str = match.group(5)  # Extracted date-time
        extracted_datetime = datetime.strptime(datetime_str, "%Y-%m-%dT%H:%M:%S.%f%z")
        assert isinstance(extracted_datetime, datetime), (
            f"Expected the date-time to be a valid datetime object in the format %Y-%m-%dT%H:%M:%S.%f%z but obtained {datetime_str}"
        )

        # Try by explicitly passing name=None
        results = asyncio.run(
            self.call_tool(
                tool_name,
                mcp_client,
                name=None,
            )
        )
        assert hasattr(results, "content"), (
            "Expected the results to have a 'content' attribute."
        )
        assert len(results.content) == 1, (
            f"Expected one result for the {tool_name} tool."
        )
        result = results.content[0]
        assert hasattr(result, "text"), (
            "Expected the result to have a 'text' attribute containing the response."
        )
        match = re.match(pattern, result.text)
        assert match, (
            f"Expected the response to be a greeting in a specific format. The obtained response does not match the expected format: {result.text}"
        )
        name = match.group(2)  # Extracted name
        assert name == "World", (
            f"Expected the name in the greeting to be 'World', but got '{name}'."
        )
        version = match.group(3)  # Extracted version
        assert version == package_version, (
            f"Expected the version in the greeting to be '{package_version}', but got '{version}'."
        )
        datetime_str = match.group(5)  # Extracted date-time
        extracted_datetime = datetime.strptime(datetime_str, "%Y-%m-%dT%H:%M:%S.%f%z")
        assert isinstance(extracted_datetime, datetime), (
            f"Expected the date-time to be a valid datetime object in the format %Y-%m-%dT%H:%M:%S.%f%z but obtained {datetime_str}"
        )

    def test_tool_generate_password(self, mcp_client: Client):
        """
        Test to call the generate_password tool on the MCP server.
        """
        tool_name = "generate_password"
        password_length = 8
        results = asyncio.run(
            self.call_tool(
                tool_name,
                mcp_client,
                length=password_length,
                use_special_chars=True,
            )
        )
        assert hasattr(results, "content"), (
            "Expected the results to have a 'content' attribute."
        )
        assert len(results.content) == 1, (
            f"Expected one result for the {tool_name} tool."
        )
        result = results.content[0]
        assert hasattr(result, "text"), (
            "Expected the result to have a 'text' attribute containing the response."
        )
        contains_alphanum = any(char.isalnum() for char in result.text)
        contains_punctuation = any(char in string.punctuation for char in result.text)
        assert contains_alphanum and contains_punctuation, (
            "Expected the response to be alphanumeric with special characters."
        )
        assert len(result.text) == password_length, (
            f"Expected a random password of length {password_length}. Obtained a password of length {len(result.text)}."
        )

    def test_tool_text_web_search(self, mcp_client: Client):
        """
        Test to call the text_web_search tool on the MCP server.
        """
        tool_name = "text_web_search"
        results = asyncio.run(
            self.call_tool(
                tool_name,
                mcp_client,
                query="Python programming language",
                max_results=1,
            )
        )
        assert hasattr(results, "content"), (
            "Expected the results to have a 'content' attribute."
        )
        assert len(results.content) == 1, (
            f"Expected one result for the {tool_name} tool."
        )
        result = results.content[0]
        assert hasattr(result, "text"), (
            "Expected the result to have a 'text' attribute containing the response."
        )
        result_json = json.loads(result.text)
        assert isinstance(result_json, list), (
            "Expected the response JSON object to be a list."
        )
        assert len(result_json) == 1, (
            "Expected the response JSON object to contain exactly one search result."
        )
        assert result_json[0]["href"].startswith("http"), (
            "Expected the response JSON object with a 'href' key pointing to a HTTP(S) URL."
        )

    def test_tool_permutations(self, mcp_client: Client):
        """
        Test to call the permutations tool on the MCP server.
        """
        tool_name = "permutations"
        results = asyncio.run(self.call_tool(tool_name, mcp_client, n=16, k=8))
        assert hasattr(results, "content"), (
            "Expected the results to have a 'content' attribute."
        )
        assert len(results.content) == 1, (
            f"Expected one result for the {tool_name} tool."
        )
        result = results.content[0]
        assert hasattr(result, "text"), (
            "Expected the result to have a 'text' attribute containing the response."
        )
        assert result.text.isdigit(), "Expected the response to be a number."
        assert int(result.text) == 518918400, (
            f"Expected 518918400 permutations for n=16, k=8. Obtained {result.text}."
        )

        results = asyncio.run(self.call_tool(tool_name, mcp_client, n=16))
        assert hasattr(results, "content"), (
            "Expected the results to have a 'content' attribute."
        )
        assert len(results.content) == 1, (
            f"Expected one result for the {tool_name} tool."
        )
        result = results.content[0]
        assert hasattr(result, "text"), (
            "Expected the result to have a 'text' attribute containing the response."
        )
        assert result.text.isdigit(), "Expected the response to be a number."
        assert int(result.text) == 20922789888000, (
            f"Expected 20922789888000 permutations for n=16 since k was not provided. Obtained {result.text}."
        )
        try:
            results = asyncio.run(self.call_tool(tool_name, mcp_client, n=16, k=32))
        except ToolError as e:
            assert (
                "Error calling tool 'permutations': k (32) cannot be greater than n (16)"
                in str(e)
            )

    def test_tool_pirate_summary(self, mcp_client: Client):
        """
        Test to call the pirate_summary tool on the MCP server.
        """
        tool_name = "pirate_summary"
        results = asyncio.run(
            self.call_tool(
                tool_name,
                mcp_client,
                text="This is a sample text to request the summary of.",
            )
        )
        assert hasattr(results, "content"), (
            "Expected the results to have a 'content' attribute."
        )
        assert len(results.content) == 1, (
            f"Expected one result for the {tool_name} tool."
        )
        result = results.content[0]
        assert hasattr(result, "text"), (
            "Expected the result to have a 'text' attribute containing the response."
        )
        # Since we do not have a language model at our disposal, we expect a UUID.
        uuid_pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$"
        match = re.match(uuid_pattern, result.text)
        assert match, (
            f"Expected the response to be a UUID. The obtained response does not match the expected format: {result.text}"
        )

    def test_tool_vonmises_random(self, mcp_client: Client):
        """
        Test to call the vonmises_random tool on the MCP server.
        """
        tool_name = "vonmises_random"
        results = asyncio.run(
            self.call_tool(
                tool_name,
                mcp_client,
                mu=math.pi * random.uniform(0, 2),  # Random mu between 0 and 2*pi
            )
        )
        assert hasattr(results, "content"), (
            "Expected the results to have a 'content' attribute."
        )
        assert len(results.content) == 1, (
            f"Expected one result for the {tool_name} tool."
        )
        result = results.content[0]
        assert hasattr(result, "text"), (
            "Expected the result to have a 'text' attribute containing the response."
        )
