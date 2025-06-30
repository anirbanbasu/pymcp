import asyncio
from datetime import datetime
import math
import random
import re
import string
import uuid
from fastmcp import Client
import pytest
from fastmcp.prompts.prompt import TextContent
from fastmcp.client.sampling import SamplingMessage, SamplingParams, RequestContext
from fastmcp.client.elicitation import ElicitResult


from pymcp.server import (
    app as target_mcp_server,
    Base64EncodedBinaryDataResponse,
    code_prompt,
    generate_password,
    greet,
    package_metadata,
    permutations,
    pirate_summary,
    resource_logo,
    resource_logo_svg,
    resource_unicode_modulo10,
    vonmises_random,
)


async def random_llm_sampling_handler(
    messages: list[SamplingMessage], params: SamplingParams, context: RequestContext
) -> str:
    # Since we do not have a language model at our disposal, ignore all the paramers and generate a unique ID.
    return str(uuid.uuid4())


async def random_elicitation_handler(
    message: str, response_type: type, params, context
) -> ElicitResult:
    # Since we are in the midst of a test setup, ignore all the paramers and generate a response.
    return response_type(value=random.uniform(0.0, 1.0))


@pytest.fixture(scope="module", autouse=True)
def mcp_client():
    """
    Fixture to create a client for the MCP server.
    """
    mcp_client = Client(
        transport=target_mcp_server,
        timeout=60,
        sampling_handler=random_llm_sampling_handler,
        elicitation_handler=random_elicitation_handler,
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
        results = asyncio.run(self.read_resource(resource_logo.uri, mcp_client))
        assert len(results) == 1, (
            f"Expected one result for the {resource_logo.name} resource."
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
        results = asyncio.run(self.read_resource(resource_logo_svg.uri, mcp_client))
        assert len(results) == 1, (
            f"Expected one result for the {resource_logo_svg.name} resource."
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
        # Try the odd one first using 127. Expect a ❼ (U+277C)
        odd_number = 127
        results_odd = asyncio.run(
            self.read_resource(
                resource_unicode_modulo10.uri_template.format(number=odd_number),
                mcp_client,
            )
        )
        assert len(results_odd) == 1, (
            f"Expected one result for the {resource_unicode_modulo10.name} resource."
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
                resource_unicode_modulo10.uri_template.format(number=even_number),
                mcp_client,
            )
        )
        assert len(results_even) == 1, (
            f"Expected one result for the {resource_unicode_modulo10.name} resource."
        )
        result_even = results_even[0]
        assert hasattr(result_even, "text"), (
            "Expected the result to have a 'text' attribute containing the response."
        )
        assert result_even.text == "④", (
            f"Expected the response to be the Unicode character ④ as a modulo 10 of {even_number}."
        )

    def test_code_prompt(self, mcp_client: Client):
        f"""
        Test to call the {code_prompt.name} on the MCP server.
        """
        response = asyncio.run(
            self.get_prompt(
                code_prompt.name,
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
        f"""
        Test to call the {greet.name} tool on the MCP server.
        """
        name_to_be_greeted = "Sherlock Holmes"
        results = asyncio.run(
            self.call_tool(
                greet.name,
                mcp_client,
                name=name_to_be_greeted,
            )
        )
        assert hasattr(results, "content"), (
            "Expected the results to have a 'content' attribute."
        )
        assert len(results.content) == 1, (
            f"Expected one result for the {greet.name} tool."
        )
        result = results.content[0]
        assert hasattr(result, "text"), (
            "Expected the result to have a 'text' attribute containing the response."
        )
        pattern = r"Hello(,)? (.+)! Welcome to the pymcp-template (\d+\.\d+\.\d+) server! The current date time in UTC is ([\d\-T:.+]+)."
        match = re.match(pattern, result.text)
        assert match, (
            f"Expected the response to be a greeting in a specific format. The obtained response does not match the expected format: {result.text}"
        )
        name = match.group(2)  # Extracted name
        assert name == name_to_be_greeted if name_to_be_greeted else "World", (
            f"Expected the name in the greeting to be '{name_to_be_greeted}', but got '{name}'."
        )
        version = match.group(3)  # Extracted version
        assert version == package_metadata["Version"], (
            f"Expected the version in the greeting to be '{package_metadata['Version']}', but got '{version}'."
        )
        datetime_str = match.group(4)  # Extracted date-time
        extracted_datetime = datetime.strptime(datetime_str, "%Y-%m-%dT%H:%M:%S.%f%z")
        assert isinstance(extracted_datetime, datetime), (
            f"Expected the date-time to be a valid datetime object in the format %Y-%m-%dT%H:%M:%S.%f%z but obtained {datetime_str}"
        )

        # Try without specifying the name
        name_to_be_greeted = None
        results = asyncio.run(
            self.call_tool(
                greet.name,
                mcp_client,
                name=name_to_be_greeted,
            )
        )
        assert hasattr(results, "content"), (
            "Expected the results to have a 'content' attribute."
        )
        assert len(results.content) == 1, (
            f"Expected one result for the {greet.name} tool."
        )
        result = results.content[0]
        assert hasattr(result, "text"), (
            "Expected the result to have a 'text' attribute containing the response."
        )
        pattern = r"Hello(,)? (.+)! Welcome to the pymcp-template (\d+\.\d+\.\d+) server! The current date time in UTC is ([\d\-T:.+]+)."
        match = re.match(pattern, result.text)
        assert match, (
            f"Expected the response to be a greeting in a specific format. The obtained response does not match the expected format: {result.text}"
        )
        name = match.group(2)  # Extracted name
        assert name == name_to_be_greeted if name_to_be_greeted else "World", (
            f"Expected the name in the greeting to be '{name_to_be_greeted}', but got '{name}'."
        )
        version = match.group(3)  # Extracted version
        assert version == package_metadata["Version"], (
            f"Expected the version in the greeting to be '{package_metadata['Version']}', but got '{version}'."
        )
        datetime_str = match.group(4)  # Extracted date-time
        extracted_datetime = datetime.strptime(datetime_str, "%Y-%m-%dT%H:%M:%S.%f%z")
        assert isinstance(extracted_datetime, datetime), (
            f"Expected the date-time to be a valid datetime object in the format %Y-%m-%dT%H:%M:%S.%f%z but obtained {datetime_str}"
        )

    def test_tool_generate_password(self, mcp_client: Client):
        f"""
        Test to call the {generate_password.name} tool on the MCP server.
        """
        password_length = 8
        results = asyncio.run(
            self.call_tool(
                generate_password.name,
                mcp_client,
                length=password_length,
                use_special_chars=True,
            )
        )
        assert hasattr(results, "content"), (
            "Expected the results to have a 'content' attribute."
        )
        assert len(results.content) == 1, (
            f"Expected one result for the {generate_password.name} tool."
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

    def test_tool_permutations(self, mcp_client: Client):
        f"""
        Test to call the {permutations.name} tool on the MCP server.
        """
        results = asyncio.run(self.call_tool(permutations.name, mcp_client, n=16, k=8))
        assert hasattr(results, "content"), (
            "Expected the results to have a 'content' attribute."
        )
        assert len(results.content) == 1, (
            f"Expected one result for the {permutations.name} tool."
        )
        result = results.content[0]
        assert hasattr(result, "text"), (
            "Expected the result to have a 'text' attribute containing the response."
        )
        assert result.text.isdigit(), "Expected the response to be a number."
        assert int(result.text) == 518918400, (
            f"Expected 518918400 permutations for n=16, k=8. Obtained {result.text}."
        )

    def test_tool_pirate_summary(self, mcp_client: Client):
        f"""
        Test to call the {pirate_summary.name} tool on the MCP server.
        """
        results = asyncio.run(
            self.call_tool(
                pirate_summary.name,
                mcp_client,
                text="This is a sample text to request the summary of.",
            )
        )
        assert hasattr(results, "content"), (
            "Expected the results to have a 'content' attribute."
        )
        assert len(results.content) == 1, (
            f"Expected one result for the {pirate_summary.name} tool."
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
        f"""
        Test to call the {vonmises_random.name} tool on the MCP server.
        """
        results = asyncio.run(
            self.call_tool(
                vonmises_random.name,
                mcp_client,
                mu=math.pi * random.uniform(0, 2),  # Random mu between 0 and 2*pi
            )
        )
        assert hasattr(results, "content"), (
            "Expected the results to have a 'content' attribute."
        )
        assert len(results.content) == 1, (
            f"Expected one result for the {vonmises_random.name} tool."
        )
        result = results.content[0]
        assert hasattr(result, "text"), (
            "Expected the result to have a 'text' attribute containing the response."
        )
