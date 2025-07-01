#!/bin/bash
# Upgrade the dependencies including those from Git sources
uv lock -U
# Export the requirements to a requirements.txt file
uv export --no-hashes --format requirements-txt > requirements.txt
# Run the tests and report coverage with missing values
uv run --group test coverage run -m pytest tests/
uv run coverage report -m
