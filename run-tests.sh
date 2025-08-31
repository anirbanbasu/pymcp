#!/bin/bash
# Run the tests and report coverage with missing values
uv run --group test coverage run -m pytest -vvv --log-cli-level=INFO tests/
uv run coverage report -m
