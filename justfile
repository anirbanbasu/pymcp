# Install minimal project dependencies in a virtual environment
install:
    @echo "Installing project dependencies in a virtual environment..."
    @uv sync --no-dev
    @echo "Project dependencies installed."

# Install all project dependencies in a virtual environment
install-all:
    @echo "Installing all project dependencies in a virtual environment..."
    @uv sync --all-groups
    @echo "All project dependencies installed."

# Install pre-commit hooks using 'prek'
install-pre-commit-hooks:
    @echo "Installing pre-commit hooks using prek..."
    @prek install
    @echo "Pre-commit hooks installed."

# Update pre-commit hooks using 'prek'
pre-commit-update:
    @echo "Updating pre-commit hooks using prek..."
    @prek auto-update
    @echo "Pre-commit hooks updated."

# Upgrade project dependencies using 'uv'
upgrade-dependencies:
    @echo "Upgrading project dependencies..."
    @uv lock -U
    @echo "Dependencies upgraded."

# Bump the patch version of the project using 'uv'
bump-patch:
    @echo "Updating current project version: $(uv version --short)"
    @uv version --bump patch
    @echo "Updated project to: $(uv version --short)"

# Format the code
format:
    @echo "Formatting code..."
    @uv run ruff format
    @uv run ruff check --fix --fix-only
    @echo "Code formatted."

# Run the type checker
type-check:
    @echo "Running type checker..."
    @uv run ty check
    @echo "Type checking complete."

export MCP_SERVER_TRANSPORT := "streamable-http"
# Run tests with coverage reporting
test-coverage:
    @echo "Running tests with coverage..."
    @uv run --group test coverage run -m pytest --capture=tee-sys -vvv --log-cli-level=INFO tests/
    @uv run coverage report -m
    @echo "Test coverage complete."
