# Contributing

## Development Setup

1. Install [uv](https://github.com/astral-sh/uv)
2. `uv sync --extra mcp --group dev` (or `uv sync --extra all --group dev` for everything)
3. `uv run pre-commit install`
4. `cp .env.example .env` and fill in credentials

## Before Submitting a PR

- `uv run pytest tests/ -v` — all tests pass
- `uv run ruff check src/ apps/ mcp/ tests/ *.py` — no lint errors
- `uv run ruff format src/ apps/ mcp/ tests/ *.py` — code formatted
- `uv run pre-commit run --all-files` — all hooks pass

## Security

- Never commit credentials, API keys, or tokens
- Use environment variables for all secrets
- See [SECURITY.md](SECURITY.md) for vulnerability reporting
