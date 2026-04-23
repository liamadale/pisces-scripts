# Contributing

## Branching model

This project uses a three-tier branching model:

- **`main`** — stable release branch. Direct pushes are blocked; all changes arrive via PR from `dev`.
- **`dev`** — integration branch. Feature branches are merged here first. CI runs as advisory.
- **`feat/`, `fix/`, `chore/` branches** — short-lived branches for individual tasks, branched off `dev` and merged back via PR.

### Day-to-day workflow

```bash
# Start from up-to-date dev
git checkout dev && git pull origin dev

# Create a branch for your task
git checkout -b feat/my-feature

# Work, commit, push
git add <files>
git commit -m "feat: description of change"
git push origin feat/my-feature

# Open a PR into dev
gh pr create --base dev --title "feat: description" --body "..."
```

Once reviewed and merged into `dev`, changes are promoted to `main` via a separate PR when `dev` is in a stable state.

---

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/). Use one of these types:

| Type | When to use |
|---|---|
| `feat` | New feature or capability |
| `fix` | Bug fix |
| `chore` | Maintenance, dependency updates, config changes |
| `docs` | Documentation only |
| `test` | Adding or updating tests |
| `refactor` | Code restructuring with no behaviour change |
| `style` | Formatting changes only |
| `ci` | CI/CD pipeline changes |

For changes tied to a user report or GitHub issue, add trailers:

```bash
git commit -m "fix: description" \
  --trailer "Reported-by:Name" \
  --trailer "Github-Issue:#42"
```

Keep commits focused — one logical change per commit makes review and revert easier.

---

## Pull requests

- **Target `dev`**, not `main`, for all feature and fix PRs
- Keep PRs small and focused — a PR that does one thing is easier to review than one that does five
- Write a description that explains *why* the change is needed, not just what changed
- Add `liamadale` as a reviewer on all PRs
- Do not merge your own PR without review unless it is a trivial docs or config fix

---

## CI and code quality

Before opening a PR, make sure these pass locally:

```bash
uv run pytest tests/ -v                                      # all tests pass
uv run ruff check src/ apps/ mcp/ tests/ *.py               # no lint errors
uv run ruff format src/ apps/ mcp/ tests/ *.py              # code formatted
uv run pre-commit run --all-files                            # all hooks pass
```

CI runs automatically on PR open and push. Checks that block merging to `main`:

- `pytest` — all tests must pass
- `ruff check` — no lint errors

Format, pip-audit, and bandit run as advisory. Fix them if you can, but they will not block merge to `dev`.

---

## Development setup

1. Install [uv](https://github.com/astral-sh/uv)
2. `uv sync --extra mcp --group dev` (or `uv sync --extra all --group dev` for everything)
3. `uv run pre-commit install`
4. `cp .env.example .env` and fill in credentials

---

## Using AI tooling

AI coding assistants are encouraged — this project was built with them. A few expectations:

- **Review all AI-generated code before committing.** You are responsible for what goes into the PR, regardless of how it was written.
- **Do not commit AI tooling config files** (`CLAUDE.md`, `AGENT.md`, `.kiro/`, etc.). These are gitignored intentionally — they may contain personal paths or sensitive context.
- **Test AI-generated changes.** Run the relevant tests and check the output manually. AI tools can produce plausible-looking code that doesn't actually work.
- **Keep commit messages accurate.** Describe what the code does, not what the AI was asked to do.

---

## Security

- Never commit credentials, API keys, or tokens
- Use environment variables for all secrets (see `.env.example`)
- See [SECURITY.md](SECURITY.md) for vulnerability reporting
