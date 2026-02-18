# Contributing to Donjon Platform

Thank you for your interest in contributing to the Donjon Platform.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/donjon-platform.git`
3. Create a feature branch: `git checkout -b feature/your-feature`
4. Run setup: `bash bin/setup.sh` (Linux/macOS) or `bin\setup-windows.bat` (Windows)

## Development Environment

- Python 3.9+
- Virtual environment managed by `bin/setup.sh`
- Dependencies listed in `requirements.txt` (pinned versions)

## Project Structure

```
bin/            # Launcher scripts and CLI entry points
lib/            # Core libraries (evidence, AI, risk, licensing, etc.)
scanners/       # Security scanner modules (network, web, cloud, etc.)
utilities/      # Orchestrator, reporter, dashboard, delta reports
web/            # REST API server
config/         # Configuration files (YAML)
docs/           # Documentation and knowledge base
data/           # Runtime data (evidence DB, reports, logs)
```

## Code Style

- Follow existing patterns in the codebase
- Use type hints where practical
- All scanner modules extend `BaseScanner` from `scanners/base.py`
- SQL queries must use parameterized queries or validated column whitelists
- External URLs must be scheme-validated before use with `urllib`

## Security

- Never commit credentials, API keys, or secrets
- Run `bandit -r lib/ scanners/ web/ -ll` before submitting
- All `shell=True` subprocess calls require justification and `# nosec B602` annotation
- SSH `AutoAddPolicy` usage requires `# nosec B507` annotation with explanation

## Testing

```bash
# Full test suite
python run_full_test.py

# Specific phases
python run_full_test.py --phase 1 2

# With reports
python run_full_test.py --json --junit
```

## Submitting Changes

1. Ensure all tests pass
2. Run bandit with no HIGH findings
3. Commit with clear, descriptive messages
4. Push to your fork and open a Pull Request
5. Describe what changed and why in the PR description

## Reporting Issues

Use GitHub Issues with the provided templates. Include:
- Platform (Windows/Linux/macOS) and Python version
- Steps to reproduce
- Expected vs actual behavior
- Relevant log output from `data/logs/`

## License

By contributing, you agree that your contributions will be licensed under the BSL 1.1 license (see LICENSE).
