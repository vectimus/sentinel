# Contributing to Sentinel

Contributions are welcome across the pipeline.

## Areas of contribution

- **Threat sources** — Add new sources for the Threat Hunter to scan
- **Sandbox replay** — Improve the policy evaluation sandbox
- **Advisory templates** — Improve output quality for the Threat Analyst
- **Pipeline tooling** — Orchestration, scheduling, error handling
- **Tests and evals** — Expand the evaluation suite

## Getting started

```bash
git clone https://github.com/vectimus/sentinel.git
cd sentinel
pip install -r pipeline/requirements.txt
```

See `HANDOVER.md` for the full environment variable reference.

## Development workflow

1. **Fork and clone** the repository
2. **Create a branch** from `main`
3. **Test your changes** against the evaluation suite in `evals/`
4. **Open a PR** with a clear description of what changed and why

## Pipeline structure

```
agents/              # Agent specifications and prompts
pipeline/            # Orchestrator, tools, schemas, config
_sandbox/            # Policy evaluation sandbox
findings/            # Threat Hunter output (JSON)
guardrails/          # Vectimus policies governing Sentinel itself
evals/               # Pipeline evaluation suite
tests/               # Test suite
```

## Security vulnerabilities

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions will be licensed under Apache 2.0.
