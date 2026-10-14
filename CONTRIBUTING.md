# Contributing to Gadbad

Thanks for helping. The most valuable contributions are reports of scam APKs Gadbad misses (false negatives) and of real apps it wrongly flags (false positives), plus translations of the explanations into more Indian languages.

## Ground rules

- **No malware in the repo.** Don't commit, attach or upload real APK samples anywhere in this project. Share the SHA-256 and describe the behaviour. Tests build synthetic APKs with `tests/builders.py`.
- **Static only.** Gadbad must never execute app code or contact the servers it finds.
- **No dependencies** in the runtime package unless there's a strong reason. It needs to be easy to install for investigators on locked-down machines.

## Development setup

```bash
git clone https://github.com/kirtanbhatt10/gadbad.git
cd gadbad
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Before opening a pull request, run the same checks as CI:

```bash
ruff check .
ruff format --check .
mypy
pytest --cov --cov-fail-under=85
```

## Adding a detection rule

1. Add the rule to `gadbad/rules.py` with a severity, a weight, a title and explanations in English and Hindi. Explanations are for the person who received the APK, so keep them short and free of jargon.
2. Trigger it in `_apply_rules` in `gadbad/analyzer.py`.
3. Add a test that builds a synthetic APK which triggers it, and one that shows a similar benign app doesn't.
4. Note the change in `CHANGELOG.md` under **Unreleased**.

## Adding a language

Explanations live in `gadbad/rules.py` (`Rule`) and `ADVICE`. Add a field for the new language code, add it to `--lang` in `gadbad/cli.py`, and ask a native speaker to review the wording.

## Releasing (maintainers)

1. Update `__version__` in `gadbad/__init__.py` and move the **Unreleased** notes in `CHANGELOG.md` under the new version.
2. Merge to `main` and wait for CI to pass.
3. Tag and push: `git tag v1.2.3 && git push origin v1.2.3`. The release workflow checks the tag matches the version, publishes to PyPI and creates the GitHub release.
