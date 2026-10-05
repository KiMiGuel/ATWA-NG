# Contributing

## Gates

All three must pass before opening a PR.

```bash
ruff check src/
mypy src/
pytest
```

## Commits

[Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <summary>
```

**Types** — `feat`, `fix`, `refactor`, `test`, `docs`, `chore`

**Scopes** — `scan`, `attacks`, `eapol`, `frames`, `crack`, `gui`, `radio`, `capture`

```
feat(eapol): passive handshake capture
fix(frames): correct key_data_len for 24-byte MIC
refactor(gui): extract TargetsMixin
```

Summary in imperative mood, no trailing period, 72 characters max.

## Branches

```
feat/pixie-dust-prng
fix/mic-offset-24
```

Lowercase, hyphen-separated, prefixed with the type.

## Pull requests

- One logical change per PR
- Title matches the commit subject
- Body states what changed and why; omit if self-evident
- Reference the issue with `Closes #123`
- Note hardware-dependent verification explicitly — GUI and radio paths are not covered by `pytest`

## Code

- `src/` layout; new modules join the existing package tree
- Core must not import `gui/` or `cli_commands/`
- No new runtime dependencies without discussion in the PR

## Do not commit

`*.pcap`, `*.cap`, `*.22000`, `creds.json`, `graphify-out/`, any file containing captured credentials.