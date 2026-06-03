---
name: omrelease
description: Prep an OpenMaskit release — bumps the version across pyproject, tests, publish workflow, CHANGELOG, and uv.lock; verifies the test suite; commits on a prep branch; then reminds the user of the manual follow-ups (ASCII banner, Rust backend, smoke-test command).
---

# omrelease

Prepare OpenMaskit for a new release.

## Inputs

The user passes the new version as the skill argument (e.g. `/omrelease 0.4.0`).

- `<new>` — the version they passed (e.g. `0.4.0`). Must be `MAJOR.MINOR.PATCH`.
- `<prev>` — the version currently in `pyproject.toml` (read it; don't assume).

If the user didn't pass a version, ask once: *"What version are we releasing?"*. Don't assume.

## Steps

### 0. Branch hygiene

You should be on `main` with a clean tree. Verify with `git status` and `git branch --show-current`. If main is dirty or you're elsewhere, **stop and ask** before continuing — releases off a dirty tree are how surprises ship.

Create the prep branch:

```bash
git checkout -b prep-<new>
```

### 1. CHANGELOG entries

Read the commits between tags so the CHANGELOG reflects what actually shipped, not vibes:

```bash
git log v<prev>..main --oneline
```

For each commit, decide whether it's `Added`, `Changed`, `Fixed`, or `Removed` (Keep-a-Changelog conventions). Then in `CHANGELOG.md`:

- Insert a new `## [<new>] - YYYY-MM-DD` section between `## [Unreleased]` and the previous release. Use today's date in UTC.
- Append a comparison link at the bottom: `[<new>]: https://github.com/MaskitMCP/openmaskit/compare/v<prev>...v<new>`
- Update the existing `[Unreleased]: ...compare/v<prev>...HEAD` line to point at `v<new>...HEAD`.

Keep entries fact-focused: what changed, briefly why. No marketing language. Group small related changes into one bullet if helpful.

### 2. Version bumps (parallel Edits)

These are the files that carry the literal version string. Send the Edits in one parallel batch.

| File | What to change |
|---|---|
| `pyproject.toml` | `version = "<prev>"` → `version = "<new>"` (top of `[project]`) |
| `tests/test_backend_client.py` | `replace_all` on `openmaskit_version="<prev>"` |
| `tests/test_cli.py` | the single line `assert __version__ == "<prev>" or __version__ == "unknown"` |
| `.github/workflows/publish.yml` | two `replace_all` passes — first `v<prev>`, then `openmaskit==<prev>` |

### 3. Verify pyproject saved (lesson learned)

In one past run, the pyproject.toml Edit reported success but the file remained unchanged when re-grepped later. After step 2, re-grep:

```bash
grep '^version' pyproject.toml
```

If it still shows `<prev>`, Edit it again before continuing.

### 4. uv.lock — the load-bearing single-line edit

`uv sync`, `uv lock`, and `uv lock --upgrade-package openmaskit` all refuse to update the workspace entry's `version` field when only pyproject changes. Deleting `uv.lock` and regenerating would update it — **but at the cost of bumping every transitive dependency** (certifi, click, ~50 others), which is *not* what a version-bump-only release wants.

**The right move:** edit the lock entry directly. The block looks like:

```toml
[[package]]
name = "openmaskit"
version = "<prev>"
source = { editable = "." }
```

Bump that one line to `<new>` using Edit. Then re-sync the env against the (now-correct) frozen lock:

```bash
uv sync --frozen
uv run python -c "from openmaskit import __version__; print(__version__)"
```

The second command **must** print `<new>`. If it still shows `<prev>`, the editable install didn't pick up — re-check that pyproject.toml is actually at `<new>` (step 3).

### 5. README + CLAUDE.md drift check

Scan both for:

- Literal version mentions (rare but possible — search for `<prev>`).
- Documentation drift related to features in this release (read `CHANGELOG.md` `### Added` / `### Changed` entries and verify the docs still describe reality).

Don't add docs for every internal change — only update if a user-facing or architecture-shaping change is misrepresented. If unsure, ask the user before adding a paragraph.

### 6. Tests

```bash
uv run pytest tests/ -q
```

All must pass. If `test_cli.py` or `test_backend_client.py` fail with version mismatches, step 2 missed something. If unrelated tests fail, **stop** and surface them — the prep is not the place to fix them.

### 7. Commit

```bash
git add -u
git commit -m "release: <new>"
```

Don't push automatically — the user pushes and opens the PR themselves.

### 8. Final reminders

Print this checklist to the user verbatim, with `<new>` substituted:

```
Pre-tag checklist:

1. **ASCII banner.** Update the version string in `src/openmaskit/__main__.py` (the startup banner). Not auto-edited because styling is your call.
2. **Rust backend.** Bump the latest-release version pinned in the Rust backend (catalog API / version gate) to <new>.
3. **GitHub Environment tag protection.** If this opens a new MINOR series, add `v<MAJOR>.<MINOR>.*` to the pypi environment's deployment-tag protection rule in the GitHub Settings UI. Tag will not deploy without it.

When the tag fires and TestPyPI publish succeeds, smoke-test with:

uvx --index https://test.pypi.org/simple/ \
    --extra-index-url https://pypi.org/simple/ \
    --index-strategy unsafe-best-match \
    --from openmaskit==<new> \
    --refresh \
    openmaskit
```

Two non-obvious things in that command worth carrying forward:

- `--index-strategy unsafe-best-match` is **required** because TestPyPI carries an ancient `aiosqlite==0.2.1` that doesn't satisfy our `>=0.20.0` constraint. uv's default "first index wins" strategy picks the TestPyPI version and never falls through to PyPI without this flag.
- `--refresh` is needed because uvx caches resolved versions; without it you may smoke-test a stale build that happens to have the same name+version.

## What this skill explicitly does NOT do

- Push branches or open PRs. The user does that.
- Tag and publish. That's the user's manual action against the prep PR after it lands on main.
- Auto-edit the ASCII banner. The user prefers to keep styling in their hands.
- Touch any other repos.
