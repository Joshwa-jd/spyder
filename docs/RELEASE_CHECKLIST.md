# Release Checklist

The process for cutting a SPYDER release. Most of it is enforced by CI — the
manual items are the ones a machine cannot check.

## 1. Version

- [ ] Bump `__version__` in `spyder/__init__.py`. **This is the only place.**
      `pyproject.toml` reads it via `[tool.setuptools.dynamic]`, and
      `tests/test_release_v1.py` fails if a second static version reappears.
- [ ] Follow SemVer — see the policy in [MIGRATION.md](MIGRATION.md#versioning-policy-from-100-onward).

## 2. Changelog

- [ ] Move `[Unreleased]` entries into a new `## [X.Y.Z] — YYYY-MM-DD` section.
      The release workflow refuses to build a tag with no matching section.
- [ ] Every user-visible change is listed under Added / Fixed / Changed /
      Security, with the *why*, not just the what.
- [ ] Update the `[Unreleased]` and version compare links at the bottom.
- [ ] Fill in **Verified** with numbers you actually measured this pass.
- [ ] Fill in **Known limitations** honestly. An untested area named is worth
      more than an untested area implied.

## 3. Migration notes

- [ ] Add a `X.Y.Z` section to [MIGRATION.md](MIGRATION.md) for any behaviour
      change, even a fix, if someone could have scripted around the old
      behaviour.
- [ ] Document any database schema change and whether it auto-migrates.

## 4. Automated verification

Run locally before tagging; CI runs the same:

```bash
ruff check .
mypy spyder/
pytest -q
```

- [ ] `ruff check .` clean
- [ ] `mypy spyder/` clean
- [ ] Full suite passes; note the count for the changelog
- [ ] Documentation tests pass — they check that every documented command, flag,
      config key, path, and link is real

## 5. Packaging

```bash
rm -rf dist build *.egg-info
python -m build
twine check dist/*

python -m venv /tmp/fresh && /tmp/fresh/bin/pip install dist/*.whl
/tmp/fresh/bin/spyder --version
/tmp/fresh/bin/python -m spyder --version
/tmp/fresh/bin/python main.py --version
```

- [ ] `twine check` passes on both sdist and wheel
- [ ] All three entry points report the identical version
- [ ] Packaged metadata version == `spyder.__version__`
- [ ] `py.typed`, the report templates, and the logo SVG ship in the wheel
- [ ] A clean install works from **outside** the repository directory

## 6. Manual acceptance

CI cannot do these. Do them by hand on a real terminal.

- [ ] `spyder` with no arguments opens the REPL; banner renders at row 1
- [ ] Full workflow against a target you are authorized to test:
      `workspace new` → `scan` → `crawl` → `connector` → `findings` →
      `report html` → exit → `spyder -w <ws>` → data is still there
- [ ] `dashboard` launches, streams events, and `Ctrl+C` **and** `Ctrl+Q` each
      return to a clean shell — cursor visible, no mouse reporting, not stuck in
      the alternate screen
- [ ] Resize the terminal while the dashboard is running
- [ ] `Ctrl+W` opens the replay workbench and returns cleanly
- [ ] `clear`, `restart`, and workspace switching all repaint identically
- [ ] Tab completion and command history work in the REPL
- [ ] `Ctrl+C` during a running scan interrupts without corrupting the terminal
- [ ] Open an exported HTML report in a browser and confirm it renders
- [ ] Every external connector you have installed still runs

## 7. Security

- [ ] `tests/test_security_invariants.py` passes
- [ ] CodeQL has no new alerts
- [ ] Dependabot PRs are merged or triaged
- [ ] `pip-audit` reviewed — reachable advisories addressed
- [ ] No unauthorized-target data anywhere in the repo, docs, or test fixtures

## 8. Documentation

- [ ] README version badge matches the release
- [ ] Install instructions work from a clean clone on a clean machine
- [ ] Every code example in the docs was executed, not assumed
- [ ] Screenshots reflect the current UI

## 9. Tag and publish

```bash
git add -A
git commit -m "release: vX.Y.Z"
git tag -a vX.Y.Z -m "SPYDER vX.Y.Z"
git push origin main --tags
```

- [ ] Tag is `vX.Y.Z` and matches `spyder.__version__` (the workflow enforces it)
- [ ] Release workflow succeeded
- [ ] Draft release notes reviewed, then published
- [ ] Artifacts attached and downloadable

## 10. Post-release

- [ ] Install the published artifact on a clean machine and smoke test it
- [ ] Open a fresh `[Unreleased]` section in the changelog
- [ ] Update the roadmap in the README

---

## Outstanding before the repository goes public

Items that are prepared but need a human with account access:

- [ ] Push to `github.com/joshwa-n/spyder` and set the default branch
- [ ] Repository topics: `security`, `recon`, `pentesting`, `bug-bounty`,
      `red-team`, `osint`, `python`, `cli`, `kali-linux`, `security-tools`
- [ ] Enable Discussions (the issue template config links to it)
- [ ] Enable Dependabot alerts and security updates
- [ ] Enable private vulnerability reporting (Settings → Security)
- [ ] Enable CodeQL (the workflow is committed; Actions must be allowed)
- [ ] Branch protection on `main`: require CI, require review
- [ ] Add a repository description and website
- [ ] Capture image screenshots of the dashboard and replay workbench, and
      replace the terminal captures in the README's Screenshots section
- [ ] Decide on PyPI: reserve `spyder-recon`, configure a Trusted Publisher,
      then uncomment the `pypi` job in `.github/workflows/release.yml`
