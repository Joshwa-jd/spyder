# Summary

<!-- What changes, and why. One paragraph is usually enough. -->

Fixes #

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] New connector or plugin
- [ ] Documentation
- [ ] Performance
- [ ] Refactor (no behaviour change)

## Verification

<!-- "Verified" in this project means you ran it. Paste real output. -->

- [ ] `pytest` passes — result: <!-- e.g. 335 passed -->
- [ ] `ruff check .` clean
- [ ] `mypy spyder/` clean
- [ ] For a bug fix: added a regression test that **fails before** and passes after
- [ ] Manually exercised the affected commands

```
<!-- paste the relevant command output here -->
```

**What did you NOT test?**

<!-- An honest gap is more useful than an untested claim. -->

## Scope posture

- [ ] This adds no exploitation payloads or automated attack sequences
- [ ] This adds no scope-bypass or WAF-evasion logic
- [ ] This does not fabricate, estimate, or infer findings that were not observed
- [ ] Any detected secrets are stored redacted
- [ ] No unauthorized-target data (hostnames, IPs, findings) appears in this PR

## Documentation

- [ ] Updated docs for any user-visible change
- [ ] Added a `CHANGELOG.md` entry under `[Unreleased]`
- [ ] Docs match the implementation (every documented command/example works)

## Notes for reviewers

<!-- Anything non-obvious: tradeoffs, alternatives rejected, follow-up work. -->
