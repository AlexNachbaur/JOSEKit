# Summary

<!-- What does this PR change, and why? Link related issues with "Fixes #123". -->

## Checklist

- [ ] `swift format lint --strict --recursive Sources Tests Package.swift` and `swift test` pass locally
- [ ] Tests added or updated for behavioural changes, and each new guard was broken by hand to confirm a test fails
- [ ] Fixtures changed only by rerunning their generator in `interop/`; `./scripts/interop.sh` run if tokens on the wire are affected
- [ ] No `try?`, `try!`, force unwraps or force casts; no static-only types (DESIGN.md D24)
- [ ] Public API changes are documented (doc comments, README, `Documentation/`, DESIGN.md as appropriate)
