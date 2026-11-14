# Instructions for AI coding assistants

- Read `specs/conversions.md` before changing code. If a request is not covered by a
  requirement there, propose a spec change first and wait for confirmation.
- Keep the structure described in `docs/architecture.md`: pure functions in
  `src/tempconv/convert.py`, validation only in `_check`.
- Every behaviour change needs a test in `tests/` that names the requirement id it covers.
- Do not add dependencies. Do not weaken or delete tests to make them pass.
- Before finishing, run `pytest` and `eaf assess .` and report the result of both.
- Update `CHANGELOG.md` in the same change.
