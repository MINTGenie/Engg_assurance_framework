# Architecture

## Components

`tempconv/convert.py` is the only module with logic. It contains three public conversion
functions and one private validator, `_check`, which every public function calls so that the
absolute-zero rule (REQ-004) is enforced in exactly one place. `tempconv/__init__.py`
re-exports the public functions and defines `__all__`.

## Design decisions

- ADR-1: pure functions, no classes. The problem has no state; a class would add nothing.
- ADR-2: validate in Celsius. Fahrenheit input is converted first and then validated, so
  there is one threshold constant (`ABSOLUTE_ZERO_C`) instead of three.
- ADR-3: no runtime dependencies. The formulas need only float arithmetic.

## Interfaces

Python import API only. No network, file or environment access.
