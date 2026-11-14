# Specification: temperature conversions

## Problem

Callers need to convert temperatures between Celsius, Fahrenheit and Kelvin without
re-deriving the formulas, and must be protected from physically impossible values.

## Behaviour

The library exposes three pure functions. Each takes and returns a float. No function
performs I/O or keeps state. Inputs below absolute zero are rejected rather than converted.

## Requirements and acceptance criteria

- REQ-001 `celsius_to_fahrenheit(c)` shall return `c * 9 / 5 + 32`.
  Given 100.0 when converted then the result is 212.0.
- REQ-002 `fahrenheit_to_celsius(f)` shall return `(f - 32) * 5 / 9`.
  Given the output of REQ-001 for 21.5 when converted back then the result is 21.5.
- REQ-003 `celsius_to_kelvin(c)` shall return `c + 273.15`.
  Given 0.0 when converted then the result is 273.15.
- REQ-004 Every function shall raise `ValueError` for a temperature below -273.15 degC.
  Given -300.0 when converted then `ValueError` is raised.

## Out of scope

Rankine and Réaumur scales; unit parsing from strings; vectorised input.

## Traceability

REQ-001 and REQ-002: `tests/test_convert.py::test_round_trip`.
REQ-003: `tests/test_convert.py::test_kelvin`.
REQ-004: `tests/test_convert.py::test_below_absolute_zero_rejected`.
