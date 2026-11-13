"""Conversions between Celsius, Fahrenheit and Kelvin."""

ABSOLUTE_ZERO_C = -273.15


def _check(celsius: float) -> float:
    if celsius < ABSOLUTE_ZERO_C:
        raise ValueError(f"{celsius} degC is below absolute zero")
    return celsius


def celsius_to_fahrenheit(celsius: float) -> float:
    return _check(celsius) * 9.0 / 5.0 + 32.0


def fahrenheit_to_celsius(fahrenheit: float) -> float:
    return _check((fahrenheit - 32.0) * 5.0 / 9.0)


def celsius_to_kelvin(celsius: float) -> float:
    return _check(celsius) - ABSOLUTE_ZERO_C
