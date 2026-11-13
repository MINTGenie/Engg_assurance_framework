import pytest

from tempconv import celsius_to_fahrenheit, celsius_to_kelvin, fahrenheit_to_celsius


def test_round_trip():
    assert fahrenheit_to_celsius(celsius_to_fahrenheit(21.5)) == pytest.approx(21.5)


def test_kelvin():
    assert celsius_to_kelvin(0.0) == pytest.approx(273.15)


def test_below_absolute_zero_rejected():
    with pytest.raises(ValueError):
        celsius_to_kelvin(-300.0)
