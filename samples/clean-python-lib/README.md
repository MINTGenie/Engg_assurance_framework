# tempconv (EAF negative-control fixture)

## Overview

Tiny temperature conversion library. It is the "what good looks like" fixture: it is expected
to produce no scanner findings and to evidence every engineering practice EAF looks for.

## Installation

    pip install -e .

## Usage

    from tempconv import celsius_to_fahrenheit
    celsius_to_fahrenheit(21.5)

## Testing

    pip install -r requirements-dev.txt && pytest
