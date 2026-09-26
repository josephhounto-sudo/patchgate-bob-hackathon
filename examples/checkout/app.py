"""Synthetic checkout functions for the impact-link demonstration."""

from decimal import Decimal


def calculate_total(subtotal: Decimal, tax_rate: Decimal) -> Decimal:
    tax = subtotal * tax_rate
    return (subtotal + tax).quantize(Decimal("0.01"))


def authorize_payment(amount: Decimal) -> bool:
    return amount > Decimal("0.00")
