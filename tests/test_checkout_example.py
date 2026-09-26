import unittest
from decimal import Decimal

from examples.checkout.app import calculate_total


class CheckoutExampleTests(unittest.TestCase):
    def test_calculate_total_rounds_to_cents(self):
        self.assertEqual(calculate_total(Decimal("10.00"), Decimal("0.075")),
                         Decimal("10.75"))


if __name__ == "__main__":
    unittest.main()
