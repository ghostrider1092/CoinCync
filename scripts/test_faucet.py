import unittest

import faucet


def encode_base58(data):
    value = int.from_bytes(data, "big")
    encoded = ""
    while value:
        value, remainder = divmod(value, 58)
        encoded = faucet.ALPHABET[remainder] + encoded
    leading_zeroes = len(data) - len(data.lstrip(b"\0"))
    return "1" * leading_zeroes + encoded


class FaucetAddressTests(unittest.TestCase):
    def test_decode_address_only_restores_leading_zeroes(self):
        payload = bytes([1, 0]) + bytes([0x11]) * 32 + bytes([0x22]) * 32 + bytes(4)
        encoded = encode_base58(payload)
        self.assertIn("1", encoded)
        self.assertFalse(encoded.startswith("1"))

        self.assertEqual(faucet.decode_address("tCYNC" + encoded), payload)

    def test_extract_recipient_keys_skips_network_and_type_bytes(self):
        spend = bytes([0x11]) * 32
        view = bytes([0x22]) * 32
        payload = bytes([1, 0]) + spend + view + bytes(4)

        self.assertEqual(
            faucet.extract_recipient_keys("tCYNC" + encode_base58(payload)),
            (spend.hex(), view.hex()),
        )

    def test_extract_recipient_keys_rejects_invalid_layouts(self):
        spend = bytes([0x11]) * 32
        view = bytes([0x22]) * 32
        invalid_payloads = [
            bytes([0, 0]) + spend + view + bytes(4),
            bytes([1, 3]) + spend + view + bytes(4),
            bytes([1, 0]) + spend + view + bytes(3),
            bytes([1, 2]) + spend + view + bytes(4),
        ]

        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                self.assertIsNone(
                    faucet.extract_recipient_keys("tCYNC" + encode_base58(payload))
                )


class FaucetSendResultTests(unittest.TestCase):
    def test_accepts_current_wallet_mempool_success_output(self):
        output = "Submitting to node...\n  OK: tx accepted by mempool.\n"

        self.assertTrue(faucet.wallet_send_succeeded(0, output))

    def test_rejects_nonzero_exit_with_acceptance_output(self):
        self.assertFalse(
            faucet.wallet_send_succeeded(1, "OK: tx accepted by mempool.")
        )

    def test_rejects_generic_success_words(self):
        self.assertFalse(faucet.wallet_send_succeeded(0, "broadcast success"))


if __name__ == "__main__":
    unittest.main()
