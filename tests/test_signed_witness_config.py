import base64
import unittest

from narf import NARFError, SignedWitnessAuthority


_PUBLIC_KEY = base64.b64encode(b"k" * 32).decode("ascii")


class SignedWitnessConfigTests(unittest.TestCase):
    def test_requires_https_by_default(self):
        with self.assertRaisesRegex(NARFError, "HTTPS required"):
            SignedWitnessAuthority("http://127.0.0.1:8080", _PUBLIC_KEY)

    def test_allows_explicit_loopback_http_for_fixture(self):
        authority = SignedWitnessAuthority(
            "http://127.0.0.1:8080",
            _PUBLIC_KEY,
            allow_insecure_http=True,
        )
        self.assertEqual(
            authority.domain_key(),
            ("signed-witness-ed25519", authority.public_key_fingerprint),
        )

    def test_same_signing_key_is_same_domain_across_urls(self):
        first = SignedWitnessAuthority("https://witness-a.example", _PUBLIC_KEY)
        second = SignedWitnessAuthority("https://witness-b.example", _PUBLIC_KEY)
        self.assertEqual(first.domain_key(), second.domain_key())

    def test_rejects_invalid_public_key(self):
        with self.assertRaisesRegex(NARFError, "invalid signed witness public key"):
            SignedWitnessAuthority("https://witness.example", "not-base64")


if __name__ == "__main__":
    unittest.main()
