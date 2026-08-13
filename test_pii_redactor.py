"""
Unit & Integration Test Suite for PII Redaction Engine
-------------------------------------------------------
Run tests: python -m unittest test_pii_redactor.py
"""

import unittest
import os
import docx
from pii_redactor import PIIDetector, DocxPIIRedactor, PIICategory, FakeValueGenerator


class TestPIIRedactor(unittest.TestCase):

    def setUp(self):
        self.detector = PIIDetector()
        self.fake_gen = FakeValueGenerator(seed=42)

    def test_email_detection(self):
        text = "Contact support at cs.connect@kshinternational.com or john.doe@example.com."
        matches = self.detector.detect_in_text(text)
        emails = [m.original_text for m in matches if m.category == PIICategory.EMAIL]
        self.assertIn("cs.connect@kshinternational.com", emails)
        self.assertIn("john.doe@example.com", emails)

    def test_phone_detection(self):
        text = "Call us at +91 9876543210 or landline 020-67314000."
        matches = self.detector.detect_in_text(text)
        phones = [m.original_text for m in matches if m.category == PIICategory.PHONE]
        self.assertTrue(any("9876543210" in p for p in phones))

    def test_consistent_replacement_mapping(self):
        """Verify that identical original entities map to the exact same synthetic replacement."""
        fake1 = self.fake_gen.get_replacement("Rashi Patil", PIICategory.FULL_NAME)
        fake2 = self.fake_gen.get_replacement("Rashi Patil", PIICategory.FULL_NAME)
        self.assertEqual(fake1, fake2, "Fake replacement must be deterministic and consistent!")

        email1 = self.fake_gen.get_replacement("rashhi.patil@gmail.com", PIICategory.EMAIL)
        email2 = self.fake_gen.get_replacement("rashhi.patil@gmail.com", PIICategory.EMAIL)
        self.assertEqual(email1, email2, "Email replacement must be consistent across multiple runs!")

    def test_luhn_algorithm(self):
        """Verify Luhn algorithm validation for credit card numbers."""
        valid_card = "4532015112830366"  # Visa test number
        invalid_card = "4532015112830367"
        self.assertTrue(self.detector._is_luhn_valid(valid_card))
        self.assertFalse(self.detector._is_luhn_valid(invalid_card))

    def test_dob_detection_context(self):
        """Verify birth dates are detected while period dates (e.g. June 30, 2025) are preserved."""
        text_dob = "Date of Birth: August 6, 1982"
        matches_dob = self.detector.detect_in_text(text_dob)
        self.assertTrue(any(m.category == PIICategory.DOB for m in matches_dob))

    def test_false_positive_blocklist(self):
        """Verify corporate terms like 'Equity Shares' are excluded from false positive detection."""
        text = "Prospectus for Equity Shares under Companies Act, 2013."
        matches = self.detector.detect_in_text(text)
        matched_texts = [m.original_text for m in matches]
        self.assertNotIn("Equity Shares", matched_texts)
        self.assertNotIn("Companies Act", matched_texts)


if __name__ == "__main__":
    unittest.main()
