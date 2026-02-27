#!/usr/bin/python
"""Tests for utility functions in ad_ldap module."""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ad_ldap import ad_ldap, constants


class TestADFileTimeToUnix(unittest.TestCase):
    """Test cases for ADFileTimeToUnix function."""

    def test_conversion_basic(self):
        """Test basic AD filetime to Unix timestamp conversion."""
        # AD filetime for 1970-01-01 00:00:00 UTC
        ad_time = constants.EPOCH_AS_FILETIME
        result = ad_ldap.ADFileTimeToUnix(ad_time)
        self.assertEqual(result, 0)

    def test_conversion_one_second(self):
        """Test conversion with one second offset."""
        ad_time = constants.EPOCH_AS_FILETIME + 10000000  # Add 1 second
        result = ad_ldap.ADFileTimeToUnix(ad_time)
        self.assertEqual(result, 1)

    def test_conversion_one_day(self):
        """Test conversion with one day offset."""
        ad_time = constants.EPOCH_AS_FILETIME + (86400 * 10000000)  # Add 1 day
        result = ad_ldap.ADFileTimeToUnix(ad_time)
        self.assertEqual(result, 86400)


class TestToStr(unittest.TestCase):
    """Test cases for ToStr function."""

    def test_string_passthrough(self):
        """Test that strings are passed through unchanged."""
        test_str = "hello world"
        result = ad_ldap.ToStr(test_str)
        self.assertEqual(result, test_str)
        self.assertIsInstance(result, str)

    def test_bytes_conversion(self):
        """Test that bytes are converted to strings."""
        test_bytes = b"hello world"
        result = ad_ldap.ToStr(test_bytes)
        self.assertEqual(result, "hello world")
        self.assertIsInstance(result, str)

    def test_utf8_conversion(self):
        """Test UTF-8 conversion."""
        test_bytes = "café".encode('utf-8')
        result = ad_ldap.ToStr(test_bytes)
        self.assertEqual(result, "café")

    def test_empty_string(self):
        """Test conversion of empty string."""
        result = ad_ldap.ToStr("")
        self.assertEqual(result, "")

    def test_empty_bytes(self):
        """Test conversion of empty bytes."""
        result = ad_ldap.ToStr(b"")
        self.assertEqual(result, "")


class TestToBytes(unittest.TestCase):
    """Test cases for ToBytes function."""

    def test_string_conversion(self):
        """Test that strings are converted to bytes."""
        test_str = "hello world"
        result = ad_ldap.ToBytes(test_str)
        self.assertEqual(result, b"hello world")
        self.assertIsInstance(result, bytes)

    def test_bytes_passthrough(self):
        """Test that bytes are passed through unchanged."""
        test_bytes = b"hello world"
        result = ad_ldap.ToBytes(test_bytes)
        self.assertEqual(result, test_bytes)
        self.assertIsInstance(result, bytes)

    def test_utf8_encoding(self):
        """Test UTF-8 encoding."""
        test_str = "café"
        result = ad_ldap.ToBytes(test_str)
        self.assertEqual(result, "café".encode('utf-8'))

    def test_empty_string(self):
        """Test conversion of empty string."""
        result = ad_ldap.ToBytes("")
        self.assertEqual(result, b"")

    def test_empty_bytes(self):
        """Test conversion of empty bytes."""
        result = ad_ldap.ToBytes(b"")
        self.assertEqual(result, b"")


class TestBitmaskBool(unittest.TestCase):
    """Test cases for BitmaskBool function."""

    def test_bit_set(self):
        """Test that set bits return True."""
        bitmask = 0b1010
        self.assertTrue(ad_ldap.BitmaskBool(bitmask, 0b0010))
        self.assertTrue(ad_ldap.BitmaskBool(bitmask, 0b1000))

    def test_bit_not_set(self):
        """Test that unset bits return False."""
        bitmask = 0b1010
        self.assertFalse(ad_ldap.BitmaskBool(bitmask, 0b0001))
        self.assertFalse(ad_ldap.BitmaskBool(bitmask, 0b0100))

    def test_with_constants(self):
        """Test with actual ADS constants."""
        # User account disabled flag (bit 1)
        user_account_control = 514  # Disabled account
        result = ad_ldap.BitmaskBool(
            user_account_control, constants.ADS_UF_ACCOUNTDISABLE)
        self.assertTrue(result)

    def test_enabled_account(self):
        """Test with enabled account."""
        user_account_control = 512  # Normal account
        result = ad_ldap.BitmaskBool(
            user_account_control, constants.ADS_UF_ACCOUNTDISABLE)
        self.assertFalse(result)


class TestEscape(unittest.TestCase):
    """Test cases for Escape function."""

    def test_escape_special_characters(self):
        """Test escaping of LDAP special characters."""
        test_input = "test*user"
        result = ad_ldap.Escape(test_input)
        self.assertIn("\\2a", result)  # * is escaped

    def test_escape_parentheses(self):
        """Test escaping of parentheses."""
        test_input = "test(user)"
        result = ad_ldap.Escape(test_input)
        self.assertIn("\\28", result)  # (
        self.assertIn("\\29", result)  # )

    def test_escape_backslash(self):
        """Test escaping of backslash."""
        test_input = "test\\user"
        result = ad_ldap.Escape(test_input)
        self.assertIn("\\5c", result)  # \

    def test_no_escape_needed(self):
        """Test that normal characters don't need escaping."""
        test_input = "testuser"
        result = ad_ldap.Escape(test_input)
        self.assertEqual(result, "testuser")

    def test_escape_bytes_input(self):
        """Test escaping with bytes input."""
        test_input = b"test*user"
        result = ad_ldap.Escape(test_input)
        self.assertIn("\\2a", result)


class TestADTextTimeToUnix(unittest.TestCase):
    """Test cases for ADTextTimeToUnix function."""

    def test_valid_format(self):
        """Test conversion of valid time format."""
        # Format: YYYYMMDDHHMMSS.0Z
        time_str = "20100115143022.0Z"
        result = ad_ldap.ADTextTimeToUnix(time_str)
        self.assertIsInstance(result, (int, float))
        self.assertGreater(result, 0)

    def test_midnight(self):
        """Test conversion at midnight."""
        time_str = "20100101000000.0Z"
        result = ad_ldap.ADTextTimeToUnix(time_str)
        self.assertIsInstance(result, (int, float))
        self.assertGreater(result, 0)


if __name__ == '__main__':
    unittest.main()
