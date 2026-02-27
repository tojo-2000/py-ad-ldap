#!/usr/bin/python
"""Tests for constants module."""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ad_ldap import constants


class TestMandatoryProps(unittest.TestCase):
    """Test cases for mandatory properties constants."""

    def test_mandatory_props_default_exists(self):
        """Test that MANDATORY_PROPS_DEFAULT is defined."""
        self.assertIsNotNone(constants.MANDATORY_PROPS_DEFAULT)
        self.assertIsInstance(constants.MANDATORY_PROPS_DEFAULT, tuple)

    def test_mandatory_props_default_contains_required_fields(self):
        """Test that required fields are in MANDATORY_PROPS_DEFAULT."""
        required = ['distinguishedName', 'objectClass', 'objectCategory', 'name']
        for prop in required:
            self.assertIn(prop, constants.MANDATORY_PROPS_DEFAULT)

    def test_mandatory_props_user_contains_default(self):
        """Test that USER props include DEFAULT props."""
        for prop in constants.MANDATORY_PROPS_DEFAULT:
            self.assertIn(prop, constants.MANDATORY_PROPS_USER)

    def test_mandatory_props_user_contains_sam_account(self):
        """Test that USER props include sAMAccountName."""
        self.assertIn('sAMAccountName', constants.MANDATORY_PROPS_USER)

    def test_mandatory_props_computer_contains_user(self):
        """Test that COMPUTER props include USER props."""
        for prop in constants.MANDATORY_PROPS_USER:
            self.assertIn(prop, constants.MANDATORY_PROPS_COMPUTER)

    def test_mandatory_props_group_contains_default(self):
        """Test that GROUP props include DEFAULT props."""
        for prop in constants.MANDATORY_PROPS_DEFAULT:
            self.assertIn(prop, constants.MANDATORY_PROPS_GROUP)


class TestUserAccountControlFlags(unittest.TestCase):
    """Test cases for user account control flag constants."""

    def test_script_flag(self):
        """Test ADS_UF_SCRIPT flag."""
        self.assertEqual(constants.ADS_UF_SCRIPT, 1)

    def test_account_disable_flag(self):
        """Test ADS_UF_ACCOUNTDISABLE flag."""
        self.assertEqual(constants.ADS_UF_ACCOUNTDISABLE, 2)

    def test_homedir_required_flag(self):
        """Test ADS_UF_HOMEDIR_REQUIRED flag."""
        self.assertEqual(constants.ADS_UF_HOMEDIR_REQUIRED, 8)

    def test_lockout_flag(self):
        """Test ADS_UF_LOCKOUT flag."""
        self.assertEqual(constants.ADS_UF_LOCKOUT, 16)

    def test_passwd_notreqd_flag(self):
        """Test ADS_UF_PASSWD_NOTREQD flag."""
        self.assertEqual(constants.ADS_UF_PASSWD_NOTREQD, 32)

    def test_normal_account_flag(self):
        """Test ADS_UF_NORMAL_ACCOUNT flag."""
        self.assertEqual(constants.ADS_UF_NORMAL_ACCOUNT, 512)


class TestRegularExpressions(unittest.TestCase):
    """Test cases for regular expressions in constants."""

    def test_hostname_regex_exists(self):
        """Test that hostname regex is defined."""
        self.assertIsNotNone(constants.RE_HOSTNAME)

    def test_text_time_regex_exists(self):
        """Test that text time regex is defined."""
        self.assertIsNotNone(constants.RE_TEXT_TIME)

    def test_text_time_regex_matches_valid_format(self):
        """Test that text time regex matches valid AD time format."""
        valid_time = "20100115143022.0Z"
        matches = constants.RE_TEXT_TIME.findall(valid_time)
        self.assertTrue(len(matches) > 0)

    def test_hostname_regex_matches_simple_hostname(self):
        """Test that hostname regex matches simple hostnames."""
        hostname = "testpc"
        match = constants.RE_HOSTNAME.match(hostname)
        self.assertIsNotNone(match)

    def test_hostname_regex_matches_fqdn(self):
        """Test that hostname regex matches FQDN."""
        hostname = "testpc.example.com"
        match = constants.RE_HOSTNAME.match(hostname)
        self.assertIsNotNone(match)


class TestEpochConstant(unittest.TestCase):
    """Test cases for epoch constant."""

    def test_epoch_filetime_exists(self):
        """Test that EPOCH_AS_FILETIME is defined."""
        self.assertIsNotNone(constants.EPOCH_AS_FILETIME)

    def test_epoch_filetime_is_valid(self):
        """Test that EPOCH_AS_FILETIME has expected value."""
        # EPOCH_AS_FILETIME represents Jan 1, 1601 in Windows FILETIME format
        # It should be a very large number
        self.assertGreater(constants.EPOCH_AS_FILETIME, 100000000000000)


if __name__ == '__main__':
    unittest.main()
