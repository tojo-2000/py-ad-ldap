#!/usr/bin/python
"""Tests for errors module."""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ad_ldap import errors


class TestErrorClasses(unittest.TestCase):
    """Test cases for error classes."""

    def test_error_is_exception(self):
        """Test that Error inherits from Exception."""
        error = errors.Error("test")
        self.assertIsInstance(error, Exception)

    def test_object_property_not_found_error(self):
        """Test ObjectPropertyNotFoundError."""
        error = errors.ObjectPropertyNotFoundError("property not found")
        self.assertIsInstance(error, errors.Error)
        self.assertIsInstance(error, Exception)

    def test_user_not_disabled_error(self):
        """Test UserNotDisabledError."""
        error = errors.UserNotDisabledError("user not disabled")
        self.assertIsInstance(error, errors.Error)

    def test_user_not_enabled_error(self):
        """Test UserNotEnabledError."""
        error = errors.UserNotEnabledError("user not enabled")
        self.assertIsInstance(error, errors.Error)

    def test_user_not_locked_out_error(self):
        """Test UserNotLockedOutError."""
        error = errors.UserNotLockedOutError("user not locked")
        self.assertIsInstance(error, errors.Error)

    def test_no_computer_password_reset_error(self):
        """Test NoComputerPasswordResetError."""
        error = errors.NoComputerPasswordResetError("cannot reset computer password")
        self.assertIsInstance(error, errors.Error)

    def test_ldap_connection_failed_error(self):
        """Test LDAPConnectionFailedError."""
        error = errors.LDAPConnectionFailedError("connection failed")
        self.assertIsInstance(error, errors.Error)

    def test_invalid_credentials_error(self):
        """Test InvalidCredentialsError."""
        error = errors.InvalidCredentialsError("invalid credentials")
        self.assertIsInstance(error, errors.Error)

    def test_error_with_message(self):
        """Test that errors can be instantiated with messages."""
        msg = "Test error message"
        error = errors.Error(msg)
        self.assertEqual(str(error), msg)

    def test_error_hierarchy(self):
        """Test the error inheritance hierarchy."""
        self.assertTrue(issubclass(errors.ObjectPropertyNotFoundError, errors.Error))
        self.assertTrue(issubclass(errors.UserNotDisabledError, errors.Error))
        self.assertTrue(issubclass(errors.InvalidCredentialsError, errors.Error))
        self.assertTrue(issubclass(errors.Error, Exception))


class TestADDomainNotConnectedError(unittest.TestCase):
    """Test cases for ADDomainNotConnectedError."""

    def test_domain_not_connected_error_exists(self):
        """Test that ADDomainNotConnectedError is defined."""
        self.assertTrue(hasattr(errors, 'ADDomainNotConnectedError'))

    def test_domain_not_connected_error_is_error(self):
        """Test that ADDomainNotConnectedError is an Error."""
        error = errors.ADDomainNotConnectedError("not connected")
        self.assertIsInstance(error, errors.Error)


class TestAdObjectClassOnlyError(unittest.TestCase):
    """Test cases for ADObjectClassOnlyError."""

    def test_object_class_only_error_exists(self):
        """Test that ADObjectClassOnlyError is defined."""
        self.assertTrue(hasattr(errors, 'ADObjectClassOnlyError'))

    def test_object_class_only_error_is_error(self):
        """Test that ADObjectClassOnlyError is an Error."""
        error = errors.ADObjectClassOnlyError("object class required")
        self.assertIsInstance(error, errors.Error)


class TestInvalidPropertyFormatError(unittest.TestCase):
    """Test cases for InvalidPropertyFormatError."""

    def test_invalid_property_format_error_exists(self):
        """Test that InvalidPropertyFormatError is defined."""
        self.assertTrue(hasattr(errors, 'InvalidPropertyFormatError'))

    def test_invalid_property_format_error_is_error(self):
        """Test that InvalidPropertyFormatError is an Error."""
        error = errors.InvalidPropertyFormatError("invalid format")
        self.assertIsInstance(error, errors.Error)


if __name__ == '__main__':
    unittest.main()
