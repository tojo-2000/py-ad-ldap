#!/usr/bin/python
"""Tests for Domain class in ad_ldap module."""

import unittest
import sys
import os
from unittest.mock import Mock, MagicMock, patch

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ad_ldap import ad_ldap, errors
import ldap


class TestDomainInit(unittest.TestCase):
    """Test cases for Domain initialization."""

    def test_domain_creation(self):
        """Test creating a Domain object."""
        domain = ad_ldap.Domain()
        self.assertIsNotNone(domain)
        self.assertFalse(domain._connected)
        self.assertEqual(domain.dn_root, '')
        self.assertEqual(domain.dn_forest, '')
        self.assertEqual(domain.dn_schema, '')
        self.assertEqual(domain.dn_configuration, '')

    def test_domain_repr_not_connected(self):
        """Test Domain repr when not connected."""
        domain = ad_ldap.Domain()
        self.assertEqual(repr(domain), 'Domain: Not Connected')

    def test_domain_repr_connected(self):
        """Test Domain repr when connected."""
        domain = ad_ldap.Domain()
        domain._connected = True
        domain.dn_root = 'dc=example,dc=com'
        self.assertEqual(repr(domain), 'Domain: dc=example,dc=com')


class TestDomainDNSName(unittest.TestCase):
    """Test cases for Domain.dns_name property."""

    def test_dns_name_extraction(self):
        """Test DNS name extraction from distinguished name."""
        domain = ad_ldap.Domain()
        domain.dn_root = 'cn=test,dc=example,dc=com'
        self.assertEqual(domain.dns_name, 'example.com')

    def test_dns_name_single_label(self):
        """Test DNS name with single label."""
        domain = ad_ldap.Domain()
        domain.dn_root = 'dc=com'
        self.assertEqual(domain.dns_name, 'com')

    def test_dns_name_case_insensitive(self):
        """Test that dc= is case insensitive."""
        domain = ad_ldap.Domain()
        domain.dn_root = 'cn=test,DC=example,DC=com'
        self.assertEqual(domain.dns_name, 'example.com')

    def test_dns_name_with_other_attributes(self):
        """Test DNS name with other attributes mixed in."""
        domain = ad_ldap.Domain()
        domain.dn_root = 'cn=test,ou=users,dc=example,dc=com'
        self.assertEqual(domain.dns_name, 'example.com')


class TestDomainConnect(unittest.TestCase):
    """Test cases for Domain connection methods."""

    def test_disconnect(self):
        """Test disconnecting from LDAP server."""
        domain = ad_ldap.Domain()
        domain._connected = True
        domain._ldap = MagicMock()

        domain.Disconnect()

        domain._ldap.unbind_s.assert_called_once()
        self.assertFalse(domain._connected)


class TestDomainSearch(unittest.TestCase):
    """Test cases for Domain.Search method."""

    def setUp(self):
        """Set up test fixtures."""
        self.domain = ad_ldap.Domain()
        self.domain._connected = True
        self.domain.dn_root = 'dc=example,dc=com'
        self.domain._ldap = MagicMock()

    def test_search_not_connected(self):
        """Test that search raises error when not connected."""
        domain = ad_ldap.Domain()
        with self.assertRaises(errors.ADDomainNotConnectedError):
            domain.Search('objectClass=*')

    def test_search_uses_root_dn_by_default(self):
        """Test that search uses root DN when base_dn not specified."""
        self.domain._ldap.search_ext.return_value = 1
        self.domain._ldap.result3.return_value = (None, [], 1, [])

        self.domain.Search('objectClass=user')

        # Verify search_ext was called with root DN
        call_args = self.domain._ldap.search_ext.call_args
        self.assertEqual(call_args[0][0], self.domain.dn_root)


class TestDomainGetters(unittest.TestCase):
    """Test cases for Domain getter methods."""

    def setUp(self):
        """Set up test fixtures."""
        self.domain = ad_ldap.Domain()
        self.domain._connected = True
        self.domain.dn_root = 'dc=example,dc=com'
        self.domain.dn_configuration = 'cn=Configuration,dc=example,dc=com'
        self.domain._ldap = MagicMock()

    def test_get_object_by_name(self):
        """Test getting object by sAMAccountName."""
        dn = 'cn=testuser,dc=example,dc=com'
        props = {
            'distinguishedName': [dn],
            'objectClass': ['user'],
            'objectCategory': ['cn=Person,cn=Schema,cn=Configuration,dc=example,dc=com'],
            'sAMAccountName': ['testuser'],
            'name': ['testuser'],
            'description': [''],
            'createTimeStamp': ['20100101000000Z'],
            'modifyTimeStamp': ['20100101000000Z'],
        }
        mock_obj = ad_ldap.ADObject(dn, props, self.domain)
        with patch.object(self.domain, 'Search', return_value=[mock_obj]):
            result = self.domain.GetObjectByName('testuser')
            self.assertEqual(result, mock_obj)

    def test_get_object_by_name_not_found(self):
        """Test getting object by name when not found."""
        with patch.object(self.domain, 'Search', return_value=[]):
            result = self.domain.GetObjectByName('nonexistent')
            self.assertIsNone(result)

    def test_get_object_by_name_escapes_special_chars(self):
        """Test that special characters are escaped in search."""
        with patch.object(self.domain, 'Search', return_value=[]) as mock_search:
            self.domain.GetObjectByName('test*user')
            # Verify the search was called with escaped filter
            call_args = mock_search.call_args
            self.assertIn('\\2a', call_args[0][0])  # * is escaped


if __name__ == '__main__':
    unittest.main()
