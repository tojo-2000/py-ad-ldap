#!/usr/bin/python
"""Tests for ADObject and related classes in ad_ldap module."""

import unittest
import sys
import os
from unittest.mock import Mock, MagicMock, patch

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ad_ldap import ad_ldap, constants, errors


class TestADObjectInit(unittest.TestCase):
    """Test cases for ADObject initialization."""

    def setUp(self):
        """Set up test fixtures."""
        self.domain = MagicMock()
        self.domain.dns_name = 'example.com'

    def test_adobject_creation_with_dict(self):
        """Test creating ADObject with properties dict."""
        dn = 'cn=testuser,dc=example,dc=com'
        props = {
            'distinguishedName': [dn],
            'objectClass': ['user'],
            'name': ['testuser'],
        }
        obj = ad_ldap.ADObject(dn, props, self.domain)
        self.assertEqual(obj.distinguished_name, dn)

    def test_adobject_properties_dict(self):
        """Test accessing properties from ADObject."""
        dn = 'cn=testuser,dc=example,dc=com'
        props = {
            'distinguishedName': [dn],
            'name': ['testuser'],
            'description': ['Test User'],
        }
        obj = ad_ldap.ADObject(dn, props, self.domain)
        self.assertEqual(obj.properties['name'], ['testuser'])

    def test_adobject_distinguished_name_property(self):
        """Test distinguishedName property."""
        dn = 'cn=testuser,dc=example,dc=com'
        props = {
            'distinguishedName': [dn],
            'objectClass': ['user'],
            'objectCategory': ['cn=Person,cn=Schema,cn=Configuration,dc=example,dc=com'],
        }
        obj = ad_ldap.ADObject(dn, props, self.domain)
        self.assertEqual(obj.distinguished_name, dn)

    def test_adobject_name_property(self):
        """Test name property."""
        dn = 'cn=testuser,dc=example,dc=com'
        props = {'name': ['testuser']}
        obj = ad_ldap.ADObject(dn, props, self.domain)
        self.assertEqual(obj.name, 'testuser')

    def test_adobject_description_property(self):
        """Test description property."""
        dn = 'cn=testuser,dc=example,dc=com'
        props = {
            'distinguishedName': [dn],
            'objectClass': ['user'],
            'objectCategory': ['cn=Person,cn=Schema,cn=Configuration,dc=example,dc=com'],
            'description': ['A test user'],
            'name': ['testuser'],
            'createTimeStamp': ['20100101000000Z'],
            'modifyTimeStamp': ['20100101000000Z'],
        }
        obj = ad_ldap.ADObject(dn, props, self.domain)
        self.assertEqual(obj.description, 'A test user')

    def test_adobject_get_nonexistent_property(self):
        """Test accessing nonexistent property raises error."""
        dn = 'cn=testuser,dc=example,dc=com'
        props = {
            'distinguishedName': [dn],
            'objectClass': ['user'],
            'objectCategory': ['cn=Person,cn=Schema,cn=Configuration,dc=example,dc=com'],
        }
        obj = ad_ldap.ADObject(dn, props, self.domain)
        with self.assertRaises(errors.ObjectPropertyNotFoundError):
            _ = obj.nonexistent_property


class TestUserObject(unittest.TestCase):
    """Test cases for User class."""

    def setUp(self):
        """Set up test fixtures."""
        self.domain = MagicMock()
        self.domain.dns_name = 'example.com'

    def test_user_creation(self):
        """Test creating a User object."""
        dn = 'cn=testuser,cn=Users,dc=example,dc=com'
        props = {
            'distinguishedName': [dn],
            'objectClass': ['user'],
            'objectCategory': ['cn=Person,cn=Schema,cn=Configuration,dc=example,dc=com'],
            'sAMAccountName': ['testuser'],
            'userAccountControl': ['512'],
            'memberOf': [''],
            'name': ['testuser'],
            'description': [''],
            'createTimeStamp': ['20100101000000Z'],
            'modifyTimeStamp': ['20100101000000Z'],
        }
        user = ad_ldap.User(dn, props, self.domain)
        self.assertEqual(user.sam_account_name, 'testuser')

    def test_user_disabled_property_enabled(self):
        """Test User.disabled property for enabled account."""
        dn = 'cn=testuser,cn=Users,dc=example,dc=com'
        props = {
            'distinguishedName': [dn],
            'objectClass': ['user'],
            'objectCategory': ['cn=Person,cn=Schema,cn=Configuration,dc=example,dc=com'],
            'userAccountControl': ['512'],  # Normal account
            'sAMAccountName': ['testuser'],
            'memberOf': [],
            'name': ['testuser'],
            'description': [''],
            'createTimeStamp': ['20100101000000Z'],
            'modifyTimeStamp': ['20100101000000Z'],
        }
        user = ad_ldap.User(dn, props, self.domain)
        self.assertFalse(user.disabled)

    def test_user_disabled_property_disabled(self):
        """Test User.disabled property for disabled account."""
        dn = 'cn=testuser,cn=Users,dc=example,dc=com'
        props = {
            'distinguishedName': [dn],
            'objectClass': ['user'],
            'objectCategory': ['cn=Person,cn=Schema,cn=Configuration,dc=example,dc=com'],
            'userAccountControl': ['514'],  # Disabled account
            'sAMAccountName': ['testuser'],
            'memberOf': [''],
            'name': ['testuser'],
            'description': [''],
            'createTimeStamp': ['20100101000000Z'],
            'modifyTimeStamp': ['20100101000000Z'],
        }
        user = ad_ldap.User(dn, props, self.domain)
        self.assertTrue(user.disabled)

    def test_user_locked_out_property(self):
        """Test User.locked_out property."""
        dn = 'cn=testuser,cn=Users,dc=example,dc=com'
        user_account_control = 512 | constants.ADS_UF_LOCKOUT
        props = {
            'distinguishedName': [dn],
            'objectClass': ['user'],
            'objectCategory': ['cn=Person,cn=Schema,cn=Configuration,dc=example,dc=com'],
            'userAccountControl': [str(user_account_control)],
            'sAMAccountName': ['testuser'],
            'memberOf': [''],
            'name': ['testuser'],
            'description': [''],
            'createTimeStamp': ['20100101000000Z'],
            'modifyTimeStamp': ['20100101000000Z'],
        }
        user = ad_ldap.User(dn, props, self.domain)
        self.assertTrue(user.locked_out)


class TestComputerObject(unittest.TestCase):
    """Test cases for Computer class."""

    def setUp(self):
        """Set up test fixtures."""
        self.domain = MagicMock()
        self.domain.dns_name = 'example.com'

    def test_computer_creation(self):
        """Test creating a Computer object."""
        dn = 'cn=testpc,cn=Computers,dc=example,dc=com'
        props = {
            'distinguishedName': [dn],
            'objectClass': ['computer'],
            'objectCategory': ['cn=Computer,cn=Schema,cn=Configuration,dc=example,dc=com'],
            'sAMAccountName': ['testpc$'],
            'userAccountControl': ['4096'],
            'memberOf': [''],
            'dNSHostname': ['testpc.example.com'],
            'servicePrincipalName': [''],
            'operatingSystem': ['Windows 10'],
            'operatingSystemServicePack': [''],
            'operatingSystemVersion': ['10.0 (19045)'],
            'name': ['testpc'],
            'description': [''],
            'createTimeStamp': ['20100101000000Z'],
            'modifyTimeStamp': ['20100101000000Z'],
        }
        computer = ad_ldap.Computer(dn, props, self.domain)
        self.assertEqual(computer.dns_hostname, 'testpc.example.com')

    def test_computer_sam_account_name(self):
        """Test Computer.sam_account_name property."""
        dn = 'cn=testpc,cn=Computers,dc=example,dc=com'
        props = {
            'distinguishedName': [dn],
            'objectClass': ['computer'],
            'objectCategory': ['cn=Computer,cn=Schema,cn=Configuration,dc=example,dc=com'],
            'sAMAccountName': ['testpc$'],
            'userAccountControl': ['4096'],
            'memberOf': [''],
            'dNSHostname': ['testpc.example.com'],
            'servicePrincipalName': [''],
            'operatingSystem': ['Windows 10'],
            'operatingSystemServicePack': [''],
            'operatingSystemVersion': ['10.0 (19045)'],
            'name': ['testpc'],
            'description': [''],
            'createTimeStamp': ['20100101000000Z'],
            'modifyTimeStamp': ['20100101000000Z'],
        }
        computer = ad_ldap.Computer(dn, props, self.domain)
        self.assertEqual(computer.sam_account_name, 'testpc$')


class TestGroupObject(unittest.TestCase):
    """Test cases for Group class."""

    def setUp(self):
        """Set up test fixtures."""
        self.domain = MagicMock()
        self.domain.dns_name = 'example.com'

    def test_group_creation(self):
        """Test creating a Group object."""
        dn = 'cn=testgroup,cn=Users,dc=example,dc=com'
        props = {
            'distinguishedName': [dn],
            'objectClass': ['group'],
            'objectCategory': ['cn=Group,cn=Schema,cn=Configuration,dc=example,dc=com'],
            'sAMAccountName': ['testgroup'],
            'groupType': ['-2147483646'],  # UNIVERSAL_GROUP | SECURITY_GROUP
            'name': ['testgroup'],
            'description': [''],
            'createTimeStamp': ['20100101000000Z'],
            'modifyTimeStamp': ['20100101000000Z'],
        }
        group = ad_ldap.Group(dn, props, self.domain)
        self.assertEqual(group.sam_account_name, 'testgroup')

    def test_group_type_property(self):
        """Test Group.group_type property."""
        dn = 'cn=testgroup,cn=Users,dc=example,dc=com'
        group_type = '-2147483646'  # UNIVERSAL_GROUP | SECURITY_GROUP
        props = {
            'distinguishedName': [dn],
            'objectClass': ['group'],
            'objectCategory': ['cn=Group,cn=Schema,cn=Configuration,dc=example,dc=com'],
            'groupType': [group_type],
            'name': ['testgroup'],
            'description': [''],
            'createTimeStamp': ['20100101000000Z'],
            'modifyTimeStamp': ['20100101000000Z'],
        }
        group = ad_ldap.Group(dn, props, self.domain)
        self.assertEqual(group.group_type, int(group_type))


class TestContainerObject(unittest.TestCase):
    """Test cases for Container class."""

    def setUp(self):
        """Set up test fixtures."""
        self.domain = MagicMock()
        self.domain.dns_name = 'example.com'

    def test_container_creation(self):
        """Test creating a Container object."""
        dn = 'ou=Users,dc=example,dc=com'
        props = {
            'distinguishedName': [dn],
            'objectClass': ['organizationalUnit'],
            'objectCategory': ['cn=Organizational-Unit,cn=Schema,cn=Configuration,dc=example,dc=com'],
            'name': ['Users'],
            'description': [''],
            'createTimeStamp': ['20100101000000Z'],
            'modifyTimeStamp': ['20100101000000Z'],
        }
        container = ad_ldap.Container(dn, props, self.domain)
        self.assertEqual(container.distinguished_name, dn)


class TestADObjectSetProperties(unittest.TestCase):
    """Test cases for ADObject.SetProperties method."""

    def setUp(self):
        """Set up test fixtures."""
        self.domain = MagicMock()
        self.domain._connected = True
        self.domain.UpdateObject = MagicMock()

    def test_set_properties(self):
        """Test setting properties on ADObject."""
        dn = 'cn=testuser,dc=example,dc=com'
        props = {
            'distinguishedName': [dn],
            'objectClass': ['user'],
            'objectCategory': ['cn=Person,cn=Schema,cn=Configuration,dc=example,dc=com'],
            'description': ['Original description'],
            'name': ['testuser'],
            'createTimeStamp': ['20100101000000Z'],
            'modifyTimeStamp': ['20100101000000Z'],
        }
        obj = ad_ldap.ADObject(dn, props, self.domain)

        new_props = {'description': ['Updated description']}
        obj.SetProperties(new_props)

        self.domain.UpdateObject.assert_called_once()


if __name__ == '__main__':
    unittest.main()
