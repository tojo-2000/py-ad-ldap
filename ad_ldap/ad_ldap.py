#!/usr/bin/python
"""A module for using ldap to manipulate objects in AD.

This module creates two basic object classes: Domain, and ADObject.

The Domain class is used for every interaction with the Active Directory
service itself, such as creating, modifying, or searching for objects.

The ADObject class represents an object in the directory.  It could be a user,
computer, OU, or any object.  It has an attribute called 'properties' that is a
dict of the properties of the object.  To modify a property, you change it in
the dict and call SetProperties().  Every ADObject has a '_domain_obj' property
that is a link to the Domain object, which will do the actual modifications to
the directory.

User, Computer, Group, and Container all inherit from ADObject, and add some
attributes and methods for convenience.  For example, the User object has
Disable() and Enable() methods for disabling and enabling user accounts, and a
'disabled' property to make it easier to tell if an object has been disabled.


Copyright 2010 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import copy
import re
import time
from ad_ldap import constants
from ad_ldap import errors
import ldap
import ldap.controls
import ldap.filter
import ldap.modlist

def ADFileTimeToUnix(ad_time):
  """Converts AD double-wide int format to seconds since the epoch format.

  Args:
    ad_time: a 64-bit integer time format used by AD with the number of 100ns
             intervals since January 1, 1601.

  Note: cribbed from filetimes.py at http://reliablybroken.com/b/2009/09/

  Returns:
    An int with the number of seconds since January 1, 1970.
  """
  return int((ad_time - constants.EPOCH_AS_FILETIME) / 10000000)


def ToStr(byte_string):
  """Converts a string in bytes form to UTF-8.
  
  Args:
    byte_string: A byte-encoded string.
    
  Returns:
    The byte-encoded string in UTF-8, or the original object if already a string.
  """
  if isinstance(byte_string, str):
    return byte_string
  else:
    return byte_string.decode('utf-8')


def ToBytes(in_string):
  """Converts a string into a byte stream.
  
  Args:
    string: The string to convert.
  
  Returns:
    The converted string, or the original string if already a byte stream.
  """
  if isinstance(in_string, bytes):
    return in_string
  else:
    return bytes(in_string, 'utf-8')

def ADTextTimeToUnix(text_time):
  """Converts alternate time format text strings to seconds since the epoch.

  Some Active Directory properties are stored in a YYYYMMDDHHMMSS.0Z format.
  See http://msdn.microsoft.com/en-us/library/aa772189(VS.85).aspx for details.

  Args:
    text_time: the string containing the time value.

  Returns:
    The number of seconds since the epoch.
  """
  groups = constants.RE_TEXT_TIME.findall(text_time)
  time_tuple = tuple([int(x) for x in groups[0] + (0, 0, 0)])
  return time.mktime(time_tuple)


def BitmaskBool(bitmask, value):
  """Returns True or False depending on whether a particular bit has been set.

  Microsoft uses bitmasks as a compact way of denoting a number of boolean
  settings.  The second bit, for example, might be the ADS_UF_ACCOUNTDISABLE
  bit, so if the second bit is a 1, then the account is disabled, and if it is
  a 0, then it is not.

  As an example, to create the 'disabled' property of a User object, we use the
  userAccountControl property and ADS_UF_ACCOUNTDISABLE constant.

  BitmaskBool(user.user_account_control, constants.ADS_UF_ACCOUNTDISABLE)
  This will return True if the bit is set in user.user_account_control.

  Args:
    bitmask: a number representing a bitmask
    value:  the value to be checked (usually a known constant)

  Returns:
    True if the bit has been set, False if it has not.
  """
  if int(bitmask) & int(value):
    return True
  else:
    return False


def Escape(text):
  """Escapes text to be used in an ldap filter.

  Args:
    text: The text to be escaped

  Returns:
    The escaped text.
  """
  return ldap.filter.escape_filter_chars(ToStr(text))


class Domain(object):
  """Represents an Active Directory Domain.

  The Domain object performs all interactions with Active Directory, including
  searching for objects, modifying objects, and deleting objects.  Some tasks
  that can be called from a method of an ADObject, like Delete() actually
  call the parent Domain object's method to do the dirty work.
  """

  def __init__(self):
    """Initialize the Domain object."""
    self._connected = False
    self.dn_root = ''
    self.dn_forest = ''
    self.dn_schema = ''
    self.dn_configuration = ''
    self._ldap = None

  def __repr__(self):
    if self._connected:
      return 'Domain: %s' % self.dn_root
    else:
      return 'Domain: Not Connected'

  def Connect(self, ldap_host, user, password, cert_dir=None, cert_file=None):
    """Connect to the ldap server.

    Args:
      ldap_host:  The ldap host to connect to
      user: the username for authentication
      password: the password for authentication
      cert_dir: (Optional) The directory containing the SSL cert file
      cert_file: (Optional)The file name of the cert

    Raises:
      errors.LDAPConnectionFailedError: if no ldap connection can be made
      errors.InvalidCredentialsError: if the ldap credentials are not accepted
    """
    if cert_dir:
      ldap.set_option(ldap.OPT_X_TLS_CACERTDIR, cert_dir)

    if cert_file:
      ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, cert_file)

    # NOTE: I intentionally wrote this to use ldaps instead of ldap.  Using
    #       a non-SSL connection will send your domain password over the wire
    #       in cleartext.
    try:
      self._ldap = ldap.initialize('ldaps://%s' % ldap_host)
      self._ldap.protocol_version = 3
      self._ldap.simple_bind_s(user, password)
      self._connected = True
      self._ldap.set_option(ldap.OPT_REFERRALS, 0)
      self.GetRootDseAttrs()
    except ldap.SERVER_DOWN as e:
      raise errors.LDAPConnectionFailedError(e.args[0]['info'])
    except ldap.INVALID_CREDENTIALS:
      raise errors.InvalidCredentialsError

  def Disconnect(self):
    """Disconnects from ldap."""
    self._ldap.unbind_s()
    self._connected = False

  def GetRootDseAttrs(self):
    """Gets the root DSE attributes."""
    root_dse = self.Search('objectClass=*', scope=ldap.SCOPE_BASE)[0]
    self.dn_root = ToStr(root_dse.properties['defaultNamingContext'][0])
    self.dn_forest = ToStr(root_dse.properties['defaultNamingContext'][0])
    self.dn_schema = ToStr(root_dse.properties['schemaNamingContext'][0])
    self.dn_configuration = ToStr(root_dse.properties['configurationNamingContext'][0])

  @property
  def dns_name(self):
    """Constructs the dns name of the domain from the distinguished name."""
    dn_root = self.dn_root
    elements = dn_root.split(',')
    head = []

    for element in elements:
      if re.search('dc\=', element, re.IGNORECASE):
        head.append(element.split('=')[1])
    return '%s' % '.'.join(head)

  def Search(self, ldap_filter, base_dn=None, obj_class=None,
             scope=ldap.SCOPE_SUBTREE, properties=None):
    """Searches ActiveDirectory for objects that match the ldap filter.
    Args:
      ldap_filter: an LDAP filter
      base_dn: the distinguished name of the container to start in
      obj_class: can be any class that inherits from ADObject
      scope: one of the ldap SCOPE_ constants
      properties: a list of properties to retrieve
    Returns:
      A list of objects.
    Raises:
      errors.QueryTimeoutError: if the timeout period is exceeded
      errors.ADDomainNotConnectedError: if a search is attempted before calling
                                        Connect() on the Domain object
    """
    if not self._connected:
      raise errors.ADDomainNotConnectedError

    raw = []
    results = []
    result_class = obj_class
    page_size = 500

    if not base_dn:
      base_dn = self.dn_root

    if not result_class:
      result_class = ADObject

    lc = ldap.controls.SimplePagedResultsControl(True, size=page_size, cookie='')

    try:
      msgid = self._ldap.search_ext(ToStr(base_dn), scope,
                                    ToStr(ldap_filter),
                                    properties,
                                    serverctrls=[lc])
    except ldap.TIMELIMIT_EXCEEDED:
      raise errors.QueryTimeoutError

    while True:
      rtype, rdata, rmsgid, serverctrls = self._ldap.result3(msgid)

      for data in rdata:
        raw.append(data)

      page_controls = [
          c for c in serverctrls if c.controlType == ldap.controls.SimplePagedResultsControl.controlType]

      if page_controls:
        cookie = page_controls[0].cookie

        if cookie:
            lc.cookie = cookie
            msgid = self._ldap.search_ext(ToStr(base_dn),
                                          ldap.SCOPE_SUBTREE,
                                          ToStr(ldap_filter),
                                          serverctrls=[lc])
        else:
            break  # There is no more data to fetch
      else:
        break # AD seems to not return page controls when the total size of
              # the data is less than the page size.

    for result in raw:
      if result[0] is None:
        continue

      for prop in constants.MANDATORY_PROPS_DEFAULT:
        if prop not in result[1]:
          result[1][prop] = ['']
      result[1]['distinguishedName'] = [result[0]]
      obj = result_class(result[0], properties=result[1], domain_obj=self)
      results.append(obj)

    return results


  def NewObject(self, distinguished_name, properties):
    """Creates a new object in Active Directory.

    Args:
      distinguished_name: the desired distinguished name of the object
      properties: a dict of properties and values to apply to the new object

    Note:  Join one of the constants.CAT_ constants with the Domain object's
           dn_configuration property to get a DN for objectCategory.
           (e.g. 'objectCategory': '%s%s'
            % (constants.CAT_USER, ad.dn_configuration))
           Each object also needs the correct objectClass.  Check out the
           constants.CLASS_* constants.
           Also, don't forget that the values of the properties hash should
           all be lists, even if they are single-valued attributes.

    Returns:
      True on success
      False on failure

    Raises:
      errors.ADDomainNotConnectedError: if used before calling Connect()
    """
    if not self._connected:
      raise errors.ADDomainNotConnectedError

    modlist = ldap.modlist.addModlist(properties)
    self._ldap.add_s(distinguished_name, modlist)

  
  def NewUser(self, distinguished_name, properties):
    properties['objectCategory'] = constants.CAT_USER + bytes(self.dn_configuration, 'utf-8')
    properties['objectClass'] = constants.CLASS_USER

    for prop in constants.MANDATORY_PROPS_USER:
      # You can't set these properties on object creation.
      if prop in ('createTimeStamp', 'modifyTimeStamp', 'memberOf', 'distinguishedName'):
        continue

      if prop not in properties:
        raise errors.InvalidPropertyFormatError(
            "%s is missing from properties (see constants.MANDATORY_PROPS_USER).", prop)
    
    self.NewObject(distinguished_name, properties)


  def UpdateObject(self, distinguished_name, current_props, updated_props):
    """Updates an object in Active Directory.

    Args:
      distinguished_name: the distinguished name of the object to be modified
      current_props: a dict of the current properties and values
      updated_props: a dict of the new properties and values

    Returns:
      True on success
      False on failure

    Raises:
      errors.ADDomainNotConnectedError: if used before calling Connect()
    """
    if not self._connected:
      raise errors.ADDomainNotConnectedError

    mod = ldap.modlist.modifyModlist(current_props, updated_props)
    result = self._ldap.modify_s(distinguished_name, mod)

    if result[0] == 103:
      return True

  def DeleteObject(self, distinguished_name):
    """Delete an object from Active Directory.

    Args:
      distinguished_name: the full distinguished name of the object

    Raises:
      errors.ADDomainNotConnectedError: if used before calling Connect()
    """
    if not self._connected:
      raise errors.ADDomainNotConnectedError

    self._ldap.delete_s(distinguished_name)

  def GetObjectByName(self, name):
    """Get an ADObject from AD based on its sAMAccountName.

    Args:
      name: the Windows username (sAMAccountName) of the user

    Returns:
      An ADObject object on success, nothing if no user found.
    """
    result = self.Search('sAMAccountName=%s' % Escape(name))

    if result:
      return result[0]

  def GetUserByName(self, user_name):
    """Get a user object from AD based on its sAMAccountName.

    Args:
      user_name: the Windows username (sAMAccountName) of the user

    Returns:
      A user object on success, nothing if no user found.
    """
    result = self.Search('sAMAccountName=%s'
                         % Escape(user_name), obj_class=User)

    if result:
      return result[0]

  def GetComputerByName(self, computer_name):
    """Get a Computer object from AD based on its hostname.

    Args:
      computer_name: the hostname of the computer.  can be fqdn, sAMAccountName,
                     or computername
    Returns:
      A Computer object on success, nothing if no computer found.
    """
    account = constants.RE_HOSTNAME.match(computer_name).group()

    if account[-1] != '$':
      account += '$'

    result = self.Search('sAMAccountName=%s'
                         % Escape(account), obj_class=Computer)

    if result:
      return result[0]

  def GetGroupByName(self, group_name):
    """Get a Group object from AD based on its hostname.

    Args:
      group_name: the name of the group.
    Returns:
      A Group object on success, nothing if no computer found.
    """
    result = self.Search('sAMAccountName=%s'
                         % Escape(group_name), obj_class=Group)

    if result:
      return result[0]

  def GetObjectByDN(self, distinguished_name):
    """Gets an ADObject object based on the distinguished name(DN).

    Args:
      distinguished_name:  A string with the distinguished name of the object

    Returns:
      An ADObject object on success, nothing if no user found.
    """
    ldap_filter = '(distinguishedName=%s)' % Escape(distinguished_name)
    result = self.Search(ldap_filter, obj_class=User)

    if result:
      return result[0]

  def GetUserByDN(self, distinguished_name):
    """Gets a User object based on the distinguished name(DN).

    Args:
      distinguished_name:  A string with the distinguished name of the object

    Returns:
      A User object on success, nothing if no user found.
    """
    ldap_filter = ('(&(distinguishedName=%s)(objectCategory=%s%s))'
                   % (Escape(distinguished_name),
                      constants.CAT_USER,
                      self.dn_configuration))
    result = self.Search(ldap_filter, obj_class=User)

    if result:
      return result[0]

  def GetComputerByDN(self, distinguished_name):
    """Gets a Computer object based on the distinguished name(DN).

    Args:
      distinguished_name:  A string with the distinguished name of the object

    Returns:
      A Computer object on success, nothing if no user found.
    """
    ldap_filter = ('(&(distinguishedName=%s)(objectCategory=%s%s))'
                   % (Escape(distinguished_name),
                      constants.CAT_COMPUTER,
                      self.dn_configuration))
    result = self.Search(ldap_filter, obj_class=Computer)

    if result:
      return result[0]

  def GetGroupByDN(self, distinguished_name):
    """Gets a Group object based on the distinguished name(DN).

    Args:
      distinguished_name:  A string with the distinguished name of the object

    Returns:
      A User object on success, nothing if no user found.
    """
    ldap_filter = ('(&(distinguishedName=%s)(objectCategory=%s%s))'
                   % (Escape(distinguished_name),
                      constants.CAT_GROUP,
                      self.dn_configuration))
    result = self.Search(ldap_filter, obj_class=Group)

    if result:
      return result[0]

  def GetContainerByDN(self, distinguished_name):
    """Gets a Group object based on the distinguished name(DN).

    Args:
      distinguished_name:  A string with the distinguished name of the object

    Returns:
      A User object on success, nothing if no user found.
    """
    ldap_filter = ''.join(['(&(distinguishedName=%s)'
                           % Escape(distinguished_name),
                           '(|(objectCategory=%s%s)'
                           % (constants.CAT_CN, self.dn_configuration),
                           '(objectCategory=%s%s)'
                           % (constants.CAT_DOMAIN, self.dn_configuration),
                           '(objectCategory=%s%s)))'
                           % (constants.CAT_OU, self.dn_configuration)])
    result = self.Search(ldap_filter, obj_class=Container)

    if result:
      return result[0]

  def GuessObjectType(self, obj):
    """Try to find the best ad_ldap object class for the object.

    Args:
      obj: an ADObject object

    Raises:
      errors.ADObjectClassOnlyError: if the object passed is not an ADObject

    Returns:
      If the object type can be guessed: return an object of that class for
                                         the same distinguished name
      Otherwise return the object unchanged.
    """
    if not isinstance(obj, ADObject):
      raise errors.ADObjectClassOnlyError

    if 'CN=Computer' in obj.object_category:
      return self.GetComputerByDN(obj.distinguished_name)
    elif 'CN=Person' in obj.object_category:
      return self.GetUserByDN(obj.distinguished_name)
    elif 'CN=Group' in obj.object_category:
      return self.GetGroupByDN(obj.distinguished_name)
    elif 'CN=Container' in obj.object_category:
      return self.GetContainterByDN(obj.distinguished_name)
    elif 'CN=Organizational-Unit' in obj.object_category:
      return self.GetContainterByDN(obj.distinguished_name)
    else:
      return obj


class ADObject(object):
  """A generic AD Object."""

  def __init__(self, distinguished_name, properties, domain_obj):
    """Initialize the AD object.

    Args:
      distinguished_name: the full distinguished name of the object
      properties: if a list, a list of properties to retrieve.  if a hash, it is
                  a pre-populated list of properties.  If a hash is provided and
                  mandatory properties are missing, then they will be retrieved
                  by an ldap query
      domain_obj: the Domain object that the AD object is associated with
    """
    get_props = []
    self.properties = {}
    self.properties['distinguishedName'] = [distinguished_name]
    self._property_snapshot = {}

    if isinstance(properties, dict):
      self.properties = properties
      for prop in constants.MANDATORY_PROPS_DEFAULT:
        if prop not in properties:
          get_props.append(prop)
    elif isinstance(properties, list):
      for prop in constants.MANDATORY_PROPS_DEFAULT:
        if prop not in properties:
          properties.append(prop)

      get_props = properties

    self._domain_obj = domain_obj

    if get_props:
      self.GetProperties(get_props)

    self._property_snapshot = copy.deepcopy(self.properties)

  def __repr__(self):
    return 'ADObject: %s' % self.distinguished_name

  @property
  def distinguished_name(self):
    return self.properties['distinguishedName'][0]

  @property
  def object_class(self):
    return self.properties['objectClass']

  @property
  def object_category(self):
    return self.properties['objectCategory'][0]

  @property
  def created_time(self):
    if not self.properties['whenCreated'][0]:
      return 0
    else:
      return TextTimeToUnix(self.properties['whenCreated'][0])

  @property
  def modified_time(self):
    if not self.properties['whenChanged'][0]:
      return 0
    else:
      return TextTimeToUnix(self.properties['whenChanged'][0])

  @property
  def canonical_name(self):
    """Constructs the canonical name from the distinguished name."""
    elements = ToStr(self.distinguished_name).split(',')
    head = []
    tail = []

    for element in elements:
      if re.search('dc\=', element, re.IGNORECASE):
        head.append(element.split('=')[1])
      else:
        tail.append(element.split('=')[1])

    tail.reverse()
    return '%s\\%s' % ('.'.join(head), '\\'.join(tail))

  def GetProperties(self, properties):
    """Updates self.properties with the values from AD.

    Args:
      properties: a list of properties to retrieve

    Raises:
      errors.NonListParameterError: if a string is passed instead of a list
    """
    if properties.__class__.__name__ in ('str', 'unicode'):
      raise errors.NonListParameterError

    ldap_filter = 'distinguishedName=%s' % Escape(self.distinguished_name)
    result = self._domain_obj.Search(ldap_filter,
                                     properties=properties)
    if result:
      for prop in result[0].properties:
        self.properties[prop] = result[0].properties[prop]
        self._property_snapshot[prop] = result[0].properties[prop]

  def Refresh(self):
    """Update all properties with values from AD."""
    self.GetProperties([x for x in self.properties])

  def Move(self, destination):
    """Move an AD object from one part of the directory to another.

    Args:
      destination: the destination DN
    """
    prefix = None

    try:
      prefix = 'CN=%s' % constants.RE_CN.findall(self.distinguished_name)[0]
    except IndexError:
      prefix = 'OU=%s' % constants.RE_OU.findall(self.distinguished_name)[0]

    self.properties['distinguishedName'] = '%s,%s' % (prefix, destination)
    self.SetProperties()

  def Delete(self):
    """Delete the current object from AD."""
    self._domain_obj.DeleteObject(self.distinguished_name)
    self.properties = {}
    self._property_snapshot = {}

  def SetProperties(self):
    """Write changed properties to Active Directory.

    Note: A property must be retrieved at least once before updating.

    Returns:
      True: on success
      False: on failure
    """
    old = {}
    new = {}

    for prop in self._property_snapshot:
      if self._property_snapshot[prop] != self.properties[prop]:
        new[prop] = self.properties[prop]
        old[prop] = self._property_snapshot[prop]

    for prop in self.properties:
      if prop not in self._property_snapshot:
        self._property_snapshot[prop] = [None]

    result = self._domain_obj.UpdateObject(self.distinguished_name, old, new)

    if result:
      self._property_snapshot = copy.deepcopy(self.properties)
      return True
    else:
      return False


class User(ADObject):
  """An Active Directory user object.

  This class exposes user-specific properties and also adds methods for locking,
  unlocking, disabling and enabling accounts.
  """

  def __init__(self, distinguished_name, properties, domain_obj):
    ADObject.__init__(self, distinguished_name, properties, domain_obj)
    get_props = []

    if isinstance(properties, dict):
      self.properties = properties

      for prop in constants.MANDATORY_PROPS_USER:
        if prop not in properties:
          get_props.append(prop)
    elif isinstance(properties, list):
      for prop in constants.MANDATORY_PROPS_USER:
        if prop not in properties:
          properties.append(prop)

      get_props = properties

    if get_props:
      self.GetProperties(get_props)

    self._property_snapshot = copy.deepcopy(self.properties)

  def __repr__(self):
    return 'User: %s' % constants.RE_CN.findall(self.distinguished_name)[0]

  @property
  def user_account_control(self):
    return int(self.properties['userAccountControl'][0])

  @property
  def msds_ua_control_computed(self):
    return int(self.properties['msDS-User-Account-Control-Computed'][0])

  @property
  def display_name(self):
    return self.properties['displayName'][0]

  @property
  def username(self):
    return self.properties['sAMAccountName'][0]

  @property
  def disabled(self):
    return BitmaskBool(self.user_account_control,
                       constants.ADS_UF_ACCOUNTDISABLE)

  @property
  def locked_out(self):
    return BitmaskBool(self.msds_ua_control_computed,
                       constants.ADS_UF_LOCKOUT)

  @property
  def pwd_expired(self):
    return BitmaskBool(self.msds_ua_control_computed,
                       constants.ADS_UF_PASSWORD_EXPIRED)

  @property
  def pwd_never_expires(self):
    return BitmaskBool(self.user_account_control,
                       constants.ADS_UF_DONT_EXPIRE_PASSWD)

  def Unlock(self):
    """Unlock the user object in AD.

    Returns:
      True on success
      False on failure

    Raises:
      UserNotLockedOutError: if the user is not locked out
    """
    if not self.locked_out:
      raise errors.UserNotLockedOutError

    self.properties['lockoutTime'] = ['0']
    self.SetProperties()
    self.GetProperties(['msDS-User-Account-Control-Computed'])

    if not self.locked_out:
      return True
    else:
      return False

  def Disable(self):
    """Disable the user object in AD.

    Returns:
      True on success
      False on failure

    Raises:
      UserNotEnabledError: if the user is already disabled
    """
    if self.disabled:
      raise errors.UserNotEnabledError

    uac = int(self.properties['userAccountControl'][0])
    value = uac | constants.ADS_UF_ACCOUNTDISABLE
    self.properties['userAccountControl'] = [str(value)]
    self.SetProperties()

    if self.disabled:
      return True
    else:
      return False

  def Enable(self):
    """Enable the user object in AD.

    Returns:
      True on success
      False on failure

    Raises:
      UserNotDisabledError: if the user is not disabled
    """
    if not self.disabled:
      raise errors.UserNotDisabledError

    uac = int(self.properties['userAccountControl'][0])
    value = uac ^ constants.ADS_UF_ACCOUNTDISABLE
    self.properties['userAccountControl'] = [ToStr(value)]
    self.SetProperties()

    if not self.disabled:
      return True
    else:
      return False


class Computer(User):
  """An Active Directory computer object.

  This class exposes computer-specific properties at the top level to make it
  easier to work with computer objects.  Note that it also inherits from the
  User class.
  """

  def __init__(self, distinguished_name, properties, domain_obj):
    User.__init__(self, distinguished_name, properties, domain_obj)
    get_props = []

    if isinstance(properties, dict):
      self.properties = properties

      for prop in constants.MANDATORY_PROPS_COMPUTER:
        if prop not in properties:
          get_props.append(prop)
    elif isinstance(properties, list):
      for prop in constants.MANDATORY_PROPS_COMPUTER:
        if prop not in properties:
          properties.append(prop)

      get_props = properties

    if get_props:
      self.GetProperties(get_props)

    self._property_snapshot = copy.deepcopy(self.properties)

  def __repr__(self):
    return 'Computer: %s' % constants.RE_CN.findall(self.distinguished_name)[0]

  @property
  def service_principal_name(self):
    return self.properties['servicePrincipalName']

  @property
  def dns_hostname(self):
    return self.properties['dNSHostName'][0]

  @property
  def os(self):
    return self.properties['operatingSystem'][0]

  @property
  def os_service_pack(self):
    return self.properties['operatingSystemServicePack'][0]

  @property
  def os_version(self):
    return self.properties['operatingSystemVersion'][0]


class Container(ADObject):
  """An Active Directory CN or OU object.

  This class adds the GetChildren method to make it easier to return a list
  of objects in the container.
  """

  def __repr__(self):
    try:
      return ('Container: %s'
              % constants.RE_OU.findall(self.distinguished_name)[0])
    except IndexError:
      return ('Container: %s'
              % constants.RE_CN.findall(self.distinguished_name)[0])

  def GetChildren(self, recursive=False):
    """Retrieves a list of objects inside the container."""
    output = []
    scope = None

    if recursive:
      scope = ldap.SCOPE_SUBTREE
    else:
      scope = ldap.SCOPE_ONELEVEL

    results = self._domain_obj.Search('objectClass=*',
                                      base_dn=self.distinguished_name,
                                      properties=['distinguishedName'],
                                      scope=scope)
    for obj in results:
      output.append(self._domain_obj.GuessObjectType(obj))

    return output


class Group(ADObject):
  """An Active Directory Group object.

  This class provides extra methods for manipulating group memberships.
  """

  def __init__(self, distinguished_name, properties, domain_obj):
    ADObject.__init__(self, distinguished_name, properties, domain_obj)
    get_props = []

    if isinstance(properties, dict):
      self.properties = properties

      for prop in constants.MANDATORY_PROPS_GROUP:
        if prop not in properties:
          get_props.append(prop)
    elif isinstance(properties, list):
      for prop in constants.MANDATORY_PROPS_GROUP:
        if prop not in properties:
          properties.append(prop)

      get_props = properties

    if get_props:
      self.GetProperties(get_props)

    self._property_snapshot = copy.deepcopy(self.properties)

  def __repr__(self):
    return 'Group: %s' % constants.RE_CN.findall(self.distinguished_name)[0]

  def GetMembers(self):
    """Retrieves a list of objects that are members.

    GetMembers will try to find the appropriate object type for the member if
    if is a user, computer or group.

    Returns:
      A list of objects.
    """
    members = []
    output = []

    for member in self.properties['member']:
      result = self._domain_obj.Search('distinguishedName=%s' % Escape(member))

      if result:
        members.append(result[0])

    for obj in members:
      output.append(self._domain_obj.GuessObjectType(obj))

    return output

  def AddMembers(self, member_list):
    """Add users to the group.

    Args:
      member_list: a list of the sAMAccountNames of the users to remove

    Returns:
      True on success
      False on failure

    Raises:
      errors.ADGroupMemberExistsError: if the member was already in the group
      errors.NonListParameterError: if a string was passed by mistake
    """
    if member_list.__class__.__name__ in ('str', 'unicode'):
      raise errors.NonListParameterError

    members_to_add = []

    for name in member_list:
      result = self._domain_obj.GetObjectByName(name)

      if result:
        members_to_add.append(ToBytes(result.distinguished_name))

    for member in members_to_add:
      if member in self.properties['member']:
        raise errors.ADGroupMemberExistsError

    self.properties['member'] += members_to_add
    return self.SetProperties()

  def DeleteMembers(self, member_list):
    """Remove one user from the group.

    Args:
      member_list: a list of the sAMAccountNames of the users to remove

    Returns:
      True on success
      False on failure

    Raises:
      errors.NonListParameterError: if a string was passed by mistake
      errors.ADGroupMemberDoesNotExistError: if the object to be removed is not
                                             a member
    """
    if member_list.__class__.__name__ in ('str', 'unicode'):
      raise errors.NonListParameterError

    members_to_remove = []

    for name in member_list:
      result = self._domain_obj.GetObjectByName(name)

      if result:
        if result.distinguished_name not in self.properties['member']:
          self.GetProperties(['member'])
          raise errors.ADGroupMemberDoesNotExistError

        members_to_remove.append(result.distinguished_name)

    members_to_remove = set(members_to_remove)
    current = set(self.properties['member'])
    new_list = list(current - members_to_remove)

    if not new_list:
      new_list = []

    self.properties['member'] = new_list
    return self.SetProperties()

  def OverwriteMembers(self, member_list):
    """Overwrite the member list with a list of users.

    Args:
      member_list:  a list of sAMAccountNames of users or groups

    Returns:
      True on success
      False on failure

    Raises:
      errors.NonListParameterError: if a string was passed by mistake
    """
    if member_list.__class__.__name__ in ('str', 'unicode'):
      raise errors.NonListParameterError

    members = []

    for name in member_list:
      result = self._domain_obj.GetObjectByName(name)

      if result:
        members.append(result.distinguished_name)
      else:
        raise errors.ADObjectNotFoundError

    old_members = set(self.properties['member'])
    new_members = set(members)

    # If the members are the same, it's a no-op.
    if old_members == new_members:
      return True

    self.properties['member'] = members
    return self.SetProperties()
