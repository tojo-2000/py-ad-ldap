# Tests for py-ad-ldap

This directory contains comprehensive unit tests for the ad_ldap module.

## Test Coverage

### Utility Functions Tests (`test_utilities.py`)
- `ADFileTimeToUnix()` - AD filetime to Unix epoch conversion
- `ToStr()` - Bytes to string conversion
- `ToBytes()` - String to bytes conversion
- `BitmaskBool()` - Bitmask boolean flag checking
- `Escape()` - LDAP filter character escaping
- `ADTextTimeToUnix()` - AD text time format conversion

### Constants Tests (`test_constants.py`)
- Mandatory properties constants (DEFAULT, USER, COMPUTER, GROUP)
- User account control flag constants
- Regular expression patterns for hostname and time format
- Epoch constant validation

### Error Classes Tests (`test_errors.py`)
- Error class hierarchy validation
- Individual error classes (ObjectPropertyNotFoundError, UserNotDisabledError, etc.)
- Error instantiation and inheritance

### Domain Class Tests (`test_domain.py`)
- Domain initialization and properties
- Domain repr() output
- DNS name extraction from distinguished names
- Domain disconnect functionality
- Search method functionality
- Object retrieval methods (GetObjectByName, etc.)

### ADObject and Subclasses Tests (`test_adobject.py`)
- ADObject creation and properties
- User class properties and methods
- Computer class properties
- Group class properties
- Container class functionality
- Property setting (SetProperties method)

## Running the Tests

```bash
python3 -m unittest discover tests -v
```

Or run a specific test file:

```bash
python3 -m unittest tests.test_utilities -v
```

Or run a specific test class:

```bash
python3 -m unittest tests.test_domain.TestDomainDNSName -v
```

## Test Results

Current test suite: **88 tests**

The tests cover utility functions, constants, error handling, and basic Domain and ADObject functionality. Tests that require actual LDAP connections are mocked using unittest.mock.

## Notes

- Tests use mocking extensively to avoid requiring a real AD/LDAP server
- Some complex tests involving full LDAP connections may require additional configuration
- The test suite validates core functionality including type conversions, filtering, and object manipulation
