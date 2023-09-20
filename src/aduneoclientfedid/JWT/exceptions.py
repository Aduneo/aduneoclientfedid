from .registries import JWKTypesRegistry

# Exceptions
class JWException(Exception):
    pass

class JWKeyNotFound(JWException):
    """
    Raised when key needed not found 
    related to kid header
    """
    def __init__(self, message=None):
        if message:
            msg = message
        else:
            msg = 'Key Not Found'
        super(JWKeyNotFound, self).__init__(msg)

class InvalidJWSFormat(JWException):
    """
    Raised when a JWS has an invalid format
    """
    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = str(message)
        else:
            msg = 'Invalid JWS Format'
        if exception:
            msg += ' {%s}' % str(exception)
        super(InvalidJWSFormat, self).__init__(msg)

class InvalidJWSSignature(JWException):
    """
    Raised when a signature cannot be validated
    """
    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = str(message)
        else:
            msg = 'Unknown Signature Verification Failure'
        if exception:
            msg += ' {%s}' % str(exception)
        super(InvalidJWSSignature, self).__init__(msg)

class InvalidJWT(JWException):
    """
    This exception is raised when the JWT has an invalid format or content 
    """
    def __init__(self, message=None):
        if message:
            msg = message
        else:
            msg = 'Invalid JWT token'
        super(InvalidJWT, self).__init__(msg)

class InvalidJWKValue(JWException):
    """Invalid JWK usage Exception.

    This exception is raised when an invalid key usage is requested,
    based on the key type and declared usage constraints.
    """
    def __init__(self, message=None):
        if message:
            msg = message
        else:
            msg = 'Invalid JWK value'
        super(InvalidJWKSet, self).__init__(msg)

class InvalidJWKSet(JWException):
    """
    Raised when the JWK Set contains a format error
    """
    def __init__(self, message=None):
        if message:
            msg = message
        else:
            msg = 'Invalid JWK set'
        super(InvalidJWKSet, self).__init__(msg)

class InvalidJWKType(JWException):
    """Invalid JWK Type Exception.

    This exception is raised when an invalid parameter type is used.
    """

    def __init__(self, value=None):
        super(InvalidJWKType, self).__init__()
        self.value = value

    def __str__(self):
        return 'Unknown type "%s", valid types are: %s' % (
            self.value, list(JWKTypesRegistry.keys()))
    
class UnimplementedOKPCurveKey:
    @classmethod
    def generate(cls):
        raise NotImplementedError

    @classmethod
    def from_public_bytes(cls, *args):
        raise NotImplementedError

    @classmethod
    def from_private_bytes(cls, *args):
        raise NotImplementedError
    
## JWE Exceptions
class InvalidJWEData(JWException):
    """Invalid JWE Object.

    This exception is raised when the JWE Object is invalid and/or
    improperly formatted.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = message
        else:
            msg = 'Unknown Data Verification Failure'
        if exception:
            msg += ' {%s}' % str(exception)
        super(InvalidJWEData, self).__init__(msg)

class InvalidJWEOperation(JWException):
    """Invalid JWS Object.

    This exception is raised when a requested operation cannot
    be execute due to unsatisfied conditions.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = message
        else:
            msg = 'Unknown Operation Failure'
        if exception:
            msg += ' {%s}' % repr(exception)
        super(InvalidJWEOperation, self).__init__(msg)

class InvalidJWSERegOperation(JWException):
    """Invalid JWSE Header Registry Operation.

    This exception is raised when there is an error in trying to add a JW
    Signature or Encryption header to the Registry.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = message
        else:
            msg = 'Unknown Operation Failure'
        if exception:
            msg += ' {%s}' % repr(exception)
        super(InvalidJWSERegOperation, self).__init__(msg)

class InvalidJWEKeyType(JWException):
    """Invalid JWE Key Type.

    This exception is raised when the provided JWK Key does not match
    the type required by the specified algorithm.
    """

    def __init__(self, expected, obtained):
        msg = 'Expected key type %s, got %s' % (expected, obtained)
        super(InvalidJWEKeyType, self).__init__(msg)

class InvalidJWEKeyLength(JWException):
    """Invalid JWE Key Length.

    This exception is raised when the provided JWK Key does not match
    the length required by the specified algorithm.
    """

    def __init__(self, expected, obtained):
        msg = 'Expected key of length %d, got %d' % (expected, obtained)
        super(InvalidJWEKeyLength, self).__init__(msg)