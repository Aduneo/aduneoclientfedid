from enum import Enum
from collections import namedtuple

# Registries accessible to different modules
JWKTypesRegistry = {'EC': 'Elliptic Curve',
                    'RSA': 'RSA',
                    'oct': 'Octet sequence',
                    'OKP': 'Octet Key Pair'}

class ParmType(Enum):
    name = 'A string with a name'
    b64 = 'Base64url Encoded'
    b64u = 'Base64urlUint Encoded'
    unsupported = 'Unsupported Parameter'

JWKParameter = namedtuple('Parameter', 'description public required type')

JWKValuesRegistry = {
    'EC': {
        'crv': JWKParameter('Curve', True, True, ParmType.name),
        'x': JWKParameter('X Coordinate', True, True, ParmType.b64),
        'y': JWKParameter('Y Coordinate', True, True, ParmType.b64),
        'd': JWKParameter('ECC Private Key', False, False, ParmType.b64),
    },
    'RSA': {
        'n': JWKParameter('Modulus', True, True, ParmType.b64),
        'e': JWKParameter('Exponent', True, True, ParmType.b64u),
        'd': JWKParameter('Private Exponent', False, False, ParmType.b64u),
        'p': JWKParameter('First Prime Factor', False, False, ParmType.b64u),
        'q': JWKParameter('Second Prime Factor', False, False, ParmType.b64u),
        'dp': JWKParameter('First Factor CRT Exponent',
                           False, False, ParmType.b64u),
        'dq': JWKParameter('Second Factor CRT Exponent',
                           False, False, ParmType.b64u),
        'qi': JWKParameter('First CRT Coefficient',
                           False, False, ParmType.b64u),
        'oth': JWKParameter('Other Primes Info',
                            False, False, ParmType.unsupported),
    },
    'oct': {
        'k': JWKParameter('Key Value', False, True, ParmType.b64),
    },
    'OKP': {
        'crv': JWKParameter('Curve', True, True, ParmType.name),
        'x': JWKParameter('Public Key', True, True, ParmType.b64),
        'd': JWKParameter('Private Key', False, False, ParmType.b64),
    }
}

JWKParamsRegistry = {
    'kty': JWKParameter('Key Type', True, None, None),
    'use': JWKParameter('Public Key Use', True, None, None),
    'key_ops': JWKParameter('Key Operations', True, None, None),
    'alg': JWKParameter('Algorithm', True, None, None),
    'kid': JWKParameter('Key ID', True, None, None),
    'x5u': JWKParameter('X.509 URL', True, None, None),
    'x5c': JWKParameter('X.509 Certificate Chain', True, None, None),
    'x5t': JWKParameter('X.509 Certificate SHA-1 Thumbprint',
                        True, None, None),
    'x5t#S256': JWKParameter('X.509 Certificate SHA-256 Thumbprint',
                             True, None, None)
}

JWKpycaCurveMap = {'secp256r1': 'P-256',
                   'secp384r1': 'P-384',
                   'secp521r1': 'P-521',
                   'secp256k1': 'secp256k1',
                   'brainpoolP256r1': 'BP-256',
                   'brainpoolP384r1': 'BP-384',
                   'brainpoolP512r1': 'BP-512'}

JWKTypesRegistry = {'EC': 'Elliptic Curve',
                    'RSA': 'RSA',
                    'oct': 'Octet sequence',
                    'OKP': 'Octet Key Pair'}

JWSEHeaderParameter = namedtuple('Parameter', 'description mustprotect supported check_fn')
JWEHeaderRegistry = {
    'alg': JWSEHeaderParameter('Algorithm', False, True, None),
    'enc': JWSEHeaderParameter('Encryption Algorithm', False, True, None),
    'zip': JWSEHeaderParameter('Compression Algorithm', False, True, None),
    'jku': JWSEHeaderParameter('JWK Set URL', False, False, None),
    'jwk': JWSEHeaderParameter('JSON Web Key', False, False, None),
    'kid': JWSEHeaderParameter('Key ID', False, True, None),
    'x5u': JWSEHeaderParameter('X.509 URL', False, False, None),
    'x5c': JWSEHeaderParameter('X.509 Certificate Chain', False, False, None),
    'x5t': JWSEHeaderParameter('X.509 Certificate SHA-1 Thumbprint', False,
                               False, None),
    'x5t#S256': JWSEHeaderParameter('X.509 Certificate SHA-256 Thumbprint',
                                    False, False, None),
    'typ': JWSEHeaderParameter('Type', False, True, None),
    'cty': JWSEHeaderParameter('Content Type', False, True, None),
    'crit': JWSEHeaderParameter('Critical', True, True, None),
}

# JWE Allowed encryption algorithms
default_allowed_algs = [
    # Key Management Algorithms
    'RSA-OAEP', 'RSA-OAEP-256',
    'A128KW', 'A192KW', 'A256KW',
    'dir',
    'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
    'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
    'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
    # Content Encryption Algorithms
    'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512',
    'A128GCM', 'A192GCM', 'A256GCM']