from base64 import urlsafe_b64decode, b64encode
import json
from binascii import hexlify
from collections import namedtuple

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils as ec_utils
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac


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

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey, Ed25519PrivateKey
    )
except ImportError:
    Ed25519PublicKey = UnimplementedOKPCurveKey
    Ed25519PrivateKey = UnimplementedOKPCurveKey
try:
    from cryptography.hazmat.primitives.asymmetric.ed448 import (
        Ed448PublicKey, Ed448PrivateKey
    )
except ImportError:
    Ed448PublicKey = UnimplementedOKPCurveKey
    Ed448PrivateKey = UnimplementedOKPCurveKey
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PublicKey, X25519PrivateKey
    )
    priv_bytes = getattr(X25519PrivateKey, 'from_private_bytes', None)
    if priv_bytes is None:
        raise ImportError
except ImportError:
    X25519PublicKey = UnimplementedOKPCurveKey
    X25519PrivateKey = UnimplementedOKPCurveKey
try:
    from cryptography.hazmat.primitives.asymmetric.x448 import (
        X448PublicKey, X448PrivateKey
    )
except ImportError:
    X448PublicKey = UnimplementedOKPCurveKey
    X448PrivateKey = UnimplementedOKPCurveKey


_Ed25519_CURVE = namedtuple('Ed25519', 'pubkey privkey')
_Ed448_CURVE = namedtuple('Ed448', 'pubkey privkey')
_X25519_CURVE = namedtuple('X25519', 'pubkey privkey')
_X448_CURVE = namedtuple('X448', 'pubkey privkey')
_OKP_CURVES_TABLE = {
    'Ed25519': _Ed25519_CURVE(Ed25519PublicKey, Ed25519PrivateKey),
    'Ed448': _Ed448_CURVE(Ed448PublicKey, Ed448PrivateKey),
    'X25519': _X25519_CURVE(X25519PublicKey, X25519PrivateKey),
    'X448': _X448_CURVE(X448PublicKey, X448PrivateKey)
}

# Avoid base64 Incorrect padding error 
def base64url_decode(payload: str):
    size = len(payload) % 4
    if size == 2:
        payload += '=='
    elif size == 3:
        payload += '='
    elif size != 0:
        raise InvalidJWT('Invalid base64 string')
    return urlsafe_b64decode(payload)

def decode_int(n):
    return int(hexlify(base64url_decode(n)), 16)

def get_curve_by_name(curve_name):
    if curve_name == 'P-256':
        return ec.SECP256R1()
    elif curve_name == 'P-384':
        return ec.SECP384R1()
    elif curve_name == 'P-521':
        return ec.SECP521R1()
    elif curve_name == 'secp256k1':
        return ec.SECP256K1()
    elif curve_name == 'BP-256':
        return ec.BrainpoolP256R1()
    elif curve_name == 'BP-384':
        return ec.BrainpoolP384R1()
    elif curve_name == 'BP-512':
        return ec.BrainpoolP512R1()
    else:
        raise InvalidJWKValue('Unknown Curve Name [%s]' % (curve_name))

def oct_key(key: dict):
    return key.get("k")

def rsa_key(key: dict):
    e = decode_int(key.get('e'))
    n = decode_int(key.get('n'))
    return rsa.RSAPublicNumbers(e, n).public_key(default_backend())

def ec_key(key: dict, curve: str):
    if not curve:
        raise InvalidJWSSignature("Signature verification error: wrong verification key provided")
    x = decode_int(key.get('x'))
    y = decode_int(key.get('y'))
    curve_fn = get_curve_by_name(curve)
    return ec.EllipticCurvePublicNumbers(x, y, curve_fn).public_key(default_backend())

def edDSA_key(key: dict, curve: str):
    try:
        pubkey = _OKP_CURVES_TABLE[curve].pubkey
    except KeyError as e:
        raise NotImplementedError('Unknown curve "%s"' % curve) from e
    x = base64url_decode(key.get('x'))
    k = pubkey.from_public_bytes(x)
    return k

def get_fn_from_key(key: dict, **kwargs):
    """
    Checks key type and returns the appropriate verification function
    In case of EC keys, curve keyword argument must be specified
    """
    ktype = key.get('kty')
    if ktype == 'oct':
        return oct_key(key)
    elif ktype == 'RSA':
        return rsa_key(key)
    elif ktype == 'EC':
        curve = kwargs.get("curve", None)
        return ec_key(key, curve)
    elif ktype == 'OKP':
        curve = kwargs.get("curve", None)
        return edDSA_key(key, curve)
    else:
        raise NotImplementedError
  
def hs_verify(payload: bytes, signature: bytes, key: dict, hashfn: tuple):
    print("---- HS signature verifying ----")
    vkey = base64url_decode(get_fn_from_key(key))
    h = hmac.HMAC(vkey, hashfn[0], default_backend())
    h.update(payload)
    h.verify(signature)
    return

def rsa_verify(payload: bytes, signature: bytes, key: dict, paddingfn_hashfn: tuple):
    print("---- RSA signature verifying ----")
    verifyfn = get_fn_from_key(key)
    return verifyfn.verify(signature, payload, paddingfn_hashfn[0], paddingfn_hashfn[1])

def es_verify(payload: bytes, signature: bytes, key: dict, curve_hashfn: tuple):
    print("---- ES signature verifying ----")
    verifyfn = get_fn_from_key(key, curve=curve_hashfn[0])
    r = signature[:len(signature) // 2]
    s = signature[len(signature) // 2:]
    enc_signature = ec_utils.encode_dss_signature(int(hexlify(r), 16), int(hexlify(s), 16))
    return verifyfn.verify(enc_signature, payload, ec.ECDSA(curve_hashfn[1]))

def ed_verify(payload: bytes, signature: bytes, key: dict, *args):
    print("---- EdDSA signature verifying ----")
    curve = key['crv']
    if curve in ['Ed25519', 'Ed448']:
        verifyfn = get_fn_from_key(key, curve=curve)
        return verifyfn.verify(signature, payload)
    raise NotImplementedError
    
def sign(to_sign: bytes, signature: bytes, key: dict, alg: str):
    # Possible algorithms
    padfn256 = padding.PSS(padding.MGF1(hashes.SHA256()), hashes.SHA256.digest_size)
    padfn384 = padding.PSS(padding.MGF1(hashes.SHA384()), hashes.SHA384.digest_size)
    padfn512 = padding.PSS(padding.MGF1(hashes.SHA512()), hashes.SHA512.digest_size)
    SHA256 = hashes.SHA256()
    SHA384 = hashes.SHA384()
    SHA512 = hashes.SHA512()
    PKCS1v15 = padding.PKCS1v15()
    hsfn = hs_verify
    rsafn = rsa_verify
    esfn = es_verify
    edfn = ed_verify
    algorithms_registry = {
        'HS256': (hsfn, SHA256),
        'HS384': (hsfn, SHA384),
        'HS512': (hsfn, SHA512),
        'RS256': (rsafn, PKCS1v15, SHA256),
        'RS384': (rsafn, PKCS1v15, SHA384),
        'RS512': (rsafn, PKCS1v15, SHA512),
        'ES256': (esfn, 'P-256', SHA256),
        'ES256K': (esfn, 'secp256k1', SHA256),
        'ES384': (esfn, 'P-384', SHA384),
        'ES512': (esfn, 'P-521', SHA512),
        'PS256': (rsafn, padfn256, SHA256),
        'PS384': (rsafn, padfn384, SHA384),
        'PS512': (rsafn, padfn512, SHA512),
        #'RSA1_5': _Rsa15,                          # TODO: JWE enc alg
        #'RSA-OAEP': _RsaOaep,                      # TODO: JWE enc alg
        #'RSA-OAEP-256': _RsaOaep256,               # TODO: JWE enc alg
        # 'A128KW': _A128KW,                        # TODO: JWE enc alg
        # 'A192KW': _A192KW,                        # TODO: JWE enc alg
        # 'A256KW': _A256KW,                        # TODO: JWE enc alg
        # 'dir': _Direct,                           # TODO: JWE enc alg
        # 'ECDH-ES': _EcdhEs,                       # TODO: JWE enc alg
        # 'ECDH-ES+A128KW': _EcdhEsAes128Kw,        # TODO: JWE enc alg
        # 'ECDH-ES+A192KW': _EcdhEsAes192Kw,        # TODO: JWE enc alg
        # 'ECDH-ES+A256KW': _EcdhEsAes256Kw,        # TODO: JWE enc alg
        'EdDSA': (edfn, ),                    
        # 'A128GCMKW': _A128GcmKw,                  # TODO: JWE enc alg
        # 'A192GCMKW': _A192GcmKw,                  # TODO: JWE enc alg
        # 'A256GCMKW': _A256GcmKw,                  # TODO: JWE enc alg
        # 'PBES2-HS256+A128KW': _Pbes2Hs256A128Kw,  # TODO: JWE enc alg
        # 'PBES2-HS384+A192KW': _Pbes2Hs384A192Kw,  # TODO: JWE enc alg
        # 'PBES2-HS512+A256KW': _Pbes2Hs512A256Kw,  # TODO: JWE enc alg
        # 'A128CBC-HS256': _A128CbcHs256,           # TODO: JWE enc alg
        # 'A192CBC-HS384': _A192CbcHs384,           # TODO: JWE enc alg
        # 'A256CBC-HS512': _A256CbcHs512,           # TODO: JWE enc alg
        # 'A128GCM': _A128Gcm,                      # TODO: JWE enc alg
        # 'A192GCM': _A192Gcm,                      # TODO: JWE enc alg
        # 'A256GCM': _A256Gcm,                      # TODO: JWE enc alg
        'BP256R1': (esfn, 'BP-256', SHA256),        # Not Tested
        'BP384R1': (esfn, 'BP-384', SHA384),        # Not Tested
        'BP512R1': (esfn, 'BP-512', SHA512)         # Not Tested
    }
    
    # Determiner l'algorithme utiliser
    if alg in algorithms_registry:
        fdata = algorithms_registry[alg]
        signing_function: function = fdata[0]
        signing_function(to_sign, signature, key, fdata[1:])
        print("Signature validation successful")
    else:
        raise InvalidJWSSignature(f"Signing algorithm {alg} not supported")

def validate_compact_JWS(key: dict, jose_header: str, payload_b64encoded: bytes, signature_b64encoded: bytes):
    # verify that jose header is a valid json
    json_jose_header: dict = json.loads(jose_header)
    jose_header_clean: bytes = json.dumps(json_jose_header).encode("utf-8")

    alg: str = json_jose_header['alg']

    payload = base64url_decode(payload_b64encoded)
    signature = base64url_decode(signature_b64encoded)

    to_sign =  b'.'.join([b64encode(jose_header_clean.replace(b" ", b"")), b64encode(payload)])
    sign(to_sign.replace(b"=",b""), signature, key, alg)

def validate_JWE(key: dict, jwe: str):
    ...

def verify_compact_JWT(key:dict, jwt):
    jwt_list = jwt.split('.')
    jose_header_b64encoded = jwt_list[0]
    payload_b64encoded = jwt_list[1]
    signature_b64encoded = jwt_list[2]
    try:
        jose_header = base64url_decode(jose_header_b64encoded).decode("utf-8")
    except UnicodeDecodeError:
        raise InvalidJWSSignature("Invalid JOSE header - not utf8 encoded")
    is_JWS = False
    is_JWE = False
    c = jwt.count('.')
    if c == 2:
        is_JWS = True
    elif c == 4:
        is_JWE = True
    else:
        raise InvalidJWSSignature("Token format unrecognized")
    if is_JWS:
        print('JWS Validation: ')
        validate_compact_JWS(key, 
                             jose_header, 
                             payload_b64encoded, 
                             signature_b64encoded)
    elif is_JWE:
        print('JWE Validation: ')
        validate_JWE(key=key, jwe=jwt)

# comment
def validate_format(key, payload, signature, protected, header):
    protected_json = {}
    if protected:
        protected_json = json.loads(protected)
        if not isinstance(protected_json, dict):
            raise InvalidJWSSignature('Invalid Protected header')
    else:
        protected = ''
        
    if header:
        if not isinstance(header, dict):
            raise InvalidJWSSignature('Invalid Unprotected header')
    else:
        header = {}

    if 'kid' in protected_json and 'kid' in header:
        raise InvalidJWSSignature('Duplicate header: \"kid\"')
    
    # TODO: Check headers JWS:271
    jose_header = {**protected_json, **header}
    alg: str = jose_header.get('alg')

    # Find appropriate key in key set
    if 'keys' in key:
        if isinstance(key['keys'], list):
            if 'kid' in jose_header:
                kid_keys = [k for k in key['keys'] if k.get('kid') == jose_header['kid']]
                # We try to verify with the last key if multiple keys found
                try:
                    key = kid_keys[-1]
                except IndexError:
                    raise JWKeyNotFound("key not found")
            else:
                # Sinon on peut essayer de vérifier avec la première clé du keyset 
                raise InvalidJWSSignature(f"kid parameter not found in JOSE header")
        else: 
            raise InvalidJWKSet(f"{type(key['keys']) =}, type list required")

    to_sign =  b'.'.join([b64encode(protected.encode("utf8")), b64encode(payload)])
    sign(to_sign.replace(b"=",b""), signature, key, alg)

def validate_deserialized_JWT(key: dict, o: dict):
    is_valid = False
    missingkey = False
    log_errors = []
    if 'signature' in o:
        payload = o.get('payload')
        try:
            validate_format(key, payload, o['signature'], 
                            o.get('protected', None), o.get('header', None))
            is_valid = True
        except Exception as e:  
            if isinstance(e, JWKeyNotFound):
                missingkey = True
            log_errors.append('Failed: [%s]' % repr(e))

    elif 'signatures' in o:
        payload = o.get('payload')
        for o in o['signatures']:
            try:
                validate_format(key, payload, o['signature'], 
                            o.get('protected', None), o.get('header', None))
                # Ok if at least one verifies
                is_valid = True
            except Exception as e: 
                if isinstance(e, JWKeyNotFound):
                    missingkey = True
                log_errors.append('Failed: [%s]' % repr(e))
    else:
        raise InvalidJWSSignature('No signatures available')

    if not is_valid:
        if missingkey:
            raise JWKeyNotFound('No working key found in key set')
        raise InvalidJWSSignature('Verification failed for all signatures ' + repr(log_errors))

def deserialize_signature(s):
    o = {'signature': base64url_decode(str(s['signature']))}
    if 'protected' in s:
        p = base64url_decode(str(s['protected']))
        o['protected'] = p.decode('utf-8')
    if 'header' in s:
        o['header'] = s['header']
    return o

def deserialize_JWT(key:dict, djwt: dict):
    o = {}
    try:
        if 'signatures' in djwt:
            o['signatures'] = []
            for s in djwt['signatures']:
                os = deserialize_signature(s)
                o['signatures'].append(os)
        else:
            o = deserialize_signature(djwt)
        if 'payload' in djwt:
            if o.get('b64', True):
                o['payload'] = base64url_decode(str(djwt['payload']))
            else:
                o['payload'] = djwt['payload']
    except Exception as e:
        raise InvalidJWT('Invalid format') from e
    validate_deserialized_JWT(key, o)

def verify_JWT(key: dict, jwt):
    is_serialized = False
    is_compact = False
    if isinstance(jwt, str):
        try:
            jwt = json.loads(jwt)
            is_serialized = True
        except:
            if '.' in jwt:
                is_compact = True
    elif isinstance(jwt, dict):
        is_serialized = True
    
    if is_serialized:
        deserialize_JWT(key, jwt)
    elif is_compact:
        verify_compact_JWT(key, jwt)