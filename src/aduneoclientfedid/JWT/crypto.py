from binascii import hexlify
from collections import namedtuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization, constant_time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils as ec_utils
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography import x509
from cryptography.hazmat.primitives.padding import PKCS7

from .common import decode_int, encode_int_b64, base64url_decode, base64url_encode, encode_int
from .exceptions import UnimplementedOKPCurveKey, InvalidJWKValue, \
                InvalidJWSSignature, InvalidJWKType, InvalidJWEKeyType, \
                InvalidJWEKeyLength
from .registries import ParmType, JWKpycaCurveMap, JWKValuesRegistry, \
                JWKTypesRegistry, JWKParamsRegistry

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

def inbytes(x):
    return x // 8

def _bitsize(x):
    return len(x) * 8

def _rsa_pub(key: dict):
    e = decode_int(key.get('e'))
    n = decode_int(key.get('n'))
    return rsa.RSAPublicNumbers(e, n).public_key(default_backend())

def _rsa_pri(key):
    p = decode_int(key.get('p'))
    q = decode_int(key.get('q'))
    d = decode_int(key.get('d'))
    dp = decode_int(key.get('dp'))
    dq = decode_int(key.get('dq'))
    qi = decode_int(key.get('qi'))
    e = decode_int(key.get('e'))
    n = decode_int(key.get('n'))
    return rsa.RSAPrivateNumbers(p, q, d, dp, dq, qi, rsa.RSAPublicNumbers(e, n)).private_key(default_backend())

def _ec_pri(**kwargs):
    ...

def _okp_pri():
    ...
    
def get_fn_from_private_key(key, arg=None):
    ktype = key.get('kty')
    if ktype == 'oct':
        return key.get('k')
    elif ktype == 'RSA':
        return _rsa_pri(key)
    elif ktype == 'EC':
        return _ec_pri(arg)
    elif ktype == 'OKP':
        return _okp_pri()
    else:
        raise NotImplementedError

def get_fn_from_public_key(key: dict, **kwargs):
    """
    Checks key type and returns the appropriate verification function
    In case of EC keys, curve keyword argument must be specified
    """
    ktype = key.get('kty')
    if ktype == 'oct':
        return oct_key(key)
    elif ktype == 'RSA':
        return _rsa_pub(key)
    elif ktype == 'EC':
        curve = kwargs.get("curve", None)
        return ec_key(key, curve)
    elif ktype == 'OKP':
        curve = kwargs.get("curve", None)
        return edDSA_key(key, curve)
    else:
        raise NotImplementedError
    
# Encryption classes
class _AesCbcHmacSha2:

    keysize = None

    def __init__(self, hashfn):
        self.backend = default_backend()
        self.hashfn = hashfn
        self.blocksize = algorithms.AES.block_size
        self.wrap_key_size = self.keysize * 2

    def _mac(self, k, a, iv, e):
        al = encode_int(_bitsize(a), 64)
        h = hmac.HMAC(k, self.hashfn, backend=self.backend)
        h.update(a)
        h.update(iv)
        h.update(e)
        h.update(al)
        m = h.finalize()
        return m[:inbytes(self.keysize)]

    def decrypt(self, k, a, iv, e, t):
        if len(k) != inbytes(self.wrap_key_size):
            raise ValueError("Invalid input key size")

        hkey = k[:inbytes(self.keysize)]
        dkey = k[inbytes(self.keysize):]

        # verify mac
        if not constant_time.bytes_eq(t, self._mac(hkey, a, iv, e)):
            raise InvalidSignature('Failed to verify MAC')

        # decrypt
        cipher = Cipher(algorithms.AES(dkey), modes.CBC(iv),
                        backend=self.backend)
        decryptor = cipher.decryptor()
        d = decryptor.update(e) + decryptor.finalize()
        unpadder = PKCS7(self.blocksize).unpadder()
        return unpadder.update(d) + unpadder.finalize()
    
class _A128CbcHs256(_AesCbcHmacSha2):

    name = 'A128CBC-HS256'
    description = "AES_128_CBC_HMAC_SHA_256 authenticated"
    keysize = 128
    algorithm_usage_location = 'enc'
    algorithm_use = 'enc'

    def __init__(self):
        super(_A128CbcHs256, self).__init__(hashes.SHA256())

class _A192CbcHs384(_AesCbcHmacSha2):

    name = 'A192CBC-HS384'
    description = "AES_192_CBC_HMAC_SHA_384 authenticated"
    keysize = 192
    algorithm_usage_location = 'enc'
    algorithm_use = 'enc'

    def __init__(self):
        super(_A192CbcHs384, self).__init__(hashes.SHA384())


class _A256CbcHs512(_AesCbcHmacSha2):

    name = 'A256CBC-HS512'
    description = "AES_256_CBC_HMAC_SHA_512 authenticated"
    keysize = 256
    algorithm_usage_location = 'enc'
    algorithm_use = 'enc'

    def __init__(self):
        super(_A256CbcHs512, self).__init__(hashes.SHA512())

class _RSA:

    def __init__(self, padfn):
        self.padfn = padfn

    def _check_key(self, key):
        if key['kty'] != 'RSA':
            raise InvalidJWEKeyType('RSA', key['kty'])

    def unwrap(self, key, bitsize, ek, headers):
        self._check_key(key)
        rk = get_fn_from_private_key(key)
        cek = rk.decrypt(ek, self.padfn)
        if _bitsize(cek) != bitsize:
            raise InvalidJWEKeyLength(bitsize, _bitsize(cek))
        return cek

class _RsaOaep(_RSA):

    name = 'RSA-OAEP'
    description = "RSAES OAEP using default parameters"
    keysize = 2048
    algorithm_usage_location = 'alg'
    algorithm_use = 'kex'

    def __init__(self):
        super(_RsaOaep, self).__init__(
            padding.OAEP(padding.MGF1(hashes.SHA1()),
                         hashes.SHA1(), None))
        
def todo():
    ...

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
  
def hs_verify(payload: bytes, signature: bytes, key: dict, hashfn: tuple):
    print("---- HS signature verifying ----")
    vkey = base64url_decode(get_fn_from_public_key(key))
    h = hmac.HMAC(vkey, hashfn[0], default_backend())
    h.update(payload)
    h.verify(signature)
    return

def rsa_verify(payload: bytes, signature: bytes, key: dict, paddingfn_hashfn: tuple):
    print("---- RSA signature verifying ----")
    verifyfn = get_fn_from_public_key(key)

    return verifyfn.verify(signature, payload, paddingfn_hashfn[0], paddingfn_hashfn[1])

def es_verify(payload: bytes, signature: bytes, key: dict, curve_hashfn: tuple):
    print("---- ES signature verifying ----")
    verifyfn = get_fn_from_public_key(key, curve=curve_hashfn[0])
    r = signature[:len(signature) // 2]
    s = signature[len(signature) // 2:]
    enc_signature = ec_utils.encode_dss_signature(int(hexlify(r), 16), int(hexlify(s), 16))
    return verifyfn.verify(enc_signature, payload, ec.ECDSA(curve_hashfn[1]))

def ed_verify(payload: bytes, signature: bytes, key: dict, *args):
    print("---- EdDSA signature verifying ----")
    curve = key['crv']
    if curve in ['Ed25519', 'Ed448']:
        verifyfn = get_fn_from_public_key(key, curve=curve)
        return verifyfn.verify(signature, payload)
    raise NotImplementedError

def get_alg(name):
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
        'RSA-OAEP': _RsaOaep,                      # TODO: JWE enc alg
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
        'A128CBC-HS256': _A128CbcHs256,
        'A192CBC-HS384': _A192CbcHs384,
        'A256CBC-HS512': _A256CbcHs512,
        'A128GCM': todo,
        'A192GCM': todo,
        'A256GCM': todo,
        'BP256R1': (esfn, 'BP-256', SHA256),        # Not Tested
        'BP384R1': (esfn, 'BP-384', SHA384),        # Not Tested
        'BP512R1': (esfn, 'BP-512', SHA512)         # Not Tested
    }
    
    if name in algorithms_registry:
        return algorithms_registry[name]
    else:
        raise InvalidJWSSignature(f"Algorithm {name} not supported")

def sign(to_sign: bytes, signature: bytes, key: dict, alg: str):
    fdata = get_alg(alg)
    signature_type: function = fdata[0]
    signature_type(to_sign, signature, key, fdata[1:])
    print("Signature validation successful")
    
# JWE 
# Import from PEM funcs
def okp_curve_from_key(key):
    for name, val in _OKP_CURVES_TABLE.items():
        if isinstance(key, (val.pubkey, val.privkey)):
            return name
    raise InvalidJWKValue('Invalid OKP Key object %r' % key)

def test_and_update_jwk(**kwargs):
    newkey = {}
    key_vals = 0

    names = list(kwargs.keys())

    for name in list(JWKParamsRegistry.keys()):
        if name in kwargs:
            newkey[name] = kwargs[name]
            while name in names:
                names.remove(name)

    kty = newkey.get('kty')
    if kty not in JWKTypesRegistry:
        raise InvalidJWKType(kty)

    for name in list(JWKValuesRegistry[kty].keys()):
        if name in kwargs:
            newkey[name] = kwargs[name]
            key_vals += 1
            while name in names:
                names.remove(name)

    for name, val in JWKValuesRegistry[kty].items():
        if val.required and name not in newkey:
            raise InvalidJWKValue('Missing required value %s' % name)
        if val.type == ParmType.unsupported and name in newkey:
            raise InvalidJWKValue('Unsupported parameter %s' % name)
        if val.type == ParmType.b64 and name in newkey:
            # Check that the value is base64url encoded
            try:
                base64url_decode(newkey[name])
            except Exception as e:  # pylint: disable=broad-except
                raise InvalidJWKValue(
                    '"%s" is not base64url encoded' % name
                ) from e
        if val.type == ParmType.b64u and name in newkey:
            # Check that the value is Base64urlUInt encoded
            try:
                decode_int(newkey[name])
            except Exception as e:  # pylint: disable=broad-except
                raise InvalidJWKValue(
                    '"%s" is not Base64urlUInt encoded' % name
                ) from e

    # Unknown key parameters are allowed
    for name in names:
        newkey[name] = kwargs[name]

    if key_vals == 0:
        raise InvalidJWKValue('No Key Values found')

    # check key_ops
    if 'key_ops' in newkey:
        for ko in newkey['key_ops']:
            c = 0
            for cko in newkey['key_ops']:
                if ko == cko:
                    c += 1
            if c != 1:
                raise InvalidJWKValue('Duplicate values in "key_ops"')

    # check use/key_ops consistency
    if 'use' in newkey and 'key_ops' in newkey:
        sigl = ['sign', 'verify']
        encl = ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey',
                'deriveKey', 'deriveBits']
        if newkey['use'] == 'sig':
            for op in encl:
                if op in newkey['key_ops']:
                    raise InvalidJWKValue('Incompatible "use" and'
                                            ' "key_ops" values specified at'
                                            ' the same time')
        elif newkey['use'] == 'enc':
            for op in sigl:
                if op in newkey['key_ops']:
                    raise InvalidJWKValue('Incompatible "use" and'
                                            ' "key_ops" values specified at'
                                            ' the same time')
    return newkey

def export_as_dict_pri_rsa(key, **params):
    pn = key.private_numbers()
    params.update(
        kty='RSA',
        n= encode_int_b64(pn.public_numbers.n),
        e= encode_int_b64(pn.public_numbers.e),
        d= encode_int_b64(pn.d),
        p= encode_int_b64(pn.p),
        q= encode_int_b64(pn.q),
        dp= encode_int_b64(pn.dmp1),
        dq= encode_int_b64(pn.dmq1),
        qi= encode_int_b64(pn.iqmp)
    )
    clean_key = test_and_update_jwk(**params)
    return clean_key

def export_as_dict_pub_rsa(key, **params):
    pn = key.public_numbers()
    params.update(
        kty='RSA',
        n= encode_int_b64(pn.n),
        e= encode_int_b64(pn.e)
    )
    clean_key = test_and_update_jwk(**params)
    return clean_key

def export_as_dict_pri_ec(key, **params):
    pn = key.private_numbers()
    key_size = pn.public_numbers.curve.key_size
    params.update(
        kty='EC',
        crv=JWKpycaCurveMap[key.curve.name],
        x= encode_int_b64(pn.public_numbers.x, key_size),
        y= encode_int_b64(pn.public_numbers.y, key_size),
        d= encode_int_b64(pn.private_value, key_size)
    )
    clean_key = test_and_update_jwk(**params)
    return clean_key

def export_as_dict_pub_ec(key, **params):
    pn = key.public_numbers()
    key_size = pn.curve.key_size
    params.update(
        kty='EC',
        crv=JWKpycaCurveMap[key.curve.name],
        x= encode_int_b64(pn.x, key_size),
        y= encode_int_b64(pn.y, key_size),
    )
    clean_key = test_and_update_jwk(**params)
    return clean_key

def export_as_dict_pri_okp(key, **params):
    params.update(
            kty='OKP',
            crv= okp_curve_from_key(key),
            d=base64url_encode(key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption())),
            x=base64url_encode(key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw))
        )
    clean_key = test_and_update_jwk(**params)
    return clean_key

def export_as_dict_pub_okp(key, **params):
    params.update(
            kty='OKP',
            crv= okp_curve_from_key(key),
            x=base64url_encode(key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw))
        )
    clean_key = test_and_update_jwk(**params)
    return clean_key
 
def export_to_dict(key):
    if isinstance(key, rsa.RSAPrivateKey):
        return export_as_dict_pri_rsa(key)
    elif isinstance(key, rsa.RSAPublicKey):
        return export_as_dict_pub_rsa(key)
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        return export_as_dict_pri_ec(key)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        return export_as_dict_pub_ec(key)
    elif isinstance(key, (Ed25519PrivateKey, Ed448PrivateKey)):
        return export_as_dict_pri_okp(key)
    elif isinstance(key, (Ed25519PublicKey, Ed448PublicKey)):
        return export_as_dict_pub_okp(key)
    else:
        raise InvalidJWKValue('Unknown key object %r' % key)

def import_from_PEM(data, password=None, kid=None):
    try:
        key = serialization.load_pem_private_key(
            data, password=password, backend=default_backend())
    except ValueError as e:
        if password is not None:
            raise e
        try:
            key = serialization.load_pem_public_key(
                data, backend=default_backend())
        except ValueError:
            try:
                cert = x509.load_pem_x509_certificate(
                    data, backend=default_backend())
                key = cert.public_key()
            except ValueError:
                # pylint: disable=raise-missing-from
                raise e
    return export_to_dict(key)