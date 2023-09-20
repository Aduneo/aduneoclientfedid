from base64 import b64encode
import json

from .common import base64url_decode
from .crypto import sign
from .exceptions import InvalidJWSSignature, InvalidJWSFormat, InvalidJWT, \
                JWKeyNotFound, InvalidJWKSet

def validate_compact_JWS(key: dict, jose_header, payload_b64encoded: bytes, signature_b64encoded: bytes):
    # verify that jose header is a valid json
    json_jose_header: dict = json.loads(base64url_decode(jose_header).decode("utf-8"))

    alg: str = json_jose_header['alg']

    payload = base64url_decode(payload_b64encoded)
    signature = base64url_decode(signature_b64encoded)

    to_sign =  b'.'.join([jose_header.encode("utf8"), b64encode(payload)])
    sign(to_sign.replace(b"=",b""), signature, key, alg)

def verify_compact_jws(key:dict, jwt):
    jwt_list = jwt.split('.')
    jose_header_b64encoded = jwt_list[0]
    payload_b64encoded = jwt_list[1]
    signature_b64encoded = jwt_list[2]
    try:
        ## base64url_decode(jose_header_b64encoded).decode("utf-8")
        jose_header_b64 = jose_header_b64encoded
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
                             jose_header_b64, 
                             payload_b64encoded, 
                             signature_b64encoded)
    elif is_JWE:
        raise InvalidJWSFormat("JWE Format detected while the attempt was to validate a JWS")

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

def validate_deserialized_jws(key: dict, o: dict):
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

def deserialize_jws(key: dict, djwt: dict):
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
    validate_deserialized_jws(key, o)

def verify_jws(key: dict, jws):
    is_serialized = False
    is_compact = False
    if isinstance(jws, str):
        try:
            jws = json.loads(jws)
            is_serialized = True
        except:
            if '.' in jws:
                is_compact = True
    elif isinstance(jws, dict):
        is_serialized = True
    
    if is_serialized:
        deserialize_jws(key, jws)
    elif is_compact:
        verify_compact_jws(key, jws)