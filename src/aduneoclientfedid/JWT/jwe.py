from .common import json_dumps, json_loads, base64url_decode, base64url_encode
from .registries import JWEHeaderRegistry, default_allowed_algs
from .exceptions import InvalidJWEData, InvalidJWEOperation, JWKeyNotFound, \
                    InvalidJWSERegOperation
from .crypto import get_alg
    
decryptlog = []
logdata = []

def jwa_enc(name):
    allowed = default_allowed_algs
    if name not in allowed:
        raise InvalidJWEOperation('Key Encryption Algorithm not allowed')
    return get_alg(name)
    
def jwa_keymgmt(name):
    allowed = default_allowed_algs
    if name not in allowed:
        raise InvalidJWEOperation('Algorithm not allowed')
    return get_alg(name)

def check_crit(crit):
    for k in crit:
        if k not in JWEHeaderRegistry:
            raise InvalidJWEData('Unknown critical header: "%s"' % k)
        else:
            if not JWEHeaderRegistry[k].supported:
                raise InvalidJWEData('Unsupported critical header: '
                                        '"%s"' % k)
                
def merge_headers(h1, h2):
    for k in list(h1.keys()):
        if k in h2:
            raise InvalidJWEData('Duplicate header: "%s"' % k)
    h1.update(h2)
    return h1

def get_jose_header(objects, header=None):
        jh = {}
        if 'protected' in objects:
            ph = json_loads(objects['protected'])
            jh = merge_headers(jh, ph)
        if 'unprotected' in objects:
            uh = json_loads(objects['unprotected'])
            jh = merge_headers(jh, uh)
        if header:
            rh = json_loads(header)
            jh = merge_headers(jh, rh)
        return jh

def unwrap_decrypt(alg, enc, key, enckey, header,
                    aad, iv, ciphertext, tag):
    cek = alg.unwrap(key, enc.wrap_key_size, enckey, header)
    data = enc.decrypt(cek, aad, iv, ciphertext, tag)
    decryptlog.append('Success')
    return data

# Attempts to decrypt a single JWE object
def decrypt(key, jwe, objects):
    if not jwe:
        jwe = {}
    jh = get_jose_header(objects, jwe.get('header', None))

    check_crit(jh.get('crit', {}))

    for hdr in jh:
        if hdr not in JWEHeaderRegistry:
            raise InvalidJWSERegOperation('No header "%s" found in registry'
                                          % hdr)

    alg = jwa_keymgmt(jh.get('alg', None))()
    enc = jwa_enc(jh.get('enc', None))()

    aad = base64url_encode(objects.get('protected', ''))
    if 'aad' in jwe:
        aad += '.' + base64url_encode(objects['aad'])
    aad = aad.encode('utf-8')

    # Case when key is a Keyset 
    if 'keys' in key:
        keys = key
        if 'kid' in jh:
            kid_keys = key.get_keys(jh['kid'])
            if not kid_keys:
                raise JWKeyNotFound('Key ID {} not in key set'.format(
                                    jh['kid']))
            keys = kid_keys

        for k in keys:
            try:
                data = unwrap_decrypt(alg, enc, k,
                                            objects.get('encrypted_key', b''),
                                            jh, aad, objects['iv'],
                                            objects['ciphertext'],
                                            objects['tag'])
                decryptlog.append("Success")
                break
            except Exception as e:  # pylint: disable=broad-except
                keyid = k.get('kid', k.thumbprint())
                decryptlog.append('Key [{}] failed: [{}]'.format(
                                        keyid, repr(e)))

        if "Success" not in decryptlog:
            raise JWKeyNotFound('No working key found in key set')
    
    # Case when its a simple key
    else:
        data = unwrap_decrypt(alg, enc, key,
                                    objects.get('encrypted_key', b''),
                                    jh, aad, objects['iv'],
                                    objects['ciphertext'],
                                    objects['tag'])
    return data

    # TODO: check compression
    # compress = jh.get('zip', None)
    # if compress == 'DEF':
    #     self.plaintext = zlib.decompress(data, -zlib.MAX_WBITS)
    # elif compress is None:
    #     self.plaintext = data
    # else:
    #     raise ValueError('Unknown compression')

# Attempts to decrypt the JWE in JSON serialized or compact form
def general_decrypt(key: dict, objects: dict):
    if 'ciphertext' not in objects:
        raise InvalidJWEOperation("No available ciphertext")
    missingkey = False

    if 'recipients' in objects:
        for rec in objects['recipients']:
            try:
                data = decrypt(key, rec, objects)
                logdata.append(data)
            except Exception as e:  # pylint: disable=broad-except
                if isinstance(e, JWKeyNotFound):
                    missingkey = True
                decryptlog.append('Failed: [%s]' % repr(e))
    else:
        try:
            data = decrypt(key, None, objects)
            logdata.append(data)
        except Exception as e:  # pylint: disable=broad-except
            if isinstance(e, JWKeyNotFound):
                missingkey = True
            decryptlog.append('Failed: [%s]' % repr(e))

    if missingkey:
            raise JWKeyNotFound("Key Not found in JWKSet")
    
# jwe:472
def verify_jwe(key: dict, jwe):
    o = {}
    try:
        try:
            djwe = json_loads(jwe)
            o['iv'] = base64url_decode(djwe['iv'])
            o['ciphertext'] = base64url_decode(djwe['ciphertext'])
            o['tag'] = base64url_decode(djwe['tag'])
            if 'protected' in djwe:
                p = base64url_decode(djwe['protected'])
                o['protected'] = p.decode('utf-8')
            if 'unprotected' in djwe:
                o['unprotected'] = json_dumps(djwe['unprotected'])
            if 'aad' in djwe:
                o['aad'] = base64url_decode(djwe['aad'])
            if 'recipients' in djwe:
                o['recipients'] = []
                for rec in djwe['recipients']:
                    e = {}
                    if 'encrypted_key' in rec:
                        e['encrypted_key'] = \
                            base64url_decode(rec['encrypted_key'])
                    if 'header' in rec:
                        e['header'] = json_dumps(rec['header'])
                    o['recipients'].aond(e)
            else:
                if 'encrypted_key' in djwe:
                    o['encrypted_key'] = \
                        base64url_decode(djwe['encrypted_key'])
                if 'header' in djwe:
                    o['header'] = json_dumps(djwe['header'])

        except ValueError as e:
            c = jwe.split('.')
            if len(c) != 5:
                raise InvalidJWEData() from e
            p = base64url_decode(c[0])
            o['protected'] = p.decode('utf-8')
            ekey = base64url_decode(c[1])
            if ekey != b'':
                o['encrypted_key'] = base64url_decode(c[1])
            o['iv'] = base64url_decode(c[2])
            o['ciphertext'] = base64url_decode(c[3])
            o['tag'] = base64url_decode(c[4])

    except Exception as e:  # pylint: disable=broad-except
        raise InvalidJWEData('Invalid format', repr(e)) from e
    
    general_decrypt(key, o)
    return logdata