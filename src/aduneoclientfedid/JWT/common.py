from base64 import urlsafe_b64decode, urlsafe_b64encode
from binascii import hexlify, unhexlify
import json

from .exceptions import InvalidJWT

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

def base64url_encode(payload):
    if not isinstance(payload, bytes):
        payload = payload.encode('utf-8')
    encode = urlsafe_b64encode(payload)
    return encode.decode('utf-8').rstrip('=')

def json_dumps(string):
    if isinstance(string, bytes):
        string = string.decode('utf-8')
    return json.dumps(string, separators=(',', ':'), sort_keys=True)

def json_loads(string):
    if isinstance(string, bytes):
        string = string.decode('utf-8')
    return json.loads(string)

def encode_int_b64(i, bit_size=None):
    extend = 0
    if bit_size is not None:
        extend = ((bit_size + 7) // 8) * 2
    hexi = hex(i).rstrip("L").lstrip("0x")
    hexl = len(hexi)
    if extend > hexl:
        extend -= hexl
    else:
        extend = hexl % 2
    return base64url_encode(unhexlify(extend * '0' + hexi))

def decode_int(n):
    return int(hexlify(base64url_decode(n)), 16)

def encode_int(n, bits):
    e = '{:x}'.format(n)
    ilen = ((bits + 7) // 8) * 2 
    return unhexlify(e.rjust(ilen, '0')[:ilen])