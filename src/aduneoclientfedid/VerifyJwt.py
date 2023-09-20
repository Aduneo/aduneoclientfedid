from jose import jwt

def verify_jwt(jwt_token, jwks):
    unverified_header = jwt.get_unverified_header(jwt_token)
    print("unverified_header")
    print(unverified_header)
    rsa_key = {}
    print("jwks")
    print(jwks)
    for key in jwks["keys"]:
        print("key")
        print(key)
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"],
            }
    print("rsa_key")        
    print(rsa_key)        
    print("jwt_token")        
    print(jwt_token)        
    if rsa_key:
        try:
            payload = jwt.decode(
                jwt_token,
                rsa_key,
                algorithms=["RS256"],
                options={
                    "verify_aud": False, 
                    "verify_iss": False,
                    "verify_aud": False,
                    "verify_iat": False,
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iss": False,
                    "verify_sub": False,
                    "verify_jti": False,
                    "verify_at_hash": False,
        },
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise Exception("Token has expired")
        except jwt.JWTClaimsError:
            raise Exception("Invalid claims. Please check the audience and issuer")
        except Exception:
            raise Exception("Unable to parse authentication token.")
    else:
        raise Exception("Unable to find appropriate key")
