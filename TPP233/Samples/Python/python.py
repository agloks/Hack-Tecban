import os
import time
from jwcrypto import jwk, jwt
import uuid
import requests
import json
import urllib
from urllib.parse import urlparse
import re
from datetime import datetime, timedelta
import webbrowser


# The software statement ID (software_id) of the software statement created in software statements (MIT).
SOFTWARE_STATEMENT_ID = ">> SOFTWARE STATEMENT ID <<"

#  Value of the kid parameter associated with the signing certificate generated in Generate a
# transport/signing certificate pair (please note that you need to use the signing certificate kid).
KID = ">> KID <<"
# Your private signing key. You will use this to sign your JWT.
PRIVATE_RSA_KEY = """
-----BEGIN RSA PRIVATE KEY-----

-----END RSA PRIVATE KEY-----
"""

OIDC_CLIENT_ID=">> OIDC CLIENT ID <<"
OIDC_SECRET=">> OIDC SECRET <<"

#  Path to transport certificate and key
TRANSPORT_CERT_KEY = ">> /path/to/transport.key <<"
TRANSPORT_CERT = ">> /path/to/transport.pem <<"

V3_ACCT_BASEURL = ">> https://rs1.o3bank.co.uk/open-banking/v3.1/aisp/ <<"
V3_PYMT_BASEURL = ">> https://rs1.o3bank.co.uk/open-banking/v3.1/pisp/ <<"

def make_token(kid: str, model_bank_client_id: str) -> str:
    jwt_iat = int(time.time())
    jwt_exp = jwt_iat + 600
    header = dict(alg='PS256', kid=kid, typ='JWT')
    claims = dict(
        iss=model_bank_client_id,
        sub=model_bank_client_id,
        aud=">> https://as1.o3bank.co.uk/token <<",
        jti=str(uuid.uuid4()),
        iat=jwt_iat,
        exp=jwt_exp
    )
 
    token = jwt.JWT(header=header, claims=claims)
    key_obj = jwk.JWK.from_pem(PRIVATE_RSA_KEY.encode('latin-1'))
    token.make_signed_token(key_obj)
    signed_token = token.serialize()
    return signed_token

def get_access_token(signed_token: str, model_bank_client_id: str) -> str:
    data_dict = dict(
        client_assertion_type='urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        grant_type='client_credentials',
        client_id=model_bank_client_id,
        client_assertion=signed_token,
        scope="openid accounts payments"
    )
    print(data_dict)
    client = (TRANSPORT_CERT, TRANSPORT_CERT_KEY)
    response = requests.post(
        '>> https://as1.o3bank.co.uk/token <<',
        data=data_dict,
        verify=False,
        cert=client
    )
    print(response)
    print(response.json().get('access_token'))
    return response.json().get('access_token')
    
get_access_token(make_token(KID, OIDC_CLIENT_ID), OIDC_CLIENT_ID)