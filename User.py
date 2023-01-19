import tlib
import json
from Crypto.Math._IntegerGMP import IntegerGMP as IntGMP
from Crypto.PublicKey import ElGamal
from jwcrypto import jwk, jwt
from base64 import urlsafe_b64decode
from patetokens import Cipher, utils

def enc_pwd(pwd, key):
    a_key = utils.rand_felement_gmp(key)
    y_part = key.y.__pow__(a_key, key.p)
    pwd_inv = pwd.inverse(key.q)
    g_part = key.g.__pow__(pwd_inv, key.p)
    a = y_part.__mul__(g_part)
    a.inplace_pow(1, key.p)
    b = key.g.__pow__(a_key, key.p)
    Ec = Cipher(a,b,key)

    y_part_temp = y_part.__pow__(pwd, key.p)
    a_1 = y_part_temp.__mul__(key.g)
    a_1.inplace_pow(1, key.p)
    b_1_temp = key.g.__pow__(a_key, key.p)
    b_1 = b_1_temp.__pow__(pwd, key.p)

    Ec_test = Ec.exp(pwd)

    print("Ec og ({},{})".format(Ec.a, Ec.b))
    print("Ec test ({},{})".format(Ec_test.a, Ec_test.b))

    print("direct ({},{})".format(a_1, b_1))

    return Ec

def compute_B(Ec, pwd, key):
    b_key = utils.rand_felement_gmp(key)
    B = Cipher(key=key)
    B.encrypt(b_key,0)

    #y_b = key.y.__pow__(b_key, key.p)
    #g_b = key.g.__pow__(b_key, key.p)

    B_temp1 = Ec.exp(pwd)

    B.imul(B_temp1)

    g_inv = key.g.inverse(key.p)
    B_temp2 = Cipher(g_inv,1,key)
    B.imul(B_temp2)

    #y_1 = key.y.__pow__(b_key, key.p)
    #y_2_temp = key.y.__pow__(a_key, key.p)
    #y_2_temp_a = y_2_temp.__pow__(pwd, key.p)
    #y_test = y_1.__mul__(y_2_temp_a)
    #y_test.inplace_pow(1, key.p)

    #g_1 = key.g.__pow__(b_key, key.p)
    #g_2_temp = key.g.__pow__(a_key, key.p)
    #g_2_temp_a = g_2_temp.__pow__(pwd, key.p)
    #g_test = g_1.__mul__(g_2_temp_a)
    #g_test.inplace_pow(1, key.p)

    #print("B ({},{})".format(B.a, B.b.__pow__(key.x, key.p)))
    #print("Ec og ({},{})".format(Ec.a, Ec.b))
    #print("direct ({},{})".format(y_test, g_test.__pow__(key.x, key.p)))

    return (B,b_key)


def generate_serialized_token(key, username, encpwd):
    payload = {'username' : username, 'encpwd' : encpwd}
    payload = json.dumps(payload)
    Token = jws.JWS(payload.encode('utf-8'))
    Token.add_signature(key, None, json_encode({"alg": "RS256"}))
    token = Token.serialize()
    return token

def make_token(key, username, pwd):
    pwd = pwd.encode('utf-8')
    pwd = IntGMP.from_bytes(pwd)
    encpwd = enc_pwd(pwd, key)
    token = generate_serialized_token(key, username, encpwd.export_b64str())
    return token


def prep_token(token, key, pwd):

    dic = json.loads(token)
    padding = '=' * (4 - len(dic['payload']) % 4)
    payload = dic['payload']
    payload = urlsafe_b64decode(payload + padding)

    payload = json.loads(payload)
    encpwd_str = payload['encpwd']
    #(a_str, b_str) = encpwd_str.split(',')

    #a = IntGMP(bytes.fromhex(a_str))
    #b = IntGMP(bytes.fromhex(b_str))
    
    encpwd = Cipher(key=key)
    encpwd.from_b64str(encpwd_str)

    #encpwd = tlib.Cipher(a,b,key)

    (B,beta) = User.compute_B(encpwd, pwd, key)
    (V,gamma) = User.compute_V(pwd, key)

    public = (encpwd, B, V)
    private = (beta, pwd, gamma)

    return public, private
