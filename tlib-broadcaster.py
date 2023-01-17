#A library for the threshold verification process
from binascii import unhexlify
from sslib import shamir
import traceback
import os
import json
from Crypto.PublicKey import ElGamal
from Crypto.Math import _IntegerGMP, Primality
from Crypto.Hash import KangarooTwelve as K12
from jwcrypto import jwk, jwt, jws
from jwcrypto.common import json_encode 


SIZE = 2048
DEBUG = False
THRESHOLD = 2
TOTAL = 2

class NIST_Key:
    def __init__(self):
        self.p = _IntegerGMP.IntegerGMP(0xFFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF)
        self.q = _IntegerGMP.IntegerGMP(0x7FFFFFFFFFFFFFFFD6FC2A2C515DA54D57EE2B10139E9E78EC5CE2C1E7169B4AD4F09B208A3219FDE649CEE7124D9F7CBE97F1B1B1863AEC7B40D901576230BD69EF8F6AEAFEB2B09219FA8FAF83376842B1B2AA9EF68D79DAAB89AF3FABE49ACC278638707345BBF15344ED79F7F4390EF8AC509B56F39A98566527A41D3CBD5E0558C159927DB0E88454A5D96471FDDCB56D5BB06BFA340EA7A151EF1CA6FA572B76F3B1B95D8C8583D3E4770536B84F017E70E6FBF176601A0266941A17B0C8B97F4E74C2C1FFC7278919777940C1E1FF1D8DA637D6B99DDAFE5E17611002E2C778C1BE8B41D96379A51360D977FD4435A11C30942E4BFFFFFFFFFFFFFFFF)
        self.g = _IntegerGMP.IntegerGMP(2)
        self.y = None
        self.x = None

    def compute_keys(self):
        if not os.path.exists('private-keys'):
            N = _IntegerGMP.IntegerGMP(256)
            one = _IntegerGMP.IntegerGMP(1)
            returned_bits = os.urandom(40)
            integer = _IntegerGMP.IntegerGMP.from_bytes(returned_bits)
            temp = self.p.__sub__(one)
            temp2 = temp.__floordiv__(2)
            x_max_bits = _IntegerGMP.IntegerGMP(2**256)
            if x_max_bits.__le__(self.q):
                M = x_max_bits
            else:
                M = self.q
            self.x = integer.__pow__(1, M.__isub__(one))
            self.x.__iadd__(one)
            self.y = self.g.__pow__(self.x, self.p)

            x_hex = self.x.to_bytes().hex()
            y_hex = self.y.to_bytes().hex()
            serialized_priv_key = {'x': x_hex, 'y': y_hex}
            with open("private-keys", "w") as key_file:
                key_file.write(json.dumps(serialized_priv_key))

        else:
            with open("private-keys", "r") as key_file:
                key_json_str = key_file.read()

            key_dict = json.loads(key_json_str)
            self.x = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(key_dict['x']))
            self.y = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(key_dict['y']))


def generate_token_key():
    if not os.path.exists('token-key.key'):
        try:
            key = jwk.JWK.generate(kty='RSA', size=2048)
        except:
            print("error generating key")
        try:
            with open('token-key.key', 'w') as keyfile:
                keyfile.write(key.export(private_key=True, as_dict = False))
        except IOError:
            print("Error writing key to file token-key.key")
    else:
        try:
            with open('token-key.key', 'r') as keyfile:
                keystr = keyfile.read()
        except IOError:
            print("Error reading from key file token-key.key")

        key = jwk.JWK.from_json(keystr)

    return key


def generate_serialized_token(key, username, encpwd):
    payload = {'username' : username, 'encpwd' : encpwd}
    payload = json.dumps(payload)
    Token = jws.JWS(payload.encode('utf-8'))
    Token.add_signature(key, None, json_encode({"alg": "RS256"}))
    token = Token.serialize()
    return token


def secret_share(key):
    if not os.path.exists("secret-shares"):
        x_bytes = key.x.to_bytes()
        q_bytes = key.q.to_bytes()
        print("len x bytes {}".format(len(x_bytes)))
        print("len q bytes {}".format(len(q_bytes)))
        print("x greater than q? {}".format(key.x.__gt__(key.q)))
        #print(key.x.__int__())
        secrets = shamir.to_hex(shamir.split_secret(x_bytes, THRESHOLD, TOTAL, prime_mod=key.q))

        shares_dict = {}
        for share in secrets['shares']:
            (idx, share) = share.split("-")
            shares_dict[idx] = share

        with open('secret-shares', 'w') as secret_share_file:
            secret_share_file.write(json.dumps(shares_dict))
    else:
        with open('secret-shares', 'r') as secret_share_file:
            data = secret_share_file.read()

        shares_dict = json.loads(data)
        
        #FOR TEST
        #sh = shamir.to_hex(shamir.split_secret(key.x.to_bytes(), THRESHOLD, TOTAL, prime_mod=key.q))
        #print("key.x is {}".format(key.x.to_bytes()))
        #print("sh is {}".format(sh))
        #print("sh.from_hex {}".format(shamir.from_hex(sh)))
        #secret = shamir.recover_secret(shamir.from_hex(sh))
        #print("secret is {}".format(secret))

    return shares_dict

def generate_public_keys(key, secret_shares):
    if not os.path.exists("public-keys"):
        public_keys = {}
        for idx in secret_shares:
            share = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(secret_shares[idx]))
            pub_key = key.g.__pow__(share, key.p)
            public_keys[idx] = pub_key.to_bytes().hex()
        with open('public-key', 'w') as public_key_file:
            public_key_file.write(json.dumps(public_keys))

    else:

        with open('public-key', 'r') as public_key_file:
            data = public_key_file.read()
        public_keys = json.loads(data)

    return public_keys
    
    
class Cipher:
    def __init__(self, a=None, b=None, key=None):
        self.a = a
        self.b = b
        self.key = key

    def mul(self, cipher):
        try:
            a = self.a.__mul__(cipher.a)
            b = self.b.__mul__(cipher.b)
            a = a.inplace_pow(1,self.key.p)
            b = b.inplace_pow(1,self.key.p)
            return Cipher(a,b,self.key)
        except AttributeError:
            print("Ciphertext undefined in call to Cipher.mul")
            traceback.print_exc()
            exit()

    def exp(self, value):
        try:
            a = self.a.__pow__(value, self.key.p)
            b = self.b.__pow__(value, self.key.p)
            return Cipher(a,b,self.key)
        except AttributeError:
            print("Ciphertext undefined in call to Cipher.exp")
            traceback.print_exc()
            exit()

    def inverse(self):
        try:
            a = self.a.inverse(self.key.p)
            b = self.b.inverse(self.key.p)
            return Cipher(a, b, self.key)
        except AttributeError:
            print("Ciphertext undefined in call to Cipher.inv")
            traceback.print_exc()
            exit()


    def imul(self, cipher):
        try:
            self.a.__imul__(cipher.a)
            self.b.__imul__(cipher.b)
            self.a.inplace_pow(1,self.key.p)
            self.b.inplace_pow(1,self.key.p)
        except AttributeError:
            print("Ciphertext undefined in call to Cipher.imul")
            traceback.print_exc()
            exit()

    def iexp(self, value):
        try:
            self.a.inplace_pow(value, self.key.p)
            self.b.inplace_pow(value, self.key.p)
        except AttributeError:
            print("Ciphertext undefined in call to Cipher.iexp")
            traceback.print_exc()
            exit()

    def iinverse(self):
        try:
            self.a.inplace_inverse(self.key.p)
            self.b.inplace_inverse(self.key.p)
        except AttributeError:
            print("Ciphertext undefined in call to Cipher.iinv")
            traceback.print_exc()
            exit()

    def encrypt(self, ephem, message, h=None, g=None):
        try:
            #if h is None:
            self.a = self.key.y.__pow__(ephem, self.key.p)
            #else:
            #    self.a = h.__pow__(ephem, key.p)

            #if g is None:
            #gm = key.g.__pow__(message, key.p)
            #else:
            gm = self.key.g.__pow__(message,self.key.p)
            self.a.__imul__(gm)
            self.a.inplace_pow(1,self.key.p)
            self.b = self.key.g.__pow__(ephem, self.key.p)
        except AttributeError:
                print("Ciphertext undefined in call to Cipher.enc")
                traceback.print_exc()
                exit()

    def decrypt(self, message):
        temp_b = self.b.__pow__(self.key.x,self.key.p)
        inv_temp_b = temp_b.inverse(self.key.p)


        result = self.a.__mul__(inv_temp_b)
        result.inplace_pow(1,self.key.p)
        compare = self.key.g.__pow__(message, self.key.p)

        print("Decryption found matching is {} and {}, {}".format(result == compare, result, compare))


    
    def get_bytes(self):
        a_str = self.a.to_bytes()
        b_str = self.b.to_bytes()
        return a_str+b_str

    def get_string(self):
        a_str = self.a.to_bytes().hex()
        b_str = self.b.to_bytes().hex()
        return a_str + ',' + b_str

    def finalR(cipher,e):
        cipher.iexp(e,self.key.p)
        cipher.iinverse(self.key.p)
        self.imul(cipher)

def cipher_from_string(cipher_string, key):
    (a_str, b_str) = cipher_string.split(',')

    a = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(a_str))
    b = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(b_str))

    return Cipher(a,b,key)

