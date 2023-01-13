#A library for the threshold verification process
from binascii import unhexlify
#from sslib import shamir
import traceback
import os
import json
from Crypto.PublicKey import ElGamal
from Crypto.Math import _IntegerGMP, Primality
from Crypto.Hash import KangarooTwelve as K12

SIZE = 256
DEBUG = False
THRESHOLD = 2
TOTAL = 2



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
        #temp_b = self.b.inverse(self.key.p)

        #temp_b = self.b.__pow__(self.key.x,self.key.p)
        x_temp = self.b.__pow__(self.key.x, self.key.p)

        x_inv = x_temp.inverse(self.key.p)


        result = self.a.__mul__(x_inv)
        result.inplace_pow(1,self.key.p)
        compare = self.key.g.__pow__(message, self.key.p)

        print("Decryption found matching is {}".format(result == compare))


    
    def get_bytes(self):
        a_str = self.a.to_bytes()
        b_str = self.b.to_bytes()
        return a_str+b_str

    def get_string(self):
        a_str = self.a.to_bytes().hex()
        b_str = self.b.to_bytes().hex()
        return a_str + ',' + b_str


def mul_add_mod(x,e,y,key):
    x1 = x.__mul__(e)
    x2 = x1.__add__(y)
    x2.inplace_pow(1,key.q)
    return x2

def rand_feild_element(key):
    rand = os.urandom(32)
    rand = _IntegerGMP.IntegerGMP.from_bytes(rand)
    return rand.inplace_pow(1,key.q)
    #return rand

def choose_pwd():
    rand = os.urandom(8)
    rand = _IntegerGMP.IntegerGMP.from_bytes(rand)
    #return rand.inplace_pow(1,key.q)
    return rand

def enc_pwd(pwd, key):
    a_key = rand_feild_element(key)
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

def compute_B(Ec,pwd, key):
    b_key = rand_feild_element(key)
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

def compute_V(pwd, key):
    V = Cipher(key=key)
    g_key = rand_feild_element(key) 
    V.encrypt(g_key,pwd)

    return (V,g_key)

def dic_to_string(dic):
    st = ''
    for key in dic:
        st += dic[key]
    return st

def proof_to_dict(proof):
    return {'e': proof[0].to_bytes().hex(),
                'z1': proof[1].to_bytes().hex(),
                'z2': proof[2].to_bytes().hex(),
                'z3': proof[3].to_bytes().hex()
                }

#public values Ec (enc pwd), B, V
#private values beta, pwd, gamma
def proveQ(nonces, public, private, key):

    H3 = K12.new(custom=b'Q')

    #mu1, mu2, v
    rand = []
    for i in range(3):
        rand.append(rand_feild_element(key))

    #B' as B1 
    B1 = Cipher(key=key)
    B1.encrypt(rand[0],0)
    B_temp = public[0].exp(rand[1])
    B1.imul(B_temp)

    #V' as V1
    V1 = Cipher(key=key)
    V1.encrypt(rand[2],rand[1])

    hash_input = ""
    hash_input += dic_to_string(nonces)
    hash_input += public[0].get_string()
    hash_input += public[1].get_string()
    hash_input += public[2].get_string()
    hash_input += B1.get_string()
    hash_input += V1.get_string()

    hash_input = hash_input.replace(',','')
    hash_input = hash_input.encode('utf-8')

    H3.update(hash_input)

    hash_bytes = H3.read(256)
    
    e = _IntegerGMP.IntegerGMP.from_bytes(hash_bytes)

    e.inplace_pow(1,key.p)

    z = [e]
    for i in range(len(private)):
        z.append(mul_add_mod(private[i],e,rand[i],key))

    return (z)


#public parameters [Ec, B, V]
#proof [e,z1,z2,z3]
def verifyQ(nonces, public, proof, key):

    H3 = K12.new(custom=b'Q')

    (e,z1,z2,z3) = proof

    #B' as B1
    B1 = Cipher(key=key)
    B1.encrypt(z1,0)
    B_temp1 = public[0].exp(z2) 
    B_temp2 = public[1].mul(Cipher(key.g,1,key))
    B_temp2.iinverse()
    B_temp2.iexp(e)
    B1.imul(B_temp1)
    B1.imul(B_temp2)

    #V' as V1
    V1 = Cipher(key=key)
    V1.encrypt(z3,z2)
    V_temp = public[2].inverse()
    V_temp.iexp(e)
    V1.imul(V_temp)

    hash_input = ""
    hash_input += dic_to_string(nonces)
    hash_input += public[0].get_string()
    hash_input += public[1].get_string()
    hash_input += public[2].get_string()
    hash_input += B1.get_string()
    hash_input += V1.get_string() 

    hash_input = hash_input.replace(',','')
    hash_input = hash_input.encode('utf-8')

    H3.update(hash_input)
    hash_bytes = H3.read(256)
    
    hsh = _IntegerGMP.IntegerGMP.from_bytes(hash_bytes)

    hsh.inplace_pow(1,key.p)

    if e == hsh:
        return True
    else:
        return False
