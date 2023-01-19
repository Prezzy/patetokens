import os
import json
import base64
from math import ceil
from Crypto.Math._IntegerGMP import IntegerGMP as IntGMP


#NIST Simple Modular Method
# random number of m bits and s is sec parameter
# generate m+s bits 
# convert o integer in noraml way and reduce mod r. 

SIZE = ceil((2047+128)/8)




def to_b64str(byte_obj):
    return base64.b64encode(byte_obj).decode('utf-8')

def from_b64str(string):
    return base64.b64decode(string.encode('utf-8'))

def b64str_to_gmp(string):
    return IntGMP.from_bytes(from_b64str(string))

def gmp_to_b64str(gmp):
    return to_b64str(gmp.to_bytes())

def rand_felement_gmp(key):
    rand = os.urandom(SIZE)
    rand = IntGMP.from_bytes(rand)
    return rand.inplace_pow(1,key.q)
    #return rand

def rand_felement_b64str(key):
    return gmp_to_b64str(rand_felement_gmp(key))

def mul_mod(x,y,key):
    x1 = x.__mul__(y)
    x1.inplace_pow(1,key.p)
    return x1

def add_mod(x,y,key):
    x1 = x.__add__(y)
    x1.inplace_pow(1,key.p)
    return x1

def mul_add_mod(x,e,y,key):
    x1 = x.__mul__(e)
    x2 = x1.__add__(y)
    x2.inplace_pow(1,key.q)
    return x2

def choose_pwd(password):
    return password.encode('utf-8')
    
def dic_to_string(dic):
    st = ''
    for key in dic:
        st += dic[key]
    return st
    
#deprecated
def proof_to_dict(proof):
    return {'e': proof[0].to_bytes().hex(),
                'z1': proof[1].to_bytes().hex(),
                'z2': proof[2].to_bytes().hex(),
                'z3': proof[3].to_bytes().hex()
                }
