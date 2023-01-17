import os
import json
from math import ceil
from Crypto.Math import _IntegerGMP


#NIST Simple Modular Method
# random number of m bits and s is sec parameter
# generate m+s bits 
# convert o integer in noraml way and reduce mod r. 

SIZE = ceil((2047+128)/8)

def rand_feild_element(key.q):
    rand = os.urandom(SIZE)
    rand = _IntegerGMP.IntegerGMP.from_bytes(rand)
    return rand.inplace_pow(1,key.q)
    return rand

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
    
def proof_to_dict(proof):
    return {'e': proof[0].to_bytes().hex(),
                'z1': proof[1].to_bytes().hex(),
                'z2': proof[2].to_bytes().hex(),
                'z3': proof[3].to_bytes().hex()
                }
