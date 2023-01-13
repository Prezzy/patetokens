#A library for the threshold verification process
from binascii import unhexlify
from sslib import shamir
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

def generate_key():
    if not os.path.exists("el-gamal-key") or not os.path.exists("el-gamal-key-h"):
        print("no key generated, generating...")
        key = ElGamal.generate(SIZE,os.urandom)
        p_bytes_str = key.p.to_bytes().hex()
        q_bytes_str = key.q.to_bytes().hex()
        g_bytes_str = key.g.to_bytes().hex()
        y_bytes_str = key.y.to_bytes().hex()
        x_bytes_str = key.x.to_bytes().hex()
        serialized_key = {"p": p_bytes_str, "q": q_bytes_str, "g": g_bytes_str, "y": y_bytes_str, "x": x_bytes_str}
        with open("el-gamal-key", "w") as key_file:
            key_file.write(json.dumps(serialized_key))


        keyh = ElGamal.generate(SIZE,os.urandom)
        p_bytes_str = key.p.to_bytes().hex()
        g_bytes_str = key.g.to_bytes().hex()
        y_bytes_str = key.y.to_bytes().hex()
        x_bytes_str = key.x.to_bytes().hex()
        serialized_key = {"p": p_bytes_str, "q": q_bytes_str, "g": g_bytes_str, "y": y_bytes_str, "x": x_bytes_str}
        with open("el-gamal-key-h", "w") as key_file:
            key_file.write(json.dumps(serialized_key))

    else:
        print("key-exists, deserializing...")
        with open("el-gamal-key", "r") as key_file:
            key_json_str = key_file.read()

        key_dict = json.loads(key_json_str)
        p= _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(key_dict["p"]))
        q= _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(key_dict["q"]))
        g= _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(key_dict["g"]))
        y= _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(key_dict["y"]))
        x= _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(key_dict["x"]))

        key = ElGamal.construct((p,q,g,y,x))

        print("keyh-exists, deserializing...")
        with open("el-gamal-key-h", "r") as key_fileh:
            keyh_json_str = key_fileh.read()

        keyh_dict = json.loads(keyh_json_str)
        h= _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(keyh_dict["g"]))


        print("g is {}".format(g))
        print("h is {}".format(h))

        print("done with keys...")


def secret_share():
    x_bytes = key.x.to_bytes()
    print(x_bytes)
    print(key.x.__int__())
    secrets = shamir.to_hex(shamir.split_secret(x_bytes, THRESHOLD, TOTAL, prime_mod=key.q.__int__()))

    share1 = secrets["shares"][0]
    share1 = share1[2:]
    share1 = int(share1, base=16)

    share2 = secrets["shares"][1]
    share2 = share2[2:]
    share2 = int(share2, base=16)

    rec_secret = shamir.recover_secret(shamir.from_hex(secrets))
    print(rec_secret)

    #1
    lc1 = _IntegerGMP.IntegerGMP(shamir.lagrange_coefficient(0,(1,share1), [1,2], key.q.__int__()))
    g_a1 = key.g.__pow__(lc1,key.p)

    #2
    lc2 = _IntegerGMP.IntegerGMP(shamir.lagrange_coefficient(0,(2,share2), [1,2], key.q.__int__()))
    g_a2 = key.g.__pow__(lc2,key.p)


    sec = lc1.__add__(lc2)
    sec.inplace_pow(1,key.q)
    print("reconstructed key {}".format(sec))

    new_y = g_a1.__mul__(g_a2)
    new_y.inplace_pow(1,key.p)


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

    #def decrypt(self, message):
    #    temp_b = self.b.__pow__(self.key.x,self.key.p)
    #    inv_temp_b = temp_b.inverse(self.key.p)


    #    result = self.a.__mul__(inv_temp_b)
    #    result.inplace_pow(1,self.key.p)
    #    compare = self.key.g.__pow__(message, self.key.p)

    #    print("Decryption found matching is {}".format(result == compare))


    
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

def key_from_dic(key):
    p = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(key['p']))
    q = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(key['q']))
    g = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(key['g']))
    y = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(key['y']))

    key = ElGamal.construct((p,q,g,y))

    return key

def rand_feild_element(key):
    rand = os.urandom(1000)
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


def choose_pwd(key):
    return rand_feild_element(key)

def enc_pwd(pwd):
    a_key = rand_feild_element(key)
    pwd_inv = pwd.inverse(key.p)

    Ec = Cipher()
    Ec.encrypt(a_key,pwd_inv)

    return Ec

def compute_B(Ec,pwd):
    b_key = rand_feild_element(key)
    B = Cipher()
    B.encrypt(b_key,0)
    B_temp1 = Ec.exp(pwd)
    B.imul(B_temp1)
    g_inv = key.g.inverse(key.p)
    B_temp2 = Cipher(g_inv,1)
    B.imul(B_temp2)

    return (B,b_key)

def compute_V(pwd):
    V = Cipher()
    g_key = rand_feild_element(key) 
    V.encrypt(g_key,pwd)

    return (V,g_key)


def dic_to_string(dic):
    st = ''
    for key in dic:
        st += dic[key]
    return st

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
#proof dict with e, z1, z2, z3 keys and values
def verifyQ(nonces, public, proof, key):

    H3 = K12.new(custom=b'Q')

    e = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(proof['e']))
    z1 = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(proof['z1']))
    z2 = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(proof['z2']))
    z3 = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(proof['z3']))

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


#ciphers [B,V,Bi,Vi,Vi',Vi'']
#randomness = r_i, r_i', gamma_i, gamma_i', gamma_i''
def proveR(i, ciphers, randomness, key):

    H4 = K12.new(custom = b'R')

    #generate local rand nonces
    #mu1, mu2, v1, v2, v3
    rand = []    
    for j in range(5):
        rand.append(rand_feild_element(key))

    #Bi tilde as B1
    B1 = Cipher(key=key)
    B1.encrypt(rand[1],0)
    B_temp = ciphers[0].exp(rand[0])
    B1.imul(B_temp)

    #Vi tilde as V1
    V1 = Cipher(key=key)
    V1.encrypt(rand[2],rand[0])

    #Vi' tilde as V2
    V2 = Cipher(key=key)
    V2.encrypt(rand[3],rand[0],None,ciphers[1].a)

    #Vi'' tilde as V3
    V3 = Cipher(key=key)
    V3.encrypt(rand[4],rand[0],None,ciphers[1].b)

    hash_input = i
    for cipher in ciphers:
        hash_input += cipher.get_string()
    hash_input += B1.get_string()
    hash_input += V1.get_string()
    hash_input += V2.get_string()
    hash_input += V3.get_string()
    hash_input = hash_input.replace(',','')
    hash_input = hash_input.encode('utf-8')

    H4.update(hash_input)
    hash_bytes = H4.read(256)
    e = _IntegerGMP.IntegerGMP.from_bytes(hash_bytes)

    e.inplace_pow(1,key.p)

    z = [e]
    # z values
    for i in range(5):
        z.append(mul_add_mod(randomness[i],e,rand[i],key))

    proof_dic = {'e':e.to_bytes().hex(),
            'z1': z[1].to_bytes().hex(),
            'z2': z[2].to_bytes().hex(),
            'z3': z[3].to_bytes().hex(),
            'z4': z[4].to_bytes().hex(),
            'z5': z[5].to_bytes().hex()
            }

    return(proof_dic)

def round1(B,V,key):
    #rand = [ri, ri', gammai, gammai', gammai'']
    rand = []
    for i in range(5):
        rand.append(rand_feild_element(key))

    #Bi as B1
    B1 = B.exp(rand[0])  #B^{ri}
    B1_temp = Cipher(key=key)
    B1_temp.encrypt(rand[1],0)

    B1.imul(B1_temp)  # B^{ri} * (y,g)^{ri'}

    #Vi as V1
    V1 = Cipher(key=key)
    V1.encrypt(rand[2],rand[0]) #(h^{yi} g^{ri}, g^{yi})

    #Vi' as V2
    V2 = Cipher(key=key)
    V2.encrypt(rand[3],rand[0],None,V.a)

    #Vi'' as V3
    V3 = Cipher(key=key)
    V3.encrypt(rand[4],rand[0],None,V.b)

    return ([B,V,B1,V1,V2,V3],rand)

def verifyR(i,ciphers,proof, key):
    #(e,z1,z2,z3,z4,z5) = proof

    H4 = K12.new(custom = b'R')

    e = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(proof['e']))
    z1 = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(proof['z1']))
    z2 = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(proof['z2']))
    z3 = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(proof['z3']))
    z4 = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(proof['z4']))
    z5 = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(proof['z5']))

    #Bi tilde as B1
    B1 = Cipher(key=key)
    B1.encrypt(z2,0)
    B_temp1 = ciphers[0].exp(z1)

    B_temp2 = ciphers[2].inverse()
    B_temp2.iexp(e)

    B1.imul(B_temp1)
    B1.imul(B_temp2)

    #Vi tilde as V1
    V1 = Cipher(key=key)
    V1.encrypt(z3,z1)

    V1_temp = ciphers[3].inverse()
    V1_temp.iexp(e)
    V1.imul(V1_temp)


    #Vi' tilde as V2
    V2 = Cipher(key=key)
    V2.encrypt(z4,z1,None,ciphers[1].a)

    V2_temp = ciphers[4].inverse()
    V2_temp.iexp(e)

    V2.imul(V2_temp)


    #Vi'' tilde as V3
    V3 = Cipher(key=key)
    V3.encrypt(z5,z1,None,ciphers[1].b)

    V3_temp = ciphers[5].inverse()
    V3_temp.iexp(e)

    V3.imul(V3_temp)
 
    hash_input = i
    for cipher in ciphers:
        hash_input += cipher.get_string()
    hash_input += B1.get_string()
    hash_input += V1.get_string()
    hash_input += V2.get_string()
    hash_input += V3.get_string()
    hash_input = hash_input.replace(',','')
    hash_input = hash_input.encode('utf-8')


    H4.update(hash_input)
    hash_bytes = H4.read(256)
    hsh = _IntegerGMP.IntegerGMP.from_bytes(hash_bytes)
    hsh.inplace_pow(1,key.p)
    
    if e == hsh:
        return True
    else:
        return False



def proveS(i, tau_prime, Ci, Ri, randomness, key):

    H5 = K12.new(custom = b'S')

    rand = []
    for j in range(2):
        rand.append(rand_feild_element(key))

    W = key.g.__pow__(rand[0], key.p)

    R = Cipher(key=key)
    R.encrypt(rand[1], rand[0])

    hash_input = str(i) + tau_prime
    hash_input += Ci.to_bytes().hex()
    hash_input += Ri.get_string()
    hash_input += W.to_bytes().hex()
    hash_input += R.get_string()
    hash_input = hash_input.replace(',','')
    hash_input = hash_input.encode('utf-8')


    H5.update(hash_input)
    hash_bytes = H5.read(256)
    e = _IntegerGMP.IntegerGMP.from_bytes(hash_bytes)

    e.inplace_pow(1,key.p)

    z = [e]
    # z values
    for j in range(2):
        z.append(mul_add_mod(randomness[j],e,rand[j],key))

    proof_dic = {'e':e.to_bytes().hex(),
            'z1': z[1].to_bytes().hex(),
            'z2': z[2].to_bytes().hex(),
            }

    return(e, proof_dic)

def verifyS(i, tau_prime, Ci, Ri, proof, key):

    H5 = K12.new(custom = b'S')

    e = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(proof['e']))
    z1 = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(proof['z1']))
    z2 = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(proof['z2']))

    R = Cipher(key=key)
    R.encrypt(z2,z1)

    R_temp = Ri.inverse()
    R_temp.iexp(e)
    R.imul(R_temp)

    W = key.g.__pow__(z1, key.p)

    Ci_inv = Ci.inverse(key.p)
    Ci_inv.inplace_pow(e, key.p)
    W.__imul__(Ci_inv)
    W.inplace_pow(1, key.p)

    hash_input = str(i) + tau_prime
    hash_input += Ci.to_bytes().hex()
    hash_input += Ri.get_string()
    hash_input += W.to_bytes().hex()
    hash_input += R.get_string()
    hash_input = hash_input.replace(',','')
    hash_input = hash_input.encode('utf-8')


    H5.update(hash_input)
    hash_bytes = H5.read(256)
    hsh = _IntegerGMP.IntegerGMP.from_bytes(hash_bytes)

    hsh.inplace_pow(1,key.p)

    if e == hsh:
        return True
    else:
        return False


def proveT(i, tau_prime, g_bar, C_bari, Ci, Ri, randomness, key):

    H6 = K12.new(custom = b'T')

    rand = []
    for j in range(2):
        rand.append(rand_feild_element(key))

    W_bar = g_bar.__pow__(rand[0], key.p)

    W = key.g.__pow__(rand[0], key.p)

    R = Cipher(key=key)
    R.encrypt(rand[1], rand[0])

    hash_input = str(i) + tau_prime
    hash_input += g_bar.to_bytes().hex()
    hash_input += C_bari.to_bytes().hex()
    hash_input += Ci.to_bytes().hex()
    hash_input += Ri.get_string()
    hash_input += W_bar.to_bytes().hex()
    hash_input += W.to_bytes().hex()
    hash_input += R.get_string()
    hash_input = hash_input.replace(',','')
    hash_input = hash_input.encode('utf-8')


    H6.update(hash_input)
    hash_bytes = H6.read(256)
    e = _IntegerGMP.IntegerGMP.from_bytes(hash_bytes)

    e.inplace_pow(1,key.p)

    z = [e]
    # z values
    for k in range(2):
        z.append(mul_add_mod(randomness[k],e,rand[k],key))

    proof_dic = {'e':e.to_bytes().hex(),
            'z1': z[1].to_bytes().hex(),
            'z2': z[2].to_bytes().hex(),
            }

    return proof_dic


def verifyT(i, tau_prime, g_bar, C_bari, Ci, Ri, proof, key):

    H6 = K12.new(custom = b'T')

    e = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(proof['e']))
    z1 = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(proof['z1']))
    z2 = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(proof['z2']))

    R = Cipher(key=key)
    R.encrypt(z2,z1)

    R_temp = Ri.inverse()
    R_temp.iexp(e)
    R.imul(R_temp)

    W_bar = g_bar.__pow__(z1, key.p)
    W = key.g.__pow__(z1, key.p)

    C_bari_inv = C_bari.inverse(key.p)
    C_bari_inv.inplace_pow(e, key.p)

    Ci_inv = Ci.inverse(key.p)
    Ci_inv.inplace_pow(e, key.p)

    W_bar.__imul__(C_bari_inv)
    W_bar.inplace_pow(1, key.p)

    W.__imul__(Ci_inv)
    W.inplace_pow(1, key.p)

    hash_input = str(i) + tau_prime
    hash_input += g_bar.to_bytes().hex()
    hash_input += C_bari.to_bytes().hex()
    hash_input += Ci.to_bytes().hex()
    hash_input += Ri.get_string()
    hash_input += W_bar.to_bytes().hex()
    hash_input += W.to_bytes().hex()
    hash_input += R.get_string()
    hash_input = hash_input.replace(',','')
    hash_input = hash_input.encode('utf-8')

    H6.update(hash_input)
    hash_bytes = H6.read(256)
    hsh = _IntegerGMP.IntegerGMP.from_bytes(hash_bytes)

    hsh.inplace_pow(1,key.p)

    if e == hsh:
        return True
    else:
        return False


def round2(i, nonces, B, V, step1_responses, key, xi, public_keys):
    yg = Cipher(_IntegerGMP.IntegerGMP(1), _IntegerGMP.IntegerGMP(1), key=key)
    B_string = B.get_string() + V.get_string()
    V_string = ''
    for idx in step1_responses:
        yg.imul(step1_responses[idx]['ciphers'][0])
        B_string += step1_responses[idx]['ciphers'][0].get_string()
        V_string += step1_responses[idx]['ciphers'][1].get_string()
        
    indexs = list(nonces.keys())
    indexs_int = list(map(int,indexs))
    indexs_gmp = list(map(_IntegerGMP.IntegerGMP, indexs_int))

    nonces = dic_to_string(nonces)

    tau_prime = nonces + B_string + V_string

    coeffs = shamir.lagrange_coefficients(_IntegerGMP.IntegerGMP(0), indexs_gmp, key.q)

    a_i = coeffs[int(i)].__mul__(xi)
    a_i.inplace_pow(1, key.q)
    C_bar = yg.b.__pow__(a_i,key.p)
    zeta = rand_feild_element(key)
    R_i = Cipher(key=key)
    R_i.encrypt(zeta, a_i)
    C = dict()
    for idx in coeffs:
        pk_idx = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(public_keys[str(idx)]))
        C[str(idx)] = pk_idx.__pow__(coeffs[idx], key.p)

    e, proof = proveS(i, tau_prime, C[i], R_i, [a_i, zeta], key)
    result = verifyS(i, tau_prime, C[i], R_i, proof, key)

    print("self verification result S {}".format(result))
    return (proof, R_i, tau_prime, C, yg, a_i, zeta, C_bar)
