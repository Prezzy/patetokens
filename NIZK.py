import json
from Crypto.Math._IntegerGMP import IntegerGMP as IntGMP
from Crypto.Hash import KangarooTwelve as K12
from patetokens import Cipher, utils


#public values Ec (enc pwd), B, V
#private values beta, pwd, gamma
def proveQ(nonces, public, private, key):

    H3 = K12.new(custom=b'Q')

    #mu1, mu2, v
    rand = []
    for i in range(3):
        rand.append(utils.rand_felement_gmp(key))

    #B' as B1 
    B1 = Cipher.Cipher(key=key)
    B1.encrypt(rand[0],0)
    B_temp = public[0].exp(rand[1])
    B1.imul(B_temp)

    #V' as V1
    V1 = Cipher.Cipher(key=key)
    V1.encrypt(rand[2],rand[1])

    hash_input = ""
    hash_input += utils.dic_to_string(nonces)
    hash_input += public[0].export_b64str()
    hash_input += public[1].export_b64str()
    hash_input += public[2].export_b64str()
    hash_input += B1.export_b64str()
    hash_input += V1.export_b64str()

    hash_input = hash_input.replace(',','')
    hash_input = hash_input.encode('utf-8')

    H3.update(hash_input)

    hash_bytes = H3.read(256)
    
    e = IntGMP.from_bytes(hash_bytes)

    e.inplace_pow(1,key.p)

    z = [e]
    for i in range(len(private)):
        z.append(utils.mul_add_mod(private[i],e,rand[i],key))

    
    proof = {
            'e':utils.gmp_to_b64str(e),
            'z1': utils.gmp_to_b64str(z[1]),
            'z2': utils.gmp_to_b64str(z[2]),
            'z3': utils.gmp_to_b64str(z[3]),
            }

    return proof
    
    
#public parameters [Ec, B, V]
#proof dict with e, z1, z2, z3 keys and values
def verifyQ(nonces, public, proof, key):

    H3 = K12.new(custom=b'Q')

    e = utils.b64str_to_gmp(proof['e'])
    z1 = utils.b64str_to_gmp(proof['z1'])
    z2 = utils.b64str_to_gmp(proof['z2'])
    z3 = utils.b64str_to_gmp(proof['z3'])

    #B' as B1
    B1 = Cipher.Cipher(key=key)
    B1.encrypt(z1,0)
    B_temp1 = public[0].exp(z2) 
    B_temp2 = public[1].mul(Cipher.Cipher(key.g,1,key))
    B_temp2.iinverse()
    B_temp2.iexp(e)
    B1.imul(B_temp1)
    B1.imul(B_temp2)

    #V' as V1
    V1 = Cipher.Cipher(key=key)
    V1.encrypt(z3,z2)
    V_temp = public[2].inverse()
    V_temp.iexp(e)
    V1.imul(V_temp)

    hash_input = ""
    hash_input += utils.dic_to_string(nonces)
    hash_input += public[0].export_b64str()
    hash_input += public[1].export_b64str()
    hash_input += public[2].export_b64str()
    hash_input += B1.export_b64str()
    hash_input += V1.export_b64str() 

    hash_input = hash_input.replace(',','')
    hash_input = hash_input.encode('utf-8')

    H3.update(hash_input)
    hash_bytes = H3.read(256)
    
    hsh = IntGMP.from_bytes(hash_bytes)

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
        rand.append(utils.rand_felement_gmp(key))

    #Bi tilde as B1
    B1 = Cipher.Cipher(key=key)
    B1.encrypt(rand[1],0)
    B_temp = ciphers[0].exp(rand[0])
    B1.imul(B_temp)

    #Vi tilde as V1
    V1 = Cipher.Cipher(key=key)
    V1.encrypt(rand[2],rand[0])

    #Vi' tilde as V2
    V2 = Cipher.Cipher(key=key)
    V2.encrypt(rand[3],rand[0],None,ciphers[1].a)

    #Vi'' tilde as V3
    V3 = Cipher.Cipher(key=key)
    V3.encrypt(rand[4],rand[0],None,ciphers[1].b)

    hash_input = i
    for cipher in ciphers:
        hash_input += cipher.export_b64str()
    hash_input += B1.export_b64str()
    hash_input += V1.export_b64str()
    hash_input += V2.export_b64str()
    hash_input += V3.export_b64str()
    hash_input = hash_input.replace(',','')
    hash_input = hash_input.encode('utf-8')

    H4.update(hash_input)
    hash_bytes = H4.read(256)
    e = IntGMP.from_bytes(hash_bytes)

    e.inplace_pow(1,key.p)

    z = [e]
    # z values
    for i in range(5):
        z.append(utils.mul_add_mod(randomness[i],e,rand[i],key))

    proof = {
            'e':utils.gmp_to_b64str(e),
            'z1': utils.gmp_to_b64str(z[1]),
            'z2': utils.gmp_to_b64str(z[2]),
            'z3': utils.gmp_to_b64str(z[3]),
            'z4': utils.gmp_to_b64str(z[4]),
            'z5': utils.gmp_to_b64str(z[5]),
            }

    return(proof)
    
    
def verifyR(i, ciphers, proof, key):
    #(e,z1,z2,z3,z4,z5) = proof

    H4 = K12.new(custom = b'R')

    e = utils.b64str_to_gmp(proof['e'])
    z1 = utils.b64str_to_gmp(proof['z1'])
    z2 = utils.b64str_to_gmp(proof['z2'])
    z3 = utils.b64str_to_gmp(proof['z3'])
    z4 = utils.b64str_to_gmp(proof['z4'])
    z5 = utils.b64str_to_gmp(proof['z5'])

    #Bi tilde as B1
    B1 = Cipher.Cipher(key=key)
    B1.encrypt(z2,0)
    B_temp1 = ciphers[0].exp(z1)

    B_temp2 = ciphers[2].inverse()
    B_temp2.iexp(e)

    B1.imul(B_temp1)
    B1.imul(B_temp2)

    #Vi tilde as V1
    V1 = Cipher.Cipher(key=key)
    V1.encrypt(z3,z1)

    V1_temp = ciphers[3].inverse()
    V1_temp.iexp(e)
    V1.imul(V1_temp)


    #Vi' tilde as V2
    V2 = Cipher.Cipher(key=key)
    V2.encrypt(z4,z1,None,ciphers[1].a)

    V2_temp = ciphers[4].inverse()
    V2_temp.iexp(e)

    V2.imul(V2_temp)


    #Vi'' tilde as V3
    V3 = Cipher.Cipher(key=key)
    V3.encrypt(z5,z1,None,ciphers[1].b)

    V3_temp = ciphers[5].inverse()
    V3_temp.iexp(e)

    V3.imul(V3_temp)
 
    hash_input = i
    for cipher in ciphers:
        hash_input += cipher.export_b64str()
    hash_input += B1.export_b64str()
    hash_input += V1.export_b64str()
    hash_input += V2.export_b64str()
    hash_input += V3.export_b64str()
    hash_input = hash_input.replace(',','')
    hash_input = hash_input.encode('utf-8')


    H4.update(hash_input)
    hash_bytes = H4.read(256)
    hsh = IntGMP.from_bytes(hash_bytes)
    hsh.inplace_pow(1,key.p)
    
    if e == hsh:
        return True
    else:
        return False



def proveS(i, tau_prime, Ci, Ri, randomness, key):

    H5 = K12.new(custom = b'S')

    rand = []
    for j in range(2):
        rand.append(utils.rand_felement_gmp(key))

    W = key.g.__pow__(rand[0], key.p)

    R = Cipher.Cipher(key=key)
    R.encrypt(rand[1], rand[0])

    hash_input = str(i) + tau_prime
    hash_input += utils.gmp_to_b64str(Ci)
    hash_input += utils.gmp_to_b64str(Ri)
    hash_input += utils.gmp_to_b64str(W)
    hash_input += R.export_b64str()
    hash_input = hash_input.replace(',','')
    hash_input = hash_input.encode('utf-8')


    H5.update(hash_input)
    hash_bytes = H5.read(256)
    e = IntGMP.from_bytes(hash_bytes)

    e.inplace_pow(1,key.p)

    z = [e]
    # z values
    for j in range(2):
        z.append(mul_add_mod(randomness[j],e,rand[j],key))

    proof = {
            'e':utils.gmp_to_b64str(e),
            'z1': utils.gmp_to_b64str(z[1]),
            'z2': utils.gmp_to_b64str(z[2]),
            }

    return(e, proof)

def verifyS(i, tau_prime, Ci, Ri, proof, key):

    H5 = K12.new(custom = b'S')

    e = utils.b64str_to_gmp(proof['e'])
    z1 = utils.b64str_to_gmp(proof['z1'])
    z2 = utils.b64str_to_gmp(proof['z2'])

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
    hsh = IntGMP.from_bytes(hash_bytes)

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
    e = IntGMP.from_bytes(hash_bytes)

    e.inplace_pow(1,key.p)

    z = [e]
    # z values
    for k in range(2):
        z.append(mul_add_mod(randomness[k],e,rand[k],key))

    proof = {
            'e':utils.gmp_to_b64str(e),
            'z1': utils.gmp_to_b64str(z[1]),
            'z2': utils.gmp_to_b64str(z[2]),
            }

    return proof


def verifyT(i, tau_prime, g_bar, C_bari, Ci, Ri, proof, key):

    H6 = K12.new(custom = b'T')

    e = utils.b64str_to_gmp(proof['e'])
    z1 = utils.b64str_to_gmp(proof['z1'])
    z2 = utils.b64str_to_gmp(proof['z2'])

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
    hsh = IntGMP.from_bytes(hash_bytes)

    hsh.inplace_pow(1,key.p)

    if e == hsh:
        return True
    else:
        return False
        
        
    

