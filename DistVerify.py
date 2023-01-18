from sslib import shamir
from Crypto.Math._IntegerGMP import IntegerGMP as IntGMP

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
    
def round2(i, nonces, B, V, step1_responses, key, xi, public_keys):
    yg = Cipher(IntGMP(1), IntGMP(1), key=key)
    B_string = B.get_string() + V.get_string()
    V_string = ''
    for idx in step1_responses:
        yg.imul(step1_responses[idx]['ciphers'][0])
        B_string += step1_responses[idx]['ciphers'][0].get_string()
        V_string += step1_responses[idx]['ciphers'][1].get_string()
        
    indexs = list(nonces.keys())
    indexs_int = list(map(int,indexs))
    indexs_gmp = list(map(IntGMP, indexs_int))

    nonces = dic_to_string(nonces)

    tau_prime = nonces + B_string + V_string

    coeffs = shamir.lagrange_coefficients(IntGMP(0), indexs_gmp, key.q)

    a_i = coeffs[int(i)].__mul__(xi)
    a_i.inplace_pow(1, key.q)
    C_bar = yg.b.__pow__(a_i,key.p)
    zeta = utils.rand_feild_element(key)
    R_i = Cipher(key=key)
    R_i.encrypt(zeta, a_i)
    C = dict()
    for idx in coeffs:
        pk_idx = IntGMP.from_bytes(bytes.fromhex(public_keys[str(idx)]))
        C[str(idx)] = pk_idx.__pow__(coeffs[idx], key.p)

    return (tau_prime, C[i], R_i, [a_i, zeta])

    #e, proof = proveS(i, tau_prime, C[i], R_i, [a_i, zeta], key)
    #result = verifyS(i, tau_prime, C[i], R_i, proof, key)

    #print("self verification result S {}".format(result))
    #return (proof, R_i, tau_prime, C, yg, a_i, zeta, C_bar)

def round4(key, C_bars, y_bar):
    C_acc = IntGMP(1)
    for C_bari in C_bars:
        C_acc.__imul__(C_bari)
        C_acc.inplace_pow(1, key.p)

    if C_acc.__eq__(y_bar):
        print("Accept")
        return {'result': "ACCEPT"}
    else:
        print("DENY")
        return {'result' : "DENY"}
