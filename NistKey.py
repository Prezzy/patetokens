import os
from sslib import shamir
from Crypto.Math._IntegerGMP import IntegerGMP as IntGMP
from patetokens import utils

TOTAL = 2
THRESHOLD = 2

hex_string_p = ("0xFFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
      "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
      "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
      "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
      "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
      "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
      "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
      "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
      "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
      "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
      "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF")

prime_p_2048 = IntGMP(int(hex_string_p.replace(" ", ""), 16))
prime_q_2048_temp = prime_p_2048.__sub__(1)
prime_q_2048 = prime_q_2048_temp.__floordiv__(2)

class Key:
    def __init__(self):
        self.p = prime_p_2048
        self.q = prime_q_2048
        self.g = IntGMP(2)
        self.x = None
        self.y = None
        self.group_idx = None
        self.group_pks = None
            
    def from_json(self, json_keys):
        self.p = utils.b64str_to_gmp(json_keys['p'])
        self.q = utils.b64str_to_gmp(json_keys['q'])
        self.g = utils.b64str_to_gmp(json_keys['g'])
        self.y = utils.b64str_to_gmp(json_keys['y'])
        #uppack group-pks from bytes to IntGMP
        self.group_pks = dict(map(lambda keyi: (keyi[0], utils.b64str_to_gmp(keyi[1])), json_keys['group-pks'],items()))
        if 'x' in json_keys.keys():
            self.x = utils.b64str_to_gmp(json_keys['x'])
    	
    def export_keys(self, Public=True):
        json_keys = {
                'p': utils.gmp_to_b64str(self.p),
                'q': utils.gmp_to_b64str(self.q),
                'g': utils.gmp_to_b64str(self.g),
                'y': utils.gmp_to_b64str(self.y),
                'group-pks' : dict(map(lambda keyi: (keyi[0], utils.gmp_to_b64str(keyi[1])), self.group_pks.items())),
                }
        if not Public:
            try:
                json_keys['x'] = utils.gmp_to_b64str(self.x)
            except:
                print("trying to extract private key but there was an error")

        return json_keys


class DistributedKey(Key):
    def __init__(self, y, idx, x_share, group_pks):
        super().__init__()
        self.y = y
        self.idx = idx
        self.x_share = x_share
        self.group_pks = group_pks
        
    def from_json(self, json_keys):
        super(DistributedKey, self).from_json(json_keys)
        self.x_share = json_keys['x-shares']
        #uppack group-pks from bytes to IntGMP
        self.group_pks = dict(map(lambda keyi: (keyi[0], IntGMP.from_bytes(keyi[1])), json_keys['group-pks'],items()))

    def export(self, Public=True):
        json_keys = super(DistributedKey, self).export_keys(Public)
        if not Public:
            print("This is the self.x_share {}".format(self.x_share))
            json_keys['x-share'] = utils.gmp_to_b64str(self.x_share)
        return json_keys


        

class FullKey(Key):
    def __init__(self, group_idxs):
        super().__init__()
        self.group_idxs = group_idxs
        self.x_shares = None


    def generate_key(self):
        N = IntGMP(256)
        #one = IntGMP(1)
        returned_bits = os.urandom(40)
        integer = IntGMP.from_bytes(returned_bits)
        temp = self.p.__sub__(1)
        temp2 = temp.__floordiv__(2)
        x_max_bits = IntGMP(2**256)
        if x_max_bits.__le__(self.q):
            M = x_max_bits
        else:
            M = self.q
        self.x = integer.__pow__(1, M.__isub__(1))
        self.x.__iadd__(1)
        self.y = self.g.__pow__(self.x, self.p)

        #x_hex = self.x.to_bytes().hex()
        #y_hex = self.y.to_bytes().hex()
        #serialized_priv_key = {'x': x_hex, 'y': y_hex}

    def split_sk(self):
        x_bytes = self.x.to_bytes()
        secrets = shamir.to_hex(shamir.split_secret(x_bytes, THRESHOLD, TOTAL, prime_mod=self.q))

        shares_dict = {}
        for share in secrets['shares']:
            (idx, share) = share.split("-")
            shares_dict[idx] = IntGMP.from_bytes(bytes.fromhex(share))
        
        self.x_shares = shares_dict
        print("self.x_shares is set with {}".format(shares_dict))
        print("self.x is {}".format(self.x_shares))
        #FOR TEST
        #sh = shamir.to_hex(shamir.split_secret(key.x.to_bytes(), THRESHOLD, TOTAL, prime_mod=key.q))
        #print("key.x is {}".format(key.x.to_bytes()))
        #print("sh is {}".format(sh))
        #print("sh.from_hex {}".format(shamir.from_hex(sh)))
        #secret = shamir.recover_secret(shamir.from_hex(sh))
        #print("secret is {}".format(secret))

    def gen_ver_pks(self):
        public_keys = {}
        for idx in self.x_shares:
            share = self.x_shares[idx]
            pub_key = self.g.__pow__(share, self.p)
            public_keys[idx] = pub_key

        self.group_pks = public_keys


    def export_veri_key(self, idx):
        if idx not in self.group_idxs:
            print("invalid idx")
            return "Error"
        veri_key = DistributedKey(self.y, idx, self.x_shares[idx], self.group_pks)
        return veri_key.export(False)



    def from_json(self, json_keys):
        super(FullKey, self).from_json(json_keys)
        self.group_idxs = json_keys['group-idxs']
        #uppack group-pks from bytes to IntGMP
        self.x_shares = dict(map(lambda keyi: (keyi[0], utils.b64str_to_gmp(keyi[1])), json_keys['x-shares'].items()))

    def export(self, Public=True):
        json_keys = super(FullKey, self).export(Public)
        json_keys = ['group-idxs']
        if not Public:
            json_keys['x-shares'] = dict(map(lambda keyi: (keyi[0], utils.gmp_to_b64str(keyi[1])), self.x_shares.items()))
        return json_keys
