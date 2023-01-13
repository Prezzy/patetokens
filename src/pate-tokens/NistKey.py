from sslib import shamir


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
