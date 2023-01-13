from sslib import shamir

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

prime_p_2048 = int(hex_string_p.replace(" ", ""), 16)
prime_q_2048 = (prime_p_2048-1)/2

class Key:
    def __init__(self):
        self.p
        self.q
        self.g = 2
        self.x = None
        self.y = None

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


class Distributed_Key(Key):
    def __init__(self, x_share, group_keys):
        super.__init__():
        self.x_share = x_share
        self.group_pkeys = group_keys

class Full_key(Key):
    def __init__(self, group_idxs):
        super().__init__()
        self.group_idxs = group_idxs
        self.x_shares = None
        self.group_pks = None


    def secret_share(self):
        x_bytes = self.x.to_bytes()
        secrets = shamir.to_hex(shamir.split_secret(x_bytes, THRESHOLD, TOTAL, prime_mod=self.q))

        shares_dict = {}
        for share in secrets['shares']:
            (idx, share) = share.split("-")
            shares_dict[idx] = share
        
        self.x_shares = shares_dict
        #FOR TEST
        #sh = shamir.to_hex(shamir.split_secret(key.x.to_bytes(), THRESHOLD, TOTAL, prime_mod=key.q))
        #print("key.x is {}".format(key.x.to_bytes()))
        #print("sh is {}".format(sh))
        #print("sh.from_hex {}".format(shamir.from_hex(sh)))
        #secret = shamir.recover_secret(shamir.from_hex(sh))
        #print("secret is {}".format(secret))

    def generate_public_keys(self):
        public_keys = {}
        for idx in self.x_shares:
            share = _IntegerGMP.IntegerGMP.from_bytes(bytes.fromhex(self.x_shares[idx]))
            pub_key = self.g.__pow__(share, self.p)
            public_keys[idx] = pub_key.to_bytes().hex()

        self.group_pks = public_keys


class NIST_Key:
    def __init__(self):
        self.p = _IntegerGMP.IntegerGMP(prime_p_2048)
        self.q = _IntegerGMP.IntegerGMP(prime_q_2048)
        self.g = _IntegerGMP.IntegerGMP(2)
        self.y = None
        self.x = None
        self.shares = None
        self.public_keys = None

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
