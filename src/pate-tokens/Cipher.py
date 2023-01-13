from Crypto.Math import _IntegerGMP, Primality


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
