from .. import util
from .. import randomness
import warnings
import base64
import binascii
from Crypto.Math import _IntegerGMP, Primality

#Preston's Edits for Lagrange Coefficients
#Replaces python int with GMP Integer from Crypto lib
class Polynomial:
    def __init__(self, prime_mod, coefficients):
        # coefficients = [a_k, ..., a_1, a_0] where P(x) = a_k*x^k + ... + a_1*x + a_0
        if not isinstance(prime_mod, _IntegerGMP.IntegerGMP):
            raise TypeError("prime mod must be an GMP int")
        if prime_mod.__le__(1):
            raise ValueError("invalid prime mod")
        if prime_mod.__lt__(len(coefficients)):
            raise ValueError("prime mod must exceed number of coefficients")
        for coefficient in coefficients:
            if not isinstance(coefficient, _IntegerGMP.IntegerGMP):
                raise TypeError("coefficients must be GMP ints")
        for coefficient in coefficients:
            if coefficient.__lt__(0) or coefficient.__ge__(prime_mod):
                raise ValueError("out-of-range coefficients lt-0")
        self.prime_mod = prime_mod
        self.coefficients = coefficients
    def evaluate(self, x):
        if not isinstance(x, _IntegerGMP.IntegerGMP):
            raise TypeError("x-coordinate must be an GMP int")
        if x.__lt__(0) or x.__ge__(self.prime_mod):
            raise ValueError("out-of-range x-coordinate")
        if x.__eq__(0):
            raise ValueError("P(0) may not be given, as it corresponds to the secret")
        y = _IntegerGMP.IntegerGMP(0)
        for coefficient in self.coefficients:
            y.__imul__(x)
            y.inplace_pow(1,self.prime_mod)
            y.__iadd__(coefficient)
            y.inplace_pow(1,self.prime_mod)
        return y

def lagrange_interpolation(x, points, prime_mod):
    # points = [(x0, y0), (x1, y1), ...]
    if prime_mod.__le__(1):
        raise ValueError("invalid prime mod")
    if x.__lt__(0) or x.__ge__(prime_mod):
        raise ValueError("out-of-range value")
    for (xi, yi) in points:
        if xi.__lt__(0) or xi.__ge__(prime_mod) or yi.__lt__(0) or yi.__ge__(prime_mod):
            raise ValueError("invalid points")
    y = _IntegerGMP.IntegerGMP(0)
    for i, (xi, yi) in enumerate(points):
        numerator = yi
        denominator = _IntegerGMP.IntegerGMP(1)
        for j, (xj, yj) in enumerate(points):
            if j == i:
                continue
            temp_num = x.__sub__(xj)
            temp_num.__iadd__(prime_mod)
            temp_num.inplace_pow(1,prime_mod)
            numerator.__imul__(temp_num) #*= (x - xj + prime_mod) % prime_mod
            numerator.inplace_pow(1,prime_mod) #numerator %= prime_mod

            temp_den = xi.__sub__(xj)
            temp_den.__iadd__(prime_mod)
            temp_den.inplace_pow(1, prime_mod)
            denominator.__imul__(temp_den) #*= (xi - xj + prime_mod) % prime_mod
            denominator.inplace_pow(1,prime_mod)#denominator %= prime_mod

        denominator.inplace_inverse(prime_mod)
        numerator.__imul__(denominator)
        numerator.inplace_pow(1,prime_mod)
        y.__iadd__(numerator) #+= (numerator*util.modular_inverse(denominator, prime_mod)) % prime_mod
        y.inplace_pow(1,prime_mod) #%= prime_mod
    return y

#def lagrange_coefficient(x, point, indexs, prime_mod):
def lagrange_coefficients(x, points, prime_mod):
    if prime_mod.__le__(1):
        raise ValueError("invalid prime mode")
    if x.__lt__(0) or x.__ge__(prime_mod):
        print(x)
        raise ValueError("out-of-range value")
    if x.__ge__(prime_mod):
        print("The ge test passes")
    #disable the range checking b/c yi is bytes type
    #for (xi, yi) in points:
        #if xi.__lt__(0) or xi.__ge__(prime_mod) or yi.__lt__(0) or yi.__ge__(prime_mod):
    #        raise ValueError("invalid points")
    #y = _IntegerGMP.IntegerGMP(0)
    lagrange_coefficients = dict()
    for i, (xi) in enumerate(points):
        numerator = _IntegerGMP.IntegerGMP(1)
        denominator = _IntegerGMP.IntegerGMP(1)
        for j, (xj) in enumerate(points):
            if xj == xi:
                continue
            temp_num = x.__sub__(xj)
            temp_num.__iadd__(prime_mod)
            temp_num.inplace_pow(1,prime_mod)
            numerator.__imul__(temp_num) #*= (x - xj + prime_mod) % prime_mod
            numerator.inplace_pow(1,prime_mod) #numerator %= prime_mod

            temp_den = xi.__sub__(xj)
            temp_den.__iadd__(prime_mod)
            temp_den.inplace_pow(1, prime_mod)
            denominator.__imul__(temp_den) #*= (xi - xj + prime_mod) % prime_mod
            denominator.inplace_pow(1,prime_mod)#denominator %= prime_mod

        denominator.inplace_inverse(prime_mod)
        numerator.__imul__(denominator)
        numerator.inplace_pow(1,prime_mod)
        lagrange_coefficients[xi.__int__()] = numerator
        #y.__iadd__(numerator) #+= (numerator*util.modular_inverse(denominator, prime_mod)) % prime_mod
        #y.inplace_pow(1,prime_mod) #%= prime_mod

    return lagrange_coefficients


def split_secret(secret_bytes, required_shares, distributed_shares, prime_mod, **kwargs):
    if required_shares > distributed_shares:
        raise ValueError("distributed_shares must be greater than or equal to required_shares")
    #secret_bytes = bytes([42]) + secret_bytes
    secret_length = len(secret_bytes)
    largest_representable_secret = _IntegerGMP.IntegerGMP.from_bytes(secret_bytes)
    #prime_mod = kwargs.get('prime_mod', util.select_prime_larger_than(largest_representable_secret))
    if largest_representable_secret.__ge__(prime_mod):
        raise ValueError("prime mod is not large enough")
    prime_bytes = prime_mod.size_in_bytes()
    with kwargs.get('randomness_source', randomness.RandomReader() if secret_length <= 65 else randomness.UrandomReader()) as randomness_source:
        secret = _IntegerGMP.IntegerGMP.from_bytes(secret_bytes)
        coefficients = []
        for i in range(1, required_shares):
            coefficient = _IntegerGMP.IntegerGMP.from_bytes(randomness_source.next_bytes(prime_bytes))
            coefficient.inplace_pow(1, prime_mod)
            coefficients.append(coefficient)#_IntegerGMP.IntegerGMP.from_bytes(randomness_source.next_bytes(prime_bytes)) % prime_mod)
        coefficients.append(secret)
        polynomial = Polynomial(prime_mod, coefficients)
        shares = []
        for i in range(1, distributed_shares+1):
            shares.append((_IntegerGMP.IntegerGMP(i), polynomial.evaluate(_IntegerGMP.IntegerGMP(i))))
        return {
            'required_shares': required_shares,
            'prime_mod': prime_mod,
            'shares': shares,
        }

def recover_secret(data):
    shares = data.get('shares')
    if not shares:
        raise ValueError("shares must be provided")
    required_shares = data.get('required_shares')
    if required_shares:
        if len(shares) < required_shares:
            raise ValueError("not enough shares have been provided")
        shares = shares[0:required_shares]
    else:
        warnings.warn("The number of required shares has not been specified. If not enough shares are provided, an incorrect secret will be produced without detection.")
    prime_mod = data.get('prime_mod')
    if prime_mod is None:
        raise ValueError("prime mod must be provided")
    if isinstance(prime_mod, bytes):
        prime_mod = _IntegerGMP.IntegerGMP.from_bytes(prime_mod)
    if not isinstance(prime_mod, _IntegerGMP.IntegerGMP):
        raise TypeError("invalid prime mod")
    if prime_mod.__le__(1):
        raise ValueError("invalid prime mod")
    points = []
    for x, y in shares:
        if not isinstance(x, int):
            raise TypeError("the first entry of each a share must be an int")
        if not isinstance(y, bytes):
            raise TypeError("the second entry of each a share must be an array of bytes")
        points.append((_IntegerGMP.IntegerGMP(x), _IntegerGMP.IntegerGMP.from_bytes(y)))
    return lagrange_interpolation(_IntegerGMP.IntegerGMP(0), points, prime_mod).to_bytes()

def to_base64(data):
    encode_share = lambda xy: str(xy[0]) + "-" + base64.b64encode(xy[1]).decode('ascii')
    return {
        'required_shares': data['required_shares'],
        'prime_mod': base64.b64encode(data['prime_mod']).decode('ascii'),
        'shares': list(map(encode_share, data['shares']))
    }

def from_base64(data):
    decode_tuple = lambda xy: (int(xy[0]), base64.b64decode(xy[1]))
    decode_share = lambda s: decode_tuple(tuple(s.split("-")))
    return {
        'required_shares': data['required_shares'],
        'prime_mod': data['prime_mod'] if isinstance(data['prime_mod'], int) else base64.b64decode(data['prime_mod']),
        'shares': list(map(decode_share, data['shares']))
    }


def to_hex(data):
    encode_share = lambda xy: xy[0].__str__() + "-" + xy[1].to_bytes().hex()
    return {
            'required_shares': data['required_shares'],
            'prime_mod': data['prime_mod'].to_bytes().hex(),
            'shares': list(map(encode_share, data['shares']))
    }

#def to_hex(data):
#    encode_share = lambda xy: str(xy[0]) + "-" + binascii.hexlify(xy[1]).decode('ascii')
#    return {
#        'required_shares': data['required_shares'],
#        'prime_mod': binascii.hexlify(data['prime_mod']).decode('ascii'),
#        'shares': list(map(encode_share, data['shares']))
#    }

def from_hex(data):
    decode_tuple = lambda xy: (int(xy[0]), binascii.unhexlify(xy[1]))
    decode_share = lambda s: decode_tuple(tuple(s.split("-")))
    return {
        'required_shares': data['required_shares'],
        'prime_mod': data['prime_mod'] if isinstance(data['prime_mod'], int) else binascii.unhexlify(data['prime_mod']),
        'shares': list(map(decode_share, data['shares']))
    }
