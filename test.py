from Crypto.Math._IntegerGMP import IntegerGMP as IntGMP



test_dict = {'p': IntGMP(1).to_bytes(), 'q': IntGMP(2).to_bytes()}

print(test_dict)

new_dict = dict(map(lambda x: (x[0], IntGMP.from_bytes(x[1])), test_dict.items()))

print(new_dict)
