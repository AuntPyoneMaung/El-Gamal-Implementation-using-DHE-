
from math import sqrt
import random
import json
import time


# region import JSON
testfile = open(r'C:\Users\APM Z\Desktop\ComSec CW1\180405646.json')
jsondata = json.load(testfile)
testfile.close()
text_to_decrypt = jsondata["exercise"]["message"]["text"]
min = int(jsondata["exercise"]["min"])
max = int(jsondata["exercise"]["max"])
name = jsondata["name"]
srn = (jsondata["srn"])
print(name, srn)
# print(text_to_decrypt[:4])
# endregion import JSON

# region Primality Testing, choose Prime
primes_known = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
                67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137,
                139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
                223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
                293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379,
                383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461,
                463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563,
                569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643,
                647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739,
                743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829,
                839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937,
                941, 947, 953, 967, 971, 977, 983, 991, 997]


def randNumber(n):
    return random.randrange(2**(n-1)+1, 2**n - 1)


def lowlevelPrime(n):
    while True:
        random_num = randNumber(n)
        for i in primes_known:
            if random_num % i == 0 and i**2 <= random_num:
                break
        else:
            return random_num


def is_composite(a, d, n, s):
    if pow(a, d, n) == 1:
        return False
    for i in range(s):
        if pow(a, 2**i * d, n) == n-1:
            return False
    return True


def is_prime(n):
    if n in primes_known:
        return True
    if any((n % p) == 0 for p in primes_known) or n in (0, 1):
        return False
    d, s = n - 1, 0
    while not d % 2:
        d, s = d >> 1, s + 1
    if n < 18446744073709551616:
        return not any(is_composite(a, d, n, s) for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37))
    if n < 318665857834031151167461:
        return not any(is_composite(a, d, n, s) for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37))


if __name__ == '__main__':
    runtime_start = time.time()
    while True:
        n = 64
        prime_candidate = lowlevelPrime(n)
        if not is_prime(prime_candidate):
            continue
        elif prime_candidate in range(min, max):
            print(n, "bit prime is: \n", prime_candidate)
            print("Primality check runtime: ",
                  (time.time() - runtime_start), 'seconds')
            break
# endregion Primality Testing, choose Prime


# region Generator g
def primeFactors(s, p):

    while (p % 2 == 0):
        s.add(2)
        p = p // 2

    for i in range(3, int(sqrt(p)), 2):
        while (p % i == 0):
            s.add(i)
            p = p // i

    if (n > 2):
        s.add(p)


def primitiveRootG(p):
    s = set()
    phiPrime = p - 1
    primeFactors(s, phiPrime)

    for g in range(2, phiPrime):
        flag = False
        for pf in s:
            if (pow(g, phiPrime // pf, p) == 1):
                flag = True
                break
        if (flag == False):
            return g

    return -1
# endregion Generator g


# region ELGAMAL encrypt, decrypt
def elgamalEncryption(text, p, y, g):

    msgblock_keys = []  # k values for each block
    x = []  # x values for repective block
    r = []  # r values for repective block

    # Bob sk [largest 32 bit signed integer]
    sk = random.randint(2, 4294967295)
    print('Bob private key [sk]: ', sk, '\n')

    bob_key = pow(g, sk, p)
    print('Bob public key [pk]: ', bob_key, '\n')

    shared_key = pow(y, sk, p)
    print('Shared key [shared]:', shared_key, '\n')

    enc0 = int.from_bytes(text[0:7].encode('utf-8'), byteorder='big')
    enc1 = int.from_bytes(text[7:14].encode('utf-8'), byteorder='big')
    enc2 = int.from_bytes(text[14:21].encode('utf-8'), byteorder='big')
    enc3 = int.from_bytes(text[21:28].encode('utf-8'), byteorder='big')
    enc4 = int.from_bytes(text[28:].ljust(7).encode('utf-8'), byteorder='big')
    encoded = []
    encoded.append(enc0)
    encoded.append(enc1)
    encoded.append(enc2)
    encoded.append(enc3)
    encoded.append(enc4)

    for _ in range(5):
        keys = random.randint(2, 4294967295)
        msgblock_keys.append(keys)

    for i in range(0, len(msgblock_keys)):
        x_values = pow(y, msgblock_keys[i], p)
        x.append(x_values)

    for i in range(0, len(encoded)):
        encoded[i] = encoded[i] * x[i]  # values of c

    for i in range(0, len(msgblock_keys)):
        r_values = pow(g, msgblock_keys[i], p)
        r.append(r_values)

    return encoded, r  # returns c,r pair. Discards values of k and x


def elgmalDecryption(encoded, r, key_alice, p):
    decoded_text = []
    x = []
    inverse = []

    for i in range(0, len(r)):
        x.append(pow(r[i], key_alice, p))
    # inverse
    for i in range(0, len(x)):
        inverse.append(pow(x[i], -1, p))

    # decrypt
    for i in range(0, len(encoded)):
        decoded_text.append(pow(encoded[i]*inverse[i], 1, p))
    print("Encoded plain text after decryption: ", decoded_text)

    for i in range(0, len(decoded_text)):
        decoded_text[i] = int.to_bytes(
            decoded_text[i], length=7, byteorder='big').decode('utf-8')

    return decoded_text
# endregion ELGAMAL encrypt, decrypt


def main():
    text = text_to_decrypt
    # Alice and Bob agrees on prime p and generator g
    p = 11802904305386828087
    g = 5

    # receiver [Alice] private key, sk [alice decrypt]
    key_alice = random.randint(2, 4294967295)
    y = pow(g, key_alice, p)  # receiver public key, pk

    encoded, r = elgamalEncryption(text, p, y, g)
    decoded_text = elgmalDecryption(encoded, r, key_alice, p)
    join_frags = ''.join(decoded_text)
    decrypted_text_output = join_frags.replace('   ', '')
    print("Decrypted Message :", decrypted_text_output)

    # region For write to JSON purposes only
    enc0 = int.from_bytes(text[0:7].encode('utf-8'), byteorder='big')
    enc1 = int.from_bytes(text[7:14].encode('utf-8'), byteorder='big')
    enc2 = int.from_bytes(text[14:21].encode('utf-8'), byteorder='big')
    enc3 = int.from_bytes(text[21:28].encode('utf-8'), byteorder='big')
    enc4 = int.from_bytes(text[28:].ljust(7).encode('utf-8'), byteorder='big')
    # endregion For write to JSON purposes only
    data = {
        "srn": srn,
        "name": name,
        'exercise': {
            'min': str(min),
            'max': str(max),
            'p': str(p),
            'g': str(g),
            "alice": {
                'sk': str(key_alice),
                'pk': str(y),
                # replace manually from code output
                'shared': str(11111111111111111111)
            },
            "bob": {
                # replace manually from code output
                'sk': str(11111111111111111111),
                # replace manually from code output
                'pk': str(11111111111111111111),
                # replace manually from code output
                'shared': str(11111111111111111111)
            },
            'message': {
                'text': decrypted_text_output,
                'encoded': [
                    str(enc0),
                    str(enc1),
                    str(enc2),
                    str(enc3),
                    str(enc4)
                ],
                'encrypted': [
                    {
                        'r': str(r[0]),
                        'c': str(encoded[0])
                    },
                    {
                        'r': str(r[1]),
                        'c': str(encoded[1])
                    },
                    {
                        'r': str(r[2]),
                        'c': str(encoded[2])
                    },
                    {
                        'r': str(r[3]),
                        'c': str(encoded[3])
                    },
                    {
                        'r': str(r[4]),
                        'c': str(encoded[4])
                    }
                ]
            }
        }
    }

    answer = json.dumps(data)
    print(answer)

    with open('AuntPyoneMaung_180405646_CO3326cw1.json_test', 'w') as jsonoutput:
        jsonoutput.write(answer)


if __name__ == '__main__':
    main()
