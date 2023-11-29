# NOTE: program is written and executed in Python 3.12 and uses updated pow module
# If your Python version is < 3.5 you may need to replace pow module with an alternative that can be used in your version
import random
import hashlib
from math import gcd


# Primality Check function tests if input integer is prime using probabilistic Miller-Rabin test as a core
# method and deterministicly checks if m is a composite of prime numbers less than 100
def PrimalityCheck(m):
    primary_num = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
    m = int(m, 2)
    for i in range(0, len(primary_num)):
        if m % primary_num[i] == 0:
            return False
    r = m - 1
    while r % 2 == 0:
        r //= 2
    # higher amount of iterations is desired, but not necessary
    # you may increase amount of iterations if you desire higher accuracy
    for i in range(0, 10):
        a = 2 + random.randint(1, m - 4)
        x = pow(a, r, m)
        if x == 1 or x == m - 1:
            return True
        while r != m - 1:
            x = (x * x) % m
            r *= 2
            if x == 1:
                return False
            if x == m - 1:
                return True
        return False


def GeneratePrime(keylength):
    h = ''
    # RSA supports key length of 1024, 2048 or 4096 bits. If it's neither, key length is rejected
    if keylength not in [1024, 2048, 4096]:
        return "Desired keylength is invalid, it must be either 1024 bits, 2048 bits or 4096 bits"
    num_iter = int(keylength / 4)
    # Generating hex numbers with random and the turning them into binary has shown to be faster than
    # generating 0 and 1 bits in approximately half of the tests
    for i in range(0, num_iter):
        h += bin(random.randint(0, 15))[2:].zfill(4)
    # If generated number passes primality check already then it's passed down
    if PrimalityCheck(h):
        return h
    # Otherwise, new one generated until the one which passes the test is generated
    else:
        # Usually, amount of iterations exceeds 992 and python throws Recursion Error, following code
        # is made to guarantee that a number is generated at every instance
        try:
            h = GeneratePrime(keylength)
            return h
        except RecursionError:
            h = GeneratePrime(keylength)
            return h

# Key generating function, firstly, two prime numbers of desired key length found, after that key is generated
# according to RSA algorythm
def KeyGen(keylength=1024):
    p = int(GeneratePrime(keylength), 2)
    q = int(GeneratePrime(keylength), 2)
    n = p * q
    m = (p - 1) * (q - 1)
    d = random.randint(2, m - 2)
    while gcd(d, m) != 1:
        d = random.randint(2, m - 2)
    e = pow(d, -1, m)
    priv_key = (n, e)
    pub_key = (n, d)
    return priv_key, pub_key

# Encryption and decryption functions are quite simple due to update of pow module in Python 3.5
def enc(message, private):
    element = bin(pow(int(message, 2), private[1], private[0]))[2:]
    c_bin = element.zfill(((len(element) // 8 + 1) * 8))
    return c_bin


def dec(ciphertext, public):
    element = bin(pow(int(ciphertext, 2), public[1], public[0]))[2:]
    m_bin = element.zfill((len(element) // 8 + 1) * 8)
    return m_bin


# RSA functions works as both encryption and decryption function. In order to use it for encryption please
# specify that encrypt=True upon calling function, for decryption use decrypt=True
def RSA(pr_key, pb_key, message='', ciphertext='', encrypt=False, decrypt=False):
    if encrypt:
        mes_bin = ''
        for char in message:
            mes_bin += bin(ord(char))[2:].zfill(8)
        return enc(mes_bin, pr_key)
    if decrypt:
        return dec(ciphertext, pb_key)
    if not encrypt and not decrypt:
        return "Please, specify if you want to encrypt message or decrypt it"

# Signing functions turns message into its sha-256 hash, encodes and returns tuple of message hash and its signature
def sign(message, pr_key):
    message = message.encode()
    hashed = hashlib.sha256(message).hexdigest()
    return hashed, RSA(pr_key, 0, message=hashed, encrypt=True)

# Digital signature verification function, according to RSA algorythm
def verify(mess, ciphertext, pub_key):
    hash_bin = ''
    for char in mess:
        hash_bin += bin(ord(char))[2:].zfill(8)
    if hash_bin == RSA(0, pub_key, ciphertext=ciphertext, decrypt=True):
        return "The signature is authentic"
    else:
        return "Message or public key may have been compromised"

# Test examples
def TestVer(pr_key, pb_key):
    m1 = "Attack at dawn"
    h1, c1 = sign(m1, pr_key)
    print(verify(h1, c1, pb_key))
    h2 = h1[1:]
    print(verify(h2, c1, pb_key))
    c2 = bin(int(c1, 2) - 1)[2:]
    print(verify(h1, c2, pb_key))


pr_key, pb_key = KeyGen()
TestVer(pr_key, pb_key)
# For you own uses please run the following code with substituting message value with desired value
message = "Hello World"
hashed, signature = sign(message, pr_key)
print(verify(hashed, signature, pb_key))
