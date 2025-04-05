from hashlib import shake_256
from pwn import xor
from galois import gf_mul, byte2bin


def F(x: bytes):
    x_hex = x.hex()
    part = [int.from_bytes(S[i][int(x_hex[2*i: 2*(i+1)], 16)])
            for i in range(4)]
    v1 = gf_mul(part[0], part[1], 4295000729)
    v2 = v1 ^ part[2]
    v3 = gf_mul(v2, part[3], 4295000729)
    return v3.to_bytes(4, "big")


def blowfish(L, R, K, way="enc"):
    if way == "enc":
        pass
    elif way == 'dec':
        K = list(K)
        K.reverse()
    for r in range(16):
        L = xor(L, K[r])
        R = xor(F(L), R)
        L, R = R, L
    L, R = R, L
    R = xor(R, K[16])
    L = xor(L, K[17])
    return L, R


key = b'klucz'
PI = shake_256(key).hexdigest(4168)

P = [PI[i*4:(i+1)*4] for i in range(18)]


S = [[bytes.fromhex(PI[i*1024+j*4+72:i*1024+(j+1)*4+72])
      for j in range(256)] for i in range(4)]

K = key

while len(K.hex()) <= 72:
    K += key
K1 = K.hex()[:72]
K2 = [K1[i*4:(i+1)*4] for i in range(18)]
Pxor = [xor(P[i], K2[i]) for i in range(18)]

T = (bytes.fromhex("00000000"), bytes.fromhex("00000000"))
for i in range(9):
    T = blowfish(T[0], T[1], Pxor)
    Pxor[2*i], Pxor[2*i+1] = T

for i in range(4):
    for j in range(128):
        T = blowfish(T[0], T[1], Pxor)
        S[i][2*j], S[i][2*j+1] = blowfish(T[0], T[1], Pxor)


def encrypt(key, text):
    return blowfish(text[:len(text)//2], text[len(text)//2:], key)


def gcm(keys, text, iv_input, AAD, way="enc"):
    H = encrypt(keys, b'00000000')  # stała w algorytmie
    H = H[0] + H[1]
    p = 340282366920938463463374607431768211591  # p = x^128+x^7+x^2+x+1
    iv = int.from_bytes(iv_input + b'0000')

    divided_string = [text[i:i+8]
                      for i in range(0, len(text), 8)]
    last = divided_string[-1]
    if way == "enc":
        if len(last) != 8:
            last = byte2bin(last)
            last += '1'
            last = last.ljust(64, '0')
            last2 = int(last, 2)
            divided_string[-1] = last2.to_bytes((len(last) + 7) // 8, 'big')
        else:
            binary_string = '1000000000000000000000000000000000000000000000000000000000000000'
            integer_value = int(binary_string, 2)
            byte_array = integer_value.to_bytes(
                (len(binary_string) + 7) // 8, 'big')
            divided_string.append(byte_array)

    amount = len(divided_string)

    counter = [0 for i in range(amount)]
    for i in range(len(counter)):
        counter[i] = (iv + i).to_bytes(length=((iv + i).bit_length() + 7) // 8)

    cipher_block = [0 for i in range(amount)]
    for i in range(amount):
        cipher_block[i] = xor(encrypt(keys, counter[i]), divided_string[i])

    g = [0 for i in range(amount)]
    g[0] = gf_mul(int.from_bytes(H), int.from_bytes(AAD), p)

    for i in range(1, amount):
        g[i] = gf_mul(g[i-1] ^ int.from_bytes(cipher_block[i]),
                      int.from_bytes(H), p)

    T = gf_mul(g[-1], int.from_bytes(H), p) ^ int.from_bytes(cipher_block[0])
    cipher_block = bytes().join(cipher_block)
    return [cipher_block, T, AAD]


key = Pxor
text = b'matematyka jest super'
iv = b'0123'
AAD = b'Karol Kasia Oskar'

encrypted = gcm(key, text, iv, AAD)
decrypted = gcm(key, encrypted[0], iv, AAD)
print(text, iv, AAD, decrypted[0])
