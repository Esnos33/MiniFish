def byte2bin(b):
    return ''.join(format(byte, '08b') for byte in b)


def deg(a):
    deg = len(bin(a)[2:])-1
    return deg


def gf_mul(a, b, m):
    p = 0
    while a > 0:
        if a & 1:
            p = p ^ b

        a = a >> 1
        b = b << 1

        if deg(b) == deg(m):
            b = b ^ m

    return p


def in_polynomial(b):
    ls = []
    j = 0
    a = list(bin(b)[2:])
    a.reverse()
    for i in a:
        if i == '1':
            ls.append(j)
        j += 1
    return ls


def parser(ls: list):
    a = ''
    for i in ls:
        a += f"x^{str(i)} +"
    return a[:-2]


def convert_to_field_element(a):
    p = 4295000729  # p = x^32 + x^15 + x^9 + x^7 + x^4 + x^3 + 1
    # p = 340282366920938463463374607431768211591  # p = x^128+x^7+x^2+x+1
    if deg(a) >= deg(p):
        return a ^ p
    else:
        return a
