import os
import string
from random import randint, choice

max_uint32 = 2 ** 32
max_negative_int32 = -2 ** 31
max_positive_int32 = 2 ** 31

max_uint64 = 2 ** 64
max_negative_int64 = -2 ** 63
max_positive_int64 = 2 ** 63
string_set = string.ascii_letters + string.digits


def random_int32():
    return randint(max_negative_int32, max_positive_int32)


def random_int64():
    return randint(max_negative_int64, max_positive_int64)


def random_bytes(n=100):
    # if default size then return binary and printable data
    if n == 100:
        return bytes([i for i in range(n)])
    return os.urandom(n)


def random_str(n=10):
    return ''.join([choice(string_set) for _ in range(n)])


def random_email(n=20):
    left = random_str(n // 2)
    right = random_str(n // 2 - 1)
    return '{}@{}'.format(left, right)
