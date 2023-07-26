import os
import string
from random import randint, choice

max_uint32 = 2 ** 32
max_negative_int32 = -2 ** 31
max_positive_int32 = 2 ** 31

max_uint64 = 2 ** 64
max_negative_int64 = -2 ** 63
max_positive_int64 = 2 ** 63

# Update this to include code point ranges to be sampled
unicode_ranges = [
    ( 0x0021, 0x0021 ),
    # without #$%&
    #( 0x0023, 0x0026 ),
    # without \:;<=>?@ due to they can make conflict with our string manipulations over SQL queries
    # with different placeholders acceptable by different drivers/db

    ( 0x0028, 0x0039 ),
    ( 0x0041, 0x005B ),
    ( 0x005D, 0x007E ),

    ( 0x00A1, 0x00AC ),
    ( 0x00AE, 0x00FF ),
    ( 0x0100, 0x017F ),
    ( 0x0180, 0x024F ),
    ( 0x2C60, 0x2C7F ),
    ( 0x16A0, 0x16F0 ),
    ( 0x0370, 0x0377 ),
    ( 0x037A, 0x037E ),
    ( 0x0384, 0x038A ),
    ( 0x038C, 0x038C ),
]

string_set = [
    chr(code_point) for current_range in unicode_ranges
    for code_point in range(current_range[0], current_range[1] + 1)
]

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
