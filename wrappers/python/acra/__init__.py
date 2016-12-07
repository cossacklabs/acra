# Copyright 2016, Cossack Labs Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# coding: utf-8
import sys
from random import randint

import struct
from pythemis.scell import scell_seal
from pythemis.skeygen import themis_gen_key_pair
from pythemis.smessage import smessage as smessage_

__author__ = 'Lagovas <lagovas.lagovas@gmail.com>'
__all__ = ('create_acra_struct', 'Acra')

#BEGIN_TAG = [133, 32, 251]
BEGIN_TAG = [ord('"')]*8

if sys.version[0] == 3:
    BEGIN_TAG = bytes(BEGIN_TAG)
    def generate_key():
        return bytes([randint(0, 255) for _ in range(SYMMETRIC_KEY_LENGTH)])
else:
    BEGIN_TAG = bytes(bytearray(BEGIN_TAG))
    def generate_key():
        return bytes(bytearray([randint(0, 255) for _ in range(SYMMETRIC_KEY_LENGTH)]))

SYMMETRIC_KEY_LENGTH = 32
ZONE_BEGIN = b'ZXC'
#public_key - 45
#smessage public key - 97


def create_acra_struct(data, acra_public_key, context=None):
    random_kp = themis_gen_key_pair('EC')
    smessage = smessage_(random_kp.export_private_key(), acra_public_key)
    random_key = generate_key()
    wrapped_random_key = smessage.wrap(random_key)

    scell = scell_seal(random_key)
    encrypted_data = scell.encrypt(data, context)
    del random_key
    encrypted_data_len = struct.pack('<Q', len(encrypted_data))

    acrastruct = (
        BEGIN_TAG +
        random_kp.export_public_key() +
        wrapped_random_key +
        encrypted_data_len + encrypted_data
    )
    del random_kp
    del wrapped_random_key
    return acrastruct
create_acra_struct.__annotations__ = {
    'data': bytes, 'acra_public_key': bytes, 'context': bytes
}


class Acra(object):
    """class helper if you need load public key once and create acrastructs
    multiple times. help avoid pass public key every time"""
    LENGTH_SIZE = 8

    def __init__(self, public_key):
        self._public_key = public_key

    def create(self, data):
        return create_acra_struct(data, self._public_key)

    @classmethod
    def unpack(cls, data):
        size = struct.unpack('<Q', data[:Acra.LENGTH_SIZE])[0]
        # size must be less than data so return data as is
        if size > len(data):
            return data
        # check that next characters are the same
        if data[8+size] != data[8+size+1] != data[-1]:
            return data
        return data[Acra.LENGTH_SIZE:Acra.LENGTH_SIZE+size]

    @staticmethod
    def load_from_file(filepath):
        with open(filepath, 'rb') as f:
            return Acra(f.read())
