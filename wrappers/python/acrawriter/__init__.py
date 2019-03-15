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
import os
import sys
import struct

from pythemis.scell import SCellSeal
from pythemis.skeygen import GenerateKeyPair, KEY_PAIR_TYPE
from pythemis.smessage import SMessage

__all__ = ('create_acrastruct', 'generate_key')

BEGIN_TAG = [ord('"')]*8
SYMMETRIC_KEY_LENGTH = 32


def generate_key():
    return os.urandom(SYMMETRIC_KEY_LENGTH)


if sys.version[0] == 3:
    BEGIN_TAG = bytes(BEGIN_TAG)
else:
    BEGIN_TAG = bytes(bytearray(BEGIN_TAG))


def create_acrastruct(data, acra_public_key, context=None, encoding='utf-8'):
    random_kp = GenerateKeyPair(KEY_PAIR_TYPE.EC)
    smessage = SMessage(random_kp.export_private_key(), acra_public_key)
    random_key = generate_key()
    wrapped_random_key = smessage.wrap(random_key)

    scell = SCellSeal(random_key)
    if isinstance(data, str):
        data = data.encode(encoding)
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
create_acrastruct.__annotations__ = {
    'data': bytes, 'acra_public_key': bytes, 'context': bytes, 'encoding': str,
}