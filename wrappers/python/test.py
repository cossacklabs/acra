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
import struct
import unittest
from tempfile import NamedTemporaryFile

from pythemis.skeygen import themis_gen_key_pair

from acra import Acra

__author__ = 'Lagovas <lagovas.lagovas@gmail.com>'


class AcraTest(unittest.TestCase):
    def testLoadFromFile(self):
        with NamedTemporaryFile('wb') as f:
            acra = Acra.load_from_file(f.name)

    def testUnpack(self):
        raw_test_data = b'qwertyuio'
        trash_data = b't'*100
        length = struct.pack('<Q', len(raw_test_data))
        test_data = length + raw_test_data + trash_data
        self.assertEqual(raw_test_data, Acra.unpack(test_data))

    def testCreate(self):
        data = b'some data'
        key_pair = themis_gen_key_pair('EC')
        acra = Acra(key_pair.export_public_key())
        acrastruct = acra.create(data)


if __name__ == '__main__':
    unittest.main()