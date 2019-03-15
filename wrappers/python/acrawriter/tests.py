# Copyright 2018, Cossack Labs Limited
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

import unittest
from pythemis.skeygen import GenerateKeyPair, KEY_PAIR_TYPE

from acrawriter import create_acrastruct, generate_key, SYMMETRIC_KEY_LENGTH


class TestGenerateKey(unittest.TestCase):
    def testGenerateKey(self):
        self.assertEqual(len(generate_key()), SYMMETRIC_KEY_LENGTH)


class TestCreateAcraStruct(unittest.TestCase):
    def testWithContext(self):
        test_data = b'some data'
        context = b'some context'
        public_key = GenerateKeyPair(KEY_PAIR_TYPE.EC).export_public_key()
        self.assertIsNotNone(create_acrastruct(test_data, public_key, context))

    def testWithoutContext(self):
        test_data = b'some data'
        public_key = GenerateKeyPair(KEY_PAIR_TYPE.EC).export_public_key()
        self.assertIsNotNone(create_acrastruct(test_data, public_key))

    def testWithEncoding(self):
        test_data = 'some data'
        public_key = GenerateKeyPair(KEY_PAIR_TYPE.EC).export_public_key()
        self.assertIsNotNone(create_acrastruct(test_data, public_key))


if __name__ == '__main__':
    unittest.main()