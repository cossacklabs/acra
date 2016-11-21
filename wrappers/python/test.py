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