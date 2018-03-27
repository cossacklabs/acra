# coding: utf-8
import subprocess



print(get_go_version())
exit(0)



from base64 import b64decode, b64encode
from binascii import hexlify
from acrawriter import create_acrastruct
with open('/home/lagovas/development/GOPATH/src/github.com/cossacklabs/acra/.acrakeys2/client_storage.pub', 'rb') as f:
    public = f.read()

zone_public = b64decode(b'VUVDMgAAAC0eUodjA/9Es/qB2/hjhnVSCd5uIHAbiwcflu7X3h2s51JqTYt5')
zone_id = b'DDDDDDDDSoqiMOnPZqzTVmeJ'

public = zone_public
#print(hexlify(create_acrastruct(b'test data with zone', public, zone_id)))
print(hexlify())
exit(0)

incorrect_data = b'incorrect data'
correct_data = b'correct data'
fake_offset = (3+45+84) - 1
fake_acra_struct = create_acrastruct(incorrect_data, public)[:fake_offset]
inner_acra_struct = create_acrastruct(correct_data, public)
data = fake_acra_struct + inner_acra_struct

print(hexlify(data))