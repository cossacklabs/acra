# coding: utf-8
from pythemis import smessage, scell
import yaml


def load_default_config(service_name):
    with open('configs/{}.yaml'.format(service_name), 'r') as f:
        return yaml.safe_load(f)


def read_storage_public_key(client_id, keys_dir='.acrakeys'):
    with open('{}/{}_storage.pub'.format(keys_dir, client_id), 'rb') as f:
            return f.read()

def read_zone_public_key(zone_id, keys_dir='.acrakeys'):
    with open('{}/{}_zone.pub'.format(keys_dir, zone_id), 'rb') as f:
        return f.read()


def decrypt_acrastruct(data, private_key, client_id=None, zone_id=None):
    public_key = data[8:8+45]
    encrypted_symmetric = data[8+45:8+45+84]
    smessage_decryptor = smessage.SMessage(private_key, public_key)
    symmetric = smessage_decryptor.unwrap(encrypted_symmetric)
    data = data[8+45+84+8:]
    if zone_id:
        return scell.SCellSeal(symmetric).decrypt(data, zone_id)
    else:
        return scell.SCellSeal(symmetric).decrypt(data)


def decrypt_private_key(private_key, key_id, master_key):
    return scell.SCellSeal(master_key).decrypt(private_key, key_id)