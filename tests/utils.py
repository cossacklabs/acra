# coding: utf-8
import json
import os
import subprocess

from pythemis import smessage, scell
import yaml


def get_random_data_files():
    folder = os.environ.get('TEST_RANDOM_DATA_FOLDER')
    if not folder:
        print('You must set TEST_RANDOM_DATA_FOLDER env variable and generate '
              'test data')
        exit(1)
    if not os.path.exists(folder):
        command = ['python', '.circleci/generate_random_data.py']
        print('call {}'.format(' '.join(command)))
        subprocess.check_call(command)
    return [os.path.join(folder, i) for i in os.listdir(folder)]


def load_random_data_config():
    with open('.circleci/random_data_config.json', 'r') as f:
        return json.load(f)


def load_default_config(service_name):
    with open('configs/{}.yaml'.format(service_name), 'r') as f:
        config = yaml.safe_load(f)
    # convert empty values to empty strings to avoid pass them to Popen as
    # "None" string value
    for key in config:
        if config[key] is None:
            config[key] = ''
    return config


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
    encrypted_data = data[8+45+84+8:]
    if zone_id:
        return scell.SCellSeal(symmetric).decrypt(encrypted_data, zone_id)
    else:
        return scell.SCellSeal(symmetric).decrypt(encrypted_data)


def decrypt_private_key(private_key, key_id, master_key):
    return scell.SCellSeal(master_key).decrypt(private_key, key_id)