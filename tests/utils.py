# coding: utf-8
import json
import os
import subprocess
import tempfile
import shutil

from pythemis import smessage, scell
import yaml


TEMP_DATA_GENERATED = 'TEST_RANDOM_DATA_FOLDER_GENERATE'
TEMP_DATA_FOLDER_VARNAME = 'TEST_RANDOM_DATA_FOLDER'

def clean_test_data():
    """remove temporary created folder and test files if it was generated"""
    folder = os.environ.get(TEMP_DATA_GENERATED)
    if folder:
        print("clean temporary folder <{}>".format(folder))
        shutil.rmtree(folder)


def get_random_data_files():
    folder = os.environ.get(TEMP_DATA_FOLDER_VARNAME)
    if not folder:
        folder = tempfile.mkdtemp(None, 'test_data', None)
        # set temp folder before call generator
        os.environ.setdefault(TEMP_DATA_FOLDER_VARNAME, folder)
        # remember that we generated from script to cleanup at end
        os.environ.setdefault(TEMP_DATA_GENERATED, folder)
        print("You didn't set {} env var. Test data will be generated to <{}> "
              "folder and removed at end".format(
                  TEMP_DATA_FOLDER_VARNAME, folder))
    if not os.path.exists(folder) or len(os.listdir(folder)) == 0:
        command = ['python', 'tests/generate_random_data.py']
        print('call {}'.format(' '.join(command)))
        subprocess.check_call(command, env=os.environ)
    return [os.path.join(folder, i) for i in os.listdir(folder)]


def load_random_data_config():
    with open('tests/random_data_config.json', 'r') as f:
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