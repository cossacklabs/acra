# coding: utf-8
import json
import os
import shutil
import subprocess
import sys
import tempfile

import yaml
from pythemis import smessage, scell

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
abs_path = lambda x: os.path.join(BASE_DIR, x)
BINARY_OUTPUT_FOLDER = os.environ.get('TEST_BINARY_OUTPUT_FOLDER', '/tmp/')

# used to mark case when user didn't declare explicitly variable and we generated new temporary folder
# in this case we clean temporary folder, otherwise don't touch user specified path
TEMP_DATA_GENERATED = 'TEST_RANDOM_DATA_FOLDER_GENERATE'
TEMP_DATA_FOLDER_VARNAME = 'TEST_RANDOM_DATA_FOLDER'


def send_signal_by_process_name(name, signal, timeout=1):
    try:
        output = subprocess.check_output(['pidof', name], timeout=timeout)
    except subprocess.CalledProcessError:
        return
    output = output.strip().decode('utf-8').split(' ')
    for pid in output:
        os.kill(int(pid), signal)


def get_encryptor_config(new_path):
    return os.environ.get(
        'TEST_ENCRYPTOR_DEFAULT_CONFIG', new_path)


def get_test_encryptor_config(config_path):
    return os.environ.get(
        'TEST_ENCRYPTOR_TEST_CONFIG',
        get_encryptor_config(config_path) + '.test')


def clean_test_data():
    """remove temporary created folder and test files if it was generated"""
    folder = os.environ.get(TEMP_DATA_GENERATED)
    if folder:
        print("clean temporary folder <{}>".format(folder))
        shutil.rmtree(folder)


def safe_string(str_or_bytes, encoding='utf-8'):
    if isinstance(str_or_bytes, str):
        return str_or_bytes
    return str_or_bytes.decode(encoding)


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
        command = [sys.executable, abs_path('tests/generate_random_data.py')]
        print('call {}'.format(' '.join(command)))
        subprocess.check_call(command, env=os.environ, cwd=os.getcwd())
    return [os.path.join(folder, i) for i in os.listdir(folder)]


def load_random_data_config():
    with open(abs_path('tests/random_data_config.json'), 'r') as f:
        return json.load(f)


def load_yaml_config(path):
    with open(abs_path(path), 'r') as f:
        config = yaml.safe_load(f)
    return config


def dump_yaml_config(config, path):
    with open(abs_path(path), 'w') as f:
        yaml.dump(config, f)


def load_default_config(service_name):
    config = load_yaml_config('configs/{}.yaml'.format(service_name))

    # convert empty values to empty strings to avoid pass them to Popen as
    # "None" string value

    # every config has version but service's don't have such parameter and will exit with error if we will
    # provide unexpected parameter
    # when services parse configs they ignore unknown parameters and not down for that
    skip_keys = ['version']
    for skip in skip_keys:
        del config[skip]
    for key in config:
        if config[key] is None:
            config[key] = ''
    return config


def read_key(key_id, public, keys_dir='.acrakeys', extra_kwargs: dict = None):
    """Reads key from keystore with acra-keys."""
    args = [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'), 'read', '--keys_dir={}'.format(keys_dir)]

    if extra_kwargs:
        for key, value in extra_kwargs.items():
            param = '-{0}={1}'.format(key, value)
            args.append(param)
    if public:
        args.append('--public')
    else:
        args.append('--private')
    args.append(key_id)
    return subprocess.check_output(args)


def destroy_key(key_id, keys_dir='.acrakeys'):
    """Destroys key in the keystore with acra-keys."""
    args = [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'), 'destroy', '--keys_dir={}'.format(keys_dir)]
    args.append(key_id)
    return subprocess.check_output(args)


def destroy_server_storage_key(client_id, public=True, keys_dir='.acrakeys', keystore_version='v1'):
    if keystore_version == 'v1':
        key_path = '{}/{}_storage'.format(keys_dir, client_id)
        if public:
            key_path = '{}.pub'.format(key_path)
    else:
        key_path = '{}/client/{}/storage.keyring'.format(keys_dir, client_id)

    os.remove(key_path)


def read_storage_public_key(client_id, keys_dir='.acrakeys', extra_kwargs: dict = None):
    return read_key('client/{}/storage'.format(client_id),
                    public=True, keys_dir=keys_dir, extra_kwargs=extra_kwargs)


def read_zone_public_key(zone_id, keys_dir='.acrakeys'):
    return read_key('zone/{}/storage'.format(zone_id),
                    public=True, keys_dir=keys_dir)


def deserialize_crypto_envelope_with_acrastruct(data):
    if data[:3] == b'%%%':
        crypto_id = data[8+3]
        if crypto_id != 0xF1:
            raise ValueError("invalid CryptoEnvelope with AcraStruct")
        return data[8+4:]
    raise ValueError("Invalid crypto envelope")


def deserialize_and_decrypt_acrastruct(data, private_key, client_id=None, zone_id=None):
    data = deserialize_crypto_envelope_with_acrastruct(data)
    return decrypt_acrastruct(data, private_key, client_id, zone_id)


def decrypt_acrastruct(data, private_key, client_id=None, zone_id=None):
    public_key = data[8:8 + 45]
    encrypted_symmetric = data[8 + 45:8 + 45 + 84]
    smessage_decryptor = smessage.SMessage(private_key, public_key)
    symmetric = smessage_decryptor.unwrap(encrypted_symmetric)
    encrypted_data = data[8 + 45 + 84 + 8:]
    if zone_id:
        return scell.SCellSeal(symmetric).decrypt(encrypted_data, zone_id)
    else:
        return scell.SCellSeal(symmetric).decrypt(encrypted_data)


def read_storage_private_key(keys_folder, key_id):
    return read_key('client/{}/storage'.format(key_id),
                    public=False, keys_dir=keys_folder)


def read_zone_private_key(keys_folder, key_id):
    return read_key('zone/{}/storage'.format(key_id),
                    public=False, keys_dir=keys_folder)


def read_poison_public_key(keys_dir):
    return read_key('poison-record', public=True, keys_dir=keys_dir)


def read_poison_private_key(keys_dir):
    return read_key('poison-record', public=False, keys_dir=keys_dir)


def prepare_encryptor_config(zone_id, config_path, client_id=None):
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    for table in config['schemas']:
        for column in table['encrypted']:
            if 'zone_id' in column:
                column['zone_id'] = zone_id
            if client_id and 'client_id' in column:
                column['client_id'] = client_id
    with open(get_test_encryptor_config(config_path), 'w') as f:
        yaml.dump(config, f)


def get_bool_env(var, default=False):
    """Read a boolean value from environment variable."""
    value = os.environ.get(var, None)
    if not value:
        return default
    value = value.lower()
    if value in ['no', 'n', 'false']:
        return False
    if value in ['yes', 'y', 'true']:
        return True
    # Dunno, maybe this is an integer, use C convention
    return int(value) != 0


def memoryview_to_bytes(value):
    """convert memoryview to bytes or return as is"""
    if hasattr(value, 'tobytes'):
        return value.tobytes()
    return value


def memoryview_rows_to_bytes(data):
    for row in data:
        items = row.items()
        for key, value in items:
            row[key] = memoryview_to_bytes(value)
