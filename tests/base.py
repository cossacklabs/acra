import asyncio
import collections
import collections.abc
import contextlib
import json
import logging
import os
import os.path
import random
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import traceback
import unittest
from base64 import b64decode, b64encode
from contextlib import closing
from urllib.parse import urlparse

import asyncpg
import mysql.connector
import psycopg as psycopg3
import psycopg2
import psycopg2.errors
import psycopg2.extras
import pymysql
import semver
import sqlalchemy as sa
import yaml
from pythemis import smessage, scell
from sqlalchemy.dialects import mysql as mysql_dialect
from sqlalchemy.dialects import postgresql as postgresql_dialect

import generate_random_data

# add to path our wrapper until not published to PYPI
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'wrappers/python'))

from acrawriter import create_acrastruct


def load_random_data_config():
    with open(abs_path('tests/random_data_config.json'), 'r') as f:
        return json.load(f)


def get_random_data_files():
    folder = os.environ.get(generate_random_data.TEMP_DATA_FOLDER_VARNAME)
    if not folder:
        folder = tempfile.mkdtemp(None, 'test_data', None)
        # set temp folder before call generator
        os.environ.setdefault(generate_random_data.TEMP_DATA_FOLDER_VARNAME, folder)
        # remember that we generated from script to cleanup at end
        os.environ.setdefault(TEMP_DATA_GENERATED, folder)
        print("You didn't set {} env var. Test data will be generated to <{}> "
              "folder and removed at end".format(
            generate_random_data.TEMP_DATA_FOLDER_VARNAME, folder))
    if not os.path.exists(folder) or len(os.listdir(folder)) == 0:
        command = [sys.executable, abs_path('tests/generate_random_data.py')]
        print('call {}'.format(' '.join(command)))
        subprocess.check_call(command, env=os.environ, cwd=os.getcwd())
    return [os.path.join(folder, i) for i in os.listdir(folder)]


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


BASE_DIR = os.path.dirname(os.path.dirname(__file__))
abs_path = lambda x: os.path.join(BASE_DIR, x)
BINARY_OUTPUT_FOLDER = os.environ.get('TEST_BINARY_OUTPUT_FOLDER', '/tmp/')

# used to mark case when user didn't declare explicitly variable and we generated new temporary folder
# in this case we clean temporary folder, otherwise don't touch user specified path
TEMP_DATA_GENERATED = 'TEST_RANDOM_DATA_FOLDER_GENERATE'

TEST_RANDOM_DATA_CONFIG = load_random_data_config()
TEST_RANDOM_DATA_FILES = get_random_data_files()

# log python logs with time format as in golang
format = u"%(asctime)s - %(message)s"
handler = logging.StreamHandler(stream=sys.stderr)
handler.setFormatter(logging.Formatter(fmt=format, datefmt="%Y-%m-%dT%H:%M:%S%z"))
handler.setLevel(logging.DEBUG)
logger = logging.getLogger()
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

DB_HOST = os.environ.get('TEST_DB_HOST', 'localhost')
DB_NAME = os.environ.get('TEST_DB_NAME', 'postgres')
DB_PORT = os.environ.get('TEST_DB_PORT', 5432)

TEST_TLS_CA = abs_path(os.environ.get('TEST_TLS_CA', 'tests/ssl/ca/ca.crt'))
TEST_TLS_SERVER_CERT = abs_path(
    os.environ.get('TEST_TLS_SERVER_CERT', os.path.join(os.path.dirname(__file__), 'ssl/acra-server/acra-server.crt')))
TEST_TLS_SERVER_KEY = abs_path(
    os.environ.get('TEST_TLS_SERVER_KEY', os.path.join(os.path.dirname(__file__), 'ssl/acra-server/acra-server.key')))
# keys copied to tests/* with modified rights to 0400 because keys in docker/ssl/ has access from groups/other but some
# db drivers prevent usage of keys with global rights
TEST_TLS_CLIENT_CERT = abs_path(
    os.environ.get('TEST_TLS_CLIENT_CERT', os.path.join(os.path.dirname(__file__), 'ssl/acra-writer/acra-writer.crt')))
TEST_TLS_CLIENT_KEY = abs_path(
    os.environ.get('TEST_TLS_CLIENT_KEY', os.path.join(os.path.dirname(__file__), 'ssl/acra-writer/acra-writer.key')))
TEST_TLS_CLIENT_2_CERT = abs_path(os.environ.get('TEST_TLS_CLIENT_2_CERT', os.path.join(os.path.dirname(__file__),
                                                                                        'ssl/acra-writer-2/acra-writer-2.crt')))
TEST_TLS_CLIENT_2_KEY = abs_path(os.environ.get('TEST_TLS_CLIENT_2_KEY', os.path.join(os.path.dirname(__file__),
                                                                                      'ssl/acra-writer-2/acra-writer-2.key')))
TEST_TLS_OCSP_CA = abs_path(
    os.environ.get('TEST_TLS_OCSP_CA', os.path.join(os.path.dirname(__file__), 'ssl/ca/ca.crt')))
TEST_TLS_OCSP_CERT = abs_path(os.environ.get('TEST_TLS_OCSP_CERT', os.path.join(os.path.dirname(__file__),
                                                                                'ssl/ocsp-responder/ocsp-responder.crt')))
TEST_TLS_OCSP_KEY = abs_path(os.environ.get('TEST_TLS_OCSP_KEY', os.path.join(os.path.dirname(__file__),
                                                                              'ssl/ocsp-responder/ocsp-responder.key')))
TEST_TLS_OCSP_INDEX = abs_path(
    os.environ.get('TEST_TLS_OCSP_INDEX', os.path.join(os.path.dirname(__file__), 'ssl/ca/index.txt')))
TEST_TLS_CRL_PATH = abs_path(os.environ.get('TEST_TLS_CRL_PATH', os.path.join(os.path.dirname(__file__), 'ssl/ca')))
TEST_WITH_TLS = os.environ.get('TEST_TLS', 'off').lower() == 'on'

OCSP_SERVER_PORT = int(os.environ.get('TEST_OCSP_SERVER_PORT', 8888))
CRL_HTTP_SERVER_PORT = int(os.environ.get('TEST_HTTP_SERVER_PORT', 8889))

TEST_WITH_TRACING = os.environ.get('TEST_TRACE', 'off').lower() == 'on'
TEST_WITH_REDIS = os.environ.get('TEST_REDIS', 'off').lower() == 'on'
TEST_TRACE_TO_JAEGER = os.environ.get('TEST_TRACE_JAEGER', 'off').lower() == 'on'

NoClientCert, RequestClientCert, RequireAnyClientCert, VerifyClientCertIfGiven, RequireAndVerifyClientCert = range(5)
if TEST_WITH_TLS:
    ACRA_TLS_AUTH = RequireAndVerifyClientCert  # verify if provided https://golang.org/pkg/crypto/tls/#ClientAuthType
else:
    ACRA_TLS_AUTH = VerifyClientCertIfGiven

# 200 is overhead of encryption (chosen manually)
# multiply 2 because tested acrastruct in acrastruct
COLUMN_DATA_SIZE = (TEST_RANDOM_DATA_CONFIG['data_max_size'] + 200) * 2
metadata = sa.MetaData()
test_table = sa.Table('test', metadata,
                      # sometimes MariaDB ignores explicitly set ID and uses auto incremented values
                      # in most of tests we epxlicitly set id value
                      sa.Column('id', sa.Integer, primary_key=True, autoincrement=False),
                      sa.Column('data', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
                      sa.Column('raw_data', sa.Text),
                      sa.Column('nullable_column', sa.Text, nullable=True),
                      sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
                      )

acrarollback_output_table = sa.Table('acrarollback_output', metadata,
                                     sa.Column('data', sa.LargeBinary),
                                     )
poison_record = None
poison_record_acrablock = None
master_key = None
KEYS_FOLDER = None
ACRA_MASTER_KEY_VAR_NAME = 'ACRA_MASTER_KEY'
MASTER_KEY_PATH = '/tmp/acra-test-master.key'
TEST_WITH_VAULT = os.environ.get('TEST_WITH_VAULT', 'off').lower() == 'on'
TEST_CONSUL_ENCRYPTOR_CONFIG = os.environ.get('TEST_CONSUL_ENCRYPTOR_CONFIG', 'off').lower() == 'on'
TEST_WITH_AWS_KMS = os.environ.get('TEST_WITH_AWS_KMS', 'off').lower() == 'on'
TEST_SSL_VAULT = os.environ.get('TEST_SSL_VAULT', 'off').lower() == 'on'
TEST_SSL_CONSUL = os.environ.get('TEST_SSL_CONSUL', 'off').lower() == 'on'
TEST_VAULT_TLS_CA = abs_path(os.environ.get('TEST_VAULT_TLS_CA', 'tests/ssl/ca/ca.crt'))
TEST_CONSUL_TLS_CA = abs_path(os.environ.get('TEST_CONSUL_TLS_CA', 'tests/ssl/ca/ca.crt'))
VAULT_KV_ENGINE_VERSION = os.environ.get('VAULT_KV_ENGINE_VERSION', 'v1')
CRYPTO_ENVELOPE_HEADER = b'%%%'

# Set this to False to not rebuild binaries on setup.
CLEAN_BINARIES = get_bool_env('TEST_CLEAN_BINARIES', default=True)
# Set this to False to not build binaries in principle.
BUILD_BINARIES = True

# TLS_CERT_CLIENT_* represent two different ClientIDs are used in tests, initialized in setupModule function
TLS_CERT_CLIENT_ID_1 = None
TLS_CERT_CLIENT_ID_2 = None

TLS_CLIENT_ID_SOURCE_DN = 'distinguished_name'
TLS_CLIENT_ID_SOURCE_SERIAL = 'serial_number'

POISON_KEY_PATH = '.poison_key/poison_key'

STATEMENT_TIMEOUT = 5 * 1000  # 5 sec
SETUP_SQL_COMMAND_TIMEOUT = 0.1
# how long wait forked process to respond
FORK_TIMEOUT = 2
# seconds for sleep call after failed polling forked process
FORK_FAIL_SLEEP = 0.1
CONNECTION_FAIL_SLEEP = 0.1
SOCKET_CONNECT_TIMEOUT = 3
KILL_WAIT_TIMEOUT = 2
CONNECT_TRY_COUNT = 3
SQL_EXECUTE_TRY_COUNT = 5
# http://docs.python-requests.org/en/master/user/advanced/#timeouts
# use only for requests.* methods
REQUEST_TIMEOUT = (5, 5)  # connect_timeout, read_timeout
PG_UNIX_HOST = '/tmp'

DB_USER = os.environ.get('TEST_DB_USER', 'postgres')
DB_USER_PASSWORD = os.environ.get('TEST_DB_USER_PASSWORD', 'postgres')
SSLMODE = os.environ.get('TEST_SSL_MODE', 'require' if TEST_WITH_TLS else 'disable')
TEST_MYSQL = get_bool_env('TEST_MYSQL', default=False)
TEST_MARIADB = get_bool_env('TEST_MARIADB', default=False)

if TEST_MYSQL or TEST_MARIADB:
    TEST_POSTGRESQL = False
    DB_DRIVER = "mysql+pymysql"
    TEST_MYSQL = True
    connect_args = {
        'user': DB_USER, 'password': DB_USER_PASSWORD,
        'database': DB_NAME,
        'read_timeout': SOCKET_CONNECT_TIMEOUT,
        'write_timeout': SOCKET_CONNECT_TIMEOUT,
        'ssl_disabled': True if SSLMODE == 'disable' else False,
    }
    pymysql_tls_args = {}
    if TEST_WITH_TLS:
        pymysql_tls_args.update(
            ssl={
                "ca": TEST_TLS_CA,
                "cert": TEST_TLS_CLIENT_CERT,
                "key": TEST_TLS_CLIENT_KEY,
                'check_hostname': False,
            }
        )
        connect_args.update(pymysql_tls_args)
    db_dialect = mysql_dialect.dialect()
    if TEST_MARIADB:
        TEST_MARIADB = True
else:
    TEST_POSTGRESQL = True
    DB_DRIVER = "postgresql"
    connect_args = {
        'connect_timeout': SOCKET_CONNECT_TIMEOUT,
        'user': DB_USER, 'password': DB_USER_PASSWORD,
        "options": "-c statement_timeout={}".format(STATEMENT_TIMEOUT),
        'sslmode': 'disable',
        'application_name': 'acra-tests'
    }
    asyncpg_connect_args = {
        'timeout': SOCKET_CONNECT_TIMEOUT,
        'statement_cache_size': 0,
        'command_timeout': STATEMENT_TIMEOUT,
    }
    db_dialect = postgresql_dialect.dialect()
    if TEST_WITH_TLS:
        connect_args.update({
            # for psycopg2 key names took from
            # https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNECT-SSLCERT
            'sslcert': TEST_TLS_CLIENT_CERT,
            'sslkey': TEST_TLS_CLIENT_KEY,
            'sslrootcert': TEST_TLS_CA,
            'sslmode': 'require',
        })

# THe code for mysql "Query execution was interrupted" error
MYSQL_ERR_QUERY_INTERRUPTED_CODE = 1317


def get_tls_connection_args(client_key, client_cert, for_mysql=TEST_MYSQL):
    if for_mysql:
        connect_args = {
            'user': DB_USER, 'password': DB_USER_PASSWORD,
            'read_timeout': SOCKET_CONNECT_TIMEOUT,
            'write_timeout': SOCKET_CONNECT_TIMEOUT,
        }
        pymysql_tls_args = {}
        pymysql_tls_args.update(
            ssl={
                "ca": TEST_TLS_CA,
                "cert": client_cert,
                "key": client_key,
                'check_hostname': False,
            }
        )
        connect_args.update(pymysql_tls_args)
    else:
        connect_args = {
            'connect_timeout': SOCKET_CONNECT_TIMEOUT,
            'user': DB_USER, 'password': DB_USER_PASSWORD,
            "options": "-c statement_timeout={}".format(STATEMENT_TIMEOUT),
            'sslmode': 'disable',
            'application_name': 'acra-tests'
        }

        connect_args.update({
            # for psycopg2 key names took from
            # https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNECT-SSLCERT
            'sslcert': client_cert,
            'sslkey': client_key,
            'sslrootcert': TEST_TLS_CA,
            'sslmode': SSLMODE,
        })
    return connect_args


def get_tls_connection_args_without_certificate(for_mysql=TEST_MYSQL):
    if for_mysql:
        connect_args = {
            'user': DB_USER, 'password': DB_USER_PASSWORD,
            'read_timeout': SOCKET_CONNECT_TIMEOUT,
            'write_timeout': SOCKET_CONNECT_TIMEOUT,
        }
        pymysql_tls_args = {}
        pymysql_tls_args.update(
            ssl={
                "ca": TEST_TLS_CA,
                'check_hostname': False,
            }
        )
        connect_args.update(pymysql_tls_args)
    else:
        connect_args = {
            'connect_timeout': SOCKET_CONNECT_TIMEOUT,
            'user': DB_USER, 'password': DB_USER_PASSWORD,
            "options": "-c statement_timeout={}".format(STATEMENT_TIMEOUT),
            'sslmode': 'disable',
            'application_name': 'acra-tests'
        }

        connect_args.update({
            # for psycopg2 key names took from
            # https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNECT-SSLCERT
            'sslrootcert': TEST_TLS_CA,
            'sslmode': 'require',
        })
    return connect_args


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


def load_default_config(service_name, skip_keys=['version']):
    # every config has version but service's don't have such parameter and will exit with error if we will
    # provide unexpected parameter
    # when services parse configs they ignore unknown parameters and not down for that

    config = load_yaml_config('configs/{}.yaml'.format(service_name))

    # convert empty values to empty strings to avoid pass them to Popen as
    # "None" string value

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


def deserialize_crypto_envelope_with_acrastruct(data):
    if data[:3] == b'%%%':
        crypto_id = data[8 + 3]
        if crypto_id != 0xF1:
            raise ValueError("invalid CryptoEnvelope with AcraStruct")
        return data[8 + 4:]
    raise ValueError("Invalid crypto envelope")


def deserialize_and_decrypt_acrastruct(data, private_key, client_id=None, additionalContext=None):
    data = deserialize_crypto_envelope_with_acrastruct(data)
    return decrypt_acrastruct(data, private_key, client_id, additionalContext)


def decrypt_acrastruct(data, private_key, client_id=None, additionalContext=None):
    public_key = data[8:8 + 45]
    encrypted_symmetric = data[8 + 45:8 + 45 + 84]
    smessage_decryptor = smessage.SMessage(private_key, public_key)
    symmetric = smessage_decryptor.unwrap(encrypted_symmetric)
    encrypted_data = data[8 + 45 + 84 + 8:]
    if additionalContext:
        return scell.SCellSeal(symmetric).decrypt(encrypted_data, additionalContext)
    else:
        return scell.SCellSeal(symmetric).decrypt(encrypted_data)


def read_storage_private_key(keys_folder, key_id):
    return read_key('client/{}/storage'.format(key_id),
                    public=False, keys_dir=keys_folder)


def read_poison_public_key(keys_dir):
    return read_key('poison-record', public=True, keys_dir=keys_dir)


def read_poison_private_key(keys_dir):
    return read_key('poison-record', public=False, keys_dir=keys_dir)


def prepare_encryptor_config(config_path, client_id=None):
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    for table in config['schemas']:
        for column in table['encrypted']:
            if client_id and 'client_id' in column:
                column['client_id'] = client_id
    with open(get_test_encryptor_config(config_path), 'w') as f:
        yaml.dump(config, f)


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


def get_free_port():
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]


def get_random_id():
    return random.randint(1, 100000)


def get_pregenerated_random_data():
    data_file = random.choice(TEST_RANDOM_DATA_FILES)
    with open(data_file, 'r', encoding='utf-8') as f:
        return f.read()


def create_acrastruct_with_client_id(data, client_id):
    server_public1 = read_storage_public_key(client_id, KEYS_FOLDER.name)
    if isinstance(data, str):
        data = data.encode('utf-8')
    acra_struct = create_acrastruct(data, server_public1)
    return acra_struct


def stop_process(process):
    """stop process if exists by terminate and kill at end to be sure
    that process will not alive as zombi-process"""
    if not isinstance(process, collections.abc.Iterable):
        process = [process]
    # send signal to each. they can handle it asynchronously
    for p in process:
        try:
            logger.info("terminate pid {}".format(p.pid))
            p.terminate()
        except:
            traceback.print_exc()
    # synchronously wait termination or kill
    for p in process:
        try:
            # None if not terminated yet then wait some time
            if p.poll() is None:
                p.wait(timeout=KILL_WAIT_TIMEOUT)
        except:
            traceback.print_exc()
        try:
            logger.info("kill pid {}".format(p.pid))
            p.kill()
            logger.info("killed pid {}".format(p.pid))
        except:
            traceback.print_exc()


def get_connect_args(port=5432, sslmode=None, **kwargs):
    args = connect_args.copy()
    args['port'] = int(port)
    if TEST_POSTGRESQL:
        args['sslmode'] = sslmode if sslmode else SSLMODE
    args.update(kwargs)
    return args


KEYSTORE_VERSION = os.environ.get('TEST_KEYSTORE', 'v1')


def get_master_key():
    """Returns master key value (base64-encoded)."""
    global master_key
    if not master_key:
        master_key = os.environ.get(ACRA_MASTER_KEY_VAR_NAME)
        if not master_key:
            subprocess.check_output([
                os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keymaker'), '--keystore={}'.format(KEYSTORE_VERSION),
                '--generate_master_key={}'.format(MASTER_KEY_PATH)])
            with open(MASTER_KEY_PATH, 'rb') as f:
                master_key = b64encode(f.read()).decode('ascii')
    return master_key


def get_poison_record():
    """generate one poison record for speed up tests and don't create subprocess
    for new records"""
    global poison_record
    if not poison_record:
        poison_record = b64decode(subprocess.check_output([
            os.path.join(BINARY_OUTPUT_FOLDER, 'acra-poisonrecordmaker'), '--keys_dir={}'.format(KEYS_FOLDER.name),
        ],
            timeout=PROCESS_CALL_TIMEOUT))
    return poison_record


def get_new_poison_record(extra_kwargs: dict = None, keys_dir=None):
    """generate one new poison record for speed up tests and don't create subprocess
    for new records"""
    args = [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-poisonrecordmaker')]
    if keys_dir:
        args.append('--keys_dir={}'.format(keys_dir))
    else:
        args.append('--keys_dir={}'.format(KEYS_FOLDER.name))

    if extra_kwargs:
        for key, value in extra_kwargs.items():
            param = '-{0}={1}'.format(key, value)
            args.append(param)
    return b64decode(subprocess.check_output(args, timeout=PROCESS_CALL_TIMEOUT))


def get_poison_record_with_acrablock():
    """generate one poison record with acrablock for speed up tests and don't create subprocess
    for new records"""
    global poison_record_acrablock
    if not poison_record_acrablock:
        poison_record_acrablock = b64decode(subprocess.check_output([
            os.path.join(BINARY_OUTPUT_FOLDER, 'acra-poisonrecordmaker'), '--keys_dir={}'.format(KEYS_FOLDER.name),
            '--type=acrablock',
        ],
            timeout=PROCESS_CALL_TIMEOUT))
    return poison_record_acrablock


def create_client_keypair(name, only_storage=False, keys_dir=None, extra_kwargs: dict = None):
    if not keys_dir:
        keys_dir = KEYS_FOLDER.name
    args = [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keymaker'), '-client_id={}'.format(name),
            '-keys_output_dir={}'.format(keys_dir),
            '--keys_public_output_dir={}'.format(keys_dir),
            '--keystore={}'.format(KEYSTORE_VERSION)]
    if only_storage:
        args.append('--generate_acrawriter_keys')

    if extra_kwargs:
        for key, value in extra_kwargs.items():
            param = '-{0}={1}'.format(key, value)
            args.append(param)
    return subprocess.call(args, cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT)


def create_client_keypair_from_certificate(tls_cert, extractor=TLS_CLIENT_ID_SOURCE_DN, only_storage=False,
                                           keys_dir=None, extra_kwargs: dict = None):
    if not keys_dir:
        keys_dir = KEYS_FOLDER.name
    args = [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keymaker'), '--client_id=',
            '--tls_cert={}'.format(tls_cert),
            '--tls_identifier_extractor_type={}'.format(extractor),
            '-keys_output_dir={}'.format(keys_dir),
            '--keys_public_output_dir={}'.format(keys_dir),
            '--keystore={}'.format(KEYSTORE_VERSION)]
    if only_storage:
        args.append('--generate_acrawriter_keys')

    if extra_kwargs:
        for key, value in extra_kwargs.items():
            param = '-{0}={1}'.format(key, value)
            args.append(param)
    return subprocess.call(args, cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT)


WAIT_CONNECTION_ERROR_MESSAGE = "can't wait connection"


def wait_connection(port, count=1000, sleep=0.001):
    """try connect to 127.0.0.1:port and close connection
    if can't then sleep on and try again (<count> times)
    if <count> times is failed than raise Exception
    """
    while count:
        try:
            connection = socket.create_connection(('127.0.0.1', port), timeout=SOCKET_CONNECT_TIMEOUT)
            connection.close()
            return
        except ConnectionRefusedError:
            pass
        count -= 1
        time.sleep(sleep)
    raise Exception(WAIT_CONNECTION_ERROR_MESSAGE)


def wait_command_success(command, count=10, sleep=0.200):
    """try executing `command` using `os.system()`
    if exit code != 0 then sleep on and try again (<count> times)
    if <count> times is failed than raise Exception
    """
    while count:
        ret = os.system(command)
        if ret == 0:
            return
        count -= 1
        time.sleep(sleep)
    raise Exception(f"can't wait command success: {command}")


def wait_unix_socket(socket_path, count=1000, sleep=0.005):
    last_exc = Exception("can't wait unix socket")
    while count:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(SOCKET_CONNECT_TIMEOUT)
            connection.connect(socket_path)
            return
        except Exception as exc:
            last_exc = exc
        finally:
            connection.close()
        count -= 1
        time.sleep(sleep)
    raise last_exc


def get_db_host():
    """use unix socket for postgresql and tcp with localhost for mysql"""
    if TEST_POSTGRESQL and not TEST_WITH_TLS:
        return PG_UNIX_HOST
    else:
        return DB_HOST


def get_engine_connection_string(connection_string, dbname):
    addr = urlparse(connection_string)
    port = addr.port
    if connection_string.startswith('tcp'):
        # we should not change hostname becase connection_string may be for acra-server or database
        return get_postgresql_tcp_connection_string(port, dbname, host=addr.hostname)
    else:
        port = re.search(r'\.s\.PGSQL\.(\d+)', addr.path)
        if port:
            port = port.group(1)
        return get_postgresql_unix_connection_string(port, dbname)


def get_postgresql_unix_connection_string(port, dbname):
    return '{}:///{}?host={}&port={}'.format(DB_DRIVER, dbname, PG_UNIX_HOST, port)


def get_postgresql_tcp_connection_string(port, dbname, host=DB_HOST):
    return '{}://{}:{}/{}'.format(DB_DRIVER, host, port, dbname)


def get_tcp_connection_string(port):
    return 'tcp://localhost:{}'.format(port)


def socket_path_from_connection_string(connection_string):
    if '://' in connection_string:
        return connection_string.split('://')[1]
    else:
        return connection_string


def acra_api_connection_string(port):
    return "tcp://localhost:{}".format(port)


def get_ocsp_server_connection_string(port=None):
    if not port:
        port = OCSP_SERVER_PORT
    return 'http://127.0.0.1:{}'.format(port)


def get_crl_http_server_connection_string(port=None):
    if not port:
        port = CRL_HTTP_SERVER_PORT
    return 'http://127.0.0.1:{}'.format(port)


def fork(func):
    process = func()
    count = 0
    step = FORK_TIMEOUT / FORK_FAIL_SLEEP
    while count <= FORK_TIMEOUT:
        if process.poll() is None:
            logging.info("forked %s [%s]", process.args[0], process.pid)
            return process
        count += step
        time.sleep(FORK_FAIL_SLEEP)
    stop_process(process)
    raise Exception("Can't fork")


def fork_ocsp_server(port: int, check_connection: bool = True):
    logging.info("fork OpenSSL OCSP server with port {}".format(port))

    ocsp_server_connection = get_ocsp_server_connection_string(port)

    args = {
        'port': port,
        'index': TEST_TLS_OCSP_INDEX,
        'rsigner': TEST_TLS_OCSP_CERT,
        'rkey': TEST_TLS_OCSP_KEY,
        'CA': TEST_TLS_CA,
        'ignore_err': None,
    }

    cli_args = sorted([f'-{k}={v}' if v is not None else f'-{k}' for k, v in args.items()])
    print('openssl ocsp args: {}'.format(' '.join(cli_args)))

    process = fork(lambda: subprocess.Popen(['openssl', 'ocsp'] + cli_args))

    check_cmd = f"openssl ocsp -CAfile {TEST_TLS_CA} -issuer {TEST_TLS_CA} -cert {TEST_TLS_CLIENT_CERT} -url {ocsp_server_connection}"

    if check_connection:
        print('check OCSP server connection {}'.format(ocsp_server_connection))
        try:
            wait_command_success(check_cmd)
        except:
            stop_process(process)
            raise

    logging.info("fork openssl ocsp finished [pid={}]".format(process.pid))
    return process


def fork_crl_http_server(port: int, check_connection: bool = True):
    logging.info("fork HTTP server with port {}".format(port))

    http_server_connection = get_crl_http_server_connection_string(port)
    # use cwd= parameter for Popen instead of --directory parameter to support 3.6 that doesn't accept --directory
    cli_args = ['--bind', '127.0.0.1', str(port)]
    print('python HTTP server args: {}'.format(' '.join(cli_args)))

    process = fork(lambda: subprocess.Popen(['python3', '-m', 'http.server'] + cli_args, cwd=TEST_TLS_CRL_PATH))

    if check_connection:
        print('check HTTP server connection {}'.format(http_server_connection))
        try:
            wait_connection(port)
        except:
            stop_process(process)
            raise

    logging.info("fork HTTP server finished [pid={}]".format(process.pid))
    return process


class ProcessStub(object):
    pid = 'stub'

    def kill(self, *args, **kwargs):
        pass

    def wait(self, *args, **kwargs):
        pass

    def terminate(self, *args, **kwargs):
        pass

    def poll(self, *args, **kwargs):
        pass


# declare global variables with ProcessStub by default to clean them in tearDownModule without extra checks with
# stop_process
OCSP_SERVER = ProcessStub()
CRL_HTTP_SERVER = ProcessStub()


def fork_certificate_validation_services():
    global OCSP_SERVER, CRL_HTTP_SERVER
    if TEST_WITH_TLS:
        OCSP_SERVER = fork_ocsp_server(OCSP_SERVER_PORT)
        CRL_HTTP_SERVER = fork_crl_http_server(CRL_HTTP_SERVER_PORT)


def kill_certificate_validation_services():
    if TEST_WITH_TLS:
        processes = [OCSP_SERVER, CRL_HTTP_SERVER]
        stop_process(processes)


DEFAULT_VERSION = '1.8.0'
DEFAULT_BUILD_ARGS = []
ACRAROLLBACK_MIN_VERSION = "1.8.0"
Binary = collections.namedtuple(
    'Binary', ['name', 'from_version', 'build_args'])

BINARIES = [
    Binary(name='acra-server', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-backup', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-tokens', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-keymaker', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-keys', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-poisonrecordmaker', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-rollback', from_version=ACRAROLLBACK_MIN_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-translator', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-rotate', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-backup', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-tokens', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
]

BUILD_TAGS = os.environ.get("TEST_BUILD_TAGS", '')


def build_binaries():
    """Build Acra CE binaries for testing."""
    builds = [
        (binary.from_version, ['go', 'build', '-o={}'.format(os.path.join(BINARY_OUTPUT_FOLDER, binary.name)),
                               '-tags={}'.format(BUILD_TAGS)] +
         binary.build_args +
         ['github.com/cossacklabs/acra/cmd/{}'.format(binary.name)])
        for binary in BINARIES
    ]
    go_version = get_go_version()
    GREATER, EQUAL, LESS = (1, 0, -1)
    for version, build in builds:
        if semver.VersionInfo.parse(go_version).compare(version) == LESS:
            continue
        # try to build 3 times with timeout
        build_count = 3
        for i in range(build_count):
            try:
                subprocess.check_call(build, cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT)
                break
            except (AssertionError, subprocess.TimeoutExpired):
                if i == (build_count - 1):
                    raise
                continue


def clean_binaries():
    for i in BINARIES:
        try:
            os.remove(os.path.join(BINARY_OUTPUT_FOLDER, i.name))
        except:
            pass


def clean_misc():
    pass


PROCESS_CALL_TIMEOUT = 120


def get_go_version():
    output = subprocess.check_output(['go', 'version'])
    # example: go1.7.2 or go1.7
    version = re.search(r'go([\d.]+)', output.decode('utf-8')).group(1)
    # convert to 3 part semver format
    if version.count('.') < 2:
        version = '{}.0'.format(version)
    return version


def drop_tables():
    engine_raw = sa.create_engine(
        '{}://{}:{}/{}'.format(DB_DRIVER, DB_HOST, DB_PORT, DB_NAME),
        connect_args=connect_args)
    metadata.drop_all(engine_raw)
    engine_raw.dispose()


def extract_client_id_from_cert(tls_cert, extractor=TLS_CLIENT_ID_SOURCE_DN):
    res = json.loads(subprocess.check_output([
        os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'),
        'extract-client-id',
        '--tls_identifier_extractor_type={}'.format(extractor),
        '--tls_cert={}'.format(tls_cert),
        '--print_json'
    ],
        cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT).decode('utf-8'))
    return res['client_id']


if sys.version_info[1] > 6:
    ConnectionArgs = collections.namedtuple(
        "ConnectionArgs",
        field_names=["user", "password", "host", "port", "dbname",
                     "ssl_ca", "ssl_key", "ssl_cert", "raw", "format"],
        # 'format' is optional, other fields are required.
        defaults=[None])
else:
    class ConnectionArgs:
        def __init__(self, user=None, password=None, host=None, port=None, dbname=None,
                     ssl_ca=None, ssl_key=None, ssl_cert=None, format=None, raw=None):
            self.user = user
            self.password = password
            self.host = host
            self.port = port
            self.dbname = dbname
            self.ssl_ca = ssl_ca
            self.ssl_key = ssl_key
            self.ssl_cert = ssl_cert
            self.format = format
            self.raw = raw


class QueryExecutor(object):
    def __init__(self, connection_args):
        self.connection_args = connection_args

    def execute(self, query, args=None):
        raise NotImplementedError

    def execute_prepared_statement(self, query, args=None):
        raise NotImplementedError


class PyMysqlExecutor(QueryExecutor):
    def execute(self, query, args=None):
        if args:
            self.fail("<args> param for executor {} not supported now".format(self.__class__))
        with contextlib.closing(pymysql.connect(
                host=self.connection_args.host, port=self.connection_args.port,
                user=self.connection_args.user,
                password=self.connection_args.password,
                db=self.connection_args.dbname,
                cursorclass=pymysql.cursors.DictCursor,
                **pymysql_tls_args)) as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, args)
                return cursor.fetchall()

    def execute_prepared_statement(self, query, args=None):
        if args:
            self.fail("<args> param for executor {} not supported now".format(self.__class__))
        with contextlib.closing(pymysql.connect(
                host=self.connection_args.host, port=self.connection_args.port,
                user=self.connection_args.user,
                password=self.connection_args.password,
                db=self.connection_args.dbname,
                cursorclass=pymysql.cursors.DictCursor,
                **pymysql_tls_args)) as connection:
            with connection.cursor() as cursor:
                cursor.execute("PREPARE test_statement FROM {}".format(
                    str(sa.literal(query).compile(dialect=db_dialect, compile_kwargs={"literal_binds": True}))))
                cursor.execute('EXECUTE test_statement')
                return cursor.fetchall()


# MysqlConnectorCExecutor uses CMySQLConnection type, which sends the client packets different than standard MySQLConnection
# the difference is packets order in PreparedStatements processing
# after sending CommandStatementPrepare, ConnectorC send the CommandStatementReset and expect StatementResetResult(OK|Err)
# then send the empty CommandStatementExecute without params, params come in next packets
# to handle such behaviour properly, MySQL proxy should have StatementReset handler
# and skip params parsing if the params number is 0 in CommandStatementExecute handler
class MysqlConnectorCExecutor(QueryExecutor):
    def _result_to_dict(self, description, data):
        """convert list of tuples of rows to list of dicts"""
        columns_name = [i[0] for i in description]
        result = []
        for row in data:
            row_data = {column_name: value
                        for column_name, value in zip(columns_name, row)}
            result.append(row_data)
        return result

    def execute(self, query, args=None):
        if args is None:
            args = []
        with contextlib.closing(mysql.connector.connect(
                use_unicode=True, raw=self.connection_args.raw, charset='utf8',
                host=self.connection_args.host, port=self.connection_args.port,
                user=self.connection_args.user,
                password=self.connection_args.password,
                database=self.connection_args.dbname,
                ssl_ca=self.connection_args.ssl_ca,
                ssl_cert=self.connection_args.ssl_cert,
                ssl_key=self.connection_args.ssl_key,
                ssl_disabled=not TEST_WITH_TLS)) as connection:
            with contextlib.closing(connection.cursor()) as cursor:
                cursor.execute(query, args)
                data = cursor.fetchall()
                result = self._result_to_dict(cursor.description, data)
        return result

    def execute_prepared_statement(self, query, args=None):
        if args is None:
            args = []
        with contextlib.closing(mysql.connector.connect(
                use_unicode=True, charset='utf8',
                host=self.connection_args.host, port=self.connection_args.port,
                user=self.connection_args.user,
                password=self.connection_args.password,
                database=self.connection_args.dbname,
                ssl_ca=self.connection_args.ssl_ca,
                ssl_cert=self.connection_args.ssl_cert,
                ssl_key=self.connection_args.ssl_key,
                ssl_disabled=not TEST_WITH_TLS)) as connection:
            with contextlib.closing(connection.cursor(prepared=True)) as cursor:
                cursor.execute(query, args)
                data = cursor.fetchall()
                result = self._result_to_dict(cursor.description, data)
        return result

    def execute_prepared_statement_no_result(self, query, args=None):
        if args is None:
            args = []
        with contextlib.closing(mysql.connector.connect(
                use_unicode=True, charset='utf8',
                host=self.connection_args.host, port=self.connection_args.port,
                user=self.connection_args.user,
                password=self.connection_args.password,
                database=self.connection_args.dbname,
                ssl_ca=self.connection_args.ssl_ca,
                ssl_cert=self.connection_args.ssl_cert,
                ssl_key=self.connection_args.ssl_key,
                ssl_disabled=not TEST_WITH_TLS)) as connection:
            with contextlib.closing(connection.cursor(prepared=True)) as cursor:
                cursor.execute(query, args)
                connection.commit()


class MysqlExecutor(QueryExecutor):
    def _result_to_dict(self, description, data):
        """convert list of tuples of rows to list of dicts"""
        columns_name = [i[0] for i in description]
        result = []
        for row in data:
            row_data = {column_name: value
                        for column_name, value in zip(columns_name, row)}
            result.append(row_data)
        return result

    def execute(self, query, args=None):
        if args is None:
            args = []
        with contextlib.closing(mysql.connector.connection.MySQLConnection(
                use_unicode=False, raw=self.connection_args.raw, charset='utf8',
                host=self.connection_args.host, port=self.connection_args.port,
                user=self.connection_args.user,
                password=self.connection_args.password,
                database=self.connection_args.dbname,
                ssl_ca=self.connection_args.ssl_ca,
                ssl_cert=self.connection_args.ssl_cert,
                ssl_key=self.connection_args.ssl_key,
                ssl_disabled=not TEST_WITH_TLS)) as connection:
            with contextlib.closing(connection.cursor()) as cursor:
                cursor.execute(query, args)
                data = cursor.fetchall()
                result = self._result_to_dict(cursor.description, data)
        return result

    def execute_prepared_statement(self, query, args=None):
        if args is None:
            args = []
        with contextlib.closing(mysql.connector.connection.MySQLConnection(
                use_unicode=False, charset='utf8',
                host=self.connection_args.host, port=self.connection_args.port,
                user=self.connection_args.user,
                password=self.connection_args.password,
                database=self.connection_args.dbname,
                ssl_ca=self.connection_args.ssl_ca,
                ssl_cert=self.connection_args.ssl_cert,
                ssl_key=self.connection_args.ssl_key,
                ssl_disabled=not TEST_WITH_TLS)) as connection:
            with contextlib.closing(connection.cursor(prepared=True)) as cursor:
                cursor.execute(query, args)
                data = cursor.fetchall()
                result = self._result_to_dict(cursor.description, data)
        return result

    def execute_prepared_statement_no_result(self, query, args=None):
        if args is None:
            args = []
        with contextlib.closing(mysql.connector.connection.MySQLConnection(
                use_unicode=False, charset='utf8',
                host=self.connection_args.host, port=self.connection_args.port,
                user=self.connection_args.user,
                password=self.connection_args.password,
                database=self.connection_args.dbname,
                ssl_ca=self.connection_args.ssl_ca,
                ssl_cert=self.connection_args.ssl_cert,
                ssl_key=self.connection_args.ssl_key,
                ssl_disabled=not TEST_WITH_TLS)) as connection:
            with contextlib.closing(connection.cursor(prepared=True)) as cursor:
                cursor.execute(query, args)
                connection.commit()


class AsyncpgExecutor(QueryExecutor):
    TextFormat = 'text'
    BinaryFormat = 'binary'

    async def connect(self):
        ssl_context = ssl.create_default_context(cafile=self.connection_args.ssl_ca)
        ssl_context.load_cert_chain(self.connection_args.ssl_cert, self.connection_args.ssl_key)
        ssl_context.check_hostname = True
        return await asyncpg.connect(
            host=self.connection_args.host, port=self.connection_args.port,
            user=self.connection_args.user, password=self.connection_args.password,
            database=self.connection_args.dbname,
            ssl=ssl_context,
            **asyncpg_connect_args)

    async def _set_text_format(self, conn):
        """Force text format to numeric types."""
        for pg_type in ['int2', 'int4', 'int8']:
            await conn.set_type_codec(pg_type,
                                      schema='pg_catalog',
                                      encoder=str,
                                      decoder=int,
                                      format='text')
        for pg_type in ['float4', 'float8']:
            await conn.set_type_codec(pg_type,
                                      schema='pg_catalog',
                                      encoder=str,
                                      decoder=float,
                                      format='text')

    def execute_prepared_statement(self, query, args=None):
        async def _execute_prepared_statement():
            conn = await self.connect()
            try:
                if self.connection_args.format == self.TextFormat:
                    await self._set_text_format(conn)
                stmt = await conn.prepare(query, timeout=STATEMENT_TIMEOUT)
                result = await stmt.fetch(*args, timeout=STATEMENT_TIMEOUT)
                return result
            finally:
                await conn.close()

        if not args:
            args = []
        with contextlib.closing(asyncio.new_event_loop()) as loop:
            result = loop.run_until_complete(_execute_prepared_statement())
            return result

    def execute(self, query, args=None):
        async def _execute():
            conn = await self.connect()
            try:
                if self.connection_args.format == self.TextFormat:
                    await self._set_text_format(conn)
                result = await conn.fetch(query, *args, timeout=STATEMENT_TIMEOUT)
                return result
            finally:
                await conn.close()

        if not args:
            args = []
        with contextlib.closing(asyncio.new_event_loop()) as loop:
            result = loop.run_until_complete(_execute())
            return result


class Psycopg2Executor(QueryExecutor):
    def execute(self, query, args=None):
        if args:
            self.fail("<args> param for executor {} not supported now".format(self.__class__))
        connection_args = get_connect_args(self.connection_args.port)
        with psycopg2.connect(
                host=self.connection_args.host,
                dbname=self.connection_args.dbname, **connection_args) as connection:
            with connection.cursor(
                    cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute(query, args)
                data = cursor.fetchall()
                memoryview_rows_to_bytes(data)
                return data

    def execute_prepared_statement(self, query, args=None):
        if args:
            self.fail("<args> param for executor {} not supported now".format(self.__class__))
        kwargs = get_connect_args(self.connection_args.port)
        with psycopg2.connect(
                host=self.connection_args.host,
                dbname=self.connection_args.dbname, **kwargs) as connection:
            with connection.cursor(
                    cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute("prepare test_statement as {}".format(query))
                cursor.execute("execute test_statement")
                data = cursor.fetchall()
                memoryview_rows_to_bytes(data)
                return data


# Place arguments in a linear order
# For example, if query is "$2 $1 $1 $3" and arguments are [a, b, c]
# The resulted query would be "%s %s %s %s" and arguments would be [b a a c]
def replace_pg_placeholders_with_psycopg3(query, args):
    indexes = re.findall(r'\$([0-9]+)', query)
    query = re.sub(r'\$[0-9]+', '%s', query)
    # minus 1 because python uses 0-based array, while postgres 1-based
    newargs = [args[int(i) - 1] for i in indexes]
    return query, newargs


class Psycopg3Executor(QueryExecutor):
    def _execute(self, query, args=None, prepare=None):
        query, args = replace_pg_placeholders_with_psycopg3(query, args)

        connection_args = get_connect_args(self.connection_args.port)

        connection_args['sslrootcert'] = self.connection_args.ssl_ca
        connection_args['sslkey'] = self.connection_args.ssl_key
        connection_args['sslcert'] = self.connection_args.ssl_cert
        connection_args['host'] = self.connection_args.host
        connection_args['dbname'] = self.connection_args.dbname

        with psycopg3.connect(**connection_args) as conn:
            with conn.cursor(
                    row_factory=psycopg3.rows.dict_row) as cursor:
                cursor.execute(query, args, prepare=prepare)
                try:
                    data = cursor.fetchall()
                except psycopg3.ProgrammingError as ex:
                    # psycopg3 throws an error if we want to fetch rows on
                    # responseless query, like insert. So ignore it.
                    if str(ex) == "the last operation didn't produce a result":
                        return []
                    else:
                        raise
                memoryview_rows_to_bytes(data)
                return data

    def execute(self, query, args=None):
        return self._execute(query, args, prepare=False)

    def execute_prepared_statement(self, query, args=None):
        return self._execute(query, args, prepare=True)


def collectTests(source: unittest.TestSuite, tests=[]):
    if not isinstance(source, unittest.TestSuite):
        raise TypeError('invalid source of tests')
    for tcase in source._tests:
        if not tcase:
            continue
        if isinstance(tcase, unittest.TestSuite):
            collectTests(tcase, tests)
        if isinstance(tcase, unittest.TestCase):
            tests.append(tcase)


# load_tests function that loads tests from a specific set of TestCase used
# due to unittest runs test cases one by one and calls `setUpModule` once only if test cases ordered by module name or from one module,
# otherwise if tests unordered with same modules, setUpModule will be called many times
# we specify one name for all of them because need only one call of  setUpModule/tearDownModule
# in other case, in the future, we should order by .__class__.__module__ testcases to allow call setUpModule per modules.
# https://docs.python.org/3/library/unittest.html#class-and-module-fixtures
def load_tests(loader, standard_tests, pattern):
    tests = []
    collectTests(standard_tests, tests)
    for tcase in tests:
        if not tcase:
            continue
        tcase.__class__.__module__ = 'base'
    return unittest.TestSuite(tests)


def setUpModule():
    global KEYS_FOLDER
    global TLS_CERT_CLIENT_ID_1
    global TLS_CERT_CLIENT_ID_2
    clean_misc()
    KEYS_FOLDER = tempfile.TemporaryDirectory()
    if CLEAN_BINARIES:
        clean_binaries()
    if BUILD_BINARIES:
        build_binaries()

    # must be before any call of key generators or forks of acra/proxy servers
    os.environ.setdefault(ACRA_MASTER_KEY_VAR_NAME, get_master_key())

    assert create_client_keypair_from_certificate(TEST_TLS_CLIENT_CERT) == 0
    assert create_client_keypair_from_certificate(TEST_TLS_CLIENT_2_CERT) == 0

    TLS_CERT_CLIENT_ID_1 = extract_client_id_from_cert(TEST_TLS_CLIENT_CERT)
    TLS_CERT_CLIENT_ID_2 = extract_client_id_from_cert(TEST_TLS_CLIENT_2_CERT)
    socket.setdefaulttimeout(SOCKET_CONNECT_TIMEOUT)
    drop_tables()

    fork_certificate_validation_services()


def tearDownModule():
    if CLEAN_BINARIES:
        clean_binaries()
    clean_misc()
    KEYS_FOLDER.cleanup()
    clean_test_data()
    for path in [MASTER_KEY_PATH]:
        try:
            os.remove(path)
        except:
            pass
    drop_tables()
    kill_certificate_validation_services()
