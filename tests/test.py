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
import asyncio
import collections
import collections.abc
import contextlib
import http
import json
import logging
import os
import os.path
import random
import re
import shutil
import signal
import socket

import ssl
import stat
import subprocess
import tempfile
import traceback
import unittest
from base64 import b64decode, b64encode
from tempfile import NamedTemporaryFile
from urllib.parse import urlparse
from urllib.request import urlopen

import asyncpg
import grpc
import mysql.connector
import psycopg2
import psycopg2.errors
import psycopg2.extras
import pymysql
import requests
import redis
import semver
import sqlalchemy as sa
import sys
import time
import yaml
from ddt import ddt, data
from hvac import Client
from prometheus_client.parser import text_string_to_metric_families
from sqlalchemy.dialects import mysql as mysql_dialect
from sqlalchemy.dialects import postgresql as postgresql_dialect
from sqlalchemy.dialects.postgresql import BYTEA
from sqlalchemy.exc import DatabaseError
from distutils.dir_util import copy_tree

import api_pb2
import api_pb2_grpc
import utils
from random_utils import random_bytes, random_email, random_int32, random_int64, random_str
from utils import (read_storage_public_key, read_storage_private_key,
                   read_zone_public_key, read_zone_private_key,
                   read_poison_public_key, read_poison_private_key,
                   destroy_server_storage_key,
                   decrypt_acrastruct, deserialize_and_decrypt_acrastruct,
                   load_random_data_config, get_random_data_files,
                   clean_test_data, safe_string, prepare_encryptor_config,
                   get_encryptor_config, abs_path, get_test_encryptor_config, send_signal_by_process_name,
                   load_yaml_config, dump_yaml_config, BINARY_OUTPUT_FOLDER)

# add to path our wrapper until not published to PYPI
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'wrappers/python'))

from acrawriter import create_acrastruct

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
TEST_TLS_SERVER_CERT = abs_path(os.environ.get('TEST_TLS_SERVER_CERT', os.path.join(os.path.dirname(__file__), 'ssl/acra-server/acra-server.crt')))
TEST_TLS_SERVER_KEY = abs_path(os.environ.get('TEST_TLS_SERVER_KEY', os.path.join(os.path.dirname(__file__), 'ssl/acra-server/acra-server.key')))
# keys copied to tests/* with modified rights to 0400 because keys in docker/ssl/ has access from groups/other but some
# db drivers prevent usage of keys with global rights
TEST_TLS_CLIENT_CERT = abs_path(os.environ.get('TEST_TLS_CLIENT_CERT', os.path.join(os.path.dirname(__file__), 'ssl/acra-writer/acra-writer.crt')))
TEST_TLS_CLIENT_KEY = abs_path(os.environ.get('TEST_TLS_CLIENT_KEY', os.path.join(os.path.dirname(__file__), 'ssl/acra-writer/acra-writer.key')))
TEST_TLS_CLIENT_2_CERT = abs_path(os.environ.get('TEST_TLS_CLIENT_2_CERT', os.path.join(os.path.dirname(__file__), 'ssl/acra-writer-2/acra-writer-2.crt')))
TEST_TLS_CLIENT_2_KEY = abs_path(os.environ.get('TEST_TLS_CLIENT_2_KEY', os.path.join(os.path.dirname(__file__), 'ssl/acra-writer-2/acra-writer-2.key')))
TEST_TLS_OCSP_CA = abs_path(os.environ.get('TEST_TLS_OCSP_CA', os.path.join(os.path.dirname(__file__), 'ssl/ca/ca.crt')))
TEST_TLS_OCSP_CERT = abs_path(os.environ.get('TEST_TLS_OCSP_CERT', os.path.join(os.path.dirname(__file__), 'ssl/ocsp-responder/ocsp-responder.crt')))
TEST_TLS_OCSP_KEY = abs_path(os.environ.get('TEST_TLS_OCSP_KEY', os.path.join(os.path.dirname(__file__), 'ssl/ocsp-responder/ocsp-responder.key')))
TEST_TLS_OCSP_INDEX = abs_path(os.environ.get('TEST_TLS_OCSP_INDEX', os.path.join(os.path.dirname(__file__), 'ssl/ca/index.txt')))
TEST_TLS_CRL_PATH = abs_path(os.environ.get('TEST_TLS_CRL_PATH', os.path.join(os.path.dirname(__file__), 'ssl/ca')))
TEST_WITH_TLS = os.environ.get('TEST_TLS', 'off').lower() == 'on'

OCSP_SERVER_PORT = int(os.environ.get('TEST_OCSP_SERVER_PORT', 8888))
CRL_HTTP_SERVER_PORT = int(os.environ.get('TEST_HTTP_SERVER_PORT', 8889))

TEST_WITH_TRACING = os.environ.get('TEST_TRACE', 'off').lower() == 'on'
TEST_WITH_REDIS = os.environ.get('TEST_REDIS', 'off').lower() == 'on'
TEST_TRACE_TO_JAEGER = os.environ.get('TEST_TRACE_JAEGER', 'off').lower() == 'on'

TEST_RANDOM_DATA_CONFIG = load_random_data_config()
TEST_RANDOM_DATA_FILES = get_random_data_files()

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
    sa.Column('id', sa.Integer, primary_key=True),
    sa.Column('data', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
    sa.Column('raw_data', sa.Text),
    sa.Column('nullable_column', sa.Text, nullable=True),
    sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
)

acrarollback_output_table = sa.Table('acrarollback_output', metadata,
                                     sa.Column('data', sa.LargeBinary),
                                     )
# keys of json objects that return acra-addzone tool
ZONE_ID = 'id'
ZONE_PUBLIC_KEY = 'public_key'

zones = []
poison_record = None
poison_record_acrablock = None
master_key = None
KEYS_FOLDER = None
ACRA_MASTER_KEY_VAR_NAME = 'ACRA_MASTER_KEY'
MASTER_KEY_PATH = '/tmp/acra-test-master.key'
TEST_WITH_VAULT = os.environ.get('TEST_WITH_VAULT', 'off').lower() == 'on'
TEST_SSL_VAULT = os.environ.get('TEST_SSL_VAULT', 'off').lower() == 'on'
TEST_VAULT_TLS_CA = abs_path(os.environ.get('TEST_VAULT_TLS_CA', 'tests/ssl/ca/ca.crt'))
VAULT_KV_ENGINE_VERSION=os.environ.get('VAULT_KV_ENGINE_VERSION', 'v1')
CRYPTO_ENVELOPE_HEADER = b'%%%'

# TLS_CERT_CLIENT_* represent two different ClientIDs are used in tests, initialized in setupModule function
TLS_CERT_CLIENT_ID_1 = None
TLS_CERT_CLIENT_ID_2 = None

TLS_CLIENT_ID_SOURCE_DN = 'distinguished_name'
TLS_CLIENT_ID_SOURCE_SERIAL = 'serial_number'

POISON_KEY_PATH = '.poison_key/poison_key'

STATEMENT_TIMEOUT = 5 * 1000 # 5 sec
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
TEST_MYSQL = utils.get_bool_env('TEST_MYSQL', default=False)
TEST_MARIADB = utils.get_bool_env('TEST_MARIADB', default=False)
if TEST_MYSQL or TEST_MARIADB:
    TEST_POSTGRESQL = False
    DB_DRIVER = "mysql+pymysql"
    TEST_MYSQL = True
    connect_args = {
        'user': DB_USER, 'password': DB_USER_PASSWORD,
        'read_timeout': SOCKET_CONNECT_TIMEOUT,
        'write_timeout': SOCKET_CONNECT_TIMEOUT,
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
            'sslmode': 'require',
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


def get_random_id():
    return random.randint(1, 100000)


def get_pregenerated_random_data():
    data_file = random.choice(TEST_RANDOM_DATA_FILES)
    with open(data_file, 'r') as f:
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


def get_poison_record_with_acrablock():
    """generate one poison record with acrablock for speed up tests and don't create subprocess
    for new records"""
    global poison_record_acrablock
    if not poison_record_acrablock:
        poison_record_acrablock = b64decode(subprocess.check_output([
            os.path.join(BINARY_OUTPUT_FOLDER, 'acra-poisonrecordmaker'), '--keys_dir={}'.format(KEYS_FOLDER.name), '--type=acrablock',
        ],
            timeout=PROCESS_CALL_TIMEOUT))
    return poison_record_acrablock


def create_client_keypair(name, only_storage=False, keys_dir=None, extra_kwargs: dict=None):
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


def create_client_keypair_from_certificate(tls_cert, extractor=TLS_CLIENT_ID_SOURCE_DN, only_storage=False, keys_dir=None, extra_kwargs: dict=None):
    if not keys_dir:
        keys_dir = KEYS_FOLDER.name
    args = [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keymaker'),  '--client_id=',
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
        return get_postgresql_tcp_connection_string(port, dbname)
    else:
        port = re.search(r'\.s\.PGSQL\.(\d+)', addr.path)
        if port:
            port = port.group(1)
        return get_postgresql_unix_connection_string(port, dbname)


def get_postgresql_unix_connection_string(port, dbname):
    return '{}:///{}?host={}&port={}'.format(DB_DRIVER, dbname, PG_UNIX_HOST, port)


def get_postgresql_tcp_connection_string(port, dbname):
    return '{}://localhost:{}/{}'.format(DB_DRIVER, port, dbname)


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


def fork_ocsp_server(port: int, check_connection: bool=True):
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


def fork_crl_http_server(port: int, check_connection: bool=True):
    logging.info("fork HTTP server with port {}".format(port))

    http_server_connection = get_crl_http_server_connection_string(port)

    cli_args = ['--bind', '127.0.0.1', '--directory', TEST_TLS_CRL_PATH, str(port)]
    print('python HTTP server args: {}'.format(' '.join(cli_args)))

    process = fork(lambda: subprocess.Popen(['python3', '-m', 'http.server'] + cli_args))

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
    Binary(name='acra-addzone', from_version=DEFAULT_VERSION,
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
        (binary.from_version, ['go', 'build', '-o={}'.format(os.path.join(BINARY_OUTPUT_FOLDER, binary.name)),  '-tags={}'.format(BUILD_TAGS)] +
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
                if i == (build_count-1):
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


# Set this to False to not rebuild binaries on setup.
CLEAN_BINARIES = utils.get_bool_env('TEST_CLEAN_BINARIES', default=True)
# Set this to False to not build binaries in principle.
BUILD_BINARIES = True


def setUpModule():
    global zones
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

    # first keypair for using without zones
    assert create_client_keypair_from_certificate(TEST_TLS_CLIENT_CERT) == 0
    assert create_client_keypair_from_certificate(TEST_TLS_CLIENT_2_CERT) == 0

    TLS_CERT_CLIENT_ID_1 = extract_client_id_from_cert(TEST_TLS_CLIENT_CERT)
    TLS_CERT_CLIENT_ID_2 = extract_client_id_from_cert(TEST_TLS_CLIENT_2_CERT)
    # add two zones
    zones.append(json.loads(subprocess.check_output(
        [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-addzone'), '--keys_output_dir={}'.format(KEYS_FOLDER.name)],
        cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT).decode('utf-8')))
    zones.append(json.loads(subprocess.check_output(
        [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-addzone'), '--keys_output_dir={}'.format(KEYS_FOLDER.name)],
        cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT).decode('utf-8')))
    socket.setdefaulttimeout(SOCKET_CONNECT_TIMEOUT)
    drop_tables()

    fork_certificate_validation_services()


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


def tearDownModule():
    if CLEAN_BINARIES:
        clean_binaries()
    clean_misc()
    KEYS_FOLDER.cleanup()
    # use list.clear instead >>> zones = []; to avoid creation new variable with new address and allow to use it from
    # other test modules
    zones.clear()
    clean_test_data()
    for path in [MASTER_KEY_PATH]:
        try:
            os.remove(path)
        except:
            pass
    drop_tables()
    kill_certificate_validation_services()


ConnectionArgs = collections.namedtuple("ConnectionArgs",
    field_names=["user", "password", "host", "port", "dbname",
                 "ssl_ca", "ssl_key", "ssl_cert", "format"],
    # 'format' is optional, other fields are required.
    defaults=[None])


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
                cursor.execute("PREPARE test_statement FROM {}".format(str(sa.literal(query).compile(dialect=db_dialect, compile_kwargs={"literal_binds": True}))))
                cursor.execute('EXECUTE test_statement')
                return cursor.fetchall()


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
        with contextlib.closing(mysql.connector.Connect(
                use_unicode=False, raw=True, charset='ascii',
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
        with contextlib.closing(mysql.connector.Connect(
                use_unicode=False, charset='ascii',
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
        with contextlib.closing(mysql.connector.Connect(
                use_unicode=False, charset='ascii',
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

    def _connect(self, loop):
        ssl_context = ssl.create_default_context(cafile=self.connection_args.ssl_ca)
        ssl_context.load_cert_chain(self.connection_args.ssl_cert, self.connection_args.ssl_key)
        ssl_context.check_hostname = True
        return loop.run_until_complete(
            asyncpg.connect(
                host=self.connection_args.host, port=self.connection_args.port,
                user=self.connection_args.user, password=self.connection_args.password,
                database=self.connection_args.dbname, ssl=ssl_context,
                **asyncpg_connect_args))

    def _set_text_format(self, conn):
        """Force text format to numeric types."""
        loop = asyncio.get_event_loop()
        for pg_type in ['int2', 'int4', 'int8']:
            loop.run_until_complete(
                conn.set_type_codec(pg_type,
                    schema='pg_catalog',
                    encoder=str,
                    decoder=int,
                    format='text')
            )
        for pg_type in ['float4', 'float8']:
            loop.run_until_complete(
                conn.set_type_codec(pg_type,
                    schema='pg_catalog',
                    encoder=str,
                    decoder=float,
                    format='text')
            )

    def execute_prepared_statement(self, query, args=None):
        if not args:
            args = []
        loop = asyncio.get_event_loop()
        conn = self._connect(loop)
        if self.connection_args.format == self.TextFormat:
            self._set_text_format(conn)
        try:
            stmt = loop.run_until_complete(
                conn.prepare(query, timeout=STATEMENT_TIMEOUT))
            result = loop.run_until_complete(
                stmt.fetch(*args, timeout=STATEMENT_TIMEOUT))
            return result
        finally:
            conn.terminate()

    def execute(self, query, args=None):
        if not args:
            args = []
        loop = asyncio.get_event_loop()
        conn = self._connect(loop)
        if self.connection_args.format == self.TextFormat:
            self._set_text_format(conn)
        try:
            result = loop.run_until_complete(
                conn.fetch(query, *args, timeout=STATEMENT_TIMEOUT))
            return result
        finally:
            loop.run_until_complete(conn.close(timeout=STATEMENT_TIMEOUT))


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
                utils.memoryview_rows_to_bytes(data)
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
                utils.memoryview_rows_to_bytes(data)
                return data


class KeyMakerTest(unittest.TestCase):
    def test_key_length(self):
        key_size = 32

        def random_keys(size):
            if KEYSTORE_VERSION == 'v1':
                # Keystore v1 uses simple binary data for keys
                value = os.urandom(size)
            elif KEYSTORE_VERSION == 'v2':
                # Keystore v2 uses more complex JSON format
                encryption = os.urandom(size)
                signature = os.urandom(size)
                keys = {
                    'encryption': b64encode(encryption).decode('ascii'),
                    'signature': b64encode(signature).decode('ascii'),
                }
                value = json.dumps(keys).encode('ascii')
            else:
                self.fail("keystore version not supported")

            return {ACRA_MASTER_KEY_VAR_NAME: b64encode(value)}

        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(subprocess.CalledProcessError) as exc:
                subprocess.check_output(
                    [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keymaker'), '--keystore={}'.format(KEYSTORE_VERSION),
                     '--keys_output_dir={}'.format(folder),
                     '--keys_public_output_dir={}'.format(folder)],
                    env=random_keys(key_size - 1))

        with tempfile.TemporaryDirectory() as folder:
            subprocess.check_output(
                    [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keymaker'), '--keystore={}'.format(KEYSTORE_VERSION),
                     '--keys_output_dir={}'.format(folder),
                     '--keys_public_output_dir={}'.format(folder)],
                    env=random_keys(key_size))

        with tempfile.TemporaryDirectory() as folder:
            subprocess.check_output(
                    [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keymaker'), '--keystore={}'.format(KEYSTORE_VERSION),
                     '--keys_output_dir={}'.format(folder),
                     '--keys_public_output_dir={}'.format(folder)],
                    env=random_keys(key_size * 2))

    def test_gen_keys_with_empty_client_id(self):
        #keys not needed client_id for generation
        with tempfile.TemporaryDirectory() as folder:
            subprocess.check_output(
                [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keymaker'), '--keystore={}'.format(KEYSTORE_VERSION),
                 '--keys_output_dir={}'.format(folder),
                 "--client_id=''",
                 '--generate_poisonrecord_keys',
                 '--generate_log_key',
                 '--keys_public_output_dir={}'.format(folder)])

            #check that keymaker will no fail on case of not created directory
            subprocess.check_output(
                [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keymaker'),
                 '--client_id=',
                 '--tls_cert={}'.format(TEST_TLS_CLIENT_CERT),
                 '--keystore={}'.format(KEYSTORE_VERSION),
                 '--generate_symmetric_storage_key',
                 '--keys_output_dir={}'.format('/tmp/.testkeys')])
            shutil.rmtree('/tmp/.testkeys')


class PrometheusMixin(object):
    _prometheus_addresses_field_name = 'prometheus_addresses'
    LOG_METRICS = os.environ.get('TEST_LOG_METRICS', False)

    def get_prometheus_address(self, port):
        addr = 'tcp://localhost:{}'.format(port)
        if not hasattr(self, self._prometheus_addresses_field_name):
            self.prometheus_addresses = []
        self.prometheus_addresses.append(addr)
        return addr

    def clear_prometheus_addresses(self):
        setattr(self, self._prometheus_addresses_field_name, [])

    def _get_metrics_url(self, address):
        addr = urlparse(address)
        return 'http://{}/metrics'.format(addr.netloc)

    def log_prometheus_metrics(self):
        if not self.LOG_METRICS:
            return

        for address in getattr(self, self._prometheus_addresses_field_name, []):
            response = requests.get(self._get_metrics_url(address))
            if response.status_code == 200:
                logging.info(response.text)
            else:
                logging.error(
                    "Can't fetch prometheus metrics from address: %s",
                    [address])


class TLSAuthenticationByDistinguishedNameMixin(object):
    def get_acraserver_connection_string(self, port=None):
        """unix socket connection string to allow connect directory to acra by db driver"""
        if not port:
            port = self.ACRASERVER_PORT
        return get_tcp_connection_string(port)

    def get_identifier_extractor_type(self):
        return TLS_CLIENT_ID_SOURCE_DN


class TLSAuthenticationBySerialNumberMixin(TLSAuthenticationByDistinguishedNameMixin):
    def get_identifier_extractor_type(self):
        return TLS_CLIENT_ID_SOURCE_SERIAL


class VaultClient:
    version_options = {
        'v1': dict(version=1),
        'v2': dict(version=2),
    }

    def __init__(self, verify=None):
        self.url = os.environ.get('VAULT_ADDRESS', 'http://localhost:8201')
        self.token = os.environ.get('VAULT_CLIENT_TOKEN', 'root_token')
        self.vault_client = Client(url=self.url, token=self.token, verify=verify)

    def get_vault_url(self):
        return self.url

    def get_vault_token(self):
        return self.token

    def enable_kv_secret_engine(self, mount_path=None):
        self.vault_client.sys.enable_secrets_engine(
            backend_type='kv',
            path=mount_path,
            options=self.version_options[VAULT_KV_ENGINE_VERSION],
        )
        time.sleep(2)

    def disable_kv_secret_engine(self, mount_path=None):
        self.vault_client.sys.disable_secrets_engine(path=mount_path)

    def put_master_key_by_version(self, path, version, mount_point=None):
        self.master_key = get_master_key()
        master_secret = {
            'acra_master_key': self.master_key
        }

        kv_secret_engine = None
        if version == "v1":
            kv_secret_engine = self.vault_client.secrets.kv.v1
        elif version == "v2":
            kv_secret_engine = self.vault_client.secrets.kv.v2

        kv_secret_engine.create_or_update_secret(
            path=path,
            secret=master_secret,
            mount_point=mount_point,
        )

    def get_vault_cli_args(self, mount_path=None, secret_path=None):
        args = {
            'vault_connection_api_string': self.vault_client.url,
            'vault_secrets_path': '{0}/{1}'.format(mount_path, secret_path)
        }

        if TEST_SSL_VAULT:
            args['vault_tls_transport_enable'] = True
            args['vault_tls_ca_path'] = TEST_VAULT_TLS_CA
        return args


class BaseTestCase(PrometheusMixin, unittest.TestCase):
    DEBUG_LOG = os.environ.get('DEBUG_LOG', True)
    # for debugging with manually runned acra-server
    EXTERNAL_ACRA = False
    ACRASERVER_PORT = int(os.environ.get('TEST_ACRASERVER_PORT', 10003))
    ACRASERVER_PROMETHEUS_PORT = int(os.environ.get('TEST_ACRASERVER_PROMETHEUS_PORT', 11004))
    ACRA_BYTEA = 'pgsql_hex_bytea'
    DB_BYTEA = 'hex'
    WHOLECELL_MODE = False
    ZONE = False
    TEST_DATA_LOG = False

    acra = ProcessStub()

    def checkSkip(self):
        if not TEST_WITH_TLS:
            self.skipTest("running tests with TLS")

    def wait_acraserver_connection(self, connection_string: str, *args, **kwargs):
        if connection_string.startswith('unix'):
            return wait_unix_socket(
                socket_path_from_connection_string(connection_string),
                *args, **kwargs)
        else:
            return wait_connection(connection_string.split(':')[-1])

    def get_acraserver_connection_string(self, port=None):
        if not port:
            port = self.ACRASERVER_PORT
        return get_tcp_connection_string(port)

    def get_acraserver_api_connection_string(self, port=None):
        if not port:
            port = self.ACRASERVER_PORT + 1
        elif port == self.ACRASERVER_PORT:
            port = port + 1
        return acra_api_connection_string(port)

    def get_acraserver_bin_path(self):
        return os.path.join(BINARY_OUTPUT_FOLDER, 'acra-server')

    def with_tls(self):
        return TEST_WITH_TLS

    def _fork_acra(self, acra_kwargs, popen_kwargs):
        logging.info("fork acra")
        connection_string = self.get_acraserver_connection_string(
            acra_kwargs.get('incoming_connection_port', self.ACRASERVER_PORT))
        api_connection_string = self.get_acraserver_api_connection_string(
            acra_kwargs.get('incoming_connection_api_port')
        )
        for path in [socket_path_from_connection_string(connection_string), socket_path_from_connection_string(api_connection_string)]:
            try:
                os.remove(path)
            except:
                pass

        args = {
            'db_host': DB_HOST,
            'db_port': DB_PORT,
            'logging_format': 'cef',
            # we doesn't need in tests waiting closing connections
            'incoming_connection_close_timeout': 0,
            self.ACRA_BYTEA: 'true',
            'tls_ocsp_from_cert': 'ignore',
            'tls_crl_from_cert': 'ignore',
            'incoming_connection_string': connection_string,
            'incoming_connection_api_string': api_connection_string,
            'acrastruct_wholecell_enable': 'true' if self.WHOLECELL_MODE else 'false',
            'acrastruct_injectedcell_enable': 'false' if self.WHOLECELL_MODE else 'true',
            'd': 'true' if self.DEBUG_LOG else 'false',
            'zonemode_enable': 'true' if self.ZONE else 'false',
            'http_api_enable': 'true' if self.ZONE else 'true',
            'cache_keystore_on_start': 'false',
            'keys_dir': KEYS_FOLDER.name,
        }
        if TEST_WITH_TRACING:
            args['tracing_log_enable'] = 'true'
            if TEST_TRACE_TO_JAEGER:
                args['tracing_jaeger_enable'] = 'true'
        if self.LOG_METRICS:
            args['incoming_connection_prometheus_metrics_string'] = self.get_prometheus_address(
                self.ACRASERVER_PROMETHEUS_PORT)
        if self.with_tls():
            args['tls_key'] = TEST_TLS_SERVER_KEY
            args['tls_cert'] = TEST_TLS_SERVER_CERT
            args['tls_ca'] = TEST_TLS_CA
            args['tls_auth'] = ACRA_TLS_AUTH
            args['tls_ocsp_url'] = 'http://localhost:{}'.format(OCSP_SERVER_PORT)
            args['tls_ocsp_from_cert'] = 'use'
            args['tls_crl_url'] = 'http://localhost:{}/crl.pem'.format(CRL_HTTP_SERVER_PORT)
            args['tls_crl_from_cert'] = 'use'
        else:
            # Explicitly disable certificate validation by default since otherwise we may end up
            # in a situation when some certificate contains OCSP or CRL URI while corresponding
            # services were not started by this script (because TLS testing was disabled)
            args['tls_ocsp_from_cert'] = 'ignore'
            args['tls_crl_from_cert'] = 'ignore'
        if TEST_MYSQL:
            args['mysql_enable'] = 'true'
            args['postgresql_enable'] = 'false'
        args.update(acra_kwargs)
        if not popen_kwargs:
            popen_kwargs = {}
        cli_args = sorted(['--{}={}'.format(k, v) for k, v in args.items() if v is not None])
        print("acra-server args: {}".format(' '.join(cli_args)))

        process = fork(lambda: subprocess.Popen([self.get_acraserver_bin_path()] + cli_args,
                                                     **popen_kwargs))
        try:
            self.wait_acraserver_connection(connection_string)
        except:
            stop_process(process)
            raise
        logging.info("fork acra finished [pid={}]".format(process.pid))
        return process

    def fork_acra(self, popen_kwargs: dict=None, **acra_kwargs: dict):
        return self._fork_acra(acra_kwargs, popen_kwargs)

    def fork_translator(self, translator_kwargs, popen_kwargs=None):
        logging.info("fork acra-translator")
        from utils import load_default_config
        default_config = load_default_config("acra-translator")
        default_args = {
            'incoming_connection_close_timeout': 0,
            'keys_dir': KEYS_FOLDER.name,
            'logging_format': 'cef',
        }
        default_config.update(default_args)
        default_config.update(translator_kwargs)
        if not popen_kwargs:
            popen_kwargs = {}
        if self.DEBUG_LOG:
            default_config['d'] = 1
        if TEST_WITH_TRACING:
            default_config['tracing_log_enable'] = 1
            if TEST_TRACE_TO_JAEGER:
                default_config['tracing_jaeger_enable'] = 1

        cli_args = ['--{}={}'.format(k, v) for k, v in default_config.items()]

        translator = fork(lambda: subprocess.Popen([os.path.join(BINARY_OUTPUT_FOLDER, 'acra-translator')] + cli_args, **popen_kwargs))
        try:
            if default_config['incoming_connection_grpc_string']:
                wait_connection(urlparse(default_config['incoming_connection_grpc_string']).port)
            if default_config['incoming_connection_http_string']:
                wait_connection(urlparse(default_config['incoming_connection_http_string']).port)
        except:
            stop_process(translator)
            raise
        return translator

    def setUp(self):
        self.checkSkip()
        try:
            if not self.EXTERNAL_ACRA:
                self.acra = self.fork_acra()

            base_args = get_connect_args(port=self.ACRASERVER_PORT, sslmode='require')

            tls_args_1 = base_args.copy()
            tls_args_1.update(get_tls_connection_args(TEST_TLS_CLIENT_KEY, TEST_TLS_CLIENT_CERT))
            connect_str = get_engine_connection_string(
                self.get_acraserver_connection_string(self.ACRASERVER_PORT), DB_NAME)
            self.engine1 = sa.create_engine(connect_str, connect_args=tls_args_1)

            tls_args_2 = base_args.copy()
            tls_args_2.update(get_tls_connection_args(TEST_TLS_CLIENT_2_KEY, TEST_TLS_CLIENT_2_CERT))
            self.engine2 = sa.create_engine(
                get_engine_connection_string(
                    self.get_acraserver_connection_string(self.ACRASERVER_PORT), DB_NAME), connect_args=tls_args_2)

            self.engine_raw = sa.create_engine(
                '{}://{}:{}/{}'.format(DB_DRIVER, DB_HOST, DB_PORT, DB_NAME),
                connect_args=connect_args)

            self.engines = [self.engine1, self.engine2, self.engine_raw]

            metadata.create_all(self.engine_raw)
            self.engine_raw.execute('delete from test;')
            for engine in self.engines:
                count = 0
                # try with sleep if acra not up yet
                while True:
                    try:
                        if TEST_MYSQL:
                            engine.execute("select 1;")
                        else:
                            engine.execute(
                                "UPDATE pg_settings SET setting = '{}' "
                                "WHERE name = 'bytea_output'".format(self.DB_BYTEA))
                        break
                    except Exception as e:
                        time.sleep(SETUP_SQL_COMMAND_TIMEOUT)
                        count += 1
                        if count == SQL_EXECUTE_TRY_COUNT:
                            raise
        except:
            self.tearDown()
            raise

    def tearDown(self):
        try:
            self.log_prometheus_metrics()
            self.clear_prometheus_addresses()
        except:
            pass
        try:
            self.engine_raw.execute('delete from test;')
        except:
            pass
        for engine in getattr(self, 'engines', []):
            engine.dispose()
        stop_process([getattr(self, 'acra', ProcessStub())])
        send_signal_by_process_name('acra-server', signal.SIGKILL)

    def log(self, data, expected=b'<no expected value>',
            storage_client_id=None, zone_id=None,
            poison_key=False):
        """this function for printing data which used in test and for
        reproducing error with them if any error detected"""
        if not self.TEST_DATA_LOG:
            return

        def key_name():
            if storage_client_id:
                return 'client storage, id={}'.format(storage_client_id)
            elif zone_id:
                return 'zone storage, id={}'.format(zone_id)
            elif poison_key:
                return 'poison record key'
            else:
                return 'unknown'

        log_entry = {
            'master_key': get_master_key(),
            'key_name': key_name(),
            'data': b64encode(data).decode('ascii'),
            'expected': b64encode(expected).decode('ascii'),
        }

        if storage_client_id:
            public_key = read_storage_public_key(storage_client_id, KEYS_FOLDER.name)
            private_key = read_storage_private_key(KEYS_FOLDER.name, storage_client_id)
            log_entry['public_key'] = b64encode(public_key).decode('ascii')
            log_entry['private_key'] = b64encode(private_key).decode('ascii')

        if zone_id:
            public_key = read_zone_public_key(storage_client_id, KEYS_FOLDER.name)
            private_key = read_zone_private_key(KEYS_FOLDER.name, storage_client_id)
            log_entry['zone_public'] = b64encode(public_key).decode('ascii')
            log_entry['zone_private'] = b64encode(private_key).decode('ascii')
            log_entry['zone_id'] = zone_id

        if poison_key:
            public_key = read_poison_public_key(KEYS_FOLDER.name)
            private_key = read_poison_private_key(KEYS_FOLDER.name)
            log_entry['public_key'] = b64encode(public_key).decode('ascii')
            log_entry['private_key'] = b64encode(private_key).decode('ascii')
            log_entry['poison_record'] = b64encode(get_poison_record()).decode('ascii')

        logging.debug("test log: {}".format(json.dumps(log_entry)))


class AcraCatchLogsMixin(object):
    def __init__(self, *args, **kwargs):
        self.log_files = {}
        super(AcraCatchLogsMixin, self).__init__(*args, **kwargs)

    def read_log(self, process):
        with open(self.log_files[process].name, 'r', errors='replace',
                  encoding='utf-8') as f:
            log = f.read()
            print(log.encode(encoding='utf-8', errors='replace'))
            return log

    def fork_acra(self, popen_kwargs: dict=None, **acra_kwargs: dict):
        log_file = tempfile.NamedTemporaryFile('w+', encoding='utf-8')
        popen_args = {
            'stderr': subprocess.STDOUT,
            'stdout': log_file,
            'close_fds': True,
            'bufsize': 0,
        }
        process = super(AcraCatchLogsMixin, self).fork_acra(
            popen_args, **acra_kwargs
        )
        assert process
        # register process to not forget close all descriptors
        self.log_files[process] = log_file
        return process

    def tearDown(self, *args, **kwargs):
        super(AcraCatchLogsMixin, self).tearDown(*args, **kwargs)
        for process, log_file in self.log_files.items():
            log_file.close()
            try:
                os.remove(log_file.name)
            except:
                pass
            stop_process(process)


class AcraTranslatorMixin(object):
    def get_identifier_extractor_type(self):
        return TLS_CLIENT_ID_SOURCE_DN

    def get_http_schema(self):
        return 'https'

    def get_http_default_kwargs(self):
        return {
            'timeout': REQUEST_TIMEOUT,
            'verify': TEST_TLS_CA,
            # https://requests.readthedocs.io/en/master/user/advanced/#client-side-certificates
            # first crt, second key
            'cert': (TEST_TLS_CLIENT_CERT, TEST_TLS_CLIENT_KEY),
        }

    def http_decrypt_request(self, port, client_id, zone_id, acrastruct):
        api_url = '{}://localhost:{}/v1/decrypt'.format(self.get_http_schema(), port)
        if zone_id:
            api_url = '{}?zone_id={}'.format(api_url, zone_id)
        kwargs = self.get_http_default_kwargs()
        kwargs['data'] = acrastruct
        with requests.post(api_url, **kwargs) as response:
            return response.content

    def http_encrypt_request(self, port, client_id, zone_id, data):
        api_url = '{}://localhost:{}/v1/encrypt'.format(self.get_http_schema(), port)
        if zone_id:
            api_url = '{}?zone_id={}'.format(api_url, zone_id)
        kwargs = self.get_http_default_kwargs()
        kwargs['data'] = data
        with requests.post(api_url, **kwargs) as response:
            return response.content

    def get_grpc_channel(self, port):
        '''setup grpc to use tls client authentication'''
        with open(TEST_TLS_CA, 'rb') as ca_file, open(TEST_TLS_CLIENT_KEY, 'rb') as key_file, open(TEST_TLS_CLIENT_CERT, 'rb') as cert_file:
            ca_bytes = ca_file.read()
            key_bytes = key_file.read()
            cert_bytes = cert_file.read()
        tls_credentials = grpc.ssl_channel_credentials(ca_bytes, key_bytes, cert_bytes)
        return grpc.secure_channel('localhost:{}'.format(port), tls_credentials)

    def grpc_encrypt_request(self, port, client_id, zone_id, data):
        with self.get_grpc_channel(port) as channel:
            stub = api_pb2_grpc.WriterStub(channel)
            try:
                if zone_id:
                    response = stub.Encrypt(api_pb2.EncryptRequest(
                        zone_id=zone_id.encode('ascii'), data=data,
                        client_id=client_id.encode('ascii')),
                        timeout=SOCKET_CONNECT_TIMEOUT)
                else:
                    response = stub.Encrypt(api_pb2.EncryptRequest(
                        client_id=client_id.encode('ascii'), data=data),
                        timeout=SOCKET_CONNECT_TIMEOUT)
            except grpc.RpcError as exc:
                logging.info(exc)
                return b''
            return response.acrastruct

    def grpc_decrypt_request(self, port, client_id, zone_id, acrastruct, raise_exception_on_failure=False):
        with self.get_grpc_channel(port) as channel:
            stub = api_pb2_grpc.ReaderStub(channel)
            try:
                if zone_id:
                    response = stub.Decrypt(api_pb2.DecryptRequest(
                        zone_id=zone_id.encode('ascii'), acrastruct=acrastruct,
                        client_id=client_id.encode('ascii')),
                        timeout=SOCKET_CONNECT_TIMEOUT)
                else:
                    response = stub.Decrypt(api_pb2.DecryptRequest(
                        client_id=client_id.encode('ascii'), acrastruct=acrastruct),
                        timeout=SOCKET_CONNECT_TIMEOUT)
            except grpc.RpcError as exc:
                logging.info(exc)
                if raise_exception_on_failure:
                    raise
                return b''
            return response.data


class HexFormatTest(BaseTestCase):

    def testClientIDRead(self):
        """test decrypting with correct clientID and not decrypting with
        incorrect clientID or using direct connection to db"""
        client_id = TLS_CERT_CLIENT_ID_1
        server_public1 = read_storage_public_key(client_id, KEYS_FOLDER.name)
        data = get_pregenerated_random_data()
        acra_struct = create_acrastruct(
            data.encode('ascii'), server_public1)
        row_id = get_random_id()

        self.log(storage_client_id=client_id,
                 data=acra_struct, expected=data.encode('ascii'))

        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': acra_struct, 'raw_data': data})
        result = self.engine1.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertEqual(row['data'], row['raw_data'].encode('utf-8'))
        self.assertEqual(row['empty'], b'')

        result = self.engine2.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'].decode('ascii', errors='ignore'),
                            row['raw_data'])
        self.assertEqual(row['empty'], b'')

        result = self.engine_raw.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'].decode('ascii', errors='ignore'),
                            row['raw_data'])
        self.assertEqual(row['empty'], b'')

    def testReadAcrastructInAcrastruct(self):
        """test correct decrypting acrastruct when acrastruct concatenated to
        partial another acrastruct"""
        client_id = TLS_CERT_CLIENT_ID_1
        server_public1 = read_storage_public_key(client_id, KEYS_FOLDER.name)
        incorrect_data = get_pregenerated_random_data()
        correct_data = get_pregenerated_random_data()
        suffix_data = get_pregenerated_random_data()[:10]
        fake_offset = (3+45+84) - 4
        fake_acra_struct = create_acrastruct(
            incorrect_data.encode('ascii'), server_public1)[:fake_offset]
        inner_acra_struct = create_acrastruct(
            correct_data.encode('ascii'), server_public1)
        data = fake_acra_struct + inner_acra_struct + suffix_data.encode('ascii')
        correct_data = correct_data + suffix_data
        row_id = get_random_id()

        self.log(storage_client_id=client_id,
                 data=data,
                 expected=fake_acra_struct+correct_data.encode('ascii'))

        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': data, 'raw_data': correct_data})
        result = self.engine1.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        try:
            self.assertEqual(row['data'][fake_offset:],
                             row['raw_data'].encode('utf-8'))
            self.assertEqual(row['data'][:fake_offset], fake_acra_struct[:fake_offset])
        except:
            print('incorrect data: {}\ncorrect data: {}\ndata: {}\n data len: {}'.format(
                incorrect_data, correct_data, row['data'], len(row['data'])))
            raise
        self.assertEqual(row['empty'], b'')

        result = self.engine2.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'][fake_offset:].decode('ascii', errors='ignore'),
                            row['raw_data'])
        self.assertEqual(row['empty'], b'')

        result = self.engine_raw.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'][fake_offset:].decode('ascii', errors='ignore'),
                            row['raw_data'])
        self.assertEqual(row['empty'], b'')


class BaseBinaryPostgreSQLTestCase(BaseTestCase):
    """Setup test fixture for testing PostgreSQL extended protocol."""

    def checkSkip(self):
        super().checkSkip()
        if not TEST_POSTGRESQL:
            self.skipTest("test only PostgreSQL")

    FORMAT = AsyncpgExecutor.BinaryFormat

    def setUp(self):
        super().setUp()

        def executor_with_ssl(ssl_key, ssl_cert):
            args = ConnectionArgs(
                host=get_db_host(), port=self.ACRASERVER_PORT, dbname=DB_NAME,
                user=DB_USER, password=DB_USER_PASSWORD,
                ssl_ca=TEST_TLS_CA,
                ssl_key=ssl_key,
                ssl_cert=ssl_cert,
                format=self.FORMAT,
            )
            return AsyncpgExecutor(args)

        self.executor1 = executor_with_ssl(TEST_TLS_CLIENT_KEY, TEST_TLS_CLIENT_CERT)
        self.executor2 = executor_with_ssl(TEST_TLS_CLIENT_2_KEY, TEST_TLS_CLIENT_2_CERT)

    def compileQuery(self, query, parameters={}, literal_binds=False):
        """
        Compile SQLAlchemy query and parameter dictionary
        into SQL text and parameter list for the executor.
        """
        # Ask SQLAlchemy to compile the query in database-agnostic SQL.
        # After that manually replace placeholders in text. Unfortunately,
        # passing "dialect=postgresql_dialect" does not seem to work :(
        compile_kwargs = {"literal_binds": literal_binds}
        query = str(query.compile(compile_kwargs=compile_kwargs))
        values = []
        for placeholder, value in parameters.items():
            # SQLAlchemy default dialect has placeholders of form ":name".
            # PostgreSQL syntax is "$n", with 1-based sequential parameters.
            saPlaceholder = ':' + placeholder
            pgPlaceholder = '$' + str(len(values) + 1)
            # Replace and keep values only for those placeholders which
            # are actually used in the query.
            if saPlaceholder in query:
                values.append(value)
                query = query.replace(saPlaceholder, pgPlaceholder)
        return query, values

    def compileBulkInsertQuery(self, query, parameters={}, literal_binds=False):
        """
        Compile SQLAlchemy insert query and parameter dictionary into SQL text and parameter list for the executor.
        It is used regexp parsing to get the correct order of insert params, values are stored in tuple with the same order.
        """
        compile_kwargs = {"literal_binds": literal_binds}
        query = str(query.compile(compile_kwargs=compile_kwargs))
        values = []
        # example of the insert string:
        # INSERT INTO test_table (id, zone_id, nullable_column, empty) VALUES (:id, :zone_id, :nullable_column, :empty)
        pattern_string = r'(INSERT INTO) (\S+).*\((.*?)\).*(VALUES).*\((.*?)\)(.*\;?)'

        res = re.findall(pattern_string, query, re.IGNORECASE | re.DOTALL)
        if len(res) > 0:
            # regexp matching result should look like this:
            # `id, zone_id, nullable_column, empty`
            intos = str(res[0][2])
            count = 1
            for idx, params in enumerate(parameters):
                # each value in bulk insert has unique suffix like ':id_m0'
                suffix = '_m'+str(idx)
                # so we need to split it by comma value to iterate over
                for into_value in intos.split(', '):
                    values.append(params[into_value])
                    query = query.replace(':' + into_value + suffix, '$' + str(count))
                    count += 1
        return query, tuple(values)

    def compileInsertQuery(self, query, parameters={}, literal_binds=False):
        """
        Compile SQLAlchemy insert query and parameter dictionary into SQL text and parameter list for the executor.
        It is used regexp parsing to get the correct order of insert params, values are stored in tuple with the same order.
        """
        compile_kwargs = {"literal_binds": literal_binds}
        query = str(query.compile(compile_kwargs=compile_kwargs))
        values = []
        # example of the insert string:
        # INSERT INTO test_table (id, zone_id, nullable_column, empty) VALUES (:id, :zone_id, :nullable_column, :empty)
        pattern_string = r'(INSERT INTO) (\S+).*\((.*?)\).*(VALUES).*\((.*?)\)(.*\;?)'

        res = re.findall(pattern_string, query, re.IGNORECASE | re.DOTALL)
        if len(res) > 0:
            # regexp matching result should look like this:
            # `id, zone_id, nullable_column, empty`
            intos = str(res[0][2])
            count = 1
            # so we need to split it by comma value to iterate over
            for into_value in intos.split(', '):
                values.append(parameters[into_value])
                query = query.replace(':' + into_value, '$' + str(count))
                count += 1
        return query, tuple(values)


class BaseBinaryMySQLTestCase(BaseTestCase):
    """Setup test fixture for testing MySQL extended protocol."""

    def checkSkip(self):
        super().checkSkip()
        if not TEST_MYSQL:
            self.skipTest("test only MySQL")

    def setUp(self):
        super().setUp()

        def executor_with_ssl(ssl_key, ssl_cert):
            args = ConnectionArgs(
                host=get_db_host(), port=self.ACRASERVER_PORT, dbname=DB_NAME,
                user=DB_USER, password=DB_USER_PASSWORD,
                ssl_ca=TEST_TLS_CA,
                ssl_key=ssl_key,
                ssl_cert=ssl_cert,
            )
            return MysqlExecutor(args)

        self.executor1 = executor_with_ssl(TEST_TLS_CLIENT_KEY, TEST_TLS_CLIENT_CERT)
        self.executor2 = executor_with_ssl(TEST_TLS_CLIENT_2_KEY, TEST_TLS_CLIENT_2_CERT)

    def compileInsertQuery(self, query, parameters={}, literal_binds=False):
        """
        Compile SQLAlchemy insert query and parameter dictionary into SQL text and parameter list for the executor.
        It is used regexp parsing to get the correct order of insert params, values are stored in tuple with the same order.
        """
        compile_kwargs = {"literal_binds": literal_binds}
        query = str(query.compile(compile_kwargs=compile_kwargs))
        values = []
        # example of the insert string:
        # INSERT INTO test_table (id, zone_id, nullable_column, empty) VALUES (:id, :zone_id, :nullable_column, :empty)
        pattern_string = r'(INSERT INTO) (\S+).*\((.*?)\).*(VALUES).*\((.*?)\)(.*\;?)'

        res = re.findall(pattern_string, query, re.IGNORECASE | re.DOTALL)
        if len(res) > 0:
            # regexp matching result should look like this:
            # `id, zone_id, nullable_column, empty`
            intos = str(res[0][2])

            # so we need to split it by comma value to iterate over
            for into_value in intos.split(', '):
                values.append(parameters[into_value])
                query = query.replace(':' + into_value, '?')
        return query, tuple(values)

    def compileBulkInsertQuery(self, query, parameters={}, literal_binds=False):
        """
        Compile SQLAlchemy insert query and parameter dictionary into SQL text and parameter list for the executor.
        It is used regexp parsing to get the correct order of insert params, values are stored in tuple with the same order.
        """
        compile_kwargs = {"literal_binds": literal_binds}
        query = str(query.compile(compile_kwargs=compile_kwargs))
        values = []
        # example of the insert string:
        # INSERT INTO test_table (id, zone_id, nullable_column, empty) VALUES (:id, :zone_id, :nullable_column, :empty)
        pattern_string = r'(INSERT INTO) (\S+).*\((.*?)\).*(VALUES).*\((.*?)\)(.*\;?)'

        res = re.findall(pattern_string, query, re.IGNORECASE | re.DOTALL)
        if len(res) > 0:
            # regexp matching result should look like this:
            # `id, zone_id, nullable_column, empty`
            intos = str(res[0][2])
            for idx, params in enumerate(parameters):
                # each value in bulk insert contains unique suffix like ':id_m0'
                suffix = '_m'+str(idx)
                # so we need to split it by comma value to iterate over
                for into_value in intos.split(', '):
                    values.append(params[into_value])
                    query = query.replace(':' + into_value + suffix, '?')
        return query, tuple(values)

    def compileQuery(self, query, parameters={}, literal_binds=False):
        """
        Compile SQLAlchemy query and parameter dictionary into SQL text and parameter list for the executor.
        It is used regexp parsing to get the correct order of parameters, values are stored in tuple with the same order.
        """
        compile_kwargs = {"literal_binds": literal_binds}
        query = str(query.compile(compile_kwargs=compile_kwargs))
        values = []
        # parse all parameters like `:id` in the query
        pattern_string = r'(:\w+)'
        res = re.findall(pattern_string, query, re.IGNORECASE | re.DOTALL)
        if len(res) > 0:
            for placeholder in res:
                # parameters map contain values where keys without ':' so we need trim the placeholder before
                key = placeholder.lstrip(':')
                values.append(parameters[key])
                query = query.replace(placeholder, '?')
        return query, tuple(values)


class BaseCensorTest(BaseTestCase):
    CENSOR_CONFIG_FILE = 'default.yaml'

    def fork_acra(self, popen_kwargs: dict=None, **acra_kwargs: dict):
        acra_kwargs['acracensor_config_file'] = self.CENSOR_CONFIG_FILE
        return self._fork_acra(acra_kwargs, popen_kwargs)


class FailedRunProcessMixin(object):

    def getOutputFromProcess(self, args):
        logger.info("run command '{}'".format(' '.join(args)))
        process = subprocess.Popen(args, stderr=subprocess.PIPE)
        try:
            _, stderr = process.communicate(timeout=5)  # 5 second enough to start binary and stop execution with error
        except:
            raise
        finally:
            process.kill()
        logger.debug(stderr)
        return stderr.decode('utf-8')

    def assertProcessHasNotMessage(self, args, status_code, expectedMessage):
        logger.info("run command '{}'".format(' '.join(args)))
        process = subprocess.Popen(args, stderr=subprocess.PIPE, cwd=os.getcwd())
        try:
            _, stderr = process.communicate(timeout=1)
            logger.debug(stderr)
            self.assertEqual(process.returncode, status_code)
            self.assertNotIn(expectedMessage.lower(), stderr.decode('utf-8').lower(), "Has message that should not to be in")
        except:
            raise
        finally:
            process.kill()


class TestCensorVersionChecks(BaseCensorTest, FailedRunProcessMixin):
    def setUp(self):
        # doesn't need to start acra-server and connections
        pass

    def tearDown(self):
        # doesn't need to stop acra-server and connections
        pass

    def checkErrorMessage(self, configFile, expectedMessage):
        args = [self.get_acraserver_bin_path(),
                '--acracensor_config_file={}'.format(configFile),
                # required param
                '--db_host={}'.format(DB_HOST)
                ]
        stderr = self.getOutputFromProcess(args)
        self.assertIn(expectedMessage.lower(), stderr.lower())

    def testWithoutVersion(self):
        expectedMessage = 'level=error msg="can\'t setup censor" code=561 error="acra-censor\'s config is outdated"'
        self.checkErrorMessage(abs_path('tests/acra-censor_configs/without_version.yaml'), expectedMessage)

    def testNewerVersion(self):
        expectedMessage = "acra-censor's config is outdated"
        self.checkErrorMessage(abs_path('tests/acra-censor_configs/new_version.yaml'), expectedMessage)

    def testIncorrectFormat(self):
        expectedMessage = 'level=error msg="can\'t setup censor" code=561 error="strconv.parseuint: parsing'
        self.checkErrorMessage(abs_path('tests/acra-censor_configs/incorrect_version_format.yaml'), expectedMessage)


class CensorBlacklistTest(BaseCensorTest):
    CENSOR_CONFIG_FILE = abs_path('tests/acra-censor_configs/acra-censor_blacklist.yaml')
    def testBlacklist(self):
        connection_args = ConnectionArgs(host=get_db_host(), port=self.ACRASERVER_PORT,
                           user=DB_USER, password=DB_USER_PASSWORD,
                           dbname=DB_NAME, ssl_ca=TEST_TLS_CA,
                           ssl_key=TEST_TLS_CLIENT_KEY,
                           ssl_cert=TEST_TLS_CLIENT_CERT)
        if TEST_MYSQL:
            expectedException = (pymysql.err.OperationalError,
                                 mysql.connector.errors.DatabaseError)
            expectedExceptionInPreparedStatement = mysql.connector.errors.DatabaseError
            executors = [PyMysqlExecutor(connection_args),
                         MysqlExecutor(connection_args)]
        if TEST_POSTGRESQL:
            expectedException = (psycopg2.ProgrammingError,
                                 asyncpg.exceptions.SyntaxOrAccessError)
            expectedExceptionInPreparedStatement = asyncpg.exceptions.SyntaxOrAccessError
            executors = [Psycopg2Executor(connection_args),
                         AsyncpgExecutor(connection_args)]

        testQueries = ["select * from test",  # should be denied by query
                       "select * from acrarollback_output",  # should be denied by table
                       "select data from test where id=1",  # should be denied by pattern
                       "insert into test(id, data, empty) values(1, DEFAULT, '')"]  # should be denied by pattern

        for executor in executors:
            for testQuery in testQueries:
                with self.assertRaises(expectedException):
                    executor.execute(testQuery)
                try:
                    executor.execute_prepared_statement(testQuery)
                except psycopg2.ProgrammingError as e:
                    self.assertTrue(str(e) == "no results to fetch")
                except expectedExceptionInPreparedStatement:
                    return


class CensorWhitelistTest(BaseCensorTest):
    CENSOR_CONFIG_FILE = abs_path('tests/acra-censor_configs/acra-censor_whitelist.yaml')
    def testWhitelist(self):
        connection_args = ConnectionArgs(host=get_db_host(), port=self.ACRASERVER_PORT,
                           user=DB_USER, password=DB_USER_PASSWORD,
                           dbname=DB_NAME, ssl_ca=TEST_TLS_CA,
                           ssl_key=TEST_TLS_CLIENT_KEY,
                           ssl_cert=TEST_TLS_CLIENT_CERT)
        if TEST_MYSQL:
            expectedException = (pymysql.err.OperationalError,
                                 mysql.connector.errors.DatabaseError)
            expectedExceptionInPreparedStatement = mysql.connector.errors.DatabaseError
            executors = [PyMysqlExecutor(connection_args),
                         MysqlExecutor(connection_args)]
        if TEST_POSTGRESQL:
            expectedException = (psycopg2.ProgrammingError,
                                 asyncpg.exceptions.SyntaxOrAccessError)
            expectedExceptionInPreparedStatement = asyncpg.exceptions.SyntaxOrAccessError
            executors = [Psycopg2Executor(connection_args),
                         AsyncpgExecutor(connection_args)]

        # all those queries should be denied because no matching allow rules specified
        testQueries = ["select * from acrarollback_output",
                       "insert into test(id, data, empty) values(1, DEFAULT, '')"]

        for executor in executors:
            for testQuery in testQueries:
                with self.assertRaises(expectedException):
                    executor.execute(testQuery)
                try:
                    executor.execute_prepared_statement(testQuery)
                except psycopg2.ProgrammingError as e:
                    self.assertTrue(str(e) == "no results to fetch")
                except expectedExceptionInPreparedStatement:
                    return


class ZoneHexFormatTest(BaseTestCase):
    ZONE = True

    def testRead(self):
        data = get_pregenerated_random_data()
        zone_public = b64decode(zones[0][ZONE_PUBLIC_KEY].encode('ascii'))
        acra_struct = create_acrastruct(
            data.encode('ascii'), zone_public,
            context=zones[0][ZONE_ID].encode('ascii'))
        row_id = get_random_id()
        self.log(zone_id=zones[0][ZONE_ID],
                 data=acra_struct, expected=data.encode('ascii'))
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': acra_struct, 'raw_data': data})

        zone = zones[0][ZONE_ID].encode('ascii')
        result = self.engine1.execute(
            sa.select([sa.cast(zone, BYTEA), test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertEqual(row['data'], row['raw_data'].encode('utf-8'))
        self.assertEqual(row['empty'], b'')

        # without zone in another acra-server, in the same acra-server and without any acra-server
        for engine in self.engines:
            result = engine.execute(
                sa.select([test_table])
                .where(test_table.c.id == row_id))
            row = result.fetchone()
            self.assertNotEqual(row['data'].decode('ascii', errors='ignore'), row['raw_data'])
            self.assertEqual(row['empty'], b'')

    def testReadAcrastructInAcrastruct(self):
        incorrect_data = get_pregenerated_random_data()
        correct_data = get_pregenerated_random_data()
        suffix_data = get_pregenerated_random_data()[:10]
        zone_public = b64decode(zones[0][ZONE_PUBLIC_KEY].encode('ascii'))
        fake_offset = (3+45+84) - 1
        fake_acra_struct = create_acrastruct(
            incorrect_data.encode('ascii'), zone_public, context=zones[0][ZONE_ID].encode('ascii'))[:fake_offset]
        inner_acra_struct = create_acrastruct(
            correct_data.encode('ascii'), zone_public, context=zones[0][ZONE_ID].encode('ascii'))
        data = fake_acra_struct + inner_acra_struct + suffix_data.encode('ascii')
        correct_data = correct_data + suffix_data
        self.log(zone_id=zones[0][ZONE_ID],
                 data=data,
                 expected=fake_acra_struct+correct_data.encode('ascii'))
        row_id = get_random_id()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': data, 'raw_data': correct_data})
        zone = zones[0][ZONE_ID].encode('ascii')
        result = self.engine1.execute(
            sa.select([sa.cast(zone, BYTEA), test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertEqual(row['data'][fake_offset:],
                         safe_string(row['raw_data']).encode('utf-8'))
        self.assertEqual(row['data'][:fake_offset], fake_acra_struct[:fake_offset])
        self.assertEqual(row['empty'], b'')

        result = self.engine2.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(len(row['data'][fake_offset:]), len(row['raw_data'][fake_offset:]))
        self.assertEqual(row['empty'], b'')
        result = self.engine_raw.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'][fake_offset:].decode('ascii', errors='ignore'),
                            row['raw_data'])
        self.assertEqual(row['empty'], b'')


class EscapeFormatTest(HexFormatTest):
    ACRA_BYTEA = 'pgsql_escape_bytea'
    DB_BYTEA = 'escape'

    def checkSkip(self):
        if TEST_MYSQL:
            self.skipTest("useful only for postgresql")
        elif not TEST_WITH_TLS:
            self.skipTest("running tests only with TLS")


class ZoneEscapeFormatTest(ZoneHexFormatTest):
    ACRA_BYTEA = 'pgsql_escape_bytea'
    DB_BYTEA = 'escape'


class TestConnectionClosing(BaseTestCase):
    class mysql_closing(contextlib.closing):
        """
        extended contextlib.closing that add close() method that call close()
        method of wrapped object

        Need to wrap pymysql.connection with own __enter__/__exit__
        implementation that will return connection instead of cursor (as do
        pymysql.Connection.__enter__())
        """
        def close(self):
            logger.info('mysql_closing.close()')
            self.thing.close()

    def setUp(self):
        self.checkSkip()
        try:
            if not self.EXTERNAL_ACRA:
                self.acra = self.fork_acra(
                    tls_ocsp_from_cert='ignore',
                    tls_crl_from_cert='ignore',
                    tls_ocsp_url='',
                    tls_crl_url='',
                )
        except:
            self.tearDown()
            raise

    def get_connection(self):
        count = CONNECT_TRY_COUNT
        while True:
            try:
                if TEST_MYSQL:
                    return TestConnectionClosing.mysql_closing(
                        pymysql.connect(**get_connect_args(port=self.ACRASERVER_PORT)))
                else:
                    return TestConnectionClosing.mysql_closing(psycopg2.connect(
                        host=get_db_host(), **get_connect_args(port=self.ACRASERVER_PORT)))
            except:
                count -= 1
                if count == 0:
                    raise
                time.sleep(CONNECTION_FAIL_SLEEP)

    def tearDown(self):
        procs = []
        if not self.EXTERNAL_ACRA and hasattr(self, 'acra'):
            procs.append(self.acra)
        stop_process(procs)
        send_signal_by_process_name('acra-server', signal.SIGKILL)

    def getActiveConnectionCount(self, cursor):
        if TEST_MYSQL:
            query = "SHOW STATUS WHERE `variable_name` = 'Threads_connected';"
            cursor.execute(query)
            return int(cursor.fetchone()[1])
        else:
            cursor.execute('select count(*) from pg_stat_activity;')
            return int(cursor.fetchone()[0])

    def getConnectionLimit(self, connection=None):
        created_connection = False
        if connection is None:
            connection = self.get_connection()
            created_connection = True

        if TEST_MYSQL:
            query = "SHOW VARIABLES WHERE `variable_name` = 'max_connections';"
            with connection.cursor() as cursor:
                cursor.execute(query)
                return int(cursor.fetchone()[1])

        else:
            with TestConnectionClosing.mysql_closing(connection.cursor()) as cursor:
                try:
                    cursor.execute('select setting from pg_settings where name=\'max_connections\';')
                    pg_max_connections = int(cursor.fetchone()[0])
                    cursor.execute('select rolconnlimit from pg_roles where rolname = current_user;')
                    pg_rolconnlimit = int(cursor.fetchone()[0])
                    cursor.close()
                    if pg_rolconnlimit <= 0:
                        return pg_max_connections
                    return min(pg_max_connections, pg_rolconnlimit)
                except:
                    if created_connection:
                        connection.close()
                    raise

    def check_count(self, cursor, expected):
        # give a time to close connections via postgresql
        # because performance where tests will run not always constant,
        # we wait try_count times. in best case it will not need to sleep
        timeout = 3
        step = 0.1
        iterations = timeout / step
        for i in range(int(iterations)):
            try:
                self.assertEqual(self.getActiveConnectionCount(cursor), expected)
                break
            except AssertionError:
                if i == (iterations - 1):
                    raise
                # some wait for closing. chosen manually
                time.sleep(step)

    def checkConnectionLimit(self, connection_limit):
        connections = []
        try:
            exception = None
            try:
                for i in range(connection_limit):
                    connections.append(self.get_connection())
            except Exception as exc:
                exception = exc

            self.assertIsNotNone(exception)

            is_correct_exception_message = False
            if TEST_MYSQL:
                exception_type = pymysql.err.OperationalError
                correct_messages = [
                    'Too many connections'
                ]
                for message in correct_messages:
                    if exception.args[0] in [1203, 1040] and message in exception.args[1]:
                        is_correct_exception_message = True
                        break
            else:
                exception_type = psycopg2.OperationalError
                # exception doesn't has any related code, only text messages
                correct_messages = [
                    'FATAL:  too many connections for role',
                    'FATAL:  sorry, too many clients already',
                    'FATAL:  remaining connection slots are reserved for non-replication superuser connections'
                ]
                for message in correct_messages:
                    if message in exception.args[0]:
                        is_correct_exception_message = True
                        break

            self.assertIsInstance(exception, exception_type)
            self.assertTrue(is_correct_exception_message)
        except:
            for connection in connections:
                connection.close()
            raise
        return connections

    def testClosingConnectionsWithDB(self):
        with self.get_connection() as connection:
            connection.autocommit = True
            with TestConnectionClosing.mysql_closing(connection.cursor()) as cursor:
                current_connection_count = self.getActiveConnectionCount(cursor)

                with self.get_connection():
                    self.assertEqual(self.getActiveConnectionCount(cursor),
                                     current_connection_count+1)
                    connection_limit = self.getConnectionLimit(connection)

                    created_connections = self.checkConnectionLimit(
                        connection_limit)
                    for conn in created_connections:
                        conn.close()

                self.check_count(cursor, current_connection_count)

                # try create new connection
                with self.get_connection():
                    self.check_count(cursor, current_connection_count + 1)

                self.check_count(cursor, current_connection_count)


class BasePoisonRecordTest(AcraCatchLogsMixin, AcraTranslatorMixin, BaseTestCase):
    SHUTDOWN = True
    TEST_DATA_LOG = True
    DETECT_POISON_RECORDS = True

    def get_poison_record_data(self):
        return get_poison_record()

    def setUp(self):
        super(BasePoisonRecordTest, self).setUp()
        try:
            self.log(poison_key=True, data=get_poison_record())
        except:
            self.tearDown()
            raise

    def fork_acra(self, popen_kwargs: dict=None, **acra_kwargs: dict):
        args = {
            'poison_shutdown_enable': 'true' if self.SHUTDOWN else 'false',
            'poison_detect_enable': 'true' if self.DETECT_POISON_RECORDS else 'false',
            # use text format to simplify check some error messages in logs, for example code=XXX instead of '|XXX|' in
            # CEF format
            'logging_format': 'text',
        }

        if hasattr(self, 'poisonscript'):
            args['poison_run_script_file'] = self.poisonscript
        acra_kwargs.update(args)

        return super(BasePoisonRecordTest, self).fork_acra(popen_kwargs, **acra_kwargs)

    def fork_translator(self, translator_kwargs, popen_kwargs=None):
        args = {
            'poison_shutdown_enable': 'true' if self.SHUTDOWN else 'false',
            'poison_detect_enable': 'true' if self.DETECT_POISON_RECORDS else 'false',
            # use text format to simplify check some error messages in logs, for example code=XXX instead of '|XXX|' in
            # CEF format
            'logging_format': 'text',
        }

        if hasattr(self, 'poisonscript'):
            args['poison_run_script_file'] = self.poisonscript
        translator_kwargs.update(args)

        return super(BasePoisonRecordTest, self).fork_translator(translator_kwargs, popen_kwargs)

    def get_base_translator_args(self):
        return {
            'tls_ocsp_from_cert': 'ignore',
            'tls_crl_from_cert': 'ignore',
            'tls_key': abs_path(TEST_TLS_SERVER_KEY),
            'tls_cert': abs_path(TEST_TLS_SERVER_CERT),
            'tls_ca': TEST_TLS_CA,
            'tls_identifier_extractor_type': self.get_identifier_extractor_type(),
            'acratranslator_client_id_from_connection_enable': 'true',
        }


class KeystoreCacheOnStartMixin:
    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        temp_dir = tempfile.TemporaryDirectory()
        copy_tree(KEYS_FOLDER.name, temp_dir.name)

        acra_kwargs.update({
            'cache_keystore_on_start': 'true',
            'keys_dir': temp_dir.name,
        })

        process = super(KeystoreCacheOnStartMixin, self).fork_acra(
            popen_kwargs, **acra_kwargs)
        temp_dir.cleanup()
        return process


class TestPoisonRecordShutdown(BasePoisonRecordTest):
    SHUTDOWN = True

    def testShutdown(self):
        """fetch data from table by specifying row id

        this method works with ZoneMode ON and OFF because in both cases acra-server should find poison record
        on data decryption failure
        """
        row_id = get_random_id()
        data = self.get_poison_record_data()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': data, 'raw_data': 'poison_record'})
        with self.assertRaises(DatabaseError):
            result = self.engine1.execute(
                sa.select([test_table])
                .where(test_table.c.id == row_id))
            row = result.fetchone()
            if row['data'] == data:
                self.fail("unexpected response")
        log = self.read_log(self.acra)
        self.assertIn('code=101', log)
        self.assertIn('Detected poison record, exit', log)
        self.assertNotIn('executed code after os.Exit', log)

    def testShutdown2(self):
        """check working poison record callback on full select

        this method works with ZoneMode ON and OFF because in both cases acra-server should find poison record
        on data decryption failure
        """
        row_id = get_random_id()
        data = self.get_poison_record_data()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': data, 'raw_data': 'poison_record'})
        with self.assertRaises(DatabaseError):
            result = self.engine1.execute(
                sa.select([test_table]))
            rows = result.fetchall()
            for row in rows:
                if row['id'] == row_id and row['data'] == data:
                    self.fail("unexpected response")
        log = self.read_log(self.acra)
        self.assertIn('code=101', log)
        self.assertIn('Detected poison record, exit', log)
        self.assertNotIn('executed code after os.Exit', log)

    def testShutdown3(self):
        """check working poison record callback on full select inside another data

        this method works with ZoneMode ON and OFF because in both cases acra-server should find poison record
        on data decryption failure
        """
        row_id = get_random_id()
        poison_record = get_poison_record()
        begin_tag = poison_record[:4]
        # test with extra long begin tag
        data = os.urandom(100) + begin_tag + poison_record + os.urandom(100)
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': data, 'raw_data': 'poison_record'})
        with self.assertRaises(DatabaseError):
            result = self.engine1.execute(
                sa.select([test_table]))
            rows = result.fetchall()
            for row in rows:
                if row['id'] == row_id and row['data'] == data:
                    self.fail("unexpected response")
        log = self.read_log(self.acra)
        self.assertIn('code=101', log)
        self.assertIn('Detected poison record, exit', log)
        self.assertNotIn('executed code after os.Exit', log)

    def testShutdownWithExplicitZone(self):
        """check callback with select by id and specify zone id in select query

        This method works with ZoneMode ON and OFF because in both cases acra-server should find poison record
        on data decryption failure. Plus in ZoneMode OFF acra-server will ignore ZoneID
        """
        row_id = get_random_id()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': self.get_poison_record_data(), 'raw_data': 'poison_record'})
        with self.assertRaises(DatabaseError):
            zone = zones[0][ZONE_ID].encode('ascii')
            result = self.engine1.execute(
                sa.select([sa.cast(zone, BYTEA), test_table])
                    .where(test_table.c.id == row_id))
            print(result.fetchall())
        log = self.read_log(self.acra)
        self.assertIn('code=101', log)
        self.assertIn('Detected poison record, exit', log)
        self.assertNotIn('executed code after os.Exit', log)

    def testShutdownTranslatorHTTP(self):
        """check poison record decryption via acra-translator using HTTP v1 API

        This method works with ZoneMode ON and OFF because in both cases acra-translator should match poison record
        on data decryption failure
        """
        http_port = 3356
        http_connection_string = 'tcp://127.0.0.1:{}'.format(http_port)
        translator_kwargs = self.get_base_translator_args()
        translator_kwargs.update({
            'incoming_connection_http_string': http_connection_string,
        })

        data = self.get_poison_record_data()
        with ProcessContextManager(self.fork_translator(translator_kwargs)):
            with self.assertRaises(requests.exceptions.ConnectionError) as exc:
                response = self.http_decrypt_request(http_port, TLS_CERT_CLIENT_ID_1, None, data)
        self.assertEqual(exc.exception.args[0].args[0], 'Connection aborted.')

        # check that port not listening anymore
        with self.assertRaises(Exception) as exc:
            wait_connection(http_port, count=1, sleep=0)
        self.assertEqual(exc.exception.args[0], WAIT_CONNECTION_ERROR_MESSAGE)

    def testShutdownTranslatorgRPC(self):
        """check poison record decryption via acra-translator using gRPC API

        This method works with ZoneMode ON and OFF because in both cases acra-translator should match poison record
        on data decryption failure
        """
        grpc_port = 3357
        grpc_connection_string = 'tcp://127.0.0.1:{}'.format(grpc_port)
        translator_kwargs = self.get_base_translator_args()
        translator_kwargs.update({
            'incoming_connection_grpc_string': grpc_connection_string,
        })

        data = self.get_poison_record_data()

        with ProcessContextManager(self.fork_translator(translator_kwargs)):
            with self.assertRaises(grpc.RpcError) as exc:
                response = self.grpc_decrypt_request(grpc_port, TLS_CERT_CLIENT_ID_1, None, data,
                                                     raise_exception_on_failure=True)
        self.assertEqual(exc.exception.code(), grpc.StatusCode.UNAVAILABLE)

        # check that port not listening anymore
        with self.assertRaises(Exception) as exc:
            wait_connection(grpc_port, count=1, sleep=0)
        self.assertEqual(exc.exception.args[0], WAIT_CONNECTION_ERROR_MESSAGE)


class TestPoisonRecordShutdownWithAcraBlock(TestPoisonRecordShutdown):
    def get_poison_record_data(self):
        return get_poison_record_with_acrablock()


class TestPoisonRecordOffStatus(BasePoisonRecordTest):
    SHUTDOWN = True
    DETECT_POISON_RECORDS = False

    def testShutdown(self):
        """case with select by specifying row id, checks that acra-server doesn't initialize poison record detection
        and any callbacks, and returns data as is on decryption failure even if it's valid poison record

        Works with ZoneMode On/OFF
        """
        row_id = get_random_id()
        data = self.get_poison_record_data()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': data, 'raw_data': 'poison_record'})

        result = self.engine1.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        # AcraServer must return data as is
        if row['data'] != data:
            self.fail("unexpected response")

        log = self.read_log(self.acra)
        self.assertNotIn('Recognized poison record', log)
        self.assertNotIn('Turned on poison record detection', log)
        self.assertNotIn('code=101', log)

    def testShutdown2(self):
        """case with select full table, checks that acra-server doesn't initialize poison record detection
        and any callbacks, and returns data as is on decryption failure even if it's valid poison record

        Works with ZoneMode On/OFF
        """
        row_id = get_random_id()
        data = self.get_poison_record_data()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': data, 'raw_data': 'poison_record'})

        result = self.engine1.execute(
            sa.select([test_table]))
        rows = result.fetchall()
        for row in rows:
            # AcraServer must return data as is
            if row['id'] == row_id and row['data'] != data:
                self.fail("unexpected response")

        log = self.read_log(self.acra)
        self.assertNotIn('Recognized poison record', log)
        self.assertNotIn('Turned on poison record detection', log)
        self.assertNotIn('code=101', log)

    def testShutdown3(self):
        """case with select full table and inlined poison record, checks that acra-server doesn't initialize poison
        record detection and any callbacks, and returns data as is on decryption failure even if it's valid poison
        record

        Works with ZoneMode On/OFF
        """
        row_id = get_random_id()
        poison_record = self.get_poison_record_data()
        begin_tag = poison_record[:4]
        # test with extra long begin tag
        data = os.urandom(100) + begin_tag + poison_record + os.urandom(100)
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': data, 'raw_data': 'poison_record'})

        result = self.engine1.execute(
            sa.select([test_table]))
        rows = result.fetchall()
        for row in rows:
            # AcraServer must return data as is
            if row['id'] == row_id and row['data'] != data:
                self.fail("unexpected response")

        log = self.read_log(self.acra)
        self.assertNotIn('Recognized poison record', log)
        self.assertNotIn('Turned on poison record detection', log)
        self.assertNotIn('code=101', log)

    def testShutdownWithExplicitZone(self):
        """case with explicitly specified ZoneID in SELECT query, checks that acra-server doesn't initialize poison
        record detection and any callbacks, and returns data as is on decryption failure even if it's valid poison
        record

        Works with ZoneMode On/OFF
        """
        row_id = get_random_id()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': self.get_poison_record_data(), 'raw_data': 'poison_record'})
        zone = zones[0][ZONE_ID].encode('ascii')
        result = self.engine1.execute(
            sa.select([sa.cast(zone, BYTEA), test_table])
                .where(test_table.c.id == row_id))
        rows = result.fetchall()
        for zone, _, data, raw_data, _, _ in result:
            self.assertEqual(zone, zone)
            self.assertEqual(data, poison_record)

        log = self.read_log(self.acra)
        self.assertNotIn('Recognized poison record', log)
        self.assertNotIn('Turned on poison record detection', log)
        self.assertNotIn('code=101', log)

    def testShutdownTranslatorHTTP(self):
        """check poison record ignoring via acra-translator using HTTP v1 API, omitting initialization poison
        record detection and any callbacks, returning data as is on decryption failure even if it's valid poison
        record

        Works with ZoneMode On/OFF
        """
        http_port = 3356
        http_connection_string = 'tcp://127.0.0.1:{}'.format(http_port)
        with tempfile.NamedTemporaryFile('w+', encoding='utf-8') as log_file:
            translator_kwargs = self.get_base_translator_args()
            translator_kwargs.update({
                'incoming_connection_http_string': http_connection_string,
                'log_to_file': log_file.name,
            })

            data = self.get_poison_record_data()
            with ProcessContextManager(self.fork_translator(translator_kwargs)) as translator:
                response = self.http_decrypt_request(http_port, TLS_CERT_CLIENT_ID_1, None, data)
                self.assertEqual(response, b"Can't decrypt AcraStruct")

            with open(log_file.name, 'r') as f:
                log = f.read()
            self.assertNotIn('Recognized poison record', log)
            self.assertNotIn('Turned on poison record detection', log)
            self.assertNotIn('code=101', log)

    def testShutdownTranslatorgRPC(self):
        """check poison record ignoring via acra-translator using gRPC API, omitting initialization poison
            record detection and any callbacks, returning data as is on decryption failure even if it's valid poison
            record

            Works with ZoneMode On/OFF
            """
        grpc_port = 3357
        grpc_connection_string = 'tcp://127.0.0.1:{}'.format(grpc_port)
        with tempfile.NamedTemporaryFile('w+', encoding='utf-8') as log_file:
            translator_kwargs = self.get_base_translator_args()
            translator_kwargs.update({
                'incoming_connection_grpc_string': grpc_connection_string,
                'log_to_file': log_file.name,
            })

            data = self.get_poison_record_data()

            with ProcessContextManager(self.fork_translator(translator_kwargs)):
                with self.assertRaises(grpc.RpcError) as exc:
                    response = self.grpc_decrypt_request(grpc_port, TLS_CERT_CLIENT_ID_1, None, data,
                                                         raise_exception_on_failure=True)
                self.assertEqual(exc.exception.code(), grpc.StatusCode.UNKNOWN)
                self.assertEqual(exc.exception.details(), "can't decrypt data")
            with open(log_file.name, 'r') as f:
                log = f.read()
            self.assertNotIn('Recognized poison record', log)
            self.assertNotIn('Turned on poison record detection', log)
            self.assertNotIn('code=101', log)


class TestPoisonRecordOffStatusWithAcraBlock(TestPoisonRecordOffStatus):
    def get_poison_record_data(self):
        return get_poison_record_with_acrablock()


class TestShutdownPoisonRecordWithZone(TestPoisonRecordShutdown):
    ZONE = True
    WHOLECELL_MODE = False
    SHUTDOWN = True


class TestShutdownPoisonRecordWithZoneAcraBlock(TestShutdownPoisonRecordWithZone):
    def get_poison_record_data(self):
        return get_poison_record_with_acrablock()


class TestShutdownPoisonRecordWithZoneAcraBlockWithCachedKeystore(KeystoreCacheOnStartMixin, TestShutdownPoisonRecordWithZoneAcraBlock):
    def testShutdown3(self):
        pass


class TestShutdownPoisonRecordWithZoneOffStatus(TestPoisonRecordOffStatus):
    ZONE = True
    WHOLECELL_MODE = False
    SHUTDOWN = True
    DETECT_POISON_RECORDS = False


class TestShutdownPoisonRecordWithZoneOffStatusWithAcraBlock(TestShutdownPoisonRecordWithZoneOffStatus):
    def get_poison_record_data(self):
        return get_poison_record_with_acrablock()


class TestNoCheckPoisonRecord(BasePoisonRecordTest):
    WHOLECELL_MODE = False
    SHUTDOWN = False
    DEBUG_LOG = True
    DETECT_POISON_RECORDS = False

    def testNoDetect(self):
        row_id = get_random_id()
        poison_record = get_poison_record()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': poison_record, 'raw_data': 'poison_record'})
        result = self.engine1.execute(test_table.select())
        result.fetchall()
        log = self.read_log(self.acra)
        self.assertNotIn('Recognized poison record', log)
        self.assertNotIn('Turned on poison record detection', log)
        self.assertNotIn('code=101', log)
        result = self.engine1.execute(
            sa.select([test_table]))
        for _, data, raw_data, _, _ in result:
            self.assertEqual(poison_record, data)


class TestNoCheckPoisonRecordWithZone(TestNoCheckPoisonRecord):
    ZONE = True


class TestCheckLogPoisonRecord(BasePoisonRecordTest):
    SHUTDOWN = True
    DEBUG_LOG = True
    TEST_DATA_LOG = True

    def setUp(self):
        self.poison_script_file = NamedTemporaryFile('w')
        # u+rwx
        os.chmod(self.poison_script_file.name, stat.S_IRWXU)
        self.poison_script = self.poison_script_file.name
        super(TestCheckLogPoisonRecord, self).setUp()

    def tearDown(self):
        self.poison_script_file.close()
        super(TestCheckLogPoisonRecord, self).tearDown()

    def testDetect(self):
        row_id = get_random_id()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': get_poison_record(), 'raw_data': 'poison_record'})

        with self.assertRaises(DatabaseError):
            self.engine1.execute(test_table.select())

        log = self.read_log(self.acra)
        self.assertIn('Recognized poison record', log)
        self.assertIn('Turned on poison record detection', log)
        self.assertIn('code=101', log)


class TestKeyStorageClearing(BaseTestCase):
    def setUp(self):
        self.checkSkip()
        try:
            self.init_key_stores()
            if not self.EXTERNAL_ACRA:
                self.acra = self.fork_acra(
                    zonemode_enable='true',
                    http_api_enable='true',
                    tls_ocsp_from_cert='ignore',
                    tls_crl_from_cert='ignore',
                    tls_ocsp_url='',
                    tls_crl_url='',
                    keys_dir=self.server_keys_dir)

            args = get_connect_args(port=self.ACRASERVER_PORT, sslmode='require')
            args.update(get_tls_connection_args(TEST_TLS_CLIENT_KEY, TEST_TLS_CLIENT_CERT))
            self.engine1 = sa.create_engine(
                get_engine_connection_string(
                    self.get_acraserver_connection_string(),
                    DB_NAME),
                connect_args=args)

            self.engine_raw = sa.create_engine(
                '{}://{}:{}/{}'.format(DB_DRIVER, DB_HOST, DB_PORT, DB_NAME),
                connect_args=connect_args)

            self.engines = [self.engine1, self.engine_raw]

            metadata.create_all(self.engine_raw)
            self.engine_raw.execute('delete from test;')
        except:
            self.tearDown()
            raise

    def tearDown(self):
        try:
            self.engine_raw.execute('delete from test;')
        except:
            pass

        for engine in getattr(self, 'engines', []):
            engine.dispose()

        processes = []
        if not self.EXTERNAL_ACRA and hasattr(self, 'acra'):
            processes.append(self.acra)

        stop_process(processes)
        send_signal_by_process_name('acra-server', signal.SIGKILL)
        self.server_keystore.cleanup()

    def init_key_stores(self):
        self.server_keystore = tempfile.TemporaryDirectory()
        self.server_keys_dir = os.path.join(self.server_keystore.name, '.acrakeys')

        create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_CERT, keys_dir=self.server_keys_dir, only_storage=True)

    def test_clearing(self):
        # execute any query for loading key by acra
        result = self.engine1.execute(sa.select([1]).limit(1))
        result.fetchone()
        with urlopen('http://localhost:{}/resetKeyStorage'.format(self.ACRASERVER_PORT+1)) as response:
            self.assertEqual(response.status, 200)


class HashiCorpVaultMasterKeyLoaderMixin:
    DEFAULT_MOUNT_PATH = 'test_kv'
    secret_path = 'foo'

    def setUp(self):
        if not TEST_WITH_VAULT:
            self.skipTest("test with HashiCorp Vault ACRA_MASTER_KEY loader")

        if TEST_SSL_VAULT:
            self.vault_client = VaultClient(verify=TEST_VAULT_TLS_CA)
        else:
            self.vault_client = VaultClient()

        self.vault_client.enable_kv_secret_engine(mount_path=self.DEFAULT_MOUNT_PATH)
        self.vault_client.put_master_key_by_version(self.secret_path, VAULT_KV_ENGINE_VERSION, mount_point=self.DEFAULT_MOUNT_PATH)
        super().setUp()

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        args = self.vault_client.get_vault_cli_args(self.DEFAULT_MOUNT_PATH, self.secret_path)
        acra_kwargs.update(args)
        return self._fork_acra(acra_kwargs, popen_kwargs)

    def fork_translator(self, translator_kwargs, popen_kwargs=None):
        args = self.vault_client.get_vault_cli_args(self.DEFAULT_MOUNT_PATH,self.secret_path)
        translator_kwargs.update(args)
        return super().fork_translator(translator_kwargs, popen_kwargs)

    def read_rotation_public_key(self,  extra_kwargs: dict = None):
        args = self.vault_client.get_vault_cli_args(self.DEFAULT_MOUNT_PATH,self.secret_path)
        return super().read_rotation_public_key(extra_kwargs=args)

    def create_keypair(self, extra_kwargs: dict = None):
        args = self.vault_client.get_vault_cli_args(self.DEFAULT_MOUNT_PATH,self.secret_path)
        return super().create_keypair(extra_kwargs=args)

    def tearDown(self):
        super().tearDown()
        self.vault_client.disable_kv_secret_engine(mount_path=self.DEFAULT_MOUNT_PATH)


class TestKeyStoreMigration(BaseTestCase):
    """Test "acra-keys migrate" utility."""

    # We need to test different keystore formats so we can't touch
    # the global KEYS_FOLDER. We need to launch service instances
    # with particular keystore configuration. Ignore the usual
    # setup and teardown routines that start Acra services.

    def setUp(self):
        self.checkSkip()
        self.test_dir = tempfile.TemporaryDirectory()
        self.engine_raw = sa.create_engine(
            '{}://{}:{}/{}'.format(DB_DRIVER, DB_HOST, DB_PORT, DB_NAME),
            connect_args=get_connect_args(DB_PORT))
        metadata.create_all(self.engine_raw)
        self.engine_raw.execute(test_table.delete())
        self.master_keys = {}

    def tearDown(self):
        self.engine_raw.execute(test_table.delete())
        self.engine_raw.dispose()
        self.test_dir.cleanup()

    # Instead, use these methods according to individual test needs.

    def get_master_key(self, version):
        """Returns master key value for given version (base64-encoded)."""
        if version not in self.master_keys:
            temp_file = os.path.join(self.test_dir.name, 'master.key')

            subprocess.check_output([
                os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keymaker'), '--keystore={}'.format(version),
                '--generate_master_key={}'.format(temp_file)])

            with open(temp_file, 'rb') as f:
                master_key = b64encode(f.read()).decode('ascii')
                self.master_keys[version] = master_key

            os.remove(temp_file)

        return self.master_keys[version]


    def create_key_store(self, version):
        """Create new keystore of given version."""
        # Start with service transport keys and client storage keys.
        self.client_id = TLS_CERT_CLIENT_ID_1
        subprocess.check_call([
                os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keymaker'),
                '--generate_acrawriter_keys',
                '--client_id={}'.format(self.client_id),
                '--keys_output_dir={}'.format(self.current_key_store_path()),
                '--keys_public_output_dir={}'.format(self.current_key_store_path()),
                '--keystore={}'.format(version),
            ],
            env={ACRA_MASTER_KEY_VAR_NAME: self.get_master_key(version)},
            timeout=PROCESS_CALL_TIMEOUT)

        # Then add some zones that we're going to test with.
        zone_output = subprocess.check_output([
                os.path.join(BINARY_OUTPUT_FOLDER, 'acra-addzone'),
                '--keys_output_dir={}'.format(self.current_key_store_path()),
            ],
            env={ACRA_MASTER_KEY_VAR_NAME: self.get_master_key(version)},
            timeout=PROCESS_CALL_TIMEOUT)
        zone_config = json.loads(zone_output.decode('utf-8'))
        self.zone_id = zone_config[ZONE_ID]

        # Keep the current version around, we'll need it for migration.
        self.keystore_version = version

    def migrate_key_store(self, new_version):
        """Migrate keystore from current to given new version."""
        # Run the migration tool. New keystore is in a new directory.
        subprocess.check_call([
                os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'), 'migrate',
                '--src_keys_dir={}'.format(self.current_key_store_path()),
                '--src_keys_dir_public={}'.format(self.current_key_store_path()),
                '--src_keystore={}'.format(self.keystore_version),
                '--dst_keys_dir={}'.format(self.new_key_store_path()),
                '--dst_keys_dir_public={}'.format(self.new_key_store_path()),
                '--dst_keystore={}'.format(new_version),
            ],
            env={'SRC_ACRA_MASTER_KEY': self.get_master_key(self.keystore_version),
                 'DST_ACRA_MASTER_KEY': self.get_master_key(new_version)},
            timeout=PROCESS_CALL_TIMEOUT)

        # Finalize the migration, replacing old keystore with the new one.
        # We assume the services to be not running at this moment.
        os.rename(self.current_key_store_path(), self.old_key_store_path())
        os.rename(self.new_key_store_path(), self.current_key_store_path())
        self.keystore_version = new_version

    def change_key_store_path(self):
        """Change the absolute path of the keystore directory."""
        # Swap the whole testing directory for a new one.
        old_key_store_path = self.current_key_store_path()
        old_test_dir = self.test_dir
        new_test_dir = tempfile.TemporaryDirectory()
        self.test_dir = new_test_dir
        new_key_store_path = self.current_key_store_path()
        # Move the keystore to the new location.
        os.rename(old_key_store_path, new_key_store_path)
        # Remove the old, now unneeded directory.
        old_test_dir.cleanup()

    def start_services(self, zone_mode=False):
        """Start Acra services required for testing."""
        master_key = self.get_master_key(self.keystore_version)
        master_key_env = {ACRA_MASTER_KEY_VAR_NAME: master_key}

        self.acra_server = self.fork_acra(
            zonemode_enable='true' if zone_mode else 'false',
            keys_dir=self.current_key_store_path(),
            tls_ocsp_from_cert='ignore',
            tls_crl_from_cert='ignore',
            tls_ocsp_url='',
            tls_crl_url='',
            keystore_cache_size=-1,
            popen_kwargs={'env': master_key_env})

        args = get_connect_args(port=self.ACRASERVER_PORT, sslmode='require')
        args.update(get_tls_connection_args(TEST_TLS_CLIENT_KEY, TEST_TLS_CLIENT_CERT))
        self.engine = sa.create_engine(
            get_engine_connection_string(
                self.get_acraserver_connection_string(),
                DB_NAME),
            connect_args=args)

        # Remember whether we're running in zone mode. We need to know this
        # to store and retrieve the data correctly.
        self.zone_mode = zone_mode

    def stop_services(self):
        """Gracefully stop Acra services being tested."""
        self.engine.dispose()
        stop_process(self.acra_server)

    @contextlib.contextmanager
    def running_services(self, **kwargs):
        self.start_services(**kwargs)
        try:
            yield
        finally:
            self.stop_services()

    def insert_as_client(self, data):
        """Encrypt and insert data via AcraServer."""
        # It's too bothersome to thread through the master key setting.
        # Set it here and reset it back after reading the public key.
        new_master_key = self.get_master_key(self.keystore_version)
        old_master_key = os.environ[ACRA_MASTER_KEY_VAR_NAME]
        os.environ[ACRA_MASTER_KEY_VAR_NAME] = new_master_key

        # Encryption depends on whether we're using zones or not.
        if self.zone_mode:
            acra_struct = create_acrastruct(
                data.encode('ascii'),
                read_zone_public_key(
                    self.zone_id,
                    self.current_key_store_path()),
                context=self.zone_id.encode('ascii'))
        else:
            acra_struct = create_acrastruct(
                data.encode('ascii'),
                read_storage_public_key(
                    self.client_id,
                    self.current_key_store_path()))

        os.environ[ACRA_MASTER_KEY_VAR_NAME] = old_master_key

        row_id = get_random_id()
        self.engine.execute(test_table.insert(), {
            'id': row_id, 'data': acra_struct, 'raw_data': data,
        })
        return row_id

    def select_as_client(self, row_id):
        """Select decrypted data via AcraServer."""
        # If we're using zones, zone ID should precede the encrypted data.
        if self.zone_mode:
            cols = [sa.cast(self.zone_id.encode('ascii'), BYTEA),
                    test_table.c.data, test_table.c.raw_data]
        else:
            cols = [test_table.c.data, test_table.c.raw_data]

        rows = self.engine.execute(
            sa.select(cols).where(test_table.c.id == row_id))
        return rows.first()

    def select_directly(self, row_id):
        """Select raw data directly from database."""
        rows = self.engine_raw.execute(
            sa.select([test_table.c.data]).where(test_table.c.id == row_id))
        return rows.first()

    def current_key_store_path(self):
        return os.path.join(self.test_dir.name, '.acrakeys')

    def new_key_store_path(self):
        return os.path.join(self.test_dir.name, '.acrakeys.new')

    def old_key_store_path(self):
        return os.path.join(self.test_dir.name, '.acrakeys.old')

    # Now we can proceed with the tests...

    def test_migrate_v1_to_v2(self):
        """Verify v1 -> v2 keystore migration."""
        data_1 = get_pregenerated_random_data()
        data_2 = get_pregenerated_random_data()

        self.create_key_store('v1')

        # Try saving some data with default zone
        with self.running_services():
            row_id_1 = self.insert_as_client(data_1)

            # Check that we're able to put and get data via AcraServer.
            selected = self.select_as_client(row_id_1)
            self.assertEquals(selected['data'], data_1.encode('ascii'))
            self.assertEquals(selected['raw_data'], data_1)

            # Get encrypted data. It should really be encrypted.
            encrypted_1 = self.select_directly(row_id_1)
            self.assertNotEquals(encrypted_1['data'], data_1.encode('ascii'))

        # Now do the same with a specific zone
        with self.running_services(zone_mode=True):
            row_id_1_zoned = self.insert_as_client(data_1)

            # Check that we're able to put and get data via AcraServer.
            selected = self.select_as_client(row_id_1_zoned)
            self.assertEquals(selected['data'], data_1.encode('ascii'))
            self.assertEquals(selected['raw_data'], data_1)

            # Get encrypted data. It should really be encrypted.
            encrypted_1_zoned = self.select_directly(row_id_1_zoned)
            self.assertNotEquals(encrypted_1_zoned['data'], data_1.encode('ascii'))
            # Also, it should be different from the default-zoned data.
            self.assertNotEquals(encrypted_1_zoned['data'], encrypted_1['data'])

        self.migrate_key_store('v2')

        # After we have migrated the keys, check the setup again.
        with self.running_services():
            # Old data should still be there, accessible via AcraServer.
            selected = self.select_as_client(row_id_1)
            self.assertEquals(selected['data'], data_1.encode('ascii'))
            self.assertEquals(selected['raw_data'], data_1)

            # Key migration does not change encrypted data.
            encrypted_1_migrated = self.select_directly(row_id_1)
            self.assertEquals(encrypted_1_migrated['data'],
                              encrypted_1['data'])

            # We're able to put some new data into the table and get it back.
            row_id_2 = self.insert_as_client(data_2)
            selected = self.select_as_client(row_id_2)
            self.assertEquals(selected['data'], data_2.encode('ascii'))
            self.assertEquals(selected['raw_data'], data_2)

        # And again, this time with zones.
        with self.running_services(zone_mode=True):
            # Old data should still be there, accessible via AcraServer.
            selected = self.select_as_client(row_id_1_zoned)
            self.assertEquals(selected['data'], data_1.encode('ascii'))
            self.assertEquals(selected['raw_data'], data_1)

            # Key migration does not change encrypted data.
            encrypted_1_zoned_migrated = self.select_directly(row_id_1_zoned)
            self.assertEquals(encrypted_1_zoned_migrated['data'],
                              encrypted_1_zoned['data'])

            # We're able to put some new data into the table and get it back.
            row_id_2_zoned = self.insert_as_client(data_2)
            selected = self.select_as_client(row_id_2_zoned)
            self.assertEquals(selected['data'], data_2.encode('ascii'))
            self.assertEquals(selected['raw_data'], data_2)

    def test_moved_key_store(self):
        """Verify that keystore can be moved to a different absolute path."""
        self.create_key_store(KEYSTORE_VERSION)

        # Save some data, do a sanity check.
        data = get_pregenerated_random_data()
        with self.running_services():
            row_id = self.insert_as_client(data)
            selected = self.select_as_client(row_id)
            self.assertEquals(selected['data'], data.encode('ascii'))

        # Move the keystore to a different (still temporary) location.
        self.change_key_store_path()

        # Check that keystore path is not included into encryption context.
        # We should still be able to access the data with the same keystore
        # but located at different path.
        with self.running_services():
            selected = self.select_as_client(row_id)
            self.assertEquals(selected['data'], data.encode('ascii'))


class RedisMixin:
    TEST_REDIS_KEYS_DB = 0
    TEST_REDIS_TOKEN_DB = 1

    def checkSkip(self):
        super().checkSkip()
        if not TEST_WITH_REDIS:
            self.skipTest("test only with Redis")
        elif not TEST_WITH_TLS:
            self.skipTest("running tests only with TLS")

    def setUp(self):
        self.redis_keys_client = redis.Redis(host='localhost', port=6379, db=self.TEST_REDIS_KEYS_DB)
        self.redis_tokens_client = redis.Redis(host='localhost', port=6379, db=self.TEST_REDIS_TOKEN_DB)
        super().setUp()

    def tearDown(self):
        self.redis_keys_client.flushall()
        self.redis_tokens_client.flushall()
        super().tearDown()


class TestAcraKeysWithZoneIDGeneration(unittest.TestCase):

    def setUp(self):
        self.master_key = get_master_key()
        self.zone_dir = tempfile.TemporaryDirectory()

    def test_rotate_symmetric_zone_key(self):
        zone = json.loads(subprocess.check_output(
            [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-addzone'), '--keys_output_dir={}'.format(self.zone_dir.name)],
            cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT).decode('utf-8'))

        subprocess.check_call([
            os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'),
            'generate',
            '--zone_symmetric_key',
            '--keys_dir={}'.format(self.zone_dir.name),
            '--keys_dir_public={}'.format(self.zone_dir.name),
            '--zone_id={}'.format(zone['id'])
        ],
            env={ACRA_MASTER_KEY_VAR_NAME: self.master_key},
            timeout=PROCESS_CALL_TIMEOUT)
        path = '{}/{}_zone_sym.old'.format(self.zone_dir.name, zone['id'])
        self.assertTrue(len(os.listdir(path)) != 0)


class TestAcraKeysWithClientIDGeneration(unittest.TestCase):
    def setUp(self):
        self.master_key = get_master_key()
        self.dir_with_distinguished_name_client_id = tempfile.TemporaryDirectory()
        self.dir_with_serial_number_client_id = tempfile.TemporaryDirectory()

        self.create_key_store_with_client_id_from_cert(TLS_CLIENT_ID_SOURCE_DN, self.dir_with_distinguished_name_client_id.name)
        self.create_key_store_with_client_id_from_cert(TLS_CLIENT_ID_SOURCE_SERIAL, self.dir_with_serial_number_client_id.name)

    def test_generate_client_id_from_distinguished_name(self):
        readKey = self.read_key_by_client_id(TLS_CLIENT_ID_SOURCE_DN, self.dir_with_distinguished_name_client_id.name)
        self.assertTrue(readKey)

    def test_non_client_id_keys_generation(self):
        subprocess.check_call([
            os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'),
            'generate',
            '--audit_log_symmetric_key',
            '--poison_record_keys',
            '--keys_dir={}'.format(self.dir_with_distinguished_name_client_id.name),
            '--keys_dir_public={}'.format(self.dir_with_distinguished_name_client_id.name),
            '--keystore={}'.format(KEYSTORE_VERSION),
        ],
            env={ACRA_MASTER_KEY_VAR_NAME: self.master_key},
            timeout=PROCESS_CALL_TIMEOUT)

    def test_keys_generation_without_client_id(self):
        with self.assertRaises(subprocess.CalledProcessError) as exc:
            subprocess.check_output([
                os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'),
                'generate',
                '--keys_dir={}'.format(self.dir_with_distinguished_name_client_id.name),
                '--keys_dir_public={}'.format(self.dir_with_distinguished_name_client_id.name),
                '--keystore={}'.format(KEYSTORE_VERSION),
            ],
                env={ACRA_MASTER_KEY_VAR_NAME: self.master_key},
                stderr=subprocess.STDOUT)
        self.assertIn("--client_id or --tls_cert is required to generate keys".lower(), exc.exception.output.decode('utf8').lower())
        self.assertEqual(exc.exception.returncode, 1)

        with self.assertRaises(subprocess.CalledProcessError) as exc:
            subprocess.check_output([
                os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'),
                'generate',
                "--client_id='test'",
                '--keys_dir={}'.format(self.dir_with_distinguished_name_client_id.name),
                '--keys_dir_public={}'.format(self.dir_with_distinguished_name_client_id.name),
                '--keystore={}'.format(KEYSTORE_VERSION),
            ],
                env={ACRA_MASTER_KEY_VAR_NAME: self.master_key},
                stderr=subprocess.STDOUT)
        self.assertIn("Invalid client ID".lower(), exc.exception.output.decode('utf8').lower())
        self.assertEqual(exc.exception.returncode, 1)

    def test_read_keys_symmetric(self):
        subprocess.check_call([
            os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'),
            'generate',
            '--client_id={}'.format("testclientid"),
            '--client_storage_symmetric_key',
            '--keys_dir={}'.format(self.dir_with_distinguished_name_client_id.name),
            '--keys_dir_public={}'.format(self.dir_with_distinguished_name_client_id.name),
            '--keystore={}'.format(KEYSTORE_VERSION),
        ],
            env={ACRA_MASTER_KEY_VAR_NAME: self.master_key},
            timeout=PROCESS_CALL_TIMEOUT)

        subprocess.check_call([
            os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'),
            'read',
            '--keys_dir={}'.format(self.dir_with_distinguished_name_client_id.name),
            '--keys_dir_public={}'.format(self.dir_with_distinguished_name_client_id.name),
            'client/testclientid/symmetric'
        ],
            env={ACRA_MASTER_KEY_VAR_NAME: self.master_key},
            timeout=PROCESS_CALL_TIMEOUT)

    def test_read_keys_symmetric_zone(self):
        zone = json.loads(subprocess.check_output(
            [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-addzone'), '--keys_output_dir={}'.format(self.dir_with_distinguished_name_client_id.name)],
            cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT).decode('utf-8'))

        subprocess.check_call([
            os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'),
            'read',
            '--keys_dir={}'.format(self.dir_with_distinguished_name_client_id.name),
            '--keys_dir_public={}'.format(self.dir_with_distinguished_name_client_id.name),
            'zone/{}/symmetric'.format(zone['id'])
        ],
            env={ACRA_MASTER_KEY_VAR_NAME: self.master_key},
            timeout=PROCESS_CALL_TIMEOUT)


    def test_generate_client_id_from_serial_number(self):
        readKey = self.read_key_by_client_id(TLS_CLIENT_ID_SOURCE_SERIAL, self.dir_with_serial_number_client_id.name)
        self.assertTrue(readKey)

    def read_key_by_client_id(self, extractor, dir_name):
        cmd_output = json.loads(subprocess.check_output([
            os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'),
            'extract-client-id',
            '--tls_identifier_extractor_type={}'.format(extractor),
            '--tls_cert={}'.format(TEST_TLS_SERVER_CERT),
            '--print_json'
        ],
            cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT).decode('utf-8'))

        client_id = cmd_output['client_id']
        readKey = subprocess.check_output([
            os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'),
            'read',
            '--keys_dir={}'.format(dir_name),
            '--keys_dir_public={}'.format(dir_name),
            '--public',
            'client/{}/storage'.format(client_id),
        ],
            cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT)
        return readKey

    def create_key_store_with_client_id_from_cert(self, extractor, dir_name):
        """Create new keystore of given version using acra-keys tool."""
        subprocess.check_call([
            os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'),
            'generate',
            '--tls_cert={}'.format(TEST_TLS_SERVER_CERT),
            '--tls_identifier_extractor_type={}'.format(extractor),
            '--keys_dir={}'.format(dir_name),
            '--keys_dir_public={}'.format(dir_name),
            '--keystore={}'.format(KEYSTORE_VERSION),
        ],
            env={ACRA_MASTER_KEY_VAR_NAME: self.master_key},
            timeout=PROCESS_CALL_TIMEOUT)


class TestAcraKeysWithRedis(RedisMixin, unittest.TestCase):

    def setUp(self):
        self.checkSkip()
        super().setUp()

    def checkSkip(self):
        if not TEST_WITH_REDIS:
            self.skipTest("test only with Redis")

    def test_read_command_keystore(self):
        master_key = get_master_key()
        client_id = 'keypair1'

        subprocess.check_call(
            [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keymaker'),
             '--client_id={}'.format(client_id),
             '--generate_acrawriter_keys',
             '--generate_symmetric_storage_key',
             '--redis_host_port=localhost:6379',
             '--keystore={}'.format(KEYSTORE_VERSION)
             ],
            env={ACRA_MASTER_KEY_VAR_NAME: master_key},
            timeout=PROCESS_CALL_TIMEOUT)

        subprocess.check_call([
            os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'),
            'read',
            '--public',
            '--redis_host_port=localhost:6379',
            'client/keypair1/storage'
        ],
            env={ACRA_MASTER_KEY_VAR_NAME: master_key},
            timeout=PROCESS_CALL_TIMEOUT)

        subprocess.check_call([
            os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'),
            'read',
            '--redis_host_port=localhost:6379',
            'client/keypair1/symmetric'
        ],
            env={ACRA_MASTER_KEY_VAR_NAME: master_key},
            timeout=PROCESS_CALL_TIMEOUT)

        subprocess.check_call([
            os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'),
            'read',
            '--private',
            '--redis_host_port=localhost:6379',
            'client/keypair1/storage'
        ],
            env={ACRA_MASTER_KEY_VAR_NAME: master_key},
            timeout=PROCESS_CALL_TIMEOUT)


class TestPostgreSQLParseQueryErrorSkipExit(AcraCatchLogsMixin, BaseTestCase):
    """By default AcraServer skip any errors connected SQL parse queries failures.
        It can be changed by --sql_parse_error_exit=true cmd param."""

    def checkSkip(self):
        if not TEST_POSTGRESQL:
            self.skipTest("Only for postgresql")
        super().checkSkip()

    def executePreparedStatement(self, query):
        return AsyncpgExecutor(ConnectionArgs(
            host=get_db_host(), port=self.ACRASERVER_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_USER_PASSWORD,
            format=AsyncpgExecutor.BinaryFormat,
            ssl_ca=TEST_TLS_CA,
            ssl_key=TEST_TLS_CLIENT_KEY,
            ssl_cert=TEST_TLS_CLIENT_CERT
        )).execute_prepared_statement(query=query)

    def read_public_key(self,  extra_kwargs: dict = None):
        return read_storage_public_key(TLS_CERT_CLIENT_ID_1, KEYS_FOLDER.name, extra_kwargs=extra_kwargs)

    def insert_random_data(self):
        row_id = get_random_id()
        data = get_pregenerated_random_data()
        public_key = self.read_public_key()
        acra_struct = create_acrastruct(data.encode('ascii'), public_key)
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': acra_struct, 'raw_data': data})
        return row_id, data

    def test_skip_error(self):
        # First, let's put some test data into the table.
        row_id_1, raw_data_1 = self.insert_random_data()

        query = 'WITH test_with AS (SELECT 1) SELECT * FROM test'
        # Request should be successful.
        # It should return encrypted data because of parse skipping.
        result = self.executePreparedStatement(query=query)
        row = result[0]
        self.assertEqual(row['id'], row_id_1)
        self.assertEqual(row['data'], raw_data_1.encode('utf-8'))
        self.assertEqual(row['empty'], b'')
        self.assertIn("ignoring error of non parsed sql statement", self.read_log(self.acra))


class TestPostgreSQLParseQueryErrorExit(AcraCatchLogsMixin, BaseTestCase):

    def checkSkip(self):
        if not TEST_POSTGRESQL:
            self.skipTest("Only for postgresql")
        super().checkSkip()

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        acra_kwargs['sql_parse_on_error_exit_enable'] = 'true'
        return super(TestPostgreSQLParseQueryErrorExit, self).fork_acra(popen_kwargs, **acra_kwargs)

    def executePreparedStatement(self, query):
        return AsyncpgExecutor(ConnectionArgs(
            host=get_db_host(), port=self.ACRASERVER_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_USER_PASSWORD,
            ssl_ca=TEST_TLS_CA,
            ssl_key=TEST_TLS_CLIENT_KEY,
            ssl_cert=TEST_TLS_CLIENT_CERT
        )).execute_prepared_statement(query=query)

    def test_exit_on_parse_error(self):
        query = 'WITH test_with AS (SELECT 1) SELECT * FROM test'
        try:
            self.executePreparedStatement(query=query)
        except asyncpg.exceptions.ConnectionDoesNotExistError:
            self.assertIn("Can't parse SQL from Parse packet", self.read_log(self.acra))
        pass


class TestKeyRotation(BaseTestCase):
    """Verify key rotation without data reencryption."""
    # TODO(ilammy, 2020-03-13): test with rotated zone keys as well
    # That is, as soon as it is possible to rotate them (T1581)

    def read_rotation_public_key(self,  extra_kwargs: dict = None):
        return read_storage_public_key(TLS_CERT_CLIENT_ID_1, KEYS_FOLDER.name, extra_kwargs=extra_kwargs)

    def create_keypair(self, extra_kwargs: dict = None):
        create_client_keypair(TLS_CERT_CLIENT_ID_1, only_storage=True, extra_kwargs=extra_kwargs)

    def test_read_after_rotation(self):
        """Verify that AcraServer can decrypt data with old keys."""

        def insert_random_data():
            row_id = get_random_id()
            data = get_pregenerated_random_data()
            public_key = self.read_rotation_public_key()
            acra_struct = create_acrastruct(data.encode('ascii'), public_key)
            self.engine1.execute(
                test_table.insert(),
                {'id': row_id, 'data': acra_struct, 'raw_data': data})
            return row_id, data

        # First, let's put some test data into the table.
        row_id_1, raw_data_1 = insert_random_data()

        # After that rotate the storage key for the client,
        # but don't touch the encrypted data.
        self.create_keypair()
        # Insert some more data encrypted with the new key.
        row_id_2, raw_data_2 = insert_random_data()

        # It should return expected decrypted data.
        result = self.engine1.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id_1))
        row = result.fetchone()
        self.assertEqual(row['data'], raw_data_1.encode('utf-8'))
        self.assertEqual(row['empty'], b'')

        result = self.engine1.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id_2))
        row = result.fetchone()
        self.assertEqual(row['data'], raw_data_2.encode('utf-8'))
        self.assertEqual(row['empty'], b'')


class TestAcraRollback(BaseTestCase):
    DATA_COUNT = 5

    def checkSkip(self):
        super(TestAcraRollback, self).checkSkip()
        go_version = get_go_version()
        GREATER, EQUAL, LESS = (1, 0, -1)
        if semver.compare(go_version, ACRAROLLBACK_MIN_VERSION) == LESS:
            self.skipTest("not supported go version")

    def setUp(self):
        self.checkSkip()
        self.engine_raw = sa.create_engine(
            '{}://{}:{}/{}'.format(DB_DRIVER, DB_HOST, DB_PORT,
                                   DB_NAME),
            connect_args=connect_args)
        metadata.create_all(self.engine_raw)

        self.output_filename = 'acra-rollback_output.txt'
        acrarollback_output_table.create(self.engine_raw, checkfirst=True)
        if TEST_WITH_TLS:
            self.sslmode='require'
        else:
            self.sslmode='disable'
        if TEST_MYSQL:
            # https://github.com/go-sql-driver/mysql/
            connection_string = "{user}:{password}@tcp({host}:{port})/{dbname}".format(
                user=DB_USER, password=DB_USER_PASSWORD, dbname=DB_NAME,
                port=DB_PORT, host=DB_HOST
            )

            # https://github.com/ziutek/mymysql
            # connection_string = "tcp:{host}:{port}*{dbname}/{user}/{password}".format(
            #     user=DB_USER, password=DB_USER_PASSWORD, dbname=DB_NAME,
            #     port=DB_PORT, host=DB_HOST
            # )
        else:
            connection_string = (
                'dbname={dbname} user={user} '
                'sslmode={sslmode} password={password} host={host} '
                'port={port}').format(
                     sslmode=self.sslmode, dbname=DB_NAME,
                     user=DB_USER, port=DB_PORT,
                     password=DB_USER_PASSWORD, host=DB_HOST
            )

        if TEST_MYSQL:
            self.placeholder = "?"
            DB_ARGS = ['--mysql_enable']
        else:
            self.placeholder = "$1"
            DB_ARGS = ['--postgresql_enable']

        self.default_acrarollback_args = [
            '--client_id=keypair1',
             '--connection_string={}'.format(connection_string),
             '--output_file={}'.format(self.output_filename),
            '--keys_dir={}'.format(KEYS_FOLDER.name),
        ] + DB_ARGS

    def tearDown(self):
        try:
            self.engine_raw.execute(acrarollback_output_table.delete())
            self.engine_raw.execute(test_table.delete())
        except Exception as exc:
            print(exc)
        self.engine_raw.dispose()
        if os.path.exists(self.output_filename):
            os.remove(self.output_filename)

    def run_acrarollback(self, extra_args):
        args = [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-rollback')] + self.default_acrarollback_args + extra_args
        try:
            subprocess.check_call(
                args, cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT)
        except subprocess.CalledProcessError as exc:
            if exc.stderr:
                print(exc.stderr, file=sys.stderr)
            else:
                print(exc.stdout, file=sys.stdout)
            raise

    def test_without_zone_to_file(self):
        server_public1 = read_storage_public_key(TLS_CERT_CLIENT_ID_1, KEYS_FOLDER.name)

        rows = []
        for _ in range(self.DATA_COUNT):
            data = get_pregenerated_random_data()
            row = {
                'raw_data': data,
                'data': create_acrastruct(data.encode('ascii'), server_public1),
                'id': get_random_id()
            }
            rows.append(row)
        self.engine_raw.execute(test_table.insert(), rows)
        args = [
            '--select=select data from {};'.format(test_table.name),
            '--insert=insert into {} values({});'.format(
                 acrarollback_output_table.name, self.placeholder)
        ]
        self.run_acrarollback(args)

        # execute file
        with open(self.output_filename, 'r') as f:
            for line in f:
                self.engine_raw.execute(line)

        source_data = set([i['raw_data'].encode('ascii') for i in rows])
        result = self.engine_raw.execute(acrarollback_output_table.select())
        result = result.fetchall()
        for data in result:
            self.assertIn(data[0], source_data)

    def test_with_zone_to_file(self):
        zone_public = b64decode(zones[0][ZONE_PUBLIC_KEY].encode('ascii'))
        rows = []
        for _ in range(self.DATA_COUNT):
            data = get_pregenerated_random_data()
            row = {
                'raw_data': data,
                'data': create_acrastruct(
                    data.encode('ascii'), zone_public,
                    context=zones[0][ZONE_ID].encode('ascii')),
                'id': get_random_id()
            }
            rows.append(row)
        self.engine_raw.execute(test_table.insert(), rows)
        if TEST_MYSQL:
            select_query = '--select=select \'{id}\', data from {table};'.format(
                 id=zones[0][ZONE_ID], table=test_table.name)
        else:
            select_query = '--select=select \'{id}\'::bytea, data from {table};'.format(
                 id=zones[0][ZONE_ID], table=test_table.name)
        args = [
             select_query,
             '--zonemode_enable=true',
             '--insert=insert into {} values({});'.format(
                 acrarollback_output_table.name, self.placeholder)
        ]
        self.run_acrarollback(args)

        # execute file
        with open(self.output_filename, 'r') as f:
            for line in f:
                self.engine_raw.execute(line)

        source_data = set([i['raw_data'].encode('ascii') for i in rows])
        result = self.engine_raw.execute(acrarollback_output_table.select())
        result = result.fetchall()
        for data in result:
            self.assertIn(data[0], source_data)

    def test_without_zone_execute(self):
        server_public1 = read_storage_public_key(TLS_CERT_CLIENT_ID_1, KEYS_FOLDER.name)

        rows = []
        for _ in range(self.DATA_COUNT):
            data = get_pregenerated_random_data()
            row = {
                'raw_data': data,
                'data': create_acrastruct(data.encode('ascii'), server_public1),
                'id': get_random_id()
            }
            rows.append(row)
        self.engine_raw.execute(test_table.insert(), rows)

        args = [
            '--execute=true',
            '--select=select data from {};'.format(test_table.name),
            '--insert=insert into {} values({});'.format(
                acrarollback_output_table.name, self.placeholder)
        ]
        self.run_acrarollback(args)

        source_data = set([i['raw_data'].encode('ascii') for i in rows])
        result = self.engine_raw.execute(acrarollback_output_table.select())
        result = result.fetchall()
        for data in result:
            self.assertIn(data[0], source_data)

    def test_with_zone_execute(self):
        zone_public = b64decode(zones[0][ZONE_PUBLIC_KEY].encode('ascii'))
        rows = []
        for _ in range(self.DATA_COUNT):
            data = get_pregenerated_random_data()
            row = {
                'raw_data': data,
                'data': create_acrastruct(
                    data.encode('ascii'), zone_public,
                    context=zones[0][ZONE_ID].encode('ascii')),
                'id': get_random_id()
            }
            rows.append(row)
        self.engine_raw.execute(test_table.insert(), rows)

        if TEST_MYSQL:
            select_query = '--select=select \'{id}\', data from {table};'.format(
                 id=zones[0][ZONE_ID], table=test_table.name)
        else:
            select_query = '--select=select \'{id}\'::bytea, data from {table};'.format(
                 id=zones[0][ZONE_ID], table=test_table.name)
        args = [
            '--execute=true',
            select_query,
            '--zonemode_enable=true',
            '--insert=insert into {} values({});'.format(
                acrarollback_output_table.name, self.placeholder)
        ]
        self.run_acrarollback(args)

        source_data = set([i['raw_data'].encode('ascii') for i in rows])
        result = self.engine_raw.execute(acrarollback_output_table.select())
        result = result.fetchall()
        for data in result:
            self.assertIn(data[0], source_data)

    def test_without_placeholder(self):
        args = [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-rollback'),
            '--execute=true',
            '--select=select data from {};'.format(test_table.name),
            '--insert=query without placeholders;',
            '--postgresql_enable',
            '--keys_dir={}'.format(KEYS_FOLDER.name),
        ]

        log_file = tempfile.NamedTemporaryFile('w+', encoding='utf-8')
        popen_args = {
            'stderr': subprocess.PIPE,
            'stdout': subprocess.PIPE,
            'close_fds': True
        }
        process = subprocess.Popen(args, **popen_args)
        _, err = process.communicate(timeout=5)
        stop_process(process)

        self.assertIn(b"SQL INSERT statement doesn't contain any placeholders", err)

    def test_with_rotated_keys(self):
        # TODO(ilammy, 2020-03-13): test with rotated zone keys as well
        # That is, as soon as it is possible to rotate them (T1581)

        def insert_random_data():
            rows = []
            public_key = read_storage_public_key(TLS_CERT_CLIENT_ID_1, KEYS_FOLDER.name)
            for _ in range(self.DATA_COUNT):
                data = get_pregenerated_random_data()
                row = {
                    'raw_data': data,
                    'data': create_acrastruct(data.encode('ascii'), public_key),
                    'id': get_random_id()
                }
                rows.append(row)
            self.engine_raw.execute(test_table.insert(), rows)
            return rows

        # Insert some encrypted test data into the table
        rows = insert_random_data()

        # Rotate storage keys for 'keypair1'
        create_client_keypair('keypair1', only_storage=True)

        # Insert some more data encrypted with new key
        rows = rows + insert_random_data()

        # Run acra-rollback for the test table
        self.run_acrarollback([
            '--select=select data from {};'.format(test_table.name),
            '--insert=insert into {} values({});'.format(
                acrarollback_output_table.name, self.placeholder)
        ])

        # Rollback should successfully use previous keys to decrypt data
        source_data = set([i['raw_data'].encode('ascii') for i in rows])
        result = self.engine_raw.execute(acrarollback_output_table.select())
        result = result.fetchall()
        for data in result:
            self.assertIn(data[0], source_data)


class TestAcraKeyMakers(unittest.TestCase):
    def test_only_alpha_client_id(self):
        # call with directory separator in key name
        self.assertEqual(create_client_keypair(POISON_KEY_PATH), 1)


class SSLPostgresqlMixin(AcraCatchLogsMixin):
    ACRASERVER2_PORT = BaseTestCase.ACRASERVER_PORT + 1000
    ACRASERVER2_PROMETHEUS_PORT = BaseTestCase.ACRASERVER_PROMETHEUS_PORT + 1000
    DEBUG_LOG = True

    def with_tls(self):
        return False

    def get_acraserver_connection_string(self, port=None):
        return get_tcp_connection_string(port if port else self.ACRASERVER_PORT)

    def wait_acraserver_connection(self, *args, **kwargs):
        wait_connection(self.ACRASERVER_PORT)

    def checkSkip(self):
        if not (TEST_WITH_TLS and TEST_POSTGRESQL):
            self.skipTest("running tests without TLS")

    def get_ssl_engine(self):
        return sa.create_engine(
                get_postgresql_tcp_connection_string(self.ACRASERVER2_PORT, DB_NAME),
                connect_args=get_connect_args(port=self.ACRASERVER2_PORT, sslmode='require'))

    def testConnectionCloseOnTls(self):
        engine = self.get_ssl_engine()
        try:
            with self.assertRaises(sa.exc.OperationalError):
                with engine.connect():
                    pass
            self.log_files[self.acra2].flush()
            self.assertIn('tls: no certificates configured', self.read_log(self.acra2))
        finally:
            engine.dispose()

    def setUp(self):
        self.checkSkip()
        """connect directly to acra, use sslmode=require in connections and tcp protocol on acra side
        because postgresql support tls only over tcp
        """
        try:
            if not self.EXTERNAL_ACRA:
                self.acra = self.fork_acra(
                    tls_key=abs_path(TEST_TLS_SERVER_KEY),
                    tls_cert=abs_path(TEST_TLS_SERVER_CERT),
                    tls_ca=TEST_TLS_CA,
                    client_id=TLS_CERT_CLIENT_ID_1)
                # create second acra without settings for tls to check that
                # connection will be closed on tls handshake
                self.acra2 = self.fork_acra(
                    client_id=TLS_CERT_CLIENT_ID_1,
                    incoming_connection_api_string=self.get_acraserver_api_connection_string(port=self.ACRASERVER2_PORT+5),
                    incoming_connection_port=self.ACRASERVER2_PORT,
                    incoming_connection_prometheus_metrics_string=self.get_prometheus_address(self.ACRASERVER2_PROMETHEUS_PORT))
            self.engine1 = sa.create_engine(
                get_postgresql_tcp_connection_string(self.ACRASERVER_PORT, DB_NAME), connect_args=get_connect_args(port=self.ACRASERVER_PORT))
            self.engine_raw = sa.create_engine(
                '{}://{}:{}/{}'.format(DB_DRIVER, DB_HOST, DB_PORT, DB_NAME),
                connect_args=get_connect_args(DB_PORT))
            # test case from HexFormatTest expect two engines with different client_id but here enough one and
            # raw connection
            self.engine2 = self.engine_raw

            self.engines = [self.engine1, self.engine_raw]

            metadata.create_all(self.engine_raw)
            self.engine_raw.execute('delete from test;')
            for engine in self.engines:
                count = 0
                # try with sleep if acra not up yet
                while True:
                    try:
                        engine.execute(
                            "UPDATE pg_settings SET setting = '{}' "
                            "WHERE name = 'bytea_output'".format(self.DB_BYTEA))
                        break
                    except Exception:
                        time.sleep(SETUP_SQL_COMMAND_TIMEOUT)
                        count += 1
                        if count == SQL_EXECUTE_TRY_COUNT:
                            raise
        except:
            self.tearDown()
            raise

    def tearDown(self):
        super(SSLPostgresqlMixin, self).tearDown()
        try:
            self.engine_raw.execute('delete from test;')
        except:
            traceback.print_exc()

        try:
            for engine in getattr(self, 'engines', []):
                engine.dispose()
        except:
             traceback.print_exc()

        if not self.EXTERNAL_ACRA:
            for process in [getattr(self, attr)
                            for attr in ['acra', 'acra2']
                            if hasattr(self, attr)]:
                stop_process(process)


class SSLPostgresqlConnectionTest(SSLPostgresqlMixin, HexFormatTest):
    pass


class SSLPostgresqlConnectionWithZoneTest(SSLPostgresqlMixin, ZoneHexFormatTest):
    pass


class SSLMysqlMixin(SSLPostgresqlMixin):
    def checkSkip(self):
        if not (TEST_WITH_TLS and TEST_MYSQL):
            self.skipTest("running tests without TLS")

    def get_ssl_engine(self):
        return sa.create_engine(
                get_postgresql_tcp_connection_string(self.ACRASERVER2_PORT, DB_NAME),
                connect_args=get_connect_args(
                    port=self.ACRASERVER2_PORT, ssl=self.driver_to_acraserver_ssl_settings))

    def setUp(self):
        self.checkSkip()
        """connect directly to acra, use ssl for connections and tcp protocol on acra side
        because postgresql support tls only over tcp
        """
        try:
            if not self.EXTERNAL_ACRA:
                self.acra = self.fork_acra(
                    tls_key=abs_path(TEST_TLS_SERVER_KEY),
                    tls_cert=abs_path(TEST_TLS_SERVER_CERT),
                    tls_ca=TEST_TLS_CA,
                    tls_auth=ACRA_TLS_AUTH,
                    #tls_db_sni="127.0.0.1",
                    client_id=TLS_CERT_CLIENT_ID_1)
                # create second acra without settings for tls to check that
                # connection will be closed on tls handshake
                self.acra2 = self.fork_acra(
                    client_id=TLS_CERT_CLIENT_ID_1,
                    incoming_connection_port=self.ACRASERVER2_PORT,
                    incoming_connection_api_string=self.get_acraserver_api_connection_string(port=self.ACRASERVER2_PORT+5),
                    incoming_connection_prometheus_metrics_string=self.get_prometheus_address(
                        self.ACRASERVER2_PROMETHEUS_PORT))
            self.driver_to_acraserver_ssl_settings = {
                'ca': TEST_TLS_CA,
                'cert': TEST_TLS_CLIENT_CERT,
                'key': TEST_TLS_CLIENT_KEY,
                'check_hostname': False
            }
            self.engine_raw = sa.create_engine(
                '{}://{}:{}/{}'.format(DB_DRIVER, DB_HOST,
                                       DB_PORT, DB_NAME),
                # don't provide any client's certificates to driver that connects
                # directly to mysql to avoid verifying by mysql server
                connect_args=get_connect_args(DB_PORT, ssl={'ca': None}))

            self.engine1 = sa.create_engine(
                get_postgresql_tcp_connection_string(self.ACRASERVER_PORT, DB_NAME),
                connect_args=get_connect_args(
                    port=self.ACRASERVER_PORT, ssl=self.driver_to_acraserver_ssl_settings))

            # test case from HexFormatTest expect two engines with different
            # client_id but here enough one and raw connection
            self.engine2 = self.engine_raw

            self.engines = [self.engine1, self.engine_raw]

            metadata.create_all(self.engine_raw)
            self.engine_raw.execute('delete from test;')
            for engine in self.engines:
                count = 0
                # try with sleep if acra not up yet
                while True:
                    try:
                        engine.execute("select 1")
                        break
                    except Exception:
                        time.sleep(SETUP_SQL_COMMAND_TIMEOUT)
                        count += 1
                        if count == SQL_EXECUTE_TRY_COUNT:
                            raise
        except:
            self.tearDown()
            raise


class SSLMysqlConnectionTest(SSLMysqlMixin, HexFormatTest):
    pass


class SSLMysqlConnectionWithZoneTest(SSLMysqlMixin, ZoneHexFormatTest):
    pass


class BasePrepareStatementMixin:
    def checkSkip(self):
        return

    def executePreparedStatement(self, query):
        raise NotImplementedError

    def testClientRead(self):
        """test decrypting with correct client_id and not decrypting with
        incorrect client_id or using direct connection to db"""
        client_id = TLS_CERT_CLIENT_ID_1
        server_public1 = read_storage_public_key(client_id, KEYS_FOLDER.name)
        data = get_pregenerated_random_data()
        acra_struct = create_acrastruct(
            data.encode('ascii'), server_public1)
        row_id = get_random_id()

        self.log(storage_client_id=client_id,
                 data=acra_struct, expected=data.encode('ascii'))

        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': acra_struct, 'raw_data': data})

        query = sa.select([test_table]).where(test_table.c.id == row_id).compile(compile_kwargs={"literal_binds": True}).string
        row = self.executePreparedStatement(query)[0]

        self.assertEqual(row['data'], safe_string(row['raw_data']).encode('utf-8'))
        self.assertEqual(row['empty'], b'')

        result = self.engine2.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'].decode('ascii', errors='ignore'),
                            row['raw_data'])
        self.assertEqual(row['empty'], b'')

        result = self.engine_raw.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'].decode('ascii', errors='ignore'),
                            row['raw_data'])
        self.assertEqual(row['empty'], b'')

    def testReadAcrastructInAcrastruct(self):
        """test correct decrypting acrastruct when acrastruct concatenated to
        partial another acrastruct"""
        client_id = TLS_CERT_CLIENT_ID_1
        server_public1 = read_storage_public_key(client_id, KEYS_FOLDER.name)
        incorrect_data = get_pregenerated_random_data()
        correct_data = get_pregenerated_random_data()
        suffix_data = get_pregenerated_random_data()[:10]
        fake_offset = (3+45+84) - 4
        fake_acra_struct = create_acrastruct(
            incorrect_data.encode('ascii'), server_public1)[:fake_offset]
        inner_acra_struct = create_acrastruct(
            correct_data.encode('ascii'), server_public1)
        data = fake_acra_struct + inner_acra_struct + suffix_data.encode('ascii')
        correct_data = correct_data + suffix_data
        row_id = get_random_id()

        self.log(storage_client_id=client_id,
                 data=data,
                 expected=fake_acra_struct+correct_data.encode('ascii'))

        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': data, 'raw_data': correct_data})

        query = (sa.select([test_table])
                 .where(test_table.c.id == row_id)
                 .compile(compile_kwargs={"literal_binds": True}).string)
        row = self.executePreparedStatement(query)[0]

        try:
            self.assertEqual(row['data'][fake_offset:],
                             safe_string(row['raw_data']).encode('utf-8'))
            self.assertEqual(row['data'][:fake_offset], fake_acra_struct[:fake_offset])
            self.assertEqual(row['empty'], b'')
        except:
            print('incorrect data: {}\ncorrect data: {}\ndata: {}\n data len: {}'.format(
                incorrect_data, correct_data, row['data'], len(row['data'])))
            raise

        result = self.engine2.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'][fake_offset:].decode('ascii', errors='ignore'),
                            row['raw_data'])
        self.assertEqual(row['empty'], b'')

        result = self.engine_raw.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'][fake_offset:].decode('ascii', errors='ignore'),
                            row['raw_data'])
        self.assertEqual(row['empty'], b'')


class TestMysqlTextPreparedStatement(BasePrepareStatementMixin, BaseTestCase):
    def checkSkip(self):
        if not TEST_MYSQL:
            self.skipTest("run test only for mysql")
        elif not TEST_WITH_TLS:
            self.skipTest("running tests only with TLS")

    def executePreparedStatement(self, query):
        return PyMysqlExecutor(
            ConnectionArgs(host=get_db_host(), port=self.ACRASERVER_PORT,
                           user=DB_USER, password=DB_USER_PASSWORD,
                           dbname=DB_NAME, ssl_ca=TEST_TLS_CA,
                           ssl_key=TEST_TLS_CLIENT_KEY,
                           ssl_cert=TEST_TLS_CLIENT_CERT)
        ).execute_prepared_statement(query)


class TestMysqlTextPreparedStatementWholeCell(TestMysqlTextPreparedStatement):
    WHOLECELL_MODE = True


class TestMysqlBinaryPreparedStatement(BasePrepareStatementMixin, BaseTestCase):
    def checkSkip(self):
        if not TEST_MYSQL:
            self.skipTest("run test only for mysql")
        elif not TEST_WITH_TLS:
            self.skipTest("running tests only with TLS")

    def executePreparedStatement(self, query, args=None):
        return MysqlExecutor(
            ConnectionArgs(host=get_db_host(), port=self.ACRASERVER_PORT,
                           user=DB_USER, password=DB_USER_PASSWORD,
                           dbname=DB_NAME, ssl_ca=TEST_TLS_CA,
                           ssl_key=TEST_TLS_CLIENT_KEY,
                           ssl_cert=TEST_TLS_CLIENT_CERT)
        ).execute_prepared_statement(query, args=args)


class TestMysqlBinaryPreparedStatementWholeCell(TestMysqlBinaryPreparedStatement):
    WHOLECELL_MODE = True


class TestPostgresqlTextPreparedStatement(BasePrepareStatementMixin, BaseTestCase):
    def checkSkip(self):
        if not TEST_POSTGRESQL:
            self.skipTest("run test only for postgresql")
        elif not TEST_WITH_TLS:
            self.skipTest("running tests only with TLS")

    def executePreparedStatement(self, query, args=None):
        if not args:
            args = []
        return Psycopg2Executor(ConnectionArgs(host=get_db_host(), port=self.ACRASERVER_PORT,
                           user=DB_USER, password=DB_USER_PASSWORD,
                           dbname=DB_NAME, ssl_ca=TEST_TLS_CA,
                           ssl_key=TEST_TLS_CLIENT_KEY,
                           ssl_cert=TEST_TLS_CLIENT_CERT)
                                ).execute_prepared_statement(query, args)


class TestPostgresqlTextPreparedStatementWholeCell(TestPostgresqlTextPreparedStatement):
    WHOLECELL_MODE = True


class TestPostgresqlBinaryPreparedStatement(BaseBinaryPostgreSQLTestCase, BasePrepareStatementMixin):

    def executePreparedStatement(self, query):
        return self.executor1.execute_prepared_statement(query)


class TestPostgresqlBinaryPreparedStatementWholeCell(TestPostgresqlBinaryPreparedStatement):
    WHOLECELL_MODE = True


class ProcessContextManager(object):
    """wrap subprocess.Popen result to use as context manager that call
    stop_process on __exit__
    """
    def __init__(self, process):
        self.process = process

    def __enter__(self):
        return self.process

    def __exit__(self, exc_type, exc_val, exc_tb):
        stop_process(self.process)


class TestClientIDDecryptionWithVaultMasterKeyLoader(HashiCorpVaultMasterKeyLoaderMixin, HexFormatTest):
    pass


class TestZoneIDDecryptionWithVaultMasterKeyLoader(HashiCorpVaultMasterKeyLoaderMixin, ZoneHexFormatTest):
    pass


class AcraTranslatorTest(AcraTranslatorMixin, BaseTestCase):

    def apiEncryptionTest(self, request_func, use_http=False, use_grpc=False):
        # one is set
        self.assertTrue(use_http or use_grpc)
        # two is not acceptable
        self.assertFalse(use_http and use_grpc)
        translator_port = 3456
        key_folder = tempfile.TemporaryDirectory()
        try:
            client_id = extract_client_id_from_cert(tls_cert=TEST_TLS_CLIENT_CERT, extractor=self.get_identifier_extractor_type())
            self.assertEqual(create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_CERT,
                                                                    extractor=self.get_identifier_extractor_type(), keys_dir=key_folder.name), 0)
            data = get_pregenerated_random_data().encode('ascii')
            client_id_private_key = read_storage_private_key(key_folder.name, client_id)
            connection_string = 'tcp://127.0.0.1:{}'.format(translator_port)
            translator_kwargs = {
                'incoming_connection_http_string': connection_string if use_http else '',
                # turn off grpc to avoid check connection to it
                'incoming_connection_grpc_string': connection_string if use_grpc else '',
                'tls_key': abs_path(TEST_TLS_SERVER_KEY),
                'tls_cert': abs_path(TEST_TLS_SERVER_CERT),
                'tls_ca': TEST_TLS_CA,
                'keys_dir': key_folder.name,
                'tls_identifier_extractor_type': self.get_identifier_extractor_type(),
                'acratranslator_client_id_from_connection_enable': 'true',
                'tls_ocsp_from_cert': 'ignore',
                'tls_crl_from_cert': 'ignore',
            }

            incorrect_client_id = TLS_CERT_CLIENT_ID_2
            with ProcessContextManager(self.fork_translator(translator_kwargs)):
                response = request_func(translator_port, incorrect_client_id, None, data)
                decrypted = deserialize_and_decrypt_acrastruct(response, client_id_private_key, client_id)
                self.assertEqual(data, decrypted)
        finally:
            shutil.rmtree(key_folder.name)

    def apiDecryptionTest(self, request_func, use_http=False, use_grpc=False):
        # one is set
        self.assertTrue(use_http or use_grpc)
        # two is not acceptable
        self.assertFalse(use_http and use_grpc)
        translator_port = 3456
        key_folder = tempfile.TemporaryDirectory()
        try:
            client_id = extract_client_id_from_cert(tls_cert=TEST_TLS_CLIENT_CERT, extractor=self.get_identifier_extractor_type())
            self.assertEqual(create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_CERT,
                                                                    extractor=self.get_identifier_extractor_type(), keys_dir=key_folder.name), 0)
            data = get_pregenerated_random_data().encode('ascii')
            encryption_key = read_storage_public_key(client_id, keys_dir=key_folder.name)
            acrastruct = create_acrastruct(data, encryption_key)
            connection_string = 'tcp://127.0.0.1:{}'.format(translator_port)
            translator_kwargs = {
                'incoming_connection_http_string': connection_string if use_http else '',
                # turn off grpc to avoid check connection to it
                'incoming_connection_grpc_string': connection_string if use_grpc else '',
                'tls_key': abs_path(TEST_TLS_SERVER_KEY),
                'tls_cert': abs_path(TEST_TLS_SERVER_CERT),
                'tls_ca': TEST_TLS_CA,
                'keys_dir': key_folder.name,
                'tls_identifier_extractor_type': self.get_identifier_extractor_type(),
                'acratranslator_client_id_from_connection_enable': 'true',
                'tls_ocsp_from_cert': 'ignore',
                'tls_crl_from_cert': 'ignore',
            }

            incorrect_client_id = TLS_CERT_CLIENT_ID_2
            with ProcessContextManager(self.fork_translator(translator_kwargs)):
                response = request_func(translator_port, incorrect_client_id, None, acrastruct)
                self.assertEqual(data, response)
        finally:
            shutil.rmtree(key_folder.name)

    def testHTTPSApiResponses(self):
        translator_port = 3456
        data = get_pregenerated_random_data().encode('ascii')
        encryption_key = read_storage_public_key(
            TLS_CERT_CLIENT_ID_1, keys_dir=KEYS_FOLDER.name)
        acrastruct = create_acrastruct(data, encryption_key)
        connection_string = 'tcp://127.0.0.1:{}'.format(translator_port)
        translator_kwargs = {
            'incoming_connection_http_string': connection_string,
            'tls_key': abs_path(TEST_TLS_SERVER_KEY),
            'tls_cert': abs_path(TEST_TLS_SERVER_CERT),
            'tls_ca': TEST_TLS_CA,
            'tls_identifier_extractor_type': TLS_CLIENT_ID_SOURCE_DN,
            'acratranslator_client_id_from_connection_enable': 'true',
            'tls_ocsp_from_cert': 'ignore',
            'tls_crl_from_cert': 'ignore',
        }

        api_url = 'https://localhost:{}/v1/decrypt'.format(translator_port)
        with ProcessContextManager(self.fork_translator(translator_kwargs)):
                cert = (TEST_TLS_CLIENT_CERT, TEST_TLS_CLIENT_KEY)

                # test incorrect HTTP method
                response = requests.get(api_url, data=acrastruct, cert=cert, verify=TEST_TLS_CA,
                                        timeout=REQUEST_TIMEOUT)
                self.assertEqual(
                    response.status_code, http.HTTPStatus.METHOD_NOT_ALLOWED)
                self.assertIn('405 method not allowed'.lower(),
                              response.text.lower())
                self.assertEqual(response.headers['Content-Type'], 'text/plain')

                # test without api version
                without_version_api_url = api_url.replace('v1/', '')
                response = requests.post(
                    without_version_api_url, data=acrastruct, cert=cert, verify=TEST_TLS_CA,
                    timeout=REQUEST_TIMEOUT)
                self.assertEqual(response.status_code, http.HTTPStatus.NOT_FOUND)
                self.assertIn('404 Page Not Found'.lower(), response.text.lower())
                self.assertEqual(response.headers['Content-Type'], 'text/plain')

                # incorrect version
                without_version_api_url = api_url.replace('v1/', 'v3/')
                response = requests.post(
                    without_version_api_url, data=acrastruct, cert=cert, verify=TEST_TLS_CA,
                    timeout=REQUEST_TIMEOUT)
                self.assertEqual(response.status_code,
                                 http.HTTPStatus.NOT_FOUND)
                self.assertIn('404 Page Not Found'.lower(), response.text.lower())
                self.assertEqual(response.headers['Content-Type'], 'text/plain')

                # incorrect url
                incorrect_url = 'https://localhost:{}/v1/someurl'.format(translator_port)
                response = requests.post(
                    incorrect_url, data=acrastruct, cert=cert, verify=TEST_TLS_CA, timeout=REQUEST_TIMEOUT)
                self.assertEqual(
                    response.status_code, http.HTTPStatus.NOT_FOUND)
                self.assertEqual('404 Page Not Found'.lower(), response.text.lower())
                self.assertEqual(response.headers['Content-Type'], 'text/plain')


                # without acrastruct (http body), pass empty byte array as data
                response = requests.post(api_url, data=b'', cert=cert, verify=TEST_TLS_CA,
                                         timeout=REQUEST_TIMEOUT)
                self.assertEqual(response.status_code,
                                 http.HTTPStatus.UNPROCESSABLE_ENTITY)
                self.assertIn("Can't decrypt AcraStruct".lower(),
                              response.text.lower())
                self.assertEqual(response.headers['Content-Type'], 'text/plain; charset=utf-8')

                # test with correct acrastruct
                response = requests.post(api_url, data=acrastruct, cert=cert, verify=TEST_TLS_CA,
                                         timeout=REQUEST_TIMEOUT)
                self.assertEqual(data, response.content)
                self.assertEqual(response.status_code, http.HTTPStatus.OK)
                self.assertEqual(response.headers['Content-Type'],
                                 'application/octet-stream')

    def testGRPCApi(self):
        self.apiDecryptionTest(self.grpc_decrypt_request, use_grpc=True)
        self.apiEncryptionTest(self.grpc_encrypt_request, use_grpc=True)

    def testHTTPApi(self):
        self.apiDecryptionTest(self.http_decrypt_request, use_http=True)
        self.apiEncryptionTest(self.http_encrypt_request, use_http=True)


class TestAcraTranslatorWithVaultMasterKeyLoaderByDistinguishedName(HashiCorpVaultMasterKeyLoaderMixin,
                                                 TLSAuthenticationByDistinguishedNameMixin, AcraTranslatorTest):
    pass


class TestAcraTranslatorWithVaultMasterKeyLoaderBySerialNumber(HashiCorpVaultMasterKeyLoaderMixin,
                                                                    TLSAuthenticationBySerialNumberMixin, AcraTranslatorTest):
    pass


class TestAcraTranslatorClientIDFromTLSByDistinguishedName(TLSAuthenticationByDistinguishedNameMixin, AcraTranslatorTest):
    pass


class TestAcraTranslatorClientIDFromTLSByDistinguishedNameVaultMasterKeyLoader(HashiCorpVaultMasterKeyLoaderMixin, TestAcraTranslatorClientIDFromTLSByDistinguishedName):
    pass


class TestKeyRotationWithVaultMasterKeyLoader(HashiCorpVaultMasterKeyLoaderMixin, TestKeyRotation):
    pass


class TestAcraTranslatorClientIDFromTLSBySerialNumber(TLSAuthenticationBySerialNumberMixin, TestAcraTranslatorClientIDFromTLSByDistinguishedName):
    pass


class TestAcraTranslatorClientIDFromTLSBySerialNumberVaultMasterKeyLoader(HashiCorpVaultMasterKeyLoaderMixin, TLSAuthenticationBySerialNumberMixin, TestAcraTranslatorClientIDFromTLSByDistinguishedName):
    pass


class TestAcraRotateWithZone(BaseTestCase):
    ZONE = True

    def fork_acra(self, popen_kwargs: dict=None, **acra_kwargs: dict):
        acra_kwargs['keystore_cache_size'] = -1  # no cache
        return super(TestAcraRotateWithZone, self).fork_acra(
            popen_kwargs, **acra_kwargs)

    def read_public_key(self, key_id, keys_folder):
        return read_zone_public_key(key_id, keys_folder)

    def isSamePublicKeys(self, keys_folder, keys_data):
        """check is equal zone public key on filesystem and from zone_data"""
        for key_id, public_key in keys_data.items():
            current_public = self.read_public_key(key_id, keys_folder)
            if b64decode(public_key) != current_public:
                return False
        return True

    def testFileRotation(self):
        """
        generate some zones, create AcraStructs with them and save to files
        call acra-rotate and check that public keys of zones different,
        AcraStructs different and decrypted AcraStructs (raw data) the same"""

        TestData = collections.namedtuple("TestData", ["acrastruct", "data"])
        zone_map = collections.defaultdict(list)
        # how much generate acrastructs per zone
        zone_file_count = 3
        # count of different zones
        zone_id_count = 3
        filename_template = '{dir}/{id}_{num}.acrastruct'

        zones_before_rotate = {}

        # generated acrastructs to compare with rotated
        acrastructs = {}
        with tempfile.TemporaryDirectory() as keys_folder, \
                tempfile.TemporaryDirectory() as data_folder:
            # generate zones in separate folder
            # create acrastructs with this zones
            for i in range(zone_id_count):
                zone_data = json.loads(
                    subprocess.check_output(
                        [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-addzone'),
                         '--keys_output_dir={}'.format(keys_folder)],
                        cwd=os.getcwd(),
                        timeout=PROCESS_CALL_TIMEOUT).decode('utf-8'))
                public_key = b64decode(zone_data[ZONE_PUBLIC_KEY])
                zone_id = zone_data[ZONE_ID]
                zones_before_rotate[zone_id] = zone_data[ZONE_PUBLIC_KEY]
                for i in range(zone_file_count):
                    data = get_pregenerated_random_data().encode('ascii')
                    acrastruct = create_acrastruct(
                        data, public_key, zone_id.encode("ascii"))
                    filename = filename_template.format(
                        dir=data_folder, id=zone_id, num=i)
                    acrastructs[filename] = TestData(
                        acrastruct=acrastruct, data=data)
                    with open(filename, 'wb') as f:
                        f.write(acrastruct)
                    zone_map[zone_id].append(filename)

            # keys of json objects that will be in output
            PUBLIC_KEY = 'new_public_key'
            FILES = 'file_paths'
            # True must be first because code below depends on it
            for dryRun in (True, False):
                with contextlib.closing(tempfile.NamedTemporaryFile(
                        'w', delete=False)) as zone_map_file:
                    json.dump(zone_map, zone_map_file)
                    zone_map_file.close()
                    result = subprocess.check_output(
                        [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-rotate'), '--keys_dir={}'.format(keys_folder),
                         '--file_map_config={}'.format(zone_map_file.name),
                         '--dry-run={}'.format(1 if dryRun else 0)])
                    if not isinstance(result, str):
                        result = result.decode('utf-8')
                    result = json.loads(result)
                    if dryRun:
                        # keys on filesystem should not changed
                        self.assertTrue(
                            self.isSamePublicKeys(
                                keys_folder, zones_before_rotate))
                    else:
                        # keys on filesystem must be changed
                        self.assertFalse(
                            self.isSamePublicKeys(
                                keys_folder, zones_before_rotate))
                    for zone_id in result:
                        self.assertIn(zone_id, zones_before_rotate)
                        # new public key in output must be different from
                        # previous
                        self.assertNotEqual(
                            result[zone_id][PUBLIC_KEY],
                            zones_before_rotate[zone_id])
                        # check that all files was processed and are in result
                        self.assertEqual(
                            zone_map[zone_id],  # already sorted by loop index
                            sorted(result[zone_id][FILES]))
                        # compare rotated acrastructs
                        for path in result[zone_id][FILES]:
                            with open(path, 'rb') as acrastruct_file:
                                rotated_acrastruct = acrastruct_file.read()
                            zone_private = read_zone_private_key(keys_folder, zone_id)
                            if dryRun:
                                decrypted_rotated = decrypt_acrastruct(
                                    rotated_acrastruct, zone_private,
                                    zone_id=zone_id.encode('ascii'))
                                self.assertEqual(
                                    rotated_acrastruct,
                                    acrastructs[path].acrastruct)
                            else:
                                decrypted_rotated = deserialize_and_decrypt_acrastruct(
                                    rotated_acrastruct, zone_private,
                                    zone_id=zone_id.encode('ascii'))
                                self.assertNotEqual(
                                    rotated_acrastruct,
                                    acrastructs[path].acrastruct)
                            # data should be unchanged
                            self.assertEqual(
                                decrypted_rotated, acrastructs[path].data)

    def testDatabaseRotation(self):
        # TODO(ilammy, 2020-03-13): test with rotated zone keys
        # That is, as soon as it is possible to rotate them (T1581)

        def load_zones_from_folder(keys_folder, zone_ids):
            """load zone public keys from filesystem"""
            output = {}
            for id in zone_ids:
                output[id] = b64encode(self.read_public_key(id, keys_folder))
            return output

        rotate_test_table = sa.Table(
            'rotate_zone_test',
            metadata,
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('zone_id', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
            sa.Column('data', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
            sa.Column('raw_data', sa.Text),
        )
        metadata.create_all(self.engine_raw)
        self.engine_raw.execute(sa.delete(rotate_test_table))
        zones = []
        zone_count = 5
        data_per_zone_count = 2
        for i in range(zone_count):
            zones.append(
                json.loads(subprocess.check_output(
                    [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-addzone'),
                     '--keys_output_dir={}'.format(KEYS_FOLDER.name)],
                    cwd=os.getcwd(),
                    timeout=PROCESS_CALL_TIMEOUT).decode('utf-8')))
        zone_ids = [data[ZONE_ID] for data in zones]
        data_before_rotate = {}
        for zone in zones:
            for _ in range(data_per_zone_count):
                data = get_pregenerated_random_data()
                zone_public = b64decode(zone[ZONE_PUBLIC_KEY].encode('ascii'))
                acra_struct = create_acrastruct(
                    data.encode('ascii'), zone_public,
                    context=zone[ZONE_ID].encode('ascii'))
                row_id = get_random_id()
                data_before_rotate[row_id] = acra_struct
                self.engine_raw.execute(
                    rotate_test_table.insert(),
                    {'id': row_id, 'data': acra_struct, 'raw_data': data,
                     'zone_id': zone[ZONE_ID].encode('ascii')})

        if TEST_MYSQL:
            # test:test@tcp(127.0.0.1:3306)/test
            connection_string = "{user}:{password}@tcp({host}:{port})/{db_name}".format(
                user=DB_USER, password=DB_USER_PASSWORD, host=DB_HOST,
                port=DB_PORT, db_name=DB_NAME)
            mode_arg = '--mysql_enable'
        elif TEST_POSTGRESQL:
            if TEST_WITH_TLS:
                sslmode = "require"
            else:
                sslmode = "disable"

            connection_string = "postgres://{user}:{password}@{db_host}:{db_port}/{db_name}?sslmode={sslmode}".format(
                sslmode=sslmode, user=DB_USER, password=DB_USER_PASSWORD,
                db_host=DB_HOST, db_port=DB_PORT, db_name=DB_NAME)
            mode_arg = '--postgresql_enable'
        else:
            self.fail("unsupported settings of tested db")

        for dry_run in (True, False):
            if TEST_MYSQL:
                sql_update = "update {} set data=? where id=?;".format(rotate_test_table.name)
                sql_select = 'select id, zone_id, data from {} order by id;'.format(rotate_test_table.name)
            elif TEST_POSTGRESQL:
                sql_update = "update {} set data=$1 where id=$2;".format(rotate_test_table.name)
                sql_select = 'select id, zone_id::bytea, data from {} order by id;'.format(rotate_test_table.name)
            else:
                self.fail("unsupported settings of tested db")

            default_args = [
                os.path.join(BINARY_OUTPUT_FOLDER, 'acra-rotate'),
                '--keys_dir={}'.format(KEYS_FOLDER.name),
                '--db_connection_string={}'.format(connection_string),
                '--dry-run={}'.format(1 if dry_run else 0),
                mode_arg
            ]

            zone_map = load_zones_from_folder(KEYS_FOLDER.name, zone_ids)
            # use extra arg in select and update
            subprocess.check_output(
                default_args + [
                    '--sql_select={}'.format(sql_select),
                    '--sql_update={}'.format(sql_update)
                ]
            )
            if dry_run:
                self.assertTrue(
                    self.isSamePublicKeys(KEYS_FOLDER.name, zone_map))
            else:
                self.assertFalse(
                    self.isSamePublicKeys(KEYS_FOLDER.name, zone_map))

            result = self.engine1.execute(sa.select([rotate_test_table]))
            self.check_decrypted_data(result)
            result = self.engine_raw.execute(sa.select([rotate_test_table]))
            self.check_rotation(result, data_before_rotate, dry_run)

            some_id = list(data_before_rotate.keys())[0]

            # chose any id to operate with specific row
            if TEST_MYSQL:
                sql_update = "update {} set data=? where id={{}};".format(rotate_test_table.name)
                sql_select = 'select zone_id, data from {} where id={};'.format(rotate_test_table.name, some_id)
            elif TEST_POSTGRESQL:
                sql_update = "update {} set data=$1 where id={{}};".format(rotate_test_table.name)
                sql_select = 'select zone_id::bytea, data from {} where id={};'.format(rotate_test_table.name, some_id)
            else:
                self.fail("unsupported settings of tested db")

            sql_update = sql_update.format(some_id)


            zone_map = load_zones_from_folder(KEYS_FOLDER.name, zone_ids)
            # rotate with select without extra arg
            subprocess.check_output(
                default_args + [
                    '--sql_select={}'.format(sql_select),
                    '--sql_update={}'.format(sql_update)
                ]
            )

            if dry_run:
                self.assertTrue(
                    self.isSamePublicKeys(KEYS_FOLDER.name, zone_map))
            else:
                self.assertFalse(
                    self.isSamePublicKeys(KEYS_FOLDER.name, zone_map))

            result = self.engine1.execute(
                sa.select([rotate_test_table],
                          whereclause=rotate_test_table.c.id==some_id))
            self.check_decrypted_data(result)
            # check that after rotation we can read actual data
            result = self.engine_raw.execute(
                sa.select([rotate_test_table],
                          whereclause=rotate_test_table.c.id==some_id))
            self.check_rotation(result, data_before_rotate, dry_run)

    def check_decrypted_data(self, result):
        data = result.fetchall()
        self.assertTrue(data)
        for row in data:
            # check that data was not changed
            self.assertEqual(row['data'], row['raw_data'].encode('utf-8'))

    def check_rotation(self, result, data_before_rotate, dry_run):
        data = result.fetchall()
        self.assertTrue(data)
        for row in data:
            # check that after rotation encrypted data != raw data
            self.assertNotEqual(row['data'], row['raw_data'].encode('utf-8'))
            if dry_run:
                # check that data was not changed
                self.assertEqual(row['data'], data_before_rotate[row['id']])
            else:
                # check that data was changed
                self.assertNotEqual(row['data'], data_before_rotate[row['id']])
                # update with new data to check on next stage
                data_before_rotate[row['id']] = row['data']


@ddt
class TestAcraRotate(TestAcraRotateWithZone):
    ZONE = False

    def read_public_key(self, key_id, keys_folder):
        return read_storage_public_key(key_id, keys_folder)

    def testFileRotation(self):
        """
        create AcraStructs with them and save to files
        call acra-rotate and check that public keys for client_ids different,
        AcraStructs different and decrypted AcraStructs (raw data) the same"""

        TestData = collections.namedtuple("TestData", ["acrastruct", "data"])
        filename_template = '{dir}/{id}_{num}.acrastruct'
        key_before_rotate = {}
        client_id = 'keypair1'
        keys_map = collections.defaultdict(list)
        keys_file_count = 3
        # generated acrastructs to compare with rotated
        acrastructs = {}
        with tempfile.TemporaryDirectory() as keys_folder, \
                tempfile.TemporaryDirectory() as data_folder:
            # generate keys in separate folder

            subprocess.check_output(
                [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keymaker'),
                 '--client_id={}'.format(client_id),
                 '--keys_output_dir={}'.format(keys_folder),
                 '--keys_public_output_dir={}'.format(keys_folder),
                 '--keystore={}'.format(KEYSTORE_VERSION)],
                cwd=os.getcwd(),
                timeout=PROCESS_CALL_TIMEOUT).decode('utf-8')
            # create acrastructs with this client_id
            key_before_rotate = {client_id: b64encode(self.read_public_key(client_id, keys_folder))}

            for i in range(keys_file_count):
                data = get_pregenerated_random_data().encode('ascii')
                acrastruct = create_acrastruct(data, b64decode(key_before_rotate[client_id]))
                filename = filename_template.format(
                    dir=data_folder, id=client_id, num=i)
                acrastructs[filename] = TestData(acrastruct=acrastruct, data=data)
                with open(filename, 'wb') as f:
                    f.write(acrastruct)
                keys_map[client_id].append(filename)


            # keys of json objects that will be in output
            PUBLIC_KEY = 'new_public_key'
            FILES = 'file_paths'
            # True must be first because code below depends on it
            for dryRun in (True, False):
                with contextlib.closing(tempfile.NamedTemporaryFile(
                        'w', delete=False)) as keys_map_file:
                    json.dump(keys_map, keys_map_file)
                    keys_map_file.close()
                    result = subprocess.check_output(
                        [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-rotate'), '--keys_dir={}'.format(keys_folder),
                         '--file_map_config={}'.format(keys_map_file.name),
                         '--dry-run={}'.format(1 if dryRun else 0),
                         '--zonemode_enable=false'])
                    if not isinstance(result, str):
                        result = result.decode('utf-8')
                    result = json.loads(result)
                    if dryRun:
                        # keys on filesystem should not changed
                        self.assertTrue(
                            self.isSamePublicKeys(
                                keys_folder, key_before_rotate))
                    else:
                        # keys on filesystem must be changed
                        self.assertFalse(
                            self.isSamePublicKeys(
                                keys_folder, key_before_rotate))
                    for key_id in result:
                        self.assertIn(key_id, key_before_rotate)
                        # new public key in output must be different from
                        # previous
                        self.assertNotEqual(
                            result[key_id][PUBLIC_KEY],
                            key_before_rotate[key_id])
                        # check that all files was processed and are in result
                        self.assertEqual(
                            keys_map[key_id],  # already sorted by loop index
                            sorted(result[key_id][FILES]))
                        # compare rotated acrastructs
                        for path in result[key_id][FILES]:
                            with open(path, 'rb') as acrastruct_file:
                                rotated_acrastruct = acrastruct_file.read()
                            client_id_private = read_storage_private_key(keys_folder, key_id)
                            if dryRun:
                                decrypted_rotated = decrypt_acrastruct(
                                    rotated_acrastruct, client_id_private)
                                self.assertEqual(
                                    rotated_acrastruct,
                                    acrastructs[path].acrastruct)
                            else:
                                decrypted_rotated = deserialize_and_decrypt_acrastruct(
                                    rotated_acrastruct, client_id_private)
                                self.assertNotEqual(
                                    rotated_acrastruct,
                                    acrastructs[path].acrastruct)
                            # data should be unchanged
                            self.assertEqual(
                                decrypted_rotated, acrastructs[path].data)

    # Skip inherited non-decorated test
    def testDatabaseRotation(self):
        pass

    @data(False, True)
    def testDatabaseRotation2(self, rotate_storage_keys):
        def load_keys_from_folder(keys_folder, ids):
            """load public keys from filesystem"""
            output = {}
            for id in ids:
                output[id] = b64encode(self.read_public_key(id, keys_folder))
            return output

        rotate_test_table = sa.Table(
            'rotate_client_id_test',
            metadata,
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('key_id', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
            sa.Column('data', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
            sa.Column('raw_data', sa.Text),
            keep_existing=True,
        )
        metadata.create_all(self.engine_raw)
        self.engine_raw.execute(sa.delete(rotate_test_table))

        data_before_rotate = {}

        data = get_pregenerated_random_data()
        client_id = TLS_CERT_CLIENT_ID_1
        acra_struct = create_acrastruct_with_client_id(data.encode('ascii'), client_id)
        row_id = get_random_id()
        data_before_rotate[row_id] = acra_struct
        self.engine_raw.execute(
            rotate_test_table.insert(),
            {'id': row_id, 'data': acra_struct, 'raw_data': data,
             'key_id': client_id.encode('ascii')})

        if rotate_storage_keys:
            create_client_keypair(client_id, only_storage=True)

        if TEST_MYSQL:
            # test:test@tcp(127.0.0.1:3306)/test
            connection_string = "{user}:{password}@tcp({host}:{port})/{db_name}".format(
                user=DB_USER, password=DB_USER_PASSWORD, host=DB_HOST,
                port=DB_PORT, db_name=DB_NAME)
            mode_arg = '--mysql_enable'
        elif TEST_POSTGRESQL:
            if TEST_WITH_TLS:
                sslmode = "require"
            else:
                sslmode = "disable"

            connection_string = "postgres://{user}:{password}@{db_host}:{db_port}/{db_name}?sslmode={sslmode}".format(
                sslmode=sslmode, user=DB_USER, password=DB_USER_PASSWORD,
                db_host=DB_HOST, db_port=DB_PORT, db_name=DB_NAME)
            mode_arg = '--postgresql_enable'
        else:
            self.fail("unsupported settings of tested db")

        for dry_run in (True, False):
            if TEST_MYSQL:
                sql_update = "update {} set data=? where id=?;".format(rotate_test_table.name)
                sql_select = "select id, '{}', data from {} order by id;".format(client_id, rotate_test_table.name)
            elif TEST_POSTGRESQL:
                sql_update = "update {} set data=$1 where id=$2;".format(rotate_test_table.name)
                sql_select = "select id, '{}'::bytea, data from {} order by id;".format(client_id, rotate_test_table.name)
            else:
                self.fail("unsupported settings of tested db")

            default_args = [
                os.path.join(BINARY_OUTPUT_FOLDER, 'acra-rotate'),
                '--keys_dir={}'.format(KEYS_FOLDER.name),
                '--db_connection_string={}'.format(connection_string),
                '--dry-run={}'.format(1 if dry_run else 0),
                '--zonemode_enable=false',
                mode_arg
            ]

            keys_map = load_keys_from_folder(KEYS_FOLDER.name, [client_id])
            try:
                # use extra arg in select and update
                subprocess.check_output(
                    default_args + [
                        "--sql_select={}".format(sql_select),
                        '--sql_update={}'.format(sql_update),
                    ]
                )
            except subprocess.CalledProcessError as exc:
                print(exc.output)
                raise
            if dry_run:
                self.assertTrue(
                    self.isSamePublicKeys(KEYS_FOLDER.name, keys_map))
            else:
                self.assertFalse(
                    self.isSamePublicKeys(KEYS_FOLDER.name, keys_map))

            result = self.engine1.execute(sa.select([rotate_test_table]))
            self.check_decrypted_data(result)
            result = self.engine_raw.execute(sa.select([rotate_test_table]))
            self.check_rotation(result, data_before_rotate, dry_run)
            some_id = list(data_before_rotate.keys())[0]

            # chose any id to operate with specific row
            if TEST_MYSQL:
                sql_update = "update {} set data=? where id={{}};".format(rotate_test_table.name)
                sql_select = "select '{}', data from {} where id={};".format(client_id, rotate_test_table.name, some_id)
            elif TEST_POSTGRESQL:
                sql_update = "update {} set data=$1 where id={{}};".format(rotate_test_table.name)
                sql_select = "select '{}'::bytea, data from {} where id={};".format(client_id, rotate_test_table.name, some_id)
            else:
                self.fail("unsupported settings of tested db")
            sql_update = sql_update.format(some_id)

            keys_map = load_keys_from_folder(KEYS_FOLDER.name, [client_id])
            # rotate with select without extra arg
            subprocess.check_output(
                default_args + [
                    "--sql_select={}".format(sql_select),
                    '--sql_update={}'.format(sql_update)
                ]
            )

            if dry_run:
                self.assertTrue(
                    self.isSamePublicKeys(KEYS_FOLDER.name, keys_map))
            else:
                self.assertFalse(
                    self.isSamePublicKeys(KEYS_FOLDER.name, keys_map))

            result = self.engine1.execute(
                sa.select([rotate_test_table],
                          whereclause=rotate_test_table.c.id==some_id))
            self.check_decrypted_data(result)
            # check that after rotation we can read actual data
            result = self.engine_raw.execute(
                sa.select([rotate_test_table],
                          whereclause=rotate_test_table.c.id==some_id))
            self.check_rotation(result, data_before_rotate, dry_run)


class TestPrometheusMetrics(AcraTranslatorMixin, BaseTestCase):
    LOG_METRICS = True
    # some small value but greater than 0 to compare with metrics value of time of processing
    MIN_EXECUTION_TIME = 0.0000001

    def checkMetrics(self, url, labels=None):
        """
        check that output of prometheus exporter contains all labels
        """
        exporter_metrics = [
            'go_memstats',
            'go_threads',
            'go_info',
            'go_goroutines',
            'go_gc_duration_seconds',
            'process_',
            'promhttp_',
        ]
        # check that need_skip
        def skip(need_skip):
            for label in exporter_metrics:
                if need_skip.startswith(label):
                    return True
            return False

        labels = labels if labels else {}

        response = requests.get(url)
        self.assertEqual(response.status_code, http.HTTPStatus.OK)

        # check that all labels were exported
        for label in labels.keys():
            self.assertIn(label, response.text)

        # check that labels have minimal expected value
        for family in text_string_to_metric_families(response.text):
            if skip(family.name):
                continue
            for sample in family.samples:
                try:
                    self.assertGreaterEqual(sample.value, labels[sample.name]['min_value'],
                                            '{} - {}'.format(sample.name, sample.value))
                except KeyError:
                    # python prometheus client append _total for sample names if they have type <counter> and
                    # have not _total suffix
                    if not sample.name.endswith('_total'):
                        raise
                    name = sample.name[:-len('_total')]
                    self.assertGreaterEqual(sample.value, labels[name]['min_value'],
                                            '{} - {}'.format(name, sample.value))

    def testAcraServer(self):
        # run some queries to set some values for counters
        HexFormatTest.testClientIDRead(self)
        labels = {
            # TEST_TLS_CLIENT_CERT + TEST_TLS_CLIENT_2_CERT
            'acraserver_connections_total': {'min_value': 2},

            'acraserver_connections_processing_seconds_bucket': {'min_value': 0},
            'acraserver_connections_processing_seconds_sum': {'min_value': TestPrometheusMetrics.MIN_EXECUTION_TIME},
            'acraserver_connections_processing_seconds_count': {'min_value': 1},

            'acraserver_response_processing_seconds_sum': {'min_value': TestPrometheusMetrics.MIN_EXECUTION_TIME},
            'acraserver_response_processing_seconds_bucket': {'min_value': 0},
            'acraserver_response_processing_seconds_count': {'min_value': 1},

            'acraserver_request_processing_seconds_sum': {'min_value': TestPrometheusMetrics.MIN_EXECUTION_TIME},
            'acraserver_request_processing_seconds_count': {'min_value': 1},
            'acraserver_request_processing_seconds_bucket': {'min_value': 0},

            'acra_acrastruct_decryptions_total': {'min_value': 1},

            'acraserver_version_major': {'min_value': 0},
            'acraserver_version_minor': {'min_value': 0},
            'acraserver_version_patch': {'min_value': 0},

            'acraserver_build_info': {'min_value': 1},
        }
        self.checkMetrics('http://localhost:{}/metrics'.format(
            self.ACRASERVER_PROMETHEUS_PORT), labels)


    def testAcraTranslator(self):
        labels = {
            'acratranslator_connections_total': {'min_value': 1},

            # sometimes request processing so fast that it not rounded to 1 and we have flappy tests
            # so check only that output contains such metrics
            'acratranslator_connections_processing_seconds_bucket': {'min_value': 0},
            'acratranslator_connections_processing_seconds_sum': {'min_value': 0},
            'acratranslator_connections_processing_seconds_count': {'min_value': 0},

            'acratranslator_request_processing_seconds_bucket': {'min_value': 0},
            'acratranslator_request_processing_seconds_sum': {'min_value': TestPrometheusMetrics.MIN_EXECUTION_TIME},
            'acratranslator_request_processing_seconds_count': {'min_value': 1},

            'acratranslator_version_major': {'min_value': 0},
            'acratranslator_version_minor': {'min_value': 0},
            'acratranslator_version_patch': {'min_value': 0},

            'acra_acrastruct_decryptions_total': {'min_value': 1},

            'acratranslator_build_info': {'min_value': 1},
        }
        translator_port = 3456
        metrics_port = translator_port+1
        data = get_pregenerated_random_data().encode('ascii')
        client_id = TLS_CERT_CLIENT_ID_1
        encryption_key = read_storage_public_key(
            client_id, keys_dir=KEYS_FOLDER.name)
        acrastruct = create_acrastruct(data, encryption_key)

        prometheus_metrics_address = 'tcp://localhost:{}'.format(metrics_port)
        connection_string = 'tcp://127.0.0.1:{}'.format(translator_port)
        base_translator_kwargs = {
            'incoming_connection_http_string': connection_string,
            'incoming_connection_prometheus_metrics_string': prometheus_metrics_address,
            'tls_key': abs_path(TEST_TLS_SERVER_KEY),
            'tls_cert': abs_path(TEST_TLS_SERVER_CERT),
            'tls_ca': TEST_TLS_CA,
            'tls_identifier_extractor_type': TLS_CLIENT_ID_SOURCE_DN,
            'acratranslator_client_id_from_connection_enable': 'true',
            'tls_ocsp_from_cert': 'ignore',
            'tls_crl_from_cert': 'ignore',
        }
        metrics_url = 'http://localhost:{}/metrics'.format(metrics_port)
        api_url = 'https://localhost:{}/v1/decrypt'.format(translator_port)
        with ProcessContextManager(self.fork_translator(base_translator_kwargs)):
                # test with correct acrastruct
                cert = (TEST_TLS_CLIENT_CERT, TEST_TLS_CLIENT_KEY)
                response = requests.post(api_url, data=acrastruct, cert=cert, verify=TEST_TLS_CA,
                                         timeout=REQUEST_TIMEOUT)
                self.assertEqual(response.status_code, http.HTTPStatus.OK)
                self.checkMetrics(metrics_url, labels)

        grpc_translator_kwargs = {
            'incoming_connection_grpc_string': connection_string,
            'incoming_connection_http_string': '',
            'incoming_connection_prometheus_metrics_string': prometheus_metrics_address,
        }
        base_translator_kwargs.update(grpc_translator_kwargs)
        with ProcessContextManager(self.fork_translator(base_translator_kwargs)):
                AcraTranslatorTest.grpc_decrypt_request(
                    self, translator_port, client_id, None, acrastruct)
                self.checkMetrics(metrics_url, labels)


class TestTransparentEncryption(BaseTestCase):
    WHOLECELL_MODE = True
    encryptor_table = sa.Table('test_transparent_encryption', metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('specified_client_id',
                  sa.LargeBinary(length=COLUMN_DATA_SIZE)),
        sa.Column('default_client_id',
                  sa.LargeBinary(length=COLUMN_DATA_SIZE)),

        sa.Column('number', sa.Integer),
        sa.Column('zone_id', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
        sa.Column('raw_data', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
        sa.Column('nullable', sa.Text, nullable=True),
        sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
    )
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/encryptor_config.yaml')

    def setUp(self):
        self.prepare_encryptor_config(client_id=TLS_CERT_CLIENT_ID_1)
        super(TestTransparentEncryption, self).setUp()

    def prepare_encryptor_config(self, client_id=None):
        prepare_encryptor_config(zone_id=zones[0][ZONE_ID], config_path=self.ENCRYPTOR_CONFIG, client_id=client_id)

    def tearDown(self):
        self.engine_raw.execute(self.encryptor_table.delete())
        super(TestTransparentEncryption, self).tearDown()
        try:
            os.remove(get_test_encryptor_config(self.ENCRYPTOR_CONFIG))
        except FileNotFoundError:
            pass

    def fork_acra(self, popen_kwargs: dict=None, **acra_kwargs: dict):
        acra_kwargs['encryptor_config_file'] = get_test_encryptor_config(
            self.ENCRYPTOR_CONFIG)
        return super(TestTransparentEncryption, self).fork_acra(
            popen_kwargs, **acra_kwargs)

    def get_context_data(self):
        context = {
            'id': get_random_id(),
            'default_client_id': get_pregenerated_random_data().encode('ascii'),
            'number': get_random_id(),
            'zone_id': get_pregenerated_random_data().encode('ascii'),
            'specified_client_id': get_pregenerated_random_data().encode('ascii'),
            'raw_data': get_pregenerated_random_data().encode('ascii'),
            'zone': zones[0],
            'empty': b'',
        }
        return context

    def checkDefaultIdEncryption(self, id, default_client_id,
                                 specified_client_id, number, zone_id, zone, raw_data,
                                 *args, **kwargs):
        result = self.engine2.execute(
            sa.select([self.encryptor_table])
            .where(self.encryptor_table.c.id == id))
        row = result.fetchone()
        self.assertIsNotNone(row)

        # should be decrypted
        self.assertEqual(row['default_client_id'], default_client_id)
        # should be as is
        self.assertEqual(row['number'], number)
        self.assertEqual(row['raw_data'], raw_data)
        # other data should be encrypted
        self.assertNotEqual(row['specified_client_id'], specified_client_id)
        self.assertNotEqual(row['zone_id'], zone_id)
        self.assertEqual(row['empty'], b'')

    def checkSpecifiedIdEncryption(
            self, id, default_client_id, specified_client_id, zone_id,
            zone, raw_data, *args, **kwargs):
        # fetch using another client_id that will authenticated as TEST_TLS_CLIENT_2_CERT
        result = self.engine1.execute(
            sa.select([self.encryptor_table])
            .where(self.encryptor_table.c.id == id))
        row = result.fetchone()
        self.assertIsNotNone(row)

        # should be decrypted
        self.assertEqual(row['specified_client_id'], specified_client_id)
        # should be as is
        self.assertEqual(row['raw_data'], raw_data)
        # other data should be encrypted
        self.assertNotEqual(row['default_client_id'], default_client_id)
        self.assertNotEqual(row['zone_id'], zone_id)
        self.assertEqual(row['empty'], b'')

    def insertRow(self, data):
        # send through acra-server that authenticates as client_id=keypair2
        self.engine2.execute(self.encryptor_table.insert(), data)

    def check_all_decryptions(self, **context):
        self.checkDefaultIdEncryption(**context)
        self.checkSpecifiedIdEncryption(**context)

    def testEncryptedInsert(self):
        context = self.get_context_data()
        self.insertRow(context)
        self.check_all_decryptions(**context)

        encrypted_data = self.fetch_raw_data(context)

        # update with acrastructs and AcraServer should not
        # re-encrypt
        data_fields = ['default_client_id', 'specified_client_id', 'zone_id',
                       'raw_data', 'empty']
        data = {k: encrypted_data[k] for k in data_fields}
        data['id'] = context['id']
        self.update_data(data)

        data = self.fetch_raw_data(context)
        for field in data_fields:
            # check that acrastructs the same
            self.assertEqual(data[field], encrypted_data[field])

        # generate new data
        new_context = self.get_context_data()
        # use same id and integer
        new_context['id'] = context['id']
        new_context['number'] = context['number']
        # update with not encrypted raw data
        self.update_data(new_context)

        # check that data re-encrypted
        new_data = self.fetch_raw_data(new_context)

        for field in ['default_client_id', 'specified_client_id', 'zone_id']:
            # not equal with previously encrypted
            self.assertNotEqual(new_data[field], encrypted_data[field])
            # not equal with raw data
            self.assertNotEqual(new_data[field], new_context[field])

        # check that can decrypt after re-encryption
        self.check_all_decryptions(**new_context)

    def update_data(self, context):
        self.engine2.execute(
            sa.update(self.encryptor_table)
            .where(self.encryptor_table.c.id == context['id'])
            .values(default_client_id=context['default_client_id'],
                    specified_client_id=context['specified_client_id'],
                    zone_id=context['zone_id'],
                    raw_data=context['raw_data'])
        )

    def fetch_raw_data(self, context):
        result = self.engine_raw.execute(
            sa.select([self.encryptor_table.c.default_client_id,
                       self.encryptor_table.c.specified_client_id,
                       sa.cast(context['zone'][ZONE_ID].encode('ascii'), BYTEA),
                       self.encryptor_table.c.number,
                       self.encryptor_table.c.zone_id,
                       self.encryptor_table.c.raw_data,
                       self.encryptor_table.c.nullable,
                       self.encryptor_table.c.empty])
            .where(self.encryptor_table.c.id == context['id']))
        data = result.fetchone()
        return data


class TransparentEncryptionNoKeyMixin(AcraCatchLogsMixin):
    def setUp(self):
        self.checkSkip()
        try:
            self.init_key_stores()
            super().setUp()
        except:
            self.tearDown()
            raise

    def prepare_encryptor_config(self, client_id=None):
        return super().prepare_encryptor_config(client_id=self.client_id)

    def tearDown(self):
        if hasattr(self, 'acra'):
            stop_process(self.acra)
        send_signal_by_process_name('acra-server', signal.SIGKILL)
        self.server_keystore.cleanup()
        super().tearDown()

    def init_key_stores(self):
        self.client_id = 'test_client_ID'
        self.server_keystore = tempfile.TemporaryDirectory()
        self.server_keys_dir = os.path.join(self.server_keystore.name, '.acrakeys')

        create_client_keypair(name=self.client_id, keys_dir=self.server_keys_dir, only_storage=True)

        zones.append(json.loads(subprocess.check_output(
            [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-addzone'), '--keys_output_dir={}'.format(self.server_keys_dir)],
            cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT).decode('utf-8')))


    def fork_acra(self, popen_kwargs: dict=None, **acra_kwargs: dict):
        args = {'keys_dir': self.server_keys_dir, 'client_id': self.client_id}
        acra_kwargs.update(args)
        return super().fork_acra(popen_kwargs, **acra_kwargs)

    def testEncryptedInsert(self):
        destroy_server_storage_key(client_id=self.client_id, keys_dir=self.server_keys_dir, keystore_version=KEYSTORE_VERSION)
        try:
            super().testEncryptedInsert()

        except:
            log = self.read_log(self.acra)
            if KEYSTORE_VERSION == 'v1':
                no_key_error_msg = 'open {}/.acrakeys/{}_storage_sym: no such file or directory'.format(self.server_keystore.name, self.client_id)
            else:
                no_key_error_msg = 'key path does not exist'
            self.assertIn(no_key_error_msg, log)
            pass


class TestTransparentEncryptionWithNoEncryptionKey(TransparentEncryptionNoKeyMixin, TestTransparentEncryption):
    pass


class TestTransparentEncryptionWithCachedKeystore(KeystoreCacheOnStartMixin, TestTransparentEncryption):
    pass


class TestTransparentEncryptionWithZone(TestTransparentEncryption):
    ZONE = True

    def testSearch(self):
        self.skipTest("searching with encryption with zones not supported yet")

    def testSearchWithEncryptedData(self):
        self.skipTest("searching with encryption with zones not supported yet")

    def checkZoneIdEncryption(self, zone, id, default_client_id,
                              specified_client_id, number, zone_id, raw_data,
                              *args, **kwargs):
        result = self.engine1.execute(
            sa.select([self.encryptor_table.c.default_client_id,
                       self.encryptor_table.c.specified_client_id,
                       sa.cast(zone[ZONE_ID].encode('ascii'), BYTEA),
                       self.encryptor_table.c.number,
                       self.encryptor_table.c.zone_id,
                       self.encryptor_table.c.raw_data,
                       self.encryptor_table.c.nullable,
                       self.encryptor_table.c.empty])
            .where(self.encryptor_table.c.id == id))
        row = result.fetchone()
        self.assertIsNotNone(row)

        # should be decrypted
        self.assertEqual(row['zone_id'], zone_id)
        # should be as is
        self.assertEqual(row['number'], number)
        self.assertEqual(row['raw_data'], raw_data)
        # other data should be encrypted
        self.assertNotEqual(row['default_client_id'], default_client_id)
        self.assertNotEqual(row['specified_client_id'], specified_client_id)
        self.assertEqual(row['empty'], b'')

    def check_all_decryptions(self, **context):
        self.checkZoneIdEncryption(**context)


class TestTransparentEncryptionWithZoneWithNoEncryptionKey(TransparentEncryptionNoKeyMixin, TestTransparentEncryptionWithZone):
    pass


class TestTransparentEncryptionWithZoneWithCachedKeystore(KeystoreCacheOnStartMixin, TestTransparentEncryptionWithZone):
    pass


class TestPostgresqlBinaryPreparedTransparentEncryption(BaseBinaryPostgreSQLTestCase, TestTransparentEncryption):
    """Testing transparent encryption of prepared statements in PostgreSQL (binary format)."""
    FORMAT = AsyncpgExecutor.BinaryFormat

    def filterContext(self, context):
        # Context contains some extra fields which do not correspond
        # to table columns. Remove them for prepared queries.
        return {column: value for column, value in context.items()
                if column in self.encryptor_table.columns}

    def insertRow(self, context):
        context = self.filterContext(context)
        query, parameters = self.compileQuery(
            self.encryptor_table.insert(context),
            context,
        )
        self.executor2.execute_prepared_statement(query, parameters)

    def update_data(self, context):
        context = self.filterContext(context)
        # Exclude the "id" column which is a key.
        dataColumns = {column: value for column, value in context.items()
                       if column != 'id'}
        query, parameters = self.compileQuery(
            self.encryptor_table.update().
                where(self.encryptor_table.c.id == sa.bindparam('id')).
                values(dataColumns),
            context,
        )
        self.executor2.execute_prepared_statement(query, parameters)


class TestPostgresqlTextPreparedTransparentEncryption(TestPostgresqlBinaryPreparedTransparentEncryption):
    """Testing transparent encryption of prepared statements in PostgreSQL (text format)."""
    FORMAT = AsyncpgExecutor.TextFormat


class TestSetupCustomApiPort(BaseTestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def get_acraserver_api_connection_string(self, port=None):
        # use tcp instead unix socket which set as default in tests
        return 'tcp://localhost:{}'.format(port)

    def testCustomPort(self):
        custom_port = 7373
        acra = self.fork_acra(
            None, incoming_connection_api_port=custom_port)
        try:
            wait_connection(custom_port)
        finally:
            stop_process(acra)

    def check_all_decryptions(self, **context):
        self.checkZoneIdEncryption(**context)


class TestEmptyValues(BaseTestCase):
    temp_table = sa.Table('test_empty_values', metadata,
                          sa.Column('id', sa.Integer, primary_key=True),
                          sa.Column('binary', sa.LargeBinary(length=10), nullable=True),
                          sa.Column('text', sa.Text, nullable=True),
                          )

    def testEmptyValues(self):
        null_value_id = get_random_id()

        empty_value_id = get_random_id()
        # insert with NULL value
        self.engine1.execute(
            self.temp_table.insert(),
            {'id': null_value_id, 'text': None, 'binary': None})

        # insert with empty value
        self.engine1.execute(
            self.temp_table.insert(),
            {'id': empty_value_id, 'text': '', 'binary': b''})

        # check null values
        result = self.engine1.execute(sa.select([self.temp_table]).where(self.temp_table.c.id == null_value_id))
        row = result.fetchone()
        if TEST_MYSQL:
            # PyMySQL returns empty strings for NULL values
            self.assertEqual(row['text'], '')
            self.assertEqual(row['binary'], b'')
        else:
            self.assertIsNone(row['text'])
            self.assertIsNone(row['binary'])

        # check empty values
        result = self.engine1.execute(sa.select([self.temp_table]).where(self.temp_table.c.id == empty_value_id))
        row = result.fetchone()
        self.assertEqual(row['text'], '')
        self.assertEqual(row['binary'], b'')


class TestEncryptionWithIntFields(BaseTestCase):
    temp_table = sa.Table('test_integer_data_fields', metadata,
                          sa.Column('id', sa.Integer, primary_key=True),
                          sa.Column('data', sa.LargeBinary(length=10), nullable=True),
                          sa.Column('number', sa.Integer),
                          sa.Column('binary', sa.LargeBinary(length=10), nullable=True),
                          )

    def testEncryptWithIntFields(self):
        value_id = get_random_id()
        data = b'42 is the answer'
        number = 8800
        binary = b'some\x00binary\x01data'

        data_encrypted = create_acrastruct(
            data,
            read_storage_public_key(TLS_CERT_CLIENT_ID_1, KEYS_FOLDER.name)
        )

        # insert some data
        self.engine1.execute(
            self.temp_table.insert(),
            {'id': value_id, 'data': data_encrypted, 'number': number, 'binary': binary})

        # check values (select all)
        result = self.engine1.execute(sa.select([self.temp_table]).where(self.temp_table.c.id == value_id))
        row = result.fetchone()
        self.assertEqual(row['id'], value_id)
        self.assertEqual(row['data'], data)
        self.assertEqual(row['number'], number)
        self.assertEqual(row['binary'], binary)

        # check values (select numbers only)
        result = self.engine1.execute(
            sa
                .select([self.temp_table.columns.id, self.temp_table.columns.number])
                .where(self.temp_table.c.id == value_id)
        )
        row = result.fetchone()
        self.assertEqual(row['id'], value_id)
        self.assertEqual(row['number'], number)

        # check values (select encrypted only)
        result = self.engine1.execute(
            sa
                .select([self.temp_table.columns.data])
                .where(self.temp_table.c.id == value_id)
        )
        row = result.fetchone()
        self.assertEqual(row['data'], data)

        # check values (select everything except encrypted)
        result = self.engine1.execute(
            sa
                .select([self.temp_table.columns.id, self.temp_table.columns.number, self.temp_table.columns.binary])
                .where(self.temp_table.c.id == value_id)
        )
        row = result.fetchone()
        self.assertEqual(row['id'], value_id)
        self.assertEqual(row['number'], number)
        self.assertEqual(row['binary'], binary)


class TestOutdatedServiceConfigs(BaseTestCase, FailedRunProcessMixin):
    def setUp(self):
        return

    def tearDown(self):
        return

    def remove_version_from_config(self, path):
        config = load_yaml_config(path)
        del config['version']
        dump_yaml_config(config, path)

    def replace_version_in_config(self, version, path):
        config = load_yaml_config(path)
        config['version'] = version
        dump_yaml_config(config, path)

    def testStartupWithoutVersionInConfig(self):
        files = os.listdir('cmd/')
        services = [i for i in files if os.path.isdir(os.path.join('cmd', i))]
        self.assertTrue(services)

        with tempfile.TemporaryDirectory() as tmp_dir:
            # generate configs for tests
            subprocess.check_output(['configs/regenerate.sh', tmp_dir], env={'BINARY_FOLDER': BINARY_OUTPUT_FOLDER})

            for service in services:
                self.remove_version_from_config(os.path.join(tmp_dir, service + '.yaml'))

            default_args = {
                'acra-server': ['-db_host=127.0.0.1'],
                'acra-keys': [],
                'acra-heartbeat': ['--logging_format=plaintext'],
            }
            for service in services:
                config_param = '-config_file={}'.format(os.path.join(tmp_dir, '{}.yaml'.format(service)))
                args = [os.path.join(BINARY_OUTPUT_FOLDER, service), config_param] + default_args.get(service, [])
                stderr = self.getOutputFromProcess(args)
                self.assertIn('error="config hasn\'t version key"', stderr)

    def testStartupWithOutdatedConfigVersion(self):
        files = os.listdir('cmd/')
        services = [i for i in files if os.path.isdir(os.path.join('cmd', i))]
        self.assertTrue(services)

        with tempfile.TemporaryDirectory() as tmp_dir:
            # generate configs for tests
            subprocess.check_output(['configs/regenerate.sh', tmp_dir], env={'BINARY_FOLDER': BINARY_OUTPUT_FOLDER})

            for service in services:
                self.replace_version_in_config('0.0.0', os.path.join(tmp_dir, service + '.yaml'))

            default_args = {
                'acra-server': ['-db_host=127.0.0.1'],
                'acra-keys': [],
                'acra-heartbeat': ['--logging_format=plaintext'],
            }
            for service in services:
                config_param = '-config_file={}'.format(os.path.join(tmp_dir, '{}.yaml'.format(service)))
                args = [os.path.join(BINARY_OUTPUT_FOLDER, service), config_param] + default_args.get(service, [])
                stderr = self.getOutputFromProcess(args)
                self.assertRegexpMatches(stderr, r'code=508 error="config version \\"0.0.0\\" is not supported, expects \\"[\d.]+\\" version')

    def testStartupWithDifferentConfigsPatchVersion(self):
        files = os.listdir('cmd/')
        services = [i for i in files if os.path.isdir(os.path.join('cmd/', i))]
        self.assertTrue(services)

        with tempfile.TemporaryDirectory() as tmp_dir:
            # generate configs for tests
            subprocess.check_output(['configs/regenerate.sh', tmp_dir], env={'BINARY_FOLDER': BINARY_OUTPUT_FOLDER})

            for service in services:
                config_path = os.path.join(tmp_dir, service + '.yaml')
                config = load_yaml_config(config_path)
                version = semver.parse(config['version'])
                version['patch'] = 100500
                config['version'] = semver.format_version(**version)
                dump_yaml_config(config, config_path)

            default_args = {
                'acra-addzone': ['-keys_output_dir={}'.format(KEYS_FOLDER.name)],
                'acra-heartbeat': {'args': ['--logging_format=plaintext',
                                            '--connection_string=please-fail'],
                                   'status': 1},
                'acra-keymaker': ['-keys_output_dir={}'.format(tmp_dir),
                                  '-keys_public_output_dir={}'.format(tmp_dir),
                                  '--keystore={}'.format(KEYSTORE_VERSION)],
                'acra-keys': [],
                'acra-poisonrecordmaker': ['-keys_dir={}'.format(tmp_dir)],
                'acra-rollback': {'args': ['-keys_dir={}'.format(tmp_dir)],
                                  'status': 1},
                'acra-rotate': {'args': ['-keys_dir={}'.format(tmp_dir)],
                                'status': 0},
                'acra-translator': {'connection': 'connection_string',
                                   'args': ['-keys_dir={}'.format(KEYS_FOLDER.name),
                                            # empty id to raise error
                                            '--securesession_id=""'],
                                   'status': 1},
                'acra-server': {'args': ['-keys_dir={}'.format(KEYS_FOLDER.name)],
                                'status': 1},
            }

            for service in services:
                test_data = default_args.get(service, [])
                expected_status_code = 0
                if isinstance(test_data, dict):
                    expected_status_code = test_data['status']
                    service_args = test_data['args']
                else:
                    service_args = test_data

                config_param = '-config_file={}'.format(os.path.join(tmp_dir, '{}.yaml'.format(service)))
                args = [os.path.join(BINARY_OUTPUT_FOLDER, service), config_param] + service_args
                stderr = self.getOutputFromProcess(args)
                self.assertNotRegex(stderr, r'code=508 error="config version \\"[\d.+]\\" is not supported, expects \\"[\d.]+\\" version')

    def testStartupWithoutConfig(self):
        files = os.listdir('cmd/')
        services = [i for i in files if os.path.isdir(os.path.join('cmd/', i))]
        self.assertTrue(services)

        with tempfile.TemporaryDirectory() as tmp_dir:
            default_args = {
                'acra-addzone': ['-keys_output_dir={}'.format(KEYS_FOLDER.name)],
                'acra-heartbeat': {'args': ['--logging_format=plaintext',
                                            '--connection_string=please-fail'],
                                   'status': 1},
                'acra-keymaker': ['-keys_output_dir={}'.format(tmp_dir),
                                  '-keys_public_output_dir={}'.format(tmp_dir),
                                  '--keystore={}'.format(KEYSTORE_VERSION)],
                'acra-keys': [],
                'acra-poisonrecordmaker': ['-keys_dir={}'.format(tmp_dir)],
                'acra-rollback': {'args': ['-keys_dir={}'.format(tmp_dir)],
                                  'status': 1},
                'acra-rotate': {'args': ['-keys_dir={}'.format(tmp_dir)],
                                'status': 0},
                'acra-translator': {'connection': 'connection_string',
                                    'args': ['-keys_dir={}'.format(KEYS_FOLDER.name),
                                             # empty id to raise error
                                             '--securesession_id=""'],
                                    'status': 1},
                'acra-server': {'args': ['-keys_dir={}'.format(KEYS_FOLDER.name)],
                                'status': 1},
            }

            for service in services:
                test_data = default_args.get(service, [])
                expected_status_code = 0
                if isinstance(test_data, dict):
                    expected_status_code = test_data['status']
                    service_args = test_data['args']
                else:
                    service_args = test_data

                args = [os.path.join(BINARY_OUTPUT_FOLDER, service), '-config_file=""'] + service_args
                stderr = self.getOutputFromProcess(args)
                self.assertNotRegex(stderr, r'code=508 error="config version \\"[\d.]\\" is not supported, expects \\"[\d.]+\\" version')


class TestPgPlaceholders(BaseTestCase):
    def checkSkip(self):
        if TEST_MYSQL or not TEST_POSTGRESQL:
            self.skipTest("test only for postgresql")
        elif not TEST_WITH_TLS:
            self.skipTest("running tests only with TLS")

    def testPgPlaceholders(self):
        connection_args = ConnectionArgs(host=get_db_host(), port=self.ACRASERVER_PORT,
                                         user=DB_USER, password=DB_USER_PASSWORD,
                                         dbname=DB_NAME, ssl_ca=TEST_TLS_CA,
                                         ssl_key=TEST_TLS_CLIENT_KEY,
                                         ssl_cert=TEST_TLS_CLIENT_CERT)

        executor = AsyncpgExecutor(connection_args)

        # empty table will return 0 rows in first select and return our expected data from union
        # we test placeholders in SELECT and WHERE clause in such way
        query = "select $1::bytea from {table} where {column}=$1::bytea UNION select $1::bytea;".format(
            table=test_table.name, column=test_table.c.data.name)
        test_data = b'some data'

        data = executor.execute(query, [test_data])
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0][0], test_data)

        executor.execute_prepared_statement(query, [test_data])
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0][0], test_data)


class TLSAuthenticationDirectlyToAcraMixin:
    """Start acra-server TLS mode and use clientID from certificates
    self.engine1 uses TEST_TLS_CLIENT_* and self.engine2 uses TEST_TLS_CLIENT_2_* values as TLS credentials"""
    def setUp(self):
        if not TEST_WITH_TLS:
            self.skipTest("Test works only with TLS support on db side")
        self.acra_writer_id = extract_client_id_from_cert(tls_cert=TEST_TLS_CLIENT_CERT, extractor=self.get_identifier_extractor_type())
        self.assertEqual(create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_CERT,
                                                                extractor=self.get_identifier_extractor_type(), keys_dir=KEYS_FOLDER.name), 0)
        # generate encryption keys for second certificate too
        self.assertEqual(create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_2_CERT,
                                                                extractor=self.get_identifier_extractor_type(), keys_dir=KEYS_FOLDER.name), 0)
        try:
            if not self.EXTERNAL_ACRA:
                # start acra with configured TLS
                self.acra = self.fork_acra(
                    tls_key=abs_path(TEST_TLS_SERVER_KEY),
                    tls_cert=abs_path(TEST_TLS_SERVER_CERT),
                    tls_ca=TEST_TLS_CA,
                    keys_dir=KEYS_FOLDER.name,
                    tls_identifier_extractor_type=self.get_identifier_extractor_type())

            # create two engines which should use different client's certificates for authentication
            base_args = get_connect_args(port=self.ACRASERVER_PORT, sslmode='require')
            tls_args_1 = base_args.copy()
            tls_args_1.update(get_tls_connection_args(TEST_TLS_CLIENT_KEY, TEST_TLS_CLIENT_CERT))
            self.engine1 = sa.create_engine(
                get_engine_connection_string(self.get_acraserver_connection_string(self.ACRASERVER_PORT), DB_NAME),
                connect_args=tls_args_1)

            tls_args_2 = base_args.copy()
            tls_args_2.update(get_tls_connection_args(TEST_TLS_CLIENT_2_KEY, TEST_TLS_CLIENT_2_CERT))
            self.engine2 = sa.create_engine(
                get_engine_connection_string(self.get_acraserver_connection_string(self.ACRASERVER_PORT), DB_NAME),
                connect_args=tls_args_2)

            self.engine_raw = sa.create_engine(
                '{}://{}:{}/{}'.format(DB_DRIVER, DB_HOST, DB_PORT, DB_NAME),
                connect_args=connect_args)

            self.engines = [self.engine1, self.engine2, self.engine_raw]

            metadata.create_all(self.engine_raw)
            self.engine_raw.execute('delete from test;')
            for engine in self.engines:
                count = 0
                # try with sleep if acra not up yet
                while True:
                    try:
                        if TEST_MYSQL:
                            engine.execute("select 1;")
                        else:
                            engine.execute(
                                "UPDATE pg_settings SET setting = '{}' "
                                "WHERE name = 'bytea_output'".format(self.DB_BYTEA))
                        break
                    except Exception as e:
                        time.sleep(SETUP_SQL_COMMAND_TIMEOUT)
                        count += 1
                        if count == SQL_EXECUTE_TRY_COUNT:
                            raise
        except:
            self.tearDown()
            raise

    def tearDown(self):
        try:
            self.log_prometheus_metrics()
            self.clear_prometheus_addresses()
        except:
            pass
        try:
            self.engine_raw.execute('delete from test;')
        except:
            pass
        for engine in getattr(self, 'engines', []):
            engine.dispose()
        processes = [getattr(self, 'acra', ProcessStub())]
        stop_process(processes)
        send_signal_by_process_name('acra-server', signal.SIGKILL)


class TestDirectTLSAuthenticationFailures(TLSAuthenticationBySerialNumberMixin, BaseTestCase):
    # override setUp/tearDown from BaseTestCase to avoid extra initialization
    def setUp(self):
        if not TEST_WITH_TLS:
            self.skipTest("Test works only with TLS support on db side")

    def tearDown(self):
        pass

    def testInvalidClientAuthConfiguration(self):
        # try to start server with --tls_auth=0 and extracting client_id from TLS which is invalid together
        # because tls_auth=0 doesn't require client's certificate on handshake
        self.assertEqual(create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_CERT, keys_dir=KEYS_FOLDER.name), 0)
        # generate encryption keys for second certificate too
        self.assertEqual(create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_2_CERT, keys_dir=KEYS_FOLDER.name), 0)
        with self.assertRaises(Exception) as exc:
            self.fork_acra(
                tls_key=abs_path(TEST_TLS_SERVER_KEY),
                tls_cert=abs_path(TEST_TLS_SERVER_CERT),
                tls_ca=TEST_TLS_CA,
                tls_auth=0,
                keys_dir=KEYS_FOLDER.name,
                tls_identifier_extractor_type=self.get_identifier_extractor_type())
        # sometimes process start so fast that fork returns PID and between CLI checks and returning os.Exit(1)
        # python code starts connection loop even after process interruption
        self.assertIn(exc.exception.args[0], ('Can\'t fork', WAIT_CONNECTION_ERROR_MESSAGE))

    def testDirectConnectionWithoutCertificate(self):
        # try to start server with --tls_auth >= 1 and extracting client_id from TLS and connect directly without
        # providing any certificate
        self.assertEqual(create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_CERT, keys_dir=KEYS_FOLDER.name), 0)
        # generate encryption keys for second certificate too
        self.assertEqual(create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_2_CERT, keys_dir=KEYS_FOLDER.name), 0)
        acra = ProcessStub()
        for tls_auth in range(1, 5):
            try:
                acra = self.fork_acra(
                    tls_key=abs_path(TEST_TLS_SERVER_KEY),
                    tls_cert=abs_path(TEST_TLS_SERVER_CERT),
                    tls_ca=TEST_TLS_CA,
                    tls_auth=tls_auth,
                    keys_dir=KEYS_FOLDER.name,
                    tls_identifier_extractor_type=self.get_identifier_extractor_type())

                base_args = get_connect_args(port=self.ACRASERVER_PORT, sslmode='require')
                tls_args_1 = base_args.copy()
                tls_args_1.update(get_tls_connection_args_without_certificate())
                if TEST_POSTGRESQL:
                    expected_exception = psycopg2.OperationalError
                else:
                    expected_exception = pymysql.err.OperationalError
                print(expected_exception)
                engine1 = sa.create_engine(
                    get_engine_connection_string(
                        self.get_acraserver_connection_string(self.ACRASERVER_PORT), DB_NAME),
                    connect_args=tls_args_1)
                with self.assertRaises(expected_exception) as exc:
                    # test query
                    engine1.execute('select 1')
            except Exception as exc2:
                pass
            finally:
                stop_process(acra)


class TestTLSAuthenticationDirectlyToAcraByDistinguishedName(TLSAuthenticationDirectlyToAcraMixin, TLSAuthenticationByDistinguishedNameMixin, BaseTestCase):
    """
    Tests environment when client's app connect to db through acra-server with TLS and acra-server extracts clientID from client's certificate
    instead using from --clientID CLI param
    """
    def testServerRead(self):
        """test decrypting with correct client_id and not decrypting with
        incorrect client_id or using direct connection to db"""
        self.assertEqual(create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_CERT,
                                                                extractor=self.get_identifier_extractor_type(), keys_dir=KEYS_FOLDER.name), 0)
        server_public1 = read_storage_public_key(self.acra_writer_id, KEYS_FOLDER.name)
        data = get_pregenerated_random_data()
        acra_struct = create_acrastruct(
            data.encode('ascii'), server_public1)
        row_id = get_random_id()

        self.log(storage_client_id=self.acra_writer_id,
                 data=acra_struct, expected=data.encode('ascii'))

        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': acra_struct, 'raw_data': data})
        result = self.engine1.execute(
            sa.select([test_table])
                .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertEqual(row['data'], row['raw_data'].encode('utf-8'))
        self.assertEqual(row['empty'], b'')

        result = self.engine2.execute(
            sa.select([test_table])
                .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'].decode('ascii', errors='ignore'),
                            row['raw_data'])
        self.assertEqual(row['empty'], b'')

        result = self.engine_raw.execute(
            sa.select([test_table])
                .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'].decode('ascii', errors='ignore'),
                            row['raw_data'])
        self.assertEqual(row['empty'], b'')


    def testReadAcrastructInAcrastruct(self):
        """test correct decrypting acrastruct when acrastruct concatenated to
        partial another acrastruct"""
        server_public1 = read_storage_public_key(self.acra_writer_id, KEYS_FOLDER.name)
        incorrect_data = get_pregenerated_random_data()
        correct_data = get_pregenerated_random_data()
        suffix_data = get_pregenerated_random_data()[:10]
        fake_offset = (3+45+84) - 4
        fake_acra_struct = create_acrastruct(
            incorrect_data.encode('ascii'), server_public1)[:fake_offset]
        inner_acra_struct = create_acrastruct(
            correct_data.encode('ascii'), server_public1)
        data = fake_acra_struct + inner_acra_struct + suffix_data.encode('ascii')
        correct_data = correct_data + suffix_data
        row_id = get_random_id()

        self.log(storage_client_id=self.acra_writer_id,
                 data=data,
                 expected=fake_acra_struct+correct_data.encode('ascii'))

        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': data, 'raw_data': correct_data})
        result = self.engine1.execute(
            sa.select([test_table])
                .where(test_table.c.id == row_id))
        row = result.fetchone()
        try:
            self.assertEqual(row['data'][fake_offset:],
                             row['raw_data'].encode('utf-8'))
            self.assertEqual(row['data'][:fake_offset], fake_acra_struct[:fake_offset])
        except:
            print('incorrect data: {}\ncorrect data: {}\ndata: {}\n data len: {}'.format(
                incorrect_data, correct_data, row['data'], len(row['data'])))
            raise
        self.assertEqual(row['empty'], b'')

        result = self.engine2.execute(
            sa.select([test_table])
                .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'][fake_offset:].decode('ascii', errors='ignore'),
                            row['raw_data'])
        self.assertEqual(row['empty'], b'')

        result = self.engine_raw.execute(
            sa.select([test_table])
                .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'][fake_offset:].decode('ascii', errors='ignore'),
                            row['raw_data'])
        self.assertEqual(row['empty'], b'')


class TestTLSAuthenticationDirectlyToAcraBySerialNumber(TLSAuthenticationBySerialNumberMixin,
                                                        TestTLSAuthenticationDirectlyToAcraByDistinguishedName):
    pass


class TestTLSAuthenticationDirectlyToAcraBySerialNumberConnectionsClosed(AcraCatchLogsMixin,TLSAuthenticationBySerialNumberMixin,
                                                        TestTLSAuthenticationDirectlyToAcraByDistinguishedName):
    """
    Test AcraServer proper Client/DB connections closing
    """

    def testReadAcrastructInAcrastruct(self):
        super().testReadAcrastructInAcrastruct()
        self.assertIn("Finished processing client's connection", self.read_log(self.acra))

    def testServerRead(self):
        super().testServerRead()
        self.assertIn("Finished processing client's connection", self.read_log(self.acra))


class BaseSearchableTransparentEncryption(TestTransparentEncryption):
    encryptor_table = sa.Table(
        'test_searchable_transparent_encryption', metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('specified_client_id',
                  sa.LargeBinary(length=COLUMN_DATA_SIZE)),
        sa.Column('default_client_id',
                  sa.LargeBinary(length=COLUMN_DATA_SIZE)),

        sa.Column('number', sa.Integer),
        sa.Column('zone_id', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
        sa.Column('raw_data', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
        sa.Column('nullable', sa.Text, nullable=True),
        sa.Column('searchable', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
        sa.Column('searchable_acrablock', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
        sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
        sa.Column('token_i32', sa.Integer(), nullable=False, default=1),
        sa.Column('token_i64', sa.BigInteger(), nullable=False, default=1),
        sa.Column('token_str', sa.Text, nullable=False, default=''),
        sa.Column('token_bytes', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
        sa.Column('token_email', sa.Text, nullable=False, default=''),
        sa.Column('masking', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
    )
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/ee_encryptor_config.yaml')

    def fork_acra(self, popen_kwargs: dict=None, **acra_kwargs: dict):
        # Disable keystore cache since it can interfere with rotation tests
        acra_kwargs['keystore_cache_size'] = -1
        return super(BaseSearchableTransparentEncryption, self).fork_acra(popen_kwargs, **acra_kwargs)

    def fetch_raw_data(self, context):
        result = self.engine_raw.execute(
            sa.select([self.encryptor_table.c.default_client_id,
                       self.encryptor_table.c.specified_client_id,
                       sa.cast(context['zone'][ZONE_ID].encode('ascii'), BYTEA),
                       self.encryptor_table.c.number,
                       self.encryptor_table.c.zone_id,
                       self.encryptor_table.c.raw_data,
                       self.encryptor_table.c.nullable,
                       self.encryptor_table.c.searchable,
                       self.encryptor_table.c.empty])
                .where(self.encryptor_table.c.id == context['id']))
        data = result.fetchone()
        return data

    def update_data(self, context):
        self.engine2.execute(
            sa.update(self.encryptor_table)
                .where(self.encryptor_table.c.id == context['id'])
                .values(default_client_id=context['default_client_id'],
                        specified_client_id=context['specified_client_id'],
                        zone_id=context['zone_id'],
                        raw_data=context['raw_data'],
                        searchable=context.get('searchable'),
                        empty=context.get('empty', b''),
                        nullable=context.get('nullable', None))
        )

    def get_context_data(self):
        context = {
            'id': get_random_id(),
            'default_client_id': get_pregenerated_random_data().encode('ascii'),
            'number': get_random_id(),
            'zone_id': get_pregenerated_random_data().encode('ascii'),
            'specified_client_id': get_pregenerated_random_data().encode('ascii'),
            'raw_data': get_pregenerated_random_data().encode('ascii'),
            'zone': zones[0],
            'searchable': get_pregenerated_random_data().encode('ascii'),
            'searchable_acrablock': get_pregenerated_random_data().encode('ascii'),
            'empty': b'',
            'nullable': None,
            'masking': get_pregenerated_random_data().encode('ascii'),
            'token_bytes': get_pregenerated_random_data().encode('ascii'),
            'token_email': get_pregenerated_random_data(),
            'token_str': get_pregenerated_random_data(),
            'token_i32': random.randint(0, 2 ** 16),
            'token_i64': random.randint(0, 2 ** 32),
        }
        return context

    def insertDifferentRows(self, context, count, search_term=None, search_field='searchable'):
        if not search_term:
            search_term = context[search_field]
        temp_context = context.copy()
        while count != 0:
            new_data = get_pregenerated_random_data().encode('utf-8')
            if new_data != search_term:
                temp_context[search_field] = new_data
                temp_context['id'] = context['id'] + count
                self.insertRow(temp_context)
                count -= 1

    def executeSelect2(self, query, parameters):
        """Execute a SELECT query with parameters via AcraServer for "keypair2"."""
        return self.engine2.execute(query, parameters).fetchall()

    def executeBulkInsert(self, query, values):
        """Execute a Bulk Insert query with list of values via AcraServer for "TEST_TLS_CLIENT_2_CERT"."""
        return self.engine2.execute(query.values(values))


class BaseSearchableTransparentEncryptionBinaryPostgreSQLMixin(BaseBinaryPostgreSQLTestCase, BaseTestCase):
    def executeSelect2(self, query, parameters):
        query, parameters = self.compileQuery(query, parameters)
        return self.executor2.execute_prepared_statement(query, parameters)

    def executeBulkInsert(self, query, values):
        """Execute a Bulk Insert query with list of values via AcraServer for "TEST_TLS_CLIENT_2_CERT"."""
        query, parameters = self.compileBulkInsertQuery(query.values(values), values)
        return self.executor2.execute_prepared_statement(query, parameters)


class BaseSearchableTransparentEncryptionBinaryMySQLMixin(BaseBinaryMySQLTestCase, BaseTestCase):
    def executeSelect2(self, query, parameters):
        query, parameters = self.compileQuery(query, parameters)
        return self.executor2.execute_prepared_statement(query, parameters)

    def executeBulkInsert(self, query, values):
        """Execute a Bulk Insert query with list of values via AcraServer for "TEST_TLS_CLIENT_2_CERT"."""
        query, parameters = self.compileBulkInsertQuery(query.values(values), values)
        return self.executor2.execute_prepared_statement_no_result(query, parameters)


class TestSearchableTransparentEncryption(BaseSearchableTransparentEncryption):
    def testSearch(self):
        context = self.get_context_data()
        search_term = context['searchable']

        # Insert searchable data and some additional different rows
        self.insertRow(context)
        self.insertDifferentRows(context, count=5)

        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
                .where(self.encryptor_table.c.searchable == sa.bindparam('searchable')),
            {'searchable': search_term},
            )
        self.assertEqual(len(rows), 1)

        self.checkDefaultIdEncryption(**context)
        self.assertEqual(rows[0]['searchable'], search_term)

    def testHashValidation(self):
        context = self.get_context_data()
        search_term = context['searchable']

        # Insert searchable data and some additional different rows
        self.insertRow(context)

        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
                .where(self.encryptor_table.c.searchable == sa.bindparam('searchable')),
            {'searchable': search_term},
                )
        self.assertEqual(len(rows), 1)

        self.checkDefaultIdEncryption(**context)
        self.assertEqual(rows[0]['searchable'], search_term)

        encrypted_data = self.fetch_raw_data(context)

        searchable_encrypted_data = bytearray(encrypted_data['searchable'])
        searchable_encrypted_data[5:10] = os.urandom(5)
        tamper_searchable_data = searchable_encrypted_data

        self.engine_raw.execute(
            sa.update(self.encryptor_table)
                .where(self.encryptor_table.c.id == context['id'])
                .values(searchable=tamper_searchable_data))

        result = self.engine2.execute(
            sa.select([self.encryptor_table]).where(self.encryptor_table.c.id == context['id']))

        row = result.fetchone()
        self.assertIsNotNone(row)

        self.assertEqual(row['default_client_id'], context['default_client_id'])
        self.assertNotEqual(row['searchable'], context['searchable'])
        self.assertNotEqual(row['specified_client_id'], context['specified_client_id'])

    def testBulkInsertSearch(self):
        context = self.get_context_data()
        search_term = context['searchable']

        search_context = context.copy()
        # we should delete redundant `zone` key to compile bulk insert query
        # https://docs.sqlalchemy.org/en/13/changelog/migration_08.html#unconsumed-column-names-warning-becomes-an-exception
        del search_context['zone']
        values = [search_context]
        for idx in range(5):
            insert_context = self.get_context_data()
            new_data = get_pregenerated_random_data().encode('utf-8')
            if new_data != search_term:
                insert_context['searchable'] = new_data
                del insert_context['zone']
                values.append(insert_context.copy())

        self.executeBulkInsert(self.encryptor_table.insert(), values)

        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
                .where(self.encryptor_table.c.searchable == sa.bindparam('searchable')),
            {'searchable': search_term},
                )
        self.assertEqual(len(rows), 1)

        self.checkDefaultIdEncryption(**context)
        self.assertEqual(rows[0]['searchable'], search_term)
        for value in values:
            value['zone'] = zones[0],
            self.checkDefaultIdEncryption(**value)

    def testSearchAcraBlock(self):
        context = self.get_context_data()
        row_id = context['id']
        search_term = context['searchable_acrablock']

        # Insert searchable data and some additional different rows
        self.insertRow(context)
        self.insertDifferentRows(context, count=5, search_field='searchable_acrablock')

        rows = self.engine_raw.execute(
            sa.select([self.encryptor_table.c.searchable_acrablock])
                .where(self.encryptor_table.c.id == row_id)).fetchall()
        self.assertTrue(rows)

        temp_acrastruct = create_acrastruct_with_client_id(b'somedata', TLS_CERT_CLIENT_ID_1)
        # AcraBlock should have half of AcraStruct begin tag. Check that searchable_acrablock is not AcraStruct
        self.assertNotEqual(rows[0]['searchable_acrablock'][:8], temp_acrastruct[:8])
        # skip 33 bytes of hash
        self.assertEqual(rows[0]['searchable_acrablock'][33:33+3], CRYPTO_ENVELOPE_HEADER)

        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
                .where(self.encryptor_table.c.searchable_acrablock == sa.bindparam('searchable_acrablock')),
            {'searchable_acrablock': search_term})
        self.assertEqual(len(rows), 1)

        self.checkDefaultIdEncryption(**context)
        self.assertEqual(rows[0]['searchable_acrablock'], search_term)

    def testSearchWithEncryptedData(self):
        context = self.get_context_data()
        not_encrypted_term = context['raw_data']
        search_term = context['searchable']
        encrypted_term = create_acrastruct_with_client_id(
            search_term, TLS_CERT_CLIENT_ID_2)
        context['searchable'] = encrypted_term

        # Insert searchable data and some additional different rows
        self.insertRow(context)
        # Use plaintext search term here to avoid mismatches
        self.insertDifferentRows(context, count=5, search_term=search_term)

        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
                .where(sa.and_(
                    self.encryptor_table.c.searchable == sa.bindparam('searchable'),
                    self.encryptor_table.c.raw_data == sa.bindparam('raw_data'))),
            {'searchable': search_term,
             'raw_data': not_encrypted_term},
        )
        self.assertEqual(len(rows), 1)

        self.checkDefaultIdEncryption(**context)
        self.assertEqual(rows[0]['searchable'], search_term)

        result = self.engine2.execute(
            sa.select([self.encryptor_table])
                .where(self.encryptor_table.c.searchable == encrypted_term))
        rows = result.fetchall()
        self.assertEqual(len(rows), 1)

        self.checkDefaultIdEncryption(**context)
        self.assertEqual(rows[0]['searchable'], search_term)

    def testSearchAcraBlockWithEncryptedData(self):
        context = self.get_context_data()
        row_id = context['id']
        not_encrypted_term = context['raw_data']
        search_term = context['searchable_acrablock']
        encrypted_term = create_acrastruct_with_client_id(
            search_term, TLS_CERT_CLIENT_ID_2)
        context['searchable_acrablock'] = encrypted_term

        # Insert searchable data and some additional different rows
        self.insertRow(context)
        # Use plaintext search term here to avoid mismatches
        self.insertDifferentRows(context, count=5, search_term=search_term, search_field='searchable_acrablock')

        rows = self.engine_raw.execute(
            sa.select([self.encryptor_table.c.searchable_acrablock])
                .where(self.encryptor_table.c.id == row_id)).fetchall()
        self.assertTrue(rows)

        # AcraBlock should have half of AcraStruct begin tag. Check that searchable_acrablock is not AcraStruct
        self.assertNotEqual(rows[0]['searchable_acrablock'][:8], encrypted_term[:8])
        # skip 33 bytes of hash
        self.assertEqual(rows[0]['searchable_acrablock'][33:33+4], encrypted_term[:4])

        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
                .where(sa.and_(
                self.encryptor_table.c.searchable_acrablock == sa.bindparam('searchable_acrablock'),
                self.encryptor_table.c.raw_data == sa.bindparam('raw_data'))),
            {'searchable_acrablock': search_term,
             'raw_data': not_encrypted_term},
                )
        self.assertEqual(len(rows), 1)

        self.checkDefaultIdEncryption(**context)
        self.assertEqual(rows[0]['searchable_acrablock'], search_term)

        result = self.engine2.execute(
            sa.select([self.encryptor_table])
                .where(self.encryptor_table.c.searchable_acrablock == encrypted_term))
        rows = result.fetchall()
        self.assertEqual(len(rows), 1)

        self.checkDefaultIdEncryption(**context)
        self.assertEqual(rows[0]['searchable_acrablock'], search_term)

    def testRotatedKeys(self):
        """Verify decryption of searchable data with old keys."""
        context = self.get_context_data()
        # Encrypt searchable data with epoch 1 key
        search_term = context['searchable']
        encrypted_term = create_acrastruct_with_client_id(
            search_term, TLS_CERT_CLIENT_ID_2)
        context['searchable'] = encrypted_term

        # Insert searchable data and some additional different rows
        self.insertRow(context)
        # Use plaintext search term here to avoid mismatches
        self.insertDifferentRows(context, count=5, search_term=search_term)

        # Encrypt the search term again with the same epoch 1 key,
        # this will result in different encrypted data on outside
        encrypted_term_1 = create_acrastruct_with_client_id(
            search_term, TLS_CERT_CLIENT_ID_2)
        self.assertNotEqual(encrypted_term_1, encrypted_term)

        # However, searchable encryption should still work with that
        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
                .where(self.encryptor_table.c.searchable == sa.bindparam('searchable')),
            {'searchable': encrypted_term_1},
            )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['searchable'], search_term)

        # Now, rotate the encryption keys
        create_client_keypair(TLS_CERT_CLIENT_ID_2, only_storage=True)

        # Encrypt the search term again, now with the epoch 2 key
        encrypted_term_2 = create_acrastruct_with_client_id(
            search_term, TLS_CERT_CLIENT_ID_2)
        self.assertNotEqual(encrypted_term_2, encrypted_term)
        self.assertNotEqual(encrypted_term_2, encrypted_term_1)

        # And searchable encryption should still work
        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
                .where(self.encryptor_table.c.searchable == sa.bindparam('searchable')),
            {'searchable': encrypted_term_2},
            )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['searchable'], search_term)

        # If you try the data encrypted with epoch 1 key, it should still work
        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
                .where(self.encryptor_table.c.searchable == sa.bindparam('searchable')),
            {'searchable': encrypted_term_1},
            )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['searchable'], search_term)

    def testRotatedKeysAcraBlock(self):
        """Verify decryption of searchable data with old keys."""
        context = self.get_context_data()
        row_id = context['id']
        # Encrypt searchable data with epoch 1 key
        search_term = context['searchable_acrablock']
        encrypted_term = create_acrastruct_with_client_id(
            search_term, TLS_CERT_CLIENT_ID_2)
        context['searchable_acrablock'] = encrypted_term

        # Insert searchable data and some additional different rows
        self.insertRow(context)
        # Use plaintext search term here to avoid mismatches
        self.insertDifferentRows(context, count=5, search_term=search_term, search_field='searchable_acrablock')

        rows = self.engine_raw.execute(
            sa.select([self.encryptor_table.c.searchable_acrablock])
            .where(self.encryptor_table.c.id == row_id)).fetchall()
        self.assertTrue(rows)

        # AcraBlock should have half of AcraStruct begin tag. Check that searchable_acrablock is not AcraStruct
        self.assertNotEqual(rows[0]['searchable_acrablock'][:8], encrypted_term[:8])
        # skip 33 bytes of hash
        self.assertEqual(rows[0]['searchable_acrablock'][33:33+4], encrypted_term[:4])

        # Encrypt the search term again with the same epoch 1 key,
        # this will result in different encrypted data on outside
        encrypted_term_1 = create_acrastruct_with_client_id(
            search_term, TLS_CERT_CLIENT_ID_2)
        self.assertNotEqual(encrypted_term_1, encrypted_term)

        # However, searchable encryption should still work with that
        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
                .where(self.encryptor_table.c.searchable_acrablock == sa.bindparam('searchable_acrablock')),
            {'searchable_acrablock': encrypted_term_1},
                )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['searchable_acrablock'], search_term)

        # Now, rotate the encryption keys
        create_client_keypair(TLS_CERT_CLIENT_ID_2, only_storage=True)

        # Encrypt the search term again, now with the epoch 2 key
        encrypted_term_2 = create_acrastruct_with_client_id(
            search_term, TLS_CERT_CLIENT_ID_2)
        self.assertNotEqual(encrypted_term_2, encrypted_term)
        self.assertNotEqual(encrypted_term_2, encrypted_term_1)

        # And searchable encryption should still work
        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
                .where(self.encryptor_table.c.searchable_acrablock == sa.bindparam('searchable_acrablock')),
            {'searchable_acrablock': encrypted_term_2},
                )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['searchable_acrablock'], search_term)

        # If you try the data encrypted with epoch 1 key, it should still work
        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
                .where(self.encryptor_table.c.searchable_acrablock == sa.bindparam('searchable_acrablock')),
            {'searchable_acrablock': encrypted_term_1},
                )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['searchable_acrablock'], search_term)

        rows = self.engine_raw.execute(
            sa.select([self.encryptor_table.c.searchable_acrablock])
                .where(self.encryptor_table.c.id == row_id)).fetchall()
        self.assertTrue(rows)

        # AcraBlock should have half of AcraStruct begin tag. Check that searchable_acrablock is not AcraStruct
        self.assertNotEqual(rows[0]['searchable_acrablock'][:8], encrypted_term[:8])
        # skip 33 bytes of hash
        self.assertEqual(rows[0]['searchable_acrablock'][33:33+4], encrypted_term[:4])


class TestSearchableTransparentEncryptionWithDefaultsAcraBlockBinaryPostgreSQL(BaseSearchableTransparentEncryptionBinaryPostgreSQLMixin, TestSearchableTransparentEncryption):
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/ee_acrablock_defaults_with_searchable_config.yaml')


class TestSearchableTransparentEncryptionWithDefaultsAcraBlockBinaryMySQL(BaseSearchableTransparentEncryptionBinaryMySQLMixin, TestSearchableTransparentEncryption):
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/ee_acrablock_defaults_with_searchable_config.yaml')


class TestSearchableTransparentEncryptionWithDefaultsAcraStructBinaryPostgreSQL(BaseSearchableTransparentEncryptionBinaryPostgreSQLMixin, TestSearchableTransparentEncryption):
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/ee_acrastruct_defaults_with_searchable_config.yaml')


class TestSearchableTransparentEncryptionWithDefaultsAcraStructBinaryMySQL(BaseSearchableTransparentEncryptionBinaryMySQLMixin, TestSearchableTransparentEncryption):
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/ee_acrastruct_defaults_with_searchable_config.yaml')


class TestSearchableTransparentEncryptionBinaryPostgreSQL(BaseSearchableTransparentEncryptionBinaryPostgreSQLMixin, TestSearchableTransparentEncryption):
    pass


class TestSearchableTransparentEncryptionBinaryMySQL(BaseSearchableTransparentEncryptionBinaryMySQLMixin, TestSearchableTransparentEncryption):
    pass


class TestTransparentSearchableEncryptionWithZone(BaseSearchableTransparentEncryption):
    def testSearch(self):
        self.skipTest("searching with encryption with zones not supported yet")

    def testSearchWithEncryptedData(self):
        self.skipTest("searching with encryption with zones not supported yet")

    def testRotatedKeys(self):
        self.skipTest("searching with encryption with zones not supported yet")


class BaseTokenization(BaseTestCase):
    WHOLECELL_MODE = True
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/ee_tokenization_config.yaml')

    def get_specified_client_id(self):
        return TLS_CERT_CLIENT_ID_2

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        prepare_encryptor_config(
            client_id=self.get_specified_client_id(), zone_id=zones[0][ZONE_ID], config_path=self.ENCRYPTOR_CONFIG)
        acra_kwargs.update(encryptor_config_file=get_test_encryptor_config(self.ENCRYPTOR_CONFIG))
        return super(BaseTokenization, self).fork_acra(popen_kwargs, **acra_kwargs)

    def insert_via_1(self, query, values):
        """Execute SQLAlchemy INSERT query via AcraServer with "TEST_TLS_CLIENT_CERT"."""
        return self.engine1.execute(query, values)

    def insert_via_1_bulk(self, query, values):
        """Execute SQLAlchemy Bulk INSERT query via AcraServer with "TEST_TLS_CLIENT_CERT"."""
        self.engine1.execute(query.values(values))

    def fetch_from_1(self, query):
        """Execute SQLAlchemy SELECT query via AcraServer with "TEST_TLS_CLIENT_CERT"."""
        return self.engine1.execute(query).fetchall()

    def fetch_from_2(self, query):
        """Execute SQLAlchemy SELECT query via AcraServer with "TEST_TLS_CLIENT_2_CERT"."""
        return self.engine2.execute(query).fetchall()


class BaseTokenizationWithBoltDB(BaseTokenization):
    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        acra_kwargs.update(token_db='token1.db')
        return super(BaseTokenizationWithBoltDB, self).fork_acra(popen_kwargs, **acra_kwargs)

    def tearDown(self):
        super().tearDown()
        os.remove('token1.db')


class BaseTokenizationWithRedis(RedisMixin, BaseTokenization):
    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        acra_kwargs.update(
            redis_host_port='localhost:6379',
            redis_db_tokens=self.TEST_REDIS_TOKEN_DB,
            encryptor_config_file=get_test_encryptor_config(self.ENCRYPTOR_CONFIG))
        return super(BaseTokenizationWithRedis, self).fork_acra(popen_kwargs, **acra_kwargs)


class BaseTokenizationWithBinaryBindMySQL(BaseTokenization, BaseBinaryMySQLTestCase):

    def checkSkip(self):
        if not TEST_MYSQL:
            self.skipTest("Only for MySQL")
        super().checkSkip()

    def insert_via_1(self, query, values):
        query, parameters = self.compileInsertQuery(query, values)
        self.executor1.execute_prepared_statement_no_result(query, parameters)

    def insert_via_1_bulk(self, query, values):
        """Execute SQLAlchemy Bulk INSERT query via AcraServer with "TEST_TLS_CLIENT_CERT"."""
        query, parameters = self.compileBulkInsertQuery(query.values(values), values)
        return self.executor1.execute_prepared_statement_no_result(query, parameters)

    def fetch_from_1(self, query):
        query, parameters = self.compileQuery(query, literal_binds=True)
        return self.executor1.execute_prepared_statement(query, parameters)

    def fetch_from_2(self, query):
        query, parameters = self.compileQuery(query, literal_binds=True)
        return self.executor2.execute_prepared_statement(query, parameters)


class BaseTokenizationWithBinaryPostgreSQL(BaseTokenization, BaseBinaryPostgreSQLTestCase):
    """Verify tokenization with PostgreSQL extended protocol (binary format)."""
    FORMAT = AsyncpgExecutor.BinaryFormat

    def checkSkip(self):
        if not TEST_POSTGRESQL:
            self.skipTest("Only for postgresql")
        super().checkSkip()

    def insert_via_1(self, query, values):
        query, parameters = self.compileQuery(query, values)
        self.executor1.execute_prepared_statement(query, parameters)

    def insert_via_1_bulk(self, query, values):
        """Execute SQLAlchemy Bulk INSERT query via AcraServer with "TEST_TLS_CLIENT_CERT"."""
        query, parameters = self.compileBulkInsertQuery(query.values(values), values)
        return self.executor1.execute_prepared_statement(query, parameters)

    def fetch_from_1(self, query):
        query, parameters = self.compileQuery(query, literal_binds=True)
        return self.executor1.execute_prepared_statement(query, parameters)

    def fetch_from_2(self, query):
        query, parameters = self.compileQuery(query, literal_binds=True)
        return self.executor2.execute_prepared_statement(query, parameters)


class BaseTokenizationWithTextPostgreSQL(BaseTokenizationWithBinaryPostgreSQL):
    """Verify tokenization with PostgreSQL extended protocol (text format)."""
    FORMAT = AsyncpgExecutor.TextFormat

    # TODO(ilammy, 2020-10-19): test binary formats
    # We need to skip this test only for MySQL but perform it for PostgreSQL.
    # This is already done by BaseBinaryPostgreSQLTestCase, but the parent
    # overrides checkSkip(). When parent's override is removed, this one
    # becomes unnecessary and should be removed too.
    def checkSkip(self):
        BaseBinaryPostgreSQLTestCase.checkSkip(self)


class BaseTokenizationWithBinaryMySQL(BaseTokenization):
    """Verify tokenization with MySQL binary protocol."""

    def checkSkip(self):
        if not TEST_MYSQL:
            self.skipTest('this test is only for MySQL')
        elif not TEST_WITH_TLS:
            self.skipTest("running tests only with TLS")

    def fetch_from_1(self, query):
        return self.execute(query, TEST_TLS_CLIENT_KEY, TEST_TLS_CLIENT_CERT)

    def fetch_from_2(self, query):
        return self.execute(query, TEST_TLS_CLIENT_2_KEY, TEST_TLS_CLIENT_2_CERT)

    def execute(self, query, ssl_key, ssl_cert):
        # We need a rendered SQL query here. It will be converted into
        # a prepared statement (without arguments) to use MySQL binary
        # protocol on the wire.
        query = query.compile(compile_kwargs={"literal_binds": True}).string
        args = ConnectionArgs(
            host=get_db_host(), port=self.ACRASERVER_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_USER_PASSWORD,
            ssl_ca=TEST_TLS_CA,
            ssl_key=ssl_key,
            ssl_cert=ssl_cert)
        result = MysqlExecutor(args).execute_prepared_statement(query)
        # For some weird reason MySQL connector in prepared statement mode
        # does not decode TEXT columns into Python strings. In text mode
        # it tries to decode the bytes and returns strings if they decode.
        # Do the same here.
        for row in result:
            for column, value in row.items():
                if isinstance(value, (bytes, bytearray)):
                    try:
                        row[column] = value.decode('utf8')
                    except (LookupError, UnicodeDecodeError):
                        pass
        return result


class TestTokenizationWithoutZone(BaseTokenization):
    ZONE = False

    def testTokenizationDefaultClientID(self):
        default_client_id_table = sa.Table(
            'test_tokenization_default_client_id', metadata,
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('nullable_column', sa.Text, nullable=True),
            sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('token_i32', sa.Integer()),
            sa.Column('token_i64', sa.BigInteger()),
            sa.Column('token_str', sa.Text),
            sa.Column('token_bytes', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('token_email', sa.Text),
            extend_existing=True,
        )
        metadata.create_all(self.engine_raw, [default_client_id_table])
        self.engine1.execute(default_client_id_table.delete())
        data = {
            'id': 1,
            'nullable_column': None,
            'empty': b'',
            'token_i32': random_int32(),
            'token_i64': random_int64(),
            'token_str': random_str(),
            'token_bytes': random_bytes(),
            'token_email': random_email(),
        }

        # insert data data
        self.insert_via_1(default_client_id_table.insert(), data)

        # expect that data was encrypted with client_id which used to insert (client_id==keypair1)
        source_data = self.fetch_from_1(
            sa.select([default_client_id_table])
                .where(default_client_id_table.c.id == data['id']))

        hidden_data = self.fetch_from_2(
            sa.select([default_client_id_table])
                .where(default_client_id_table.c.id == data['id']))

        if len(source_data) != len(hidden_data) != 1:
            self.fail('incorrect len of result data')

        # data owner take source data
        for k in ('token_i32', 'token_i64', 'token_str', 'token_bytes', 'token_email'):
            if isinstance(source_data[0][k], bytearray) and isinstance(data[k], str):
                self.assertEqual(source_data[0][k], bytearray(data[k], encoding='utf-8'))
            else:
                self.assertEqual(source_data[0][k], data[k])
            self.assertNotEqual(hidden_data[0][k], data[k])

    def testTokenizationDefaultClientIDWithBulkInsert(self):
        default_client_id_table = sa.Table(
            'test_tokenization_default_client_id', metadata,
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('nullable_column', sa.Text, nullable=True),
            sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('token_i32', sa.Integer()),
            sa.Column('token_i64', sa.BigInteger()),
            sa.Column('token_str', sa.Text),
            sa.Column('token_bytes', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('token_email', sa.Text),
            extend_existing=True,
        )
        metadata.create_all(self.engine_raw, [default_client_id_table])
        self.engine1.execute(default_client_id_table.delete())

        values = []
        for idx in range(5):
            insert_data = {
                'id': 1 + idx,
                'nullable_column': None,
                'empty': b'',
                'token_i32': random_int32(),
                'token_i64': random_int64(),
                'token_str': random_str(),
                'token_bytes': random_bytes(),
                'token_email': random_email(),
            }
            values.append(insert_data)

        # bulk insert data
        self.insert_via_1_bulk(default_client_id_table.insert(), values)

        # expect that data was encrypted with client_id which used to insert (client_id==TEST_TLS_CLIENT_CERT)
        source_data = self.fetch_from_1(sa.select([default_client_id_table]))

        hidden_data = self.fetch_from_2(sa.select([default_client_id_table]))

        if len(source_data) != len(hidden_data):
            self.fail('incorrect len of result data')

        for idx in range(len(source_data)):
            # data owner take source data
            for k in ('token_i32', 'token_i64', 'token_str', 'token_bytes', 'token_email'):
                if isinstance(source_data[idx][k], bytearray) and isinstance(values[idx][k], str):
                    self.assertEqual(source_data[idx][k], bytearray(values[idx][k], encoding='utf-8'))
                else:
                    self.assertEqual(source_data[idx][k], values[idx][k])
                    self.assertNotEqual(hidden_data[idx][k], values[idx][k])

    def testTokenizationSpecificClientID(self):
        specific_client_id_table = sa.Table(
            'test_tokenization_specific_client_id', metadata,
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('nullable_column', sa.Text, nullable=True),
            sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('token_i32', sa.Integer()),
            sa.Column('token_i64', sa.BigInteger()),
            sa.Column('token_str', sa.Text),
            sa.Column('token_bytes', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('token_email', sa.Text),
            extend_existing=True,
        )
        data = {
            'id': 1,
            'nullable_column': None,
            'empty': b'',
            'token_i32': random_int32(),
            'token_i64': random_int64(),
            'token_str': random_str(),
            'token_bytes': random_bytes(),
            'token_email': random_email(),
        }
        metadata.create_all(self.engine_raw, [specific_client_id_table])
        self.engine1.execute(specific_client_id_table.delete())

        # insert data data using client_id==TEST_TLS_CLIENT_CERT
        self.insert_via_1(specific_client_id_table.insert(), data)

        # expect that source data return client_id==TEST_TLS_CLIENT_2_CERT which defined in config
        source_data = self.fetch_from_2(
            sa.select([specific_client_id_table])
                .where(specific_client_id_table.c.id == data['id']))

        hidden_data = self.fetch_from_1(
            sa.select([specific_client_id_table])
                .where(specific_client_id_table.c.id == data['id']))

        if len(source_data) != len(hidden_data) != 1:
            self.fail('incorrect len of result data')

        # data owner take source data
        for k in ('token_i32', 'token_i64', 'token_str', 'token_bytes', 'token_email'):
            if isinstance(source_data[0][k], bytearray) and isinstance(data[k], str):
                self.assertEqual(source_data[0][k], bytearray(data[k], encoding='utf-8'))
            else:
                self.assertEqual(source_data[0][k], data[k])
            self.assertNotEqual(hidden_data[0][k], data[k])

    def testTokenizationDefaultClientIDStarExpression(self):
        default_client_id_table = sa.Table(
            'test_tokenization_default_client_id', metadata,
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('nullable_column', sa.Text, nullable=True),
            sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('token_i32', sa.Integer()),
            sa.Column('token_i64', sa.BigInteger()),
            sa.Column('token_str', sa.Text),
            sa.Column('token_bytes', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('token_email', sa.Text),
            extend_existing=True,
        )
        metadata.create_all(self.engine_raw, [default_client_id_table])
        self.engine1.execute(default_client_id_table.delete())
        data = {
            'id': 1,
            'nullable_column': None,
            'empty': b'',
            'token_i32': random_int32(),
            'token_i64': random_int64(),
            'token_str': random_str(),
            'token_bytes': random_bytes(),
            'token_email': random_email(),
        }

        # insert data data
        self.insert_via_1(default_client_id_table.insert(), data)

        # expect that data was encrypted with client_id which used to insert (client_id==TEST_TLS_CLIENT_CERT)
        source_data = self.fetch_from_1(
            sa.select(['*'], from_obj=default_client_id_table)
                .where(default_client_id_table.c.id == data['id']))

        hidden_data = self.fetch_from_2(
            sa.select(['*'], from_obj=default_client_id_table)
                .where(default_client_id_table.c.id == data['id']))

        if len(source_data) != len(hidden_data) != 1:
            self.fail('incorrect len of result data')

        # data owner take source data
        for k in ('token_i32', 'token_i64', 'token_str', 'token_bytes', 'token_email'):
            # binary data returned as memoryview objects
            if isinstance(source_data[0][k], bytearray) and isinstance(data[k], str):
                self.assertEqual(utils.memoryview_to_bytes(source_data[0][k]), bytearray(data[k], encoding='utf-8'))
            else:
                self.assertEqual(utils.memoryview_to_bytes(source_data[0][k]), data[k])
            self.assertNotEqual(utils.memoryview_to_bytes(hidden_data[0][k]), data[k])


class TestReturningProcessingMixing:
    ZONE = False
    specific_client_id_table = sa.Table(
        'test_tokenization_specific_client_id', metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('nullable_column', sa.Text, nullable=True),
        sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
        sa.Column('token_i32', sa.Integer()),
        sa.Column('token_i64', sa.BigInteger()),
        sa.Column('token_str', sa.Text),
        sa.Column('token_bytes', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=True, default=b''),
        sa.Column('token_email', sa.Text),
        extend_existing=True,
    )

    def insert_with_enum_and_return_data(self):
        raise NotImplementedError

    def insert_with_star_and_return_data(self):
        raise NotImplementedError

    def test_insert_returning_with_col_enum(self):
        source, hidden, data = self.insert_with_enum_and_return_data()
        self.assertEqual(source[1], data['token_str'])
        self.assertEqual(source[2], data['token_i64'])
        self.assertEqual(source[3], data['token_email'])
        self.assertEqual(source[4], data['token_i32'])
        self.assertNotEqual(hidden[1], data['token_str'])
        self.assertNotEqual(hidden[2], data['token_i64'])
        self.assertNotEqual(hidden[3], data['token_email'])
        self.assertNotEqual(hidden[4], data['token_i32'])

    def test_insert_returning_with_star(self):
        source, hidden, data = self.insert_with_star_and_return_data()
        self.assertEqual(source[3], data['token_i32'])
        self.assertEqual(source[4], data['token_i64'])
        self.assertEqual(source[5], data['token_str'])
        self.assertEqual(source[7], data['token_email'])
        self.assertNotEqual(hidden[3], data['token_i32'])
        self.assertNotEqual(hidden[4], data['token_i64'])
        self.assertNotEqual(hidden[5], data['token_str'])
        self.assertNotEqual(hidden[7], data['token_email'])


class TestReturningProcessingMariaDB(TestReturningProcessingMixing, BaseTokenization):
    data = {
        'nullable_column': None,
        'empty': b'',
        'token_i32': random_int32(),
        'token_i64': random_int64(),
        'token_str': random_str(),
        'token_bytes': random_bytes(),
        'token_email': random_email(),
    }

    def checkSkip(self):
        if not TEST_MARIADB or TEST_WITH_TLS:
            self.skipTest("Only for MariaDB")
        super().checkSkip()

    def build_raw_query_with_enum(self):
        id = get_random_id()
        # TODO(zhars, 2021-5-20): rewrite query when sqlalchemy will support RETURNING statements
        return 'INSERT INTO test_tokenization_specific_client_id ' \
               '(id, empty, token_bytes, token_i32, token_i64, token_str, token_email) ' \
               'VALUES ({}, {}, {}, {}, {}, \'{}\', \'{}\') ' \
               'RETURNING test_tokenization_specific_client_id.id, test_tokenization_specific_client_id.token_str,' \
               ' test_tokenization_specific_client_id.token_i64, test_tokenization_specific_client_id.token_email, ' \
               'test_tokenization_specific_client_id.token_i32'.format(id, self.data['empty'], self.data['empty'], self.data['token_i32'], self.data['token_i64'], self.data['token_str'], self.data['token_email'])

    def build_raw_query_with_star(self):
        id = get_random_id()
        # TODO(zhars, 2021-5-20): rewrite query when sqlalchemy will support RETURNING statements
        return 'INSERT INTO test_tokenization_specific_client_id ' \
               '(id, empty, token_bytes, token_i32, token_i64, token_str, token_email) ' \
               'VALUES ({}, {}, {}, {}, {}, \'{}\', \'{}\') ' \
               'RETURNING *'.format(id, self.data['empty'], self.data['empty'], self.data['token_i32'], self.data['token_i64'], self.data['token_str'], self.data['token_email'])

    def insert_with_enum_and_return_data(self):
        metadata.create_all(self.engine_raw, [self.specific_client_id_table])
        self.fetch_from_2(sa.select([self.specific_client_id_table]).where(self.specific_client_id_table.c.id == id))

        source = self.fetch_from_2(self.build_raw_query_with_enum())[0]
        hidden = self.fetch_from_1(self.build_raw_query_with_enum())[0]
        return source, hidden, self.data

    def insert_with_star_and_return_data(self):
        metadata.create_all(self.engine_raw, [self.specific_client_id_table])
        self.fetch_from_2(sa.select([self.specific_client_id_table]).where(self.specific_client_id_table.c.id == id))

        source = self.fetch_from_2(self.build_raw_query_with_star())[0]
        hidden = self.fetch_from_1(self.build_raw_query_with_star())[0]
        return source, hidden, self.data


class TestReturningProcessingPostgreSQL(TestReturningProcessingMixing, BaseTokenization):
    data = {
        'nullable_column': None,
        'empty': b'',
        'token_i32': random_int32(),
        'token_i64': random_int64(),
        'token_str': random_str(),
        'token_bytes': random_bytes(),
        'token_email': random_email(),
    }

    def checkSkip(self):
        if not TEST_POSTGRESQL:
            self.skipTest("Only for PostgreSQL")
        super().checkSkip()

    def build_raw_query_with_enum(self):
        self.data['id'] = get_random_id()
        return self.specific_client_id_table.insert(). \
            returning(self.specific_client_id_table.c.id, self.specific_client_id_table.c.token_str, self.specific_client_id_table.c.token_i64,
                      self.specific_client_id_table.c.token_email, self.specific_client_id_table.c.token_i32), self.data

    def build_raw_query_with_star(self):
        self.data['id'] = get_random_id()
        return self.specific_client_id_table.insert().returning(sa.literal_column('*')), self.data

    def insert_with_enum_and_return_data(self):
        metadata.create_all(self.engine_raw, [self.specific_client_id_table])
        self.fetch_from_2(sa.select([self.specific_client_id_table]).where(self.specific_client_id_table.c.id == get_random_id()))

        source_query, source_data = self.build_raw_query_with_enum()
        source = self.engine2.execute(source_query, source_data).fetchone()

        hidden_query, hidden_data = self.build_raw_query_with_enum()
        hidden = self.engine1.execute(hidden_query, hidden_data).fetchone()
        return source, hidden, self.data

    def insert_with_star_and_return_data(self):
        metadata.create_all(self.engine_raw, [self.specific_client_id_table])
        self.fetch_from_2(sa.select([self.specific_client_id_table]).where(self.specific_client_id_table.c.id == get_random_id()))

        source_query, data = self.build_raw_query_with_star()
        source = self.engine2.execute(source_query, data).fetchone()

        hidden_query, data = self.build_raw_query_with_star()
        hidden = self.engine1.execute(hidden_query, data).fetchone()
        return source, hidden, self.data


class TestTokenizationWithZone(BaseTokenization):
    ZONE = True

    def testTokenizationSpecificZoneID(self):
        specific_zone_id_table = sa.Table(
            'test_tokenization_specific_zone_id', metadata,
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('zone_id', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
            sa.Column('nullable_column', sa.Text, nullable=True),
            sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('token_i32', sa.Integer()),
            sa.Column('token_i64', sa.BigInteger()),
            sa.Column('token_str', sa.Text),
            sa.Column('token_bytes', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('token_email', sa.Text),
            extend_existing=True,
        )
        metadata.create_all(self.engine_raw, [specific_zone_id_table])
        self.engine1.execute(specific_zone_id_table.delete())
        zone_id = zones[0][ZONE_ID]
        data = {
            'id': 1,
            'nullable_column': None,
            'empty': b'',
            'zone_id': zone_id.encode('ascii'),
            'token_i32': random_int32(),
            'token_i64': random_int64(),
            'token_str': random_str(),
            'token_bytes': random_bytes(),
            'token_email': random_email(),
        }

        # insert data data using client_id==TEST_TLS_CLIENT_CERT
        self.insert_via_1(specific_zone_id_table.insert(), data)

        # expect that source data will returned from acra-servers with all client_id with correct zone id
        source_data = self.fetch_from_2(
            sa.select([specific_zone_id_table])
                .where(specific_zone_id_table.c.id == data['id']))

        hidden_data = self.fetch_from_1(
            sa.select([specific_zone_id_table])
                .where(specific_zone_id_table.c.id == data['id']))

        if len(source_data) != len(hidden_data) != 1:
            self.fail('incorrect len of result data')

        token_fields = ('token_i32', 'token_i64', 'token_str', 'token_bytes', 'token_email')
        # data owner take source data
        for k in token_fields:
            if isinstance(source_data[0][k], bytearray) and isinstance(data[k], str):
                self.assertEqual(source_data[0][k], bytearray(data[k], encoding='utf-8'))
                self.assertEqual(hidden_data[0][k], bytearray(data[k], encoding='utf-8'))
            else:
                self.assertEqual(source_data[0][k], data[k])
                self.assertEqual(hidden_data[0][k], data[k])

        # expect that source data will not returned from acra-servers with all client_id with incorrect zone id
        columns = [sa.cast(zones[1][ZONE_ID].encode('ascii'), BYTEA)]
        # all columns except zone id
        columns.extend([i for i in list(specific_zone_id_table.c) if i.name != 'zone_id'])
        source_data = self.engine2.execute(
            sa.select(columns)
                .where(specific_zone_id_table.c.id == data['id']))
        source_data = source_data.fetchall()
        for i in token_fields:
            self.assertNotEqual(source_data[0][i], data[i])

    def testTokenizationSpecificZoneIDStarExpression(self):
        specific_zone_id_table = sa.Table(
            'test_tokenization_specific_zone_id_star_expression', metadata,
            sa.Column('id', sa.Integer, primary_key=True),
            # don't store zoneID in table
            #sa.Column('zone_id', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
            sa.Column('nullable_column', sa.Text, nullable=True),
            sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('token_i32', sa.Integer()),
            sa.Column('token_i64', sa.BigInteger()),
            sa.Column('token_str', sa.Text),
            sa.Column('token_bytes', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('token_email', sa.Text),
            extend_existing=True,
        )
        metadata.drop_all(self.engine_raw, [specific_zone_id_table])
        metadata.create_all(self.engine_raw, [specific_zone_id_table])
        self.engine1.execute(specific_zone_id_table.delete())
        data = {
            'id': 1,
            'nullable_column': None,
            'empty': b'',
            'token_i32': random_int32(),
            'token_i64': random_int64(),
            'token_str': random_str(),
            'token_bytes': random_bytes(),
            'token_email': random_email(),
        }

        # insert data data using client_id==keypair1
        self.insert_via_1(specific_zone_id_table.insert(), data)

        CORRECT_ZONE, INCORRECT_ZONE = range(2)
        # expect that source data will not returned from all acra-servers with incorrect zone id
        columns = [
            sa.literal(zones[CORRECT_ZONE][ZONE_ID]),
            # mysql doesn't support query like `select 'string', * from table1`, only qualified StarExpr like `select 'string', t1.* from table1 as t1`
            sa.text('{}.*'.format(specific_zone_id_table.name))
        ]
        # expect that source data will returned from all acra-servers with correct zone id
        source_data = self.fetch_from_2(
            sa.select(columns, from_obj=specific_zone_id_table)
                .where(specific_zone_id_table.c.id == data['id']))

        hidden_data = self.fetch_from_1(
            sa.select(columns, from_obj=specific_zone_id_table)
                .where(specific_zone_id_table.c.id == data['id']))

        if len(source_data) != len(hidden_data) != 1:
            self.fail('incorrect len of result data')

        token_fields = ('token_i32', 'token_i64', 'token_str', 'token_bytes', 'token_email')
        # data owner take source data
        for k in token_fields:
            if isinstance(source_data[0][k], bytearray) and isinstance(data[k], str):
                self.assertEqual(utils.memoryview_to_bytes(source_data[0][k]), bytearray(data[k], encoding='utf-8'))
                self.assertEqual(utils.memoryview_to_bytes(hidden_data[0][k]), bytearray(data[k], encoding='utf-8'))
            else:
                self.assertEqual(utils.memoryview_to_bytes(source_data[0][k]), data[k])
                self.assertEqual(utils.memoryview_to_bytes(hidden_data[0][k]), data[k])

        # expect that source data will not returned from all acra-servers with incorrect zone id
        columns = [
            sa.literal(zones[INCORRECT_ZONE][ZONE_ID]),
            sa.text('{}.*'.format(specific_zone_id_table.name))
        ]
        source_data = self.engine2.execute(
            sa.select(columns)
                .where(specific_zone_id_table.c.id == data['id']))
        source_data = source_data.fetchall()
        for i in token_fields:
            self.assertNotEqual(utils.memoryview_to_bytes(source_data[0][i]), data[i])


class TestTokenizationWithoutZoneWithBoltDB(BaseTokenizationWithBoltDB, TestTokenizationWithoutZone):
    pass


class TestTokenizationWithZoneWithBoltDB(BaseTokenizationWithBoltDB, TestTokenizationWithZone):
    pass


class TestTokenizationWithoutZoneWithRedis(BaseTokenizationWithRedis, TestTokenizationWithoutZone):
    pass


class TestTokenizationWithZoneWithRedis(BaseTokenizationWithRedis, TestTokenizationWithZone):
    pass


class TestTokenizationWithoutZoneBinaryMySQL(BaseTokenizationWithBinaryMySQL, TestTokenizationWithoutZone):
    pass


class TestTokenizationWithZoneBinaryMySQL(BaseTokenizationWithBinaryMySQL, TestTokenizationWithZone):
    pass


class TestTokenizationWithoutZoneTextPostgreSQL(BaseTokenizationWithTextPostgreSQL, TestTokenizationWithoutZone):
    pass


class TestTokenizationWithZoneTextPostgreSQL(BaseTokenizationWithTextPostgreSQL, TestTokenizationWithZone):
    pass


class TestTokenizationWithoutZoneBinaryPostgreSQL(BaseTokenizationWithBinaryPostgreSQL, TestTokenizationWithoutZone):
    pass


class TestTokenizationWithZoneBinaryPostgreSQL(BaseTokenizationWithBinaryPostgreSQL, TestTokenizationWithZone):
    pass


class TestTokenizationWithoutZoneBinaryBindMySQL(BaseTokenizationWithBinaryBindMySQL, TestTokenizationWithoutZone):
    pass


class TestTokenizationWithZoneBinaryBindMySQL(BaseTokenizationWithBinaryBindMySQL, TestTokenizationWithZone):
    pass


class BaseMasking(BaseTokenization):
    WHOLECELL_MODE = False
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/ee_masking_config.yaml')

    def check_crypto_envelope(self, table, row_id):
        temp_acrastruct = create_acrastruct_with_client_id(b'somedata', TLS_CERT_CLIENT_ID_1)
        # expect that data was encrypted with client_id from acra-server which used to insert (client_id==TEST_TLS_CLIENT_CERT)
        source_data = self.engine_raw.execute(
            sa.select([table])
                .where(table.c.id == row_id))
        source_data = source_data.fetchone()
        for i in ('masked_prefix', 'masked_suffix', 'masked_without_plaintext', 'exact_plaintext_length',
                  'shorter_plaintext'):
            # check that data not contains AcraStruct tag begin
            self.assertNotIn(temp_acrastruct[:8], source_data[i])
            # and check that data contains AcraBlock tag begin
            self.assertIn(temp_acrastruct[:4], source_data[i])

    def get_specified_client_id(self):
        return TLS_CERT_CLIENT_ID_2

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        prepare_encryptor_config(
            client_id=self.get_specified_client_id(), zone_id=zones[0][ZONE_ID], config_path=self.ENCRYPTOR_CONFIG)
        acra_kwargs.update(token_db='token1.db',
                           encryptor_config_file=get_test_encryptor_config(self.ENCRYPTOR_CONFIG))
        return super(BaseTokenization, self).fork_acra(popen_kwargs, **acra_kwargs)

    def executeInsert(self, query, values):
        """Execute a Bulk Insert query with list of values via AcraServer for "TEST_TLS_CLIENT_CERT"."""
        return self.engine1.execute(query.values(values))

    def executeBulkInsert(self, query, values):
        """Execute a Bulk Insert query with list of values via AcraServer for "TEST_TLS_CLIENT_CERT"."""
        return self.engine1.execute(query.values(values))

    def tearDown(self):
        super().tearDown()
        os.remove('token1.db')


class BaseMaskingBinaryPostgreSQLMixin(BaseBinaryPostgreSQLTestCase, BaseTestCase):
    def executeInsert(self, query, values):
        """Execute a Insert query with list of values via AcraServer for "TEST_TLS_CLIENT_CERT"."""
        query, parameters = self.compileInsertQuery(query, values)
        return self.executor1.execute_prepared_statement(query, parameters)

    def executeBulkInsert(self, query, values):
        """Execute a Bulk Insert query with list of values via AcraServer for "TEST_TLS_CLIENT_CERT"."""
        query, parameters = self.compileBulkInsertQuery(query.values(values), values)
        return self.executor1.execute_prepared_statement(query, parameters)


class BaseMaskingBinaryMySQLMixin(BaseBinaryMySQLTestCase, BaseTestCase):
    def executeInsert(self, query, values):
        """Execute a Insert query with list of values via AcraServer for "TEST_TLS_CLIENT_CERT"."""
        query, parameters = self.compileInsertQuery(query, values)
        return self.executor1.execute_prepared_statement_no_result(query, parameters)

    def executeBulkInsert(self, query, values):
        """Execute a Bulk Insert query with list of values via AcraServer for "TEST_TLS_CLIENT_CERT"."""
        query, parameters = self.compileBulkInsertQuery(query.values(values), values)
        return self.executor1.execute_prepared_statement_no_result(query, parameters)


class TestMaskingWithoutZone(BaseMasking):
    def test_masking_default_client_id(self):
        default_client_id_table = sa.Table(
            'test_masking_default_client_id', metadata,
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('nullable_column', sa.Text, nullable=True),
            sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('masked_prefix', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('masked_suffix', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('masked_without_plaintext', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('exact_plaintext_length', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('shorter_plaintext', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            extend_existing=True
        )
        metadata.create_all(self.engine_raw, [default_client_id_table])
        self.engine_raw.execute(default_client_id_table.delete())
        data = {
            'id': 1,
            'nullable_column': None,
            'empty': b'',
            'masked_prefix': random_bytes(9),
            'masked_suffix': random_bytes(9),
            'masked_without_plaintext': random_bytes(),
            'exact_plaintext_length': random_bytes(10),
            'shorter_plaintext': random_bytes(9),
        }

        # insert data data with another client_id (keypair2) than should be encrypted (keypair1)
        self.executeInsert(default_client_id_table.insert(), data)

        self.check_crypto_envelope(default_client_id_table, data['id'])

        # expect that data was encrypted with client_id from acra-server which used to insert (client_id==TEST_TLS_CLIENT_CERT)
        source_data = self.engine1.execute(
            sa.select([default_client_id_table])
                .where(default_client_id_table.c.id == data['id']))
        source_data = source_data.fetchall()

        hidden_data = self.engine2.execute(
            sa.select([default_client_id_table])
                .where(default_client_id_table.c.id == data['id']))
        hidden_data = hidden_data.fetchall()

        if len(source_data) != len(hidden_data) != 1:
            self.fail('incorrect len of result data')

        for i in ('masked_prefix', 'masked_suffix', 'masked_without_plaintext', 'exact_plaintext_length', 'shorter_plaintext'):
            self.assertEqual(source_data[0][i], data[i])

        hidden_data = hidden_data[0]
        mask_pattern = 'xxxx'.encode('ascii')
        # check that mask at correct place
        self.assertEqual(hidden_data['masked_prefix'][:len(mask_pattern)], mask_pattern)
        # check that len of masked value not equal to source data because acrastruct always longer than plaintext
        self.assertNotEqual(len(hidden_data['masked_prefix']), len(data['masked_prefix']))
        # check that data after mask is not the same as source data
        self.assertNotEqual(hidden_data['masked_prefix'][len(mask_pattern):], data)
        # check that data after mask is not the same as source data with same offset as mask length
        self.assertNotEqual(hidden_data['masked_prefix'][len(mask_pattern):], data['masked_prefix'][len(mask_pattern):])

        # check that mask at correct place
        self.assertEqual(hidden_data['masked_suffix'][-len(mask_pattern):], mask_pattern)
        # check that len of masked value not equal to source data because acrastruct always longer than plaintext
        self.assertNotEqual(len(hidden_data['masked_suffix']), len(data['masked_suffix']))
        # check that data before mask is not the same as source data
        self.assertNotEqual(hidden_data['masked_suffix'][:-len(mask_pattern)], data)
        # check that data after mask is not the same as source data with same offset as mask length
        self.assertNotEqual(hidden_data['masked_suffix'][:-len(mask_pattern)], data['masked_suffix'][:-len(mask_pattern)])

        self.assertEqual(mask_pattern, hidden_data['masked_without_plaintext'])

        # if plaintext length > data, then whole data will be encrypted
        self.assertEqual(mask_pattern, hidden_data['exact_plaintext_length'])

        self.assertEqual(mask_pattern, hidden_data['shorter_plaintext'])

    def test_masking_specific_client_id(self):
        specific_client_id_table = sa.Table(
            'test_masking_specific_client_id', metadata,
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('nullable_column', sa.Text, nullable=True),
            sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('masked_prefix', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('masked_suffix', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('masked_without_plaintext', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('exact_plaintext_length', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('shorter_plaintext', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            extend_existing=True
        )
        metadata.create_all(self.engine_raw, [specific_client_id_table])
        self.engine_raw.execute(specific_client_id_table.delete())
        data = {
            'id': 1,
            'nullable_column': None,
            'empty': b'',
            'masked_prefix': random_bytes(9),
            'masked_suffix': random_bytes(9),
            'masked_without_plaintext': random_bytes(),
            'exact_plaintext_length': random_bytes(10),
            'shorter_plaintext': random_bytes(9),
        }

        # insert data data with another client_id (keypair1) than should be encrypted (keypair2)
        self.executeInsert(specific_client_id_table.insert(), data)

        self.check_crypto_envelope(specific_client_id_table, data['id'])

        # expect that data was encrypted with client_id from acra-server which used to insert (client_id==TEST_TLS_CLIENT_2_CERT)
        source_data = self.engine2.execute(
            sa.select([specific_client_id_table])
                .where(specific_client_id_table.c.id == data['id']))
        source_data = source_data.fetchall()

        hidden_data = self.engine1.execute(
            sa.select([specific_client_id_table])
                .where(specific_client_id_table.c.id == data['id']))
        hidden_data = hidden_data.fetchall()

        if len(source_data) != len(hidden_data) != 1:
            self.fail('incorrect len of result data')

        for i in ('masked_prefix', 'masked_suffix', 'masked_without_plaintext', 'exact_plaintext_length', 'shorter_plaintext'):
            self.assertEqual(source_data[0][i], data[i])

        hidden_data = hidden_data[0]
        mask_pattern = 'xxxx'.encode('ascii')
        # check that mask at correct place
        self.assertEqual(hidden_data['masked_prefix'][:len(mask_pattern)], mask_pattern)
        # check that len of masked value not equal to source data because acrastruct always longer than plaintext
        self.assertNotEqual(len(hidden_data['masked_prefix']), len(data['masked_prefix']))
        # check that data after mask is not the same as source data
        self.assertNotEqual(hidden_data['masked_prefix'][len(mask_pattern):], data)
        # check that data after mask is not the same as source data with same offset as mask length
        self.assertNotEqual(hidden_data['masked_prefix'][len(mask_pattern):], data['masked_prefix'][len(mask_pattern):])

        # check that mask at correct place
        self.assertEqual(hidden_data['masked_suffix'][-len(mask_pattern):], mask_pattern)
        # check that len of masked value not equal to source data because acrastruct always longer than plaintext
        self.assertNotEqual(len(hidden_data['masked_suffix']), len(data['masked_suffix']))
        # check that data before mask is not the same as source data
        self.assertNotEqual(hidden_data['masked_suffix'][:-len(mask_pattern)], data)
        # check that data after mask is not the same as source data with same offset as mask length
        self.assertNotEqual(hidden_data['masked_suffix'][:-len(mask_pattern)], data['masked_suffix'][:-len(mask_pattern)])

        self.assertEqual(mask_pattern, hidden_data['masked_without_plaintext'])

        # if plaintext length > data, then whole data will be encrypted
        self.assertEqual(mask_pattern, hidden_data['exact_plaintext_length'])

        self.assertEqual(mask_pattern, hidden_data['shorter_plaintext'])


class TestMaskingWithZonePerValue(BaseMasking):
    ZONE = True

    def test_masking_specific_zone_id_bulk(self):
        specific_zone_id_table = sa.Table(
            'test_masking_specific_zone_id', metadata,
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('nullable_column', sa.Text, nullable=True),
            sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('masked_prefix', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('masked_suffix', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('masked_without_plaintext', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('exact_plaintext_length', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('shorter_plaintext', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            extend_existing=True
        )
        metadata.create_all(self.engine_raw, [specific_zone_id_table])
        self.engine_raw.execute(specific_zone_id_table.delete())

        values = []
        for idx in range(3):
            data = {
                'id': 1 + idx,
                'nullable_column': None,
                'empty': b'',
                'masked_prefix': random_bytes(9),
                'masked_suffix': random_bytes(9),
                'masked_without_plaintext': random_bytes(),
                'exact_plaintext_length': random_bytes(10),
                'shorter_plaintext': random_bytes(9),
            }
            values.append(data)

        # insert data data with another client_id (keypair1) than should be encrypted (keypair2)
        self.executeBulkInsert(specific_zone_id_table.insert(), values)

        columns = []
        for i in ('masked_prefix', 'masked_suffix', 'masked_without_plaintext', 'exact_plaintext_length', 'shorter_plaintext'):
            # create in loop to generate new objects of literal and avoid removing in select clause by sqlalchemy
            correct_zone = sa.literal(zones[0][ZONE_ID])
            columns.append(correct_zone)
            columns.append(getattr(specific_zone_id_table.c, i))

        for value in values:
            self.check_crypto_envelope(specific_zone_id_table, value['id'])

            # check that using any acra-server with correct zone we fetch decrypted data
            for engine in (self.engine1, self.engine2):
                # expect that data was encrypted with client_id from acra-server which used to insert (client_id==TEST_TLS_CLIENT_2_CERT)
                response = engine.execute(
                    sa.select(columns)
                        .where(specific_zone_id_table.c.id == value['id']))
                source_data = response.fetchall()
                if len(source_data) != 1:
                    self.fail('incorrect len of result data')

                for i in ('masked_prefix', 'masked_suffix', 'masked_without_plaintext', 'exact_plaintext_length', 'shorter_plaintext'):
                    self.assertEqual(source_data[0][i], value[i])

            incorrect_zone = sa.literal(zones[1][ZONE_ID])
            # check that using any acra-server with incorrect zone we fetch masked data
            for engine in (self.engine1, self.engine2):
                hidden_data = engine.execute(
                    sa.select([incorrect_zone, specific_zone_id_table])
                        .where(specific_zone_id_table.c.id == value['id']))
                hidden_data = hidden_data.fetchall()

                if len(source_data) != len(hidden_data) != 1:
                    self.fail('incorrect len of result data')

                for i in ('masked_prefix', 'masked_suffix', 'masked_without_plaintext', 'exact_plaintext_length', 'shorter_plaintext'):
                    self.assertEqual(source_data[0][i], value[i])

                hidden_data = hidden_data[0]
                mask_pattern = 'xxxx'.encode('ascii')
                # check that mask at correct place
                self.assertEqual(hidden_data['masked_prefix'][:len(mask_pattern)], mask_pattern)
                # check that len of masked value not equal to source data because acrastruct always longer than plaintext
                self.assertNotEqual(len(hidden_data['masked_prefix']), len(value['masked_prefix']))
                # check that data after mask is not the same as source data
                self.assertNotEqual(hidden_data['masked_prefix'][len(mask_pattern):], value)
                # check that data after mask is not the same as source data with same offset as mask length
                self.assertNotEqual(hidden_data['masked_prefix'][len(mask_pattern):], value['masked_prefix'][len(mask_pattern):])

                # check that mask at correct place
                self.assertEqual(hidden_data['masked_suffix'][-len(mask_pattern):], mask_pattern)
                # check that len of masked value not equal to source data because acrastruct always longer than plaintext
                self.assertNotEqual(len(hidden_data['masked_suffix']), len(value['masked_suffix']))
                # check that data before mask is not the same as source data
                self.assertNotEqual(hidden_data['masked_suffix'][:-len(mask_pattern)], value)
                # check that data after mask is not the same as source data with same offset as mask length
                self.assertNotEqual(hidden_data['masked_suffix'][:-len(mask_pattern)], value['masked_suffix'][:-len(mask_pattern)])

                self.assertEqual(mask_pattern, hidden_data['masked_without_plaintext'])

                # if plaintext length > data, then whole data will be encrypted
                self.assertEqual(mask_pattern, hidden_data['exact_plaintext_length'])

                self.assertEqual(mask_pattern, hidden_data['shorter_plaintext'])

    def test_masking_specific_zone_id(self):
        specific_zone_id_table = sa.Table(
            'test_masking_specific_zone_id', metadata,
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('nullable_column', sa.Text, nullable=True),
            sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('masked_prefix', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('masked_suffix', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('masked_without_plaintext', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('exact_plaintext_length', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('shorter_plaintext', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            extend_existing=True
        )
        metadata.create_all(self.engine_raw, [specific_zone_id_table])
        self.engine_raw.execute(specific_zone_id_table.delete())
        data = {
            'id': 1,
            'nullable_column': None,
            'empty': b'',
            'masked_prefix': random_bytes(9),
            'masked_suffix': random_bytes(9),
            'masked_without_plaintext': random_bytes(),
            'exact_plaintext_length': random_bytes(10),
            'shorter_plaintext': random_bytes(9),
        }

        # insert data data with another client_id (keypair1) than should be encrypted (keypair2)
        self.engine1.execute(specific_zone_id_table.insert(values=data))

        self.check_crypto_envelope(specific_zone_id_table, data['id'])

        columns = []
        for i in ('masked_prefix', 'masked_suffix', 'masked_without_plaintext', 'exact_plaintext_length', 'shorter_plaintext'):
            # create in loop to generate new objects of literal and avoid removing in select clause by sqlalchemy
            correct_zone = sa.literal(zones[0][ZONE_ID])
            columns.append(correct_zone)
            columns.append(getattr(specific_zone_id_table.c, i))

        # check that using any acra-server with correct zone we fetch decrypted data
        for engine in (self.engine1, self.engine2):
            # expect that data was encrypted with client_id from acra-server which used to insert (client_id==TEST_TLS_CLIENT_2_CERT)
            response = engine.execute(
                sa.select(columns)
                    .where(specific_zone_id_table.c.id == data['id']))
            source_data = response.fetchall()
            if len(source_data) != 1:
                self.fail('incorrect len of result data')

            for i in ('masked_prefix', 'masked_suffix', 'masked_without_plaintext', 'exact_plaintext_length', 'shorter_plaintext'):
                self.assertEqual(source_data[0][i], data[i])

        incorrect_zone = sa.literal(zones[1][ZONE_ID])
        # check that using any acra-server with incorrect zone we fetch masked data
        for engine in (self.engine1, self.engine2):
            hidden_data = engine.execute(
                sa.select([incorrect_zone, specific_zone_id_table])
                    .where(specific_zone_id_table.c.id == data['id']))
            hidden_data = hidden_data.fetchall()

            if len(source_data) != len(hidden_data) != 1:
                self.fail('incorrect len of result data')

            for i in ('masked_prefix', 'masked_suffix', 'masked_without_plaintext', 'exact_plaintext_length', 'shorter_plaintext'):
                self.assertEqual(source_data[0][i], data[i])

            hidden_data = hidden_data[0]
            mask_pattern = 'xxxx'.encode('ascii')
            # check that mask at correct place
            self.assertEqual(hidden_data['masked_prefix'][:len(mask_pattern)], mask_pattern)
            # check that len of masked value not equal to source data because acrastruct always longer than plaintext
            self.assertNotEqual(len(hidden_data['masked_prefix']), len(data['masked_prefix']))
            # check that data after mask is not the same as source data
            self.assertNotEqual(hidden_data['masked_prefix'][len(mask_pattern):], data)
            # check that data after mask is not the same as source data with same offset as mask length
            self.assertNotEqual(hidden_data['masked_prefix'][len(mask_pattern):], data['masked_prefix'][len(mask_pattern):])

            # check that mask at correct place
            self.assertEqual(hidden_data['masked_suffix'][-len(mask_pattern):], mask_pattern)
            # check that len of masked value not equal to source data because acrastruct always longer than plaintext
            self.assertNotEqual(len(hidden_data['masked_suffix']), len(data['masked_suffix']))
            # check that data before mask is not the same as source data
            self.assertNotEqual(hidden_data['masked_suffix'][:-len(mask_pattern)], data)
            # check that data after mask is not the same as source data with same offset as mask length
            self.assertNotEqual(hidden_data['masked_suffix'][:-len(mask_pattern)], data['masked_suffix'][:-len(mask_pattern)])

            self.assertEqual(mask_pattern, hidden_data['masked_without_plaintext'])

            # if plaintext length > data, then whole data will be encrypted
            self.assertEqual(mask_pattern, hidden_data['exact_plaintext_length'])

            self.assertEqual(mask_pattern, hidden_data['shorter_plaintext'])


class TestMaskingWithZonePerRow(BaseMasking):
    ZONE = True

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        if popen_kwargs is None:
            popen_kwargs = {}
        env = popen_kwargs.get('env', {})
        env['ZONE_FOR_ROW'] = 'on'
        env.update(os.environ)
        popen_kwargs['env'] = env
        return super(TestMaskingWithZonePerRow, self).fork_acra(popen_kwargs, **acra_kwargs)

    def test_masking_specific_zone_id(self):
        specific_zone_id_table = sa.Table(
            'test_masking_specific_zone_id', metadata,
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('nullable_column', sa.Text, nullable=True),
            sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('masked_prefix', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('masked_suffix', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('masked_without_plaintext', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('exact_plaintext_length', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('shorter_plaintext', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            extend_existing=True
        )
        metadata.create_all(self.engine_raw, [specific_zone_id_table])
        self.engine_raw.execute(specific_zone_id_table.delete())
        data = {
            'id': 1,
            'nullable_column': None,
            'empty': b'',
            'masked_prefix': random_bytes(9),
            'masked_suffix': random_bytes(9),
            'masked_without_plaintext': random_bytes(),
            'exact_plaintext_length': random_bytes(10),
            'shorter_plaintext': random_bytes(9),
        }

        # insert data data with another client_id (keypair1) than should be encrypted (keypair2)
        self.engine1.execute(specific_zone_id_table.insert(values=data))

        self.check_crypto_envelope(specific_zone_id_table, data['id'])

        columns = [sa.literal(zones[0][ZONE_ID])]
        for i in ('masked_prefix', 'masked_suffix', 'masked_without_plaintext', 'exact_plaintext_length', 'shorter_plaintext'):
            # create in loop to generate new objects of literal and avoid removing in select clause by sqlalchemy
            columns.append(getattr(specific_zone_id_table.c, i))

        # check that using any acra-server with correct zone we fetch decrypted data
        for engine in (self.engine1, self.engine2):
            # expect that data was encrypted with client_id from acra-server which used to insert (client_id==TEST_TLS_CLIENT_2_CERT)
            response = engine.execute(
                sa.select(columns)
                    .where(specific_zone_id_table.c.id == data['id']))
            source_data = response.fetchall()
            if len(source_data) != 1:
                self.fail('incorrect len of result data')

            for i in ('masked_prefix', 'masked_suffix', 'masked_without_plaintext', 'exact_plaintext_length', 'shorter_plaintext'):
                self.assertEqual(source_data[0][i], data[i])

        incorrect_zone = sa.literal(zones[1][ZONE_ID])
        # check that using any acra-server with incorrect zone we fetch masked data
        for engine in (self.engine1, self.engine2):
            hidden_data = engine.execute(
                sa.select([incorrect_zone, specific_zone_id_table])
                    .where(specific_zone_id_table.c.id == data['id']))
            hidden_data = hidden_data.fetchall()

            if len(source_data) != len(hidden_data) != 1:
                self.fail('incorrect len of result data')

            for i in ('masked_prefix', 'masked_suffix', 'masked_without_plaintext', 'exact_plaintext_length', 'shorter_plaintext'):
                self.assertEqual(source_data[0][i], data[i])

            hidden_data = hidden_data[0]
            mask_pattern = 'xxxx'.encode('ascii')
            # check that mask at correct place
            self.assertEqual(hidden_data['masked_prefix'][:len(mask_pattern)], mask_pattern)
            # check that len of masked value not equal to source data because acrastruct always longer than plaintext
            self.assertNotEqual(len(hidden_data['masked_prefix']), len(data['masked_prefix']))
            # check that data after mask is not the same as source data
            self.assertNotEqual(hidden_data['masked_prefix'][len(mask_pattern):], data)
            # check that data after mask is not the same as source data with same offset as mask length
            self.assertNotEqual(hidden_data['masked_prefix'][len(mask_pattern):], data['masked_prefix'][len(mask_pattern):])

            # check that mask at correct place
            self.assertEqual(hidden_data['masked_suffix'][-len(mask_pattern):], mask_pattern)
            # check that len of masked value not equal to source data because acrastruct always longer than plaintext
            self.assertNotEqual(len(hidden_data['masked_suffix']), len(data['masked_suffix']))
            # check that data before mask is not the same as source data
            self.assertNotEqual(hidden_data['masked_suffix'][:-len(mask_pattern)], data)
            # check that data after mask is not the same as source data with same offset as mask length
            self.assertNotEqual(hidden_data['masked_suffix'][:-len(mask_pattern)], data['masked_suffix'][:-len(mask_pattern)])

            self.assertEqual(mask_pattern, hidden_data['masked_without_plaintext'])

            # if plaintext length > data, then whole data will be encrypted
            self.assertEqual(mask_pattern, hidden_data['exact_plaintext_length'])

            self.assertEqual(mask_pattern, hidden_data['shorter_plaintext'])


class BaseAcraBlockMasking:
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/ee_masking_acrablock_config.yaml')

    def check_crypto_envelope(self, table, row_id):
        temp_acrastruct = create_acrastruct_with_client_id(b'somedata', TLS_CERT_CLIENT_ID_1)
        # expect that data was encrypted with client_id from acra-server which used to insert (client_id==TEST_TLS_CLIENT_CERT)
        source_data = self.engine_raw.execute(
            sa.select([table])
                .where(table.c.id == row_id))
        source_data = source_data.fetchone()
        for i in ('masked_prefix', 'masked_suffix', 'masked_without_plaintext', 'exact_plaintext_length',
                  'shorter_plaintext'):
            # check that data not contains AcraStruct tag begin
            self.assertNotIn(temp_acrastruct[:8], source_data[i])
            # and check that data contains AcraBlock tag begin
            self.assertIn(temp_acrastruct[:4], source_data[i])


class TestMaskingAcraBlockWithoutZone(BaseAcraBlockMasking, TestMaskingWithoutZone):
    pass


class TestMaskingAcraBlockWithoutZoneWithCachedKeystore(KeystoreCacheOnStartMixin, TestMaskingAcraBlockWithoutZone):
    pass


class TestMaskingAcraBlockWithoutZoneBinaryMySQL(BaseAcraBlockMasking, BaseMaskingBinaryMySQLMixin, TestMaskingWithoutZone):
    pass


class TestMaskingAcraBlockWithoutZoneBinaryPostgreSQL(BaseAcraBlockMasking, BaseMaskingBinaryPostgreSQLMixin, TestMaskingWithoutZone):
    pass


class TestMaskingAcraBlockWithoutZoneBinaryPostgreSQLWithCachedKeystore(KeystoreCacheOnStartMixin, TestMaskingAcraBlockWithoutZoneBinaryPostgreSQL):
    pass


class TestMaskingAcraBlockWithoutZoneWithDefaults(BaseAcraBlockMasking, TestMaskingWithoutZone):
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/ee_masking_acrablock_with_defaults_config.yaml')


class TestMaskingAcraBlockWithZonePerValue(BaseAcraBlockMasking, TestMaskingWithZonePerValue):
    pass


class TestMaskingAcraBlockWithZonePerValueWithCachedKeystore(KeystoreCacheOnStartMixin, TestMaskingAcraBlockWithZonePerValue):
    pass


class TestMaskingAcraBlockWithZonePerValueBinaryMySQL(BaseAcraBlockMasking, BaseMaskingBinaryMySQLMixin, TestMaskingWithZonePerValue):
    pass


class TestMaskingAcraBlockWithZonePerValueBinaryPostgreSQL(BaseAcraBlockMasking, BaseMaskingBinaryPostgreSQLMixin, TestMaskingWithZonePerValue):
    pass


class TestMaskingAcraBlockWithZonePerValueWithDefaults(BaseAcraBlockMasking, TestMaskingWithZonePerValue):
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/ee_masking_acrablock_with_defaults_config.yaml')


class TestMaskingAcraBlockWithZonePerRow(BaseAcraBlockMasking, TestMaskingWithZonePerRow):
    pass


class TestMaskingWithoutZoneConnectorlessWithTLSByDN(TLSAuthenticationByDistinguishedNameMixin, TLSAuthenticationDirectlyToAcraMixin, TestMaskingWithoutZone):
    def get_specified_client_id(self):
        return extract_client_id_from_cert(tls_cert=TEST_TLS_CLIENT_2_CERT, extractor=self.get_identifier_extractor_type())


class TestMaskingWithoutZoneConnectorlessWithTLSBySerialNumber(TLSAuthenticationBySerialNumberMixin, TLSAuthenticationDirectlyToAcraMixin, TestMaskingWithoutZone):
    def get_specified_client_id(self):
        return extract_client_id_from_cert(tls_cert=TEST_TLS_CLIENT_2_CERT, extractor=self.get_identifier_extractor_type())


class TestMaskingWithZonePerValueConnectorlessWithTLSByDN(TLSAuthenticationByDistinguishedNameMixin, TLSAuthenticationDirectlyToAcraMixin, TestMaskingWithZonePerValue):
    def get_specified_client_id(self):
        return extract_client_id_from_cert(tls_cert=TEST_TLS_CLIENT_2_CERT, extractor=self.get_identifier_extractor_type())


class TestMaskingWithZonePerValueConnectorlessWithTLSBySerialNumber(TLSAuthenticationBySerialNumberMixin, TLSAuthenticationDirectlyToAcraMixin, TestMaskingWithZonePerValue):
    def get_specified_client_id(self):
        return extract_client_id_from_cert(tls_cert=TEST_TLS_CLIENT_2_CERT, extractor=self.get_identifier_extractor_type())


class TestTransparentEncryptionConnectorlessWithTLSBySerialNumber(TLSAuthenticationBySerialNumberMixin, TestTransparentEncryption, TLSAuthenticationDirectlyToAcraMixin):
    pass


class TestTransparentEncryptionConnectorlessWithTLSByDN(TLSAuthenticationByDistinguishedNameMixin, TestTransparentEncryption, TLSAuthenticationDirectlyToAcraMixin):
    pass


class TestSearchableTransparentEncryptionConnectorlessWithTLSByDN(TLSAuthenticationByDistinguishedNameMixin, TestSearchableTransparentEncryption, TLSAuthenticationDirectlyToAcraMixin):
    pass


class TestSearchableTransparentEncryptionConnectorlessWithTLSBySerialNumber(TLSAuthenticationBySerialNumberMixin, TestSearchableTransparentEncryption, TLSAuthenticationDirectlyToAcraMixin):
    pass


class TestSearchableTransparentEncryptionWithZoneConnectorlessWithTLSByDN(TLSAuthenticationByDistinguishedNameMixin, TestTransparentSearchableEncryptionWithZone, TLSAuthenticationDirectlyToAcraMixin):
    pass


class TestSearchableTransparentEncryptionWithZoneConnectorlessWithTLSBySerialNumber(TLSAuthenticationBySerialNumberMixin, TestTransparentSearchableEncryptionWithZone, TLSAuthenticationDirectlyToAcraMixin):
    pass


class TestTokenizationConnectorlessWithTLSBySerialNumber(TLSAuthenticationBySerialNumberMixin, TLSAuthenticationDirectlyToAcraMixin, TestTokenizationWithoutZone):
    def get_specified_client_id(self):
        return extract_client_id_from_cert(tls_cert=TEST_TLS_CLIENT_2_CERT, extractor=self.get_identifier_extractor_type())


class TestTokenizationConnectorlessWithTLSByDN(TLSAuthenticationByDistinguishedNameMixin, TLSAuthenticationDirectlyToAcraMixin, TestTokenizationWithoutZone):
    def get_specified_client_id(self):
        return extract_client_id_from_cert(tls_cert=TEST_TLS_CLIENT_2_CERT, extractor=self.get_identifier_extractor_type())


class TestTokenizationConnectorlessWithZoneWithTLSBySerialNumber(TLSAuthenticationBySerialNumberMixin, TLSAuthenticationDirectlyToAcraMixin, TestTokenizationWithZone):
    def get_specified_client_id(self):
        return extract_client_id_from_cert(tls_cert=TEST_TLS_CLIENT_2_CERT, extractor=self.get_identifier_extractor_type())


class TestTokenizationConnectorlessWithZoneWithTLSByDN(TLSAuthenticationByDistinguishedNameMixin, TLSAuthenticationDirectlyToAcraMixin, TestTokenizationWithZone):
    def get_specified_client_id(self):
        return extract_client_id_from_cert(tls_cert=TEST_TLS_CLIENT_2_CERT, extractor=self.get_identifier_extractor_type())


class TestEmptyPreparedStatementQueryPostgresql(BaseTestCase):
    def checkSkip(self):
        if not TEST_POSTGRESQL:
            self.skipTest("Only for postgresql")
        super().checkSkip()

    def testPassedEmptyQuery(self):
        # no matter which connector to use
        executor = AsyncpgExecutor(ConnectionArgs(
            host=get_db_host(), port=self.ACRASERVER_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_USER_PASSWORD,
            format=AsyncpgExecutor.BinaryFormat,
            ssl_ca=TEST_TLS_CA,
            ssl_key=TEST_TLS_CLIENT_KEY,
            ssl_cert=TEST_TLS_CLIENT_CERT
        ))
        result = executor.execute(query='')
        self.assertIsNotNone(result)
        result = executor.execute_prepared_statement(query='')
        self.assertIsNotNone(result)

        # just check that Postgresql deny empty queries for SimpleQuery protocol of queries
        executor = Psycopg2Executor(ConnectionArgs(
            host=get_db_host(), port=self.ACRASERVER_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_USER_PASSWORD,
            ssl_ca=TEST_TLS_CA,
            ssl_key=TEST_TLS_CLIENT_KEY,
            ssl_cert=TEST_TLS_CLIENT_CERT
        ))
        with self.assertRaises(psycopg2.ProgrammingError) as exc:
            executor.execute(query='')
        self.assertEqual(exc.exception.args[0].lower(), "can't execute an empty query")
        with self.assertRaises(psycopg2.errors.SyntaxError) as exc:
            executor.execute_prepared_statement(query='')
        self.assertIn('syntax error at end of input', exc.exception.args[0].lower())


class TestEmptyPreparedStatementQueryMysql(BaseTestCase):
    def checkSkip(self):
        if not TEST_MYSQL:
            self.skipTest("Only for mysql")
        super().checkSkip()

    def testNotPassedEmptyQuery(self):
        # no matter which client_id to use
        executor = MysqlExecutor(ConnectionArgs(
            host=get_db_host(), port=self.ACRASERVER_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_USER_PASSWORD,
            ssl_ca=TEST_TLS_CA,
            ssl_key=TEST_TLS_CLIENT_KEY,
            ssl_cert=TEST_TLS_CLIENT_CERT))
        with self.assertRaises(mysql.connector.errors.ProgrammingError) as exc:
            executor.execute_prepared_statement(query='')
        self.assertEqual(exc.exception.errno, 1065)
        self.assertEqual(exc.exception.sqlstate, '42000')
        self.assertEqual(exc.exception.msg.lower(), 'query was empty')


class TestKeymakerCertificateKeysFailures(unittest.TestCase):
    def testFailureOnUsageClientIDAndCertificate(self):
        with tempfile.TemporaryDirectory() as folder:
            # by default --client_id=client, so we define only --tls_cert
            with self.assertRaises(subprocess.CalledProcessError) as exc:
                subprocess.check_output(
                    [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keymaker'),
                     '--keystore={}'.format(KEYSTORE_VERSION),
                     '--keys_output_dir={}'.format(folder),
                     '--keys_public_output_dir={}'.format(folder),
                     '--tls_cert={}'.format(TEST_TLS_CLIENT_CERT)],
                    env={'ACRA_MASTER_KEY': get_master_key()},
                    stderr=subprocess.STDOUT)
            self.assertIn("You can either specify identifier for keys".lower(), exc.exception.output.decode('utf8').lower())
            self.assertEqual(exc.exception.returncode, 1)

    def testFailureEmptyExtractorType(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(subprocess.CalledProcessError) as exc:
                subprocess.check_output(
                    [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keymaker'),
                     '--keystore={}'.format(KEYSTORE_VERSION),
                     '--keys_output_dir={}'.format(folder),
                     '--keys_public_output_dir={}'.format(folder),
                     '--client_id=',
                     '--tls_cert={}'.format(TEST_TLS_CLIENT_CERT),
                     '--tls_identifier_extractor_type=""'],
                    env={'ACRA_MASTER_KEY': get_master_key()},
                    stderr=subprocess.STDOUT)
            self.assertIn("invalid identifier extractor type".lower(), exc.exception.output.decode('utf8').lower())
            self.assertEqual(exc.exception.returncode, 1)


class BaseKeymakerCertificateKeys:

    def testSuccessKeyGeneration(self):
        with tempfile.TemporaryDirectory() as folder:
            key_id = extract_client_id_from_cert(tls_cert=TEST_TLS_CLIENT_CERT, extractor=self.get_identifier_extractor_type())

            # check that key not exists
            with self.assertRaises(subprocess.CalledProcessError) as exc:
                read_storage_private_key(folder, key_id)
            self.assertEqual(exc.exception.returncode, 1)


            subprocess.check_output(
                [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keymaker'),
                 '--keystore={}'.format(KEYSTORE_VERSION),
                 '--keys_output_dir={}'.format(folder),
                 '--keys_public_output_dir={}'.format(folder),
                 '--client_id=',
                 '--tls_cert={}'.format(TEST_TLS_CLIENT_CERT),
                 '--tls_identifier_extractor_type={}'.format(self.get_identifier_extractor_type())],
                env={'ACRA_MASTER_KEY': get_master_key()},
                stderr=subprocess.STDOUT)

            # check that key exists
            self.assertIsNotNone(read_storage_private_key(folder, key_id))


class TestKeymakerCertificateKeysBySerialNumber(TLSAuthenticationBySerialNumberMixin, BaseKeymakerCertificateKeys,
                                                unittest.TestCase):
    pass


class TestKeymakerCertificateKeysByDistinguishedName(TLSAuthenticationByDistinguishedNameMixin,
                                                     BaseKeymakerCertificateKeys, unittest.TestCase):
    pass


class TestTransparentAcraBlockEncryption(TestTransparentEncryption):
    WHOLECELL_MODE = False
    encryptor_table = sa.Table('test_transparent_acrablock_encryption', metadata,
                               sa.Column('id', sa.Integer, primary_key=True),
                               sa.Column('specified_client_id',
                                         sa.LargeBinary(length=COLUMN_DATA_SIZE)),
                               sa.Column('default_client_id',
                                         sa.LargeBinary(length=COLUMN_DATA_SIZE)),
                               sa.Column('number', sa.Integer),
                               sa.Column('zone_id', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
                               sa.Column('raw_data', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
                               sa.Column('nullable', sa.Text, nullable=True),
                               sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
                               sa.Column('token_i64', sa.BigInteger(), nullable=False, default=1),
                               sa.Column('token_str', sa.Text, nullable=False, default=''),
                               sa.Column('token_bytes', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
                               sa.Column('masked_prefix', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
                               )
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/ee_acrablock_config.yaml')

    def testAcraStructReEncryption(self):
        specified_id = TLS_CERT_CLIENT_ID_1
        default_id = TLS_CERT_CLIENT_ID_2
        test_data = get_pregenerated_random_data().encode('utf-8')
        specified_acrastruct = create_acrastruct_with_client_id(test_data, specified_id)
        default_acrastruct = create_acrastruct_with_client_id(test_data, default_id)
        row_id = get_random_id()
        zone = zones[0]
        data = {'specified_client_id': specified_acrastruct,
                'default_client_id': default_acrastruct,
                'zone_id': test_data,
                'id': row_id,
                'masked_prefix': get_pregenerated_random_data().encode('ascii'),
                'token_bytes': get_pregenerated_random_data().encode('ascii'),
                'token_str': get_pregenerated_random_data(),
                'token_i64': random.randint(0, 2 ** 32),
                }
        self.insertRow(data)
        raw_data = self.engine_raw.execute(
            sa.select([self.encryptor_table.c.specified_client_id,
                       self.encryptor_table.c.default_client_id,
                       sa.LargeBinary().bind_expression(zone[ZONE_ID].encode('ascii')),
                       self.encryptor_table.c.zone_id,
                       self.encryptor_table.c.masked_prefix,
                       self.encryptor_table.c.token_bytes,
                       self.encryptor_table.c.token_str,
                       self.encryptor_table.c.token_i64])
                .where(self.encryptor_table.c.id == row_id))

        raw_data = raw_data.fetchone()
        self.assertNotEqual(raw_data['specified_client_id'], test_data)
        self.assertNotEqual(raw_data['default_client_id'], test_data)
        self.assertEqual(raw_data['specified_client_id'][:3], CRYPTO_ENVELOPE_HEADER)
        self.assertEqual(raw_data['default_client_id'][:3], CRYPTO_ENVELOPE_HEADER)
        self.assertNotEqual(raw_data['zone_id'], test_data)
        # no matter from which acrastruct take first symbols
        self.assertEqual(raw_data['zone_id'][:3], CRYPTO_ENVELOPE_HEADER)
        for i in ('masked_prefix', 'token_bytes', 'token_str', 'token_i64'):
            self.assertNotEqual(raw_data[i], data[i])

        decrypted_data = self.engine2.execute(
            sa.select([self.encryptor_table.c.specified_client_id,
                       self.encryptor_table.c.default_client_id,
                       sa.LargeBinary().bind_expression(zone[ZONE_ID].encode('ascii')),
                       self.encryptor_table.c.zone_id,
                       self.encryptor_table.c.masked_prefix,
                       self.encryptor_table.c.token_bytes,
                       self.encryptor_table.c.token_str,
                       self.encryptor_table.c.token_i64])
                .where(self.encryptor_table.c.id == row_id))
        decrypted_data = decrypted_data.fetchone()
        self.assertNotEqual(decrypted_data['specified_client_id'], specified_acrastruct)
        self.assertEqual(decrypted_data['default_client_id'], test_data)
        # haven't to be decrypted due to zonemode off
        self.assertNotEqual(decrypted_data['zone_id'], test_data)
        for i in ('masked_prefix', 'token_bytes', 'token_str', 'token_i64'):
            self.assertEqual(decrypted_data[i], data[i])


class TestTransparentAcraBlockEncryptionMissingExtraLog(TestTransparentAcraBlockEncryption):
    def fork_acra(self, popen_kwargs: dict=None, **acra_kwargs: dict):
        self.log_file = tempfile.NamedTemporaryFile('w+', encoding='utf-8')
        acra_kwargs['log_to_file'] = self.log_file.name
        acra_kwargs['poison_detect_enable'] = 'true'
        return super().fork_acra(popen_kwargs, **acra_kwargs)

    def testAcraStructReEncryption(self):
        super().testAcraStructReEncryption()
        with open(self.log_file.name, 'r') as f:
            logs = f.read()
        self.assertNotIn('invalid AcraBlock', logs)
        self.assertNotIn("Can't decrypt AcraBlock", logs)

    def testEncryptedInsert(self):
        super().testEncryptedInsert()
        with open(self.log_file.name, 'r') as f:
            logs = f.read()
        self.assertNotIn('invalid AcraBlock', logs)
        self.assertNotIn("Can't decrypt AcraBlock", logs)


class TestTransparentAcraBlockEncryptionWithDefaults(TestTransparentAcraBlockEncryption):
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/ee_acrablock_config_with_defaults.yaml')


class TestTransparentAcraBlockEncryptionWithZone(TestTransparentAcraBlockEncryption, TestTransparentEncryptionWithZone):
    ZONE = True

    zone_encryptor_table = sa.Table('test_transparent_acrablock_encryption_with_zone', metadata,
                                    sa.Column('id', sa.Integer, primary_key=True),
                                    sa.Column('specified_client_id',
                                              sa.LargeBinary(length=COLUMN_DATA_SIZE)),
                                    sa.Column('default_client_id',
                                              sa.LargeBinary(length=COLUMN_DATA_SIZE)),
                                    sa.Column('number', sa.Integer),
                                    sa.Column('zone_id', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
                                    sa.Column('raw_data', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
                                    sa.Column('nullable', sa.Text, nullable=True),
                                    sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
                                    sa.Column('token_i64', sa.BigInteger(), nullable=False, default=1),
                                    sa.Column('token_str', sa.Text, nullable=False, default=''),
                                    sa.Column('token_bytes', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
                                    sa.Column('masked_prefix', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
                                    )

    def testAcraStructReEncryption(self):
        specified_id = TLS_CERT_CLIENT_ID_1
        default_id = TLS_CERT_CLIENT_ID_2
        test_data = get_pregenerated_random_data().encode('utf-8')
        specified_acrastruct = create_acrastruct_with_client_id(test_data, specified_id)
        default_acrastruct = create_acrastruct_with_client_id(test_data, default_id)
        zone = zones[0]
        zone_acrastruct = create_acrastruct(test_data, b64decode(zone[ZONE_PUBLIC_KEY]), zone[ZONE_ID].encode('utf-8'))
        row_id = get_random_id()
        data = {'specified_client_id': specified_acrastruct,
                'default_client_id': default_acrastruct,
                'zone_id': zone_acrastruct,
                'id': row_id,
                'masked_prefix': get_pregenerated_random_data().encode('ascii'),
                'token_bytes': get_pregenerated_random_data().encode('ascii'),
                'token_str': get_pregenerated_random_data(),
                'token_i64': random.randint(0, 2 ** 32),
                }
        self.engine2.execute(self.zone_encryptor_table.insert(), data)
        raw_data = self.engine_raw.execute(
            sa.select([self.zone_encryptor_table.c.specified_client_id,
                       self.zone_encryptor_table.c.default_client_id,
                       sa.literal(zone[ZONE_ID]),
                       self.zone_encryptor_table.c.zone_id,
                       self.zone_encryptor_table.c.masked_prefix,
                       self.zone_encryptor_table.c.token_bytes,
                       self.zone_encryptor_table.c.token_str,
                       self.zone_encryptor_table.c.token_i64])
                .where(self.zone_encryptor_table.c.id == row_id))

        raw_data = raw_data.fetchone()
        # should be equal to acrablock begin tag that is first 4 symbols of acrastructs
        self.assertEqual(raw_data['specified_client_id'][:3], CRYPTO_ENVELOPE_HEADER)
        self.assertNotEqual(raw_data['specified_client_id'], test_data)
        self.assertEqual(raw_data['default_client_id'][:3], CRYPTO_ENVELOPE_HEADER)
        self.assertNotEqual(raw_data['default_client_id'], test_data)
        self.assertEqual(raw_data['zone_id'][:3], CRYPTO_ENVELOPE_HEADER)
        self.assertNotEqual(raw_data['zone_id'], test_data)

        for i in ('masked_prefix', 'token_bytes', 'token_str', 'token_i64'):
            self.assertNotEqual(raw_data[i], data[i])

        decrypted_data = self.engine2.execute(
            sa.select([self.zone_encryptor_table.c.specified_client_id,
                       self.zone_encryptor_table.c.default_client_id,
                       sa.literal(zone[ZONE_ID]),
                       self.zone_encryptor_table.c.zone_id,
                       self.zone_encryptor_table.c.masked_prefix,
                       self.zone_encryptor_table.c.token_bytes,
                       self.zone_encryptor_table.c.token_str,
                       self.zone_encryptor_table.c.token_i64])
                .where(self.zone_encryptor_table.c.id == row_id))
        decrypted_data = decrypted_data.fetchone()
        self.assertEqual(decrypted_data['specified_client_id'][:3], CRYPTO_ENVELOPE_HEADER)
        self.assertEqual(decrypted_data['default_client_id'][:3], CRYPTO_ENVELOPE_HEADER)
        self.assertEqual(decrypted_data['zone_id'], test_data)
        for i in ('masked_prefix', 'token_bytes', 'token_str', 'token_i64'):
            self.assertEqual(decrypted_data[i], data[i])


class TestTransparentAcraBlockEncryptionWithZoneWithDefaults(TestTransparentAcraBlockEncryptionWithZone):
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/ee_acrablock_config_with_defaults.yaml')


class TestInvalidCryptoEnvelope(unittest.TestCase):
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/ee_encryptor_config.yaml')

    def test_invalid_defaults(self):
        with open(self.ENCRYPTOR_CONFIG, 'r') as f:
            config = yaml.safe_load(f)
        if 'defaults' not in config:
            config['defaults'] = {
                'crypto_envelope': 'invalid',
            }

        with open(get_test_encryptor_config(self.ENCRYPTOR_CONFIG), 'w') as f:
            yaml.dump(config, f)

        with self.assertRaises(Exception) as e:
            BaseTestCase().fork_acra(encryptor_config_file=get_test_encryptor_config(self.ENCRYPTOR_CONFIG))
        self.assertEqual(str(e.exception), WAIT_CONNECTION_ERROR_MESSAGE)

    def test_invalid_specified_values(self):
        with open(self.ENCRYPTOR_CONFIG, 'r') as f:
            config = yaml.safe_load(f)

        for table in config['schemas']:
            for column in table['encrypted']:
                column['crypto_envelope'] = 'invalid'

        with open(get_test_encryptor_config(self.ENCRYPTOR_CONFIG), 'w') as f:
            yaml.dump(config, f)

        with self.assertRaises(Exception) as e:
            BaseTestCase().fork_acra(encryptor_config_file=get_test_encryptor_config(self.ENCRYPTOR_CONFIG))
        self.assertEqual(str(e.exception), WAIT_CONNECTION_ERROR_MESSAGE)


class TestRegressionInvalidOctalEncoding(BaseTokenizationWithBinaryPostgreSQL):
    def testOctalIntegerValue(self):
        default_client_id_table = sa.Table(
            'test_tokenization_default_client_id', metadata,
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('nullable_column', sa.Text, nullable=True),
            sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('token_i32', sa.Integer()),
            sa.Column('token_i64', sa.BigInteger()),
            sa.Column('token_str', sa.Text),
            sa.Column('token_bytes', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('token_email', sa.Text),
            extend_existing=True,
        )
        metadata.create_all(self.engine_raw, [default_client_id_table])
        self.engine1.execute(default_client_id_table.delete())
        data = {
            'id': 1,
            'nullable_column': None,
            'empty': b'',
            # \111 - octal value that will be decoded to 'I' or 73 byte value. And will be incorrect for uint32 conversion
            'token_i32': 1546727729,
            'token_i64': random_int64(),
            'token_str': random_str(),
            'token_bytes': random_bytes(),
            'token_email': random_email(),
        }
        #self.engine_raw.execute(default_client_id_table.insert(), data)

        # insert data data
        self.insert_via_1(default_client_id_table.insert(), data)

        # expect that data was encrypted with client_id which used to insert (client_id==TEST_TLS_CLIENT_CERT)
        source_data = self.fetch_from_1(
            sa.select([default_client_id_table])
                .where(default_client_id_table.c.id == data['id']))

        hidden_data = self.fetch_from_2(
            sa.select([default_client_id_table])
                .where(default_client_id_table.c.id == data['id']))

        if len(source_data) != len(hidden_data) != 1:
            self.fail('incorrect len of result data')

        # data owner take source data
        for k in ('token_i32', 'token_i64', 'token_str', 'token_bytes', 'token_email'):
            if isinstance(source_data[0][k], bytearray) and isinstance(data[k], str):
                self.assertEqual(source_data[0][k], bytearray(data[k], encoding='utf-8'))
            else:
                self.assertEqual(source_data[0][k], data[k])
                self.assertNotEqual(hidden_data[0][k], data[k])


if __name__ == '__main__':
    import xmlrunner
    output_path = os.environ.get('TEST_XMLOUTPUT', '')
    if output_path:
        with open(output_path, 'wb') as output:
            unittest.main(testRunner=xmlrunner.XMLTestRunner(output=output))
    else:
        unittest.main()
