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
import subprocess
import sys
import tempfile
import time
import traceback
import unittest
from base64 import b64decode, b64encode
from distutils.dir_util import copy_tree
from urllib.parse import urlparse

import asyncpg
import grpc
import mysql.connector
import psycopg as psycopg3
import psycopg2
import psycopg2.errors
import psycopg2.extras
import pymysql
import redis
import requests
import semver
import sqlalchemy as sa
from sqlalchemy.dialects import mysql as mysql_dialect
from sqlalchemy.dialects import postgresql as postgresql_dialect
from sqlalchemy.exc import DatabaseError

import api_pb2
import api_pb2_grpc
import utils
from utils import (read_storage_public_key, read_storage_private_key,
                   read_poison_public_key, read_poison_private_key,
                   deserialize_and_decrypt_acrastruct,
                   load_random_data_config, get_random_data_files,
                   clean_test_data, abs_path, send_signal_by_process_name,
                   BINARY_OUTPUT_FOLDER)

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
TEST_MYSQL = utils.get_bool_env('TEST_MYSQL', default=False)
TEST_MARIADB = utils.get_bool_env('TEST_MARIADB', default=False)
if TEST_MYSQL or TEST_MARIADB:
    TEST_POSTGRESQL = False
    DB_DRIVER = "mysql+pymysql"
    TEST_MYSQL = True
    connect_args = {
        'user': DB_USER, 'password': DB_USER_PASSWORD,
        'database': DB_NAME,
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


# Set this to False to not rebuild binaries on setup.
CLEAN_BINARIES = utils.get_bool_env('TEST_CLEAN_BINARIES', default=True)
# Set this to False to not build binaries in principle.
BUILD_BINARIES = True


hasSetUp = False


def setUpModule():
    global hasSetUp
    if hasSetUp is False:
        baseSetUpModule()
        hasSetUp = True


def tearDownModule():
    global hasSetUp
    if hasSetUp is True:
        baseTearDownModule()
        hasSetUp = False


def baseSetUpModule():
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


def baseTearDownModule():
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
                use_unicode=True, raw=self.connection_args.raw, charset='ascii',
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
                use_unicode=True, charset='ascii',
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
                use_unicode=True, charset='ascii',
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
                use_unicode=False, raw=self.connection_args.raw, charset='ascii',
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
        with contextlib.closing(mysql.connector.connection.MySQLConnection(
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
                utils.memoryview_rows_to_bytes(data)
                return data

    def execute(self, query, args=None):
        return self._execute(query, args, prepare=False)

    def execute_prepared_statement(self, query, args=None):
        return self._execute(query, args, prepare=True)


class ExecutorMixin:
    """

    ExecutorMixin setups creates executors during the `setUp`:
      - self.executor1 - connection to the Acra with the first certificate
      - self.executor2 - connection to the Acra with the second certificate
      - self.raw_executor - direct connection to the database

    It uses `self.executor_with_ssl` to set up args and `self.executor_cls`
    to create an engine of desired type.

    """
    RAW_EXECUTOR = True
    FORMAT = ''

    def setUp(self):
        super().setUp()
        acra_port = self.ACRASERVER_PORT
        self.executor1 = self.executor_with_ssl(
            TEST_TLS_CLIENT_KEY, TEST_TLS_CLIENT_CERT, acra_port, 'localhost')
        self.executor2 = self.executor_with_ssl(
            TEST_TLS_CLIENT_2_KEY, TEST_TLS_CLIENT_2_CERT, acra_port, 'localhost')
        self.raw_executor = self.executor_with_ssl(
            TEST_TLS_CLIENT_KEY, TEST_TLS_CLIENT_CERT, DB_PORT, DB_HOST)

    def executor_with_ssl(self, ssl_key, ssl_cert, port, host):
        if port is None:
            port = self.ACRASERVER_PORT
        args = ConnectionArgs(
            host=host, port=port, dbname=DB_NAME,
            user=DB_USER, password=DB_USER_PASSWORD,
            ssl_ca=TEST_TLS_CA,
            ssl_key=ssl_key,
            ssl_cert=ssl_cert,
            format=self.FORMAT,
            raw=self.RAW_EXECUTOR,
        )
        return self.executor_cls(args)


class Psycopg3ExecutorMixin(ExecutorMixin):
    executor_cls = Psycopg3Executor


class AsyncpgExecutorMixin(ExecutorMixin):
    executor_cls = AsyncpgExecutor


class MysqlExecutorMixin(ExecutorMixin):
    executor_cls = MysqlExecutor


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
        # keys not needed client_id for generation
        with tempfile.TemporaryDirectory() as folder:
            subprocess.check_output(
                [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keymaker'), '--keystore={}'.format(KEYSTORE_VERSION),
                 '--keys_output_dir={}'.format(folder),
                 "--client_id=''",
                 '--generate_poisonrecord_keys',
                 '--generate_log_key',
                 '--keys_public_output_dir={}'.format(folder)])

            # check that keymaker will no fail on case of not created directory
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


class BaseTestCase(PrometheusMixin, unittest.TestCase):
    DEBUG_LOG = utils.get_bool_env('DEBUG_LOG', True)
    # for debugging with manually runned acra-server
    EXTERNAL_ACRA = False
    ACRASERVER_PORT = int(os.environ.get('TEST_ACRASERVER_PORT', 10003))
    ACRASERVER_PROMETHEUS_PORT = int(os.environ.get('TEST_ACRASERVER_PROMETHEUS_PORT', 11004))
    ACRA_BYTEA = 'pgsql_hex_bytea'
    DB_BYTEA = 'hex'
    WHOLECELL_MODE = False
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

    def get_acra_cli_args(self, acra_kwargs):
        connection_string = self.get_acraserver_connection_string(
            acra_kwargs.get('incoming_connection_port', self.ACRASERVER_PORT))
        api_connection_string = self.get_acraserver_api_connection_string(
            acra_kwargs.get('incoming_connection_api_port')
        )
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
            'http_api_enable': 'true',
            'keystore_cache_on_start_enable': 'false',
            'keys_dir': KEYS_FOLDER.name,
        }
        # keystore v2 doest not support caching, disable it for now
        if KEYSTORE_VERSION == 'v2':
            args['keystore_cache_size'] = -1
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
        return args

    def _fork_acra(self, acra_kwargs, popen_kwargs):
        logging.info("fork acra")
        args = self.get_acra_cli_args(acra_kwargs)
        for path in [socket_path_from_connection_string(args['incoming_connection_string']),
                     socket_path_from_connection_string(args['incoming_connection_api_string'])]:
            try:
                os.remove(path)
            except:
                pass

        if not popen_kwargs:
            popen_kwargs = {}
        cli_args = sorted(['--{}={}'.format(k, v) for k, v in args.items() if v is not None])
        print("acra-server args: {}".format(' '.join(cli_args)))
        process = fork(lambda: subprocess.Popen([self.get_acraserver_bin_path()] + cli_args,
                                                **popen_kwargs))
        try:
            self.wait_acraserver_connection(args['incoming_connection_string'])
        except:
            stop_process(process)
            raise
        logging.info("fork acra finished [pid={}]".format(process.pid))
        return process

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        return self._fork_acra(acra_kwargs, popen_kwargs)

    def fork_translator(self, translator_kwargs, popen_kwargs=None):
        logging.info("fork acra-translator")
        from utils import load_default_config
        default_config = load_default_config("acra-translator")
        default_args = {
            'incoming_connection_close_timeout': 0,
            'keys_dir': KEYS_FOLDER.name,
            'logging_format': 'cef',
            'keystore_cache_on_start_enable': 'false',
        }
        default_config.update(default_args)
        default_config.update(translator_kwargs)
        if not popen_kwargs:
            popen_kwargs = {}
        if self.DEBUG_LOG:
            default_config['d'] = 1
        # keystore v2 doest not support caching, disable it for now
        if KEYSTORE_VERSION == 'v2':
            default_config['keystore_cache_size'] = -1
        if TEST_WITH_TRACING:
            default_config['tracing_log_enable'] = 1
            if TEST_TRACE_TO_JAEGER:
                default_config['tracing_jaeger_enable'] = 1

        cli_args = ['--{}={}'.format(k, v) for k, v in default_config.items()]

        translator = fork(lambda: subprocess.Popen([os.path.join(BINARY_OUTPUT_FOLDER, 'acra-translator')] + cli_args,
                                                   **popen_kwargs))
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

            base_args = get_connect_args(port=self.ACRASERVER_PORT, sslmode=SSLMODE)

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
            storage_client_id=None, poison_key=False):
        """this function for printing data which used in test and for
        reproducing error with them if any error detected"""
        if not self.TEST_DATA_LOG:
            return

        def key_name():
            if storage_client_id:
                return 'client storage, id={}'.format(storage_client_id)
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

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
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

    def http_decrypt_request(self, port, client_id, acrastruct):
        api_url = '{}://localhost:{}/v1/decrypt'.format(self.get_http_schema(), port)
        kwargs = self.get_http_default_kwargs()
        kwargs['data'] = acrastruct
        with requests.post(api_url, **kwargs) as response:
            return response.content

    def http_encrypt_request(self, port, client_id, data):
        api_url = '{}://localhost:{}/v1/encrypt'.format(self.get_http_schema(), port)
        kwargs = self.get_http_default_kwargs()
        kwargs['data'] = data
        with requests.post(api_url, **kwargs) as response:
            return response.content

    def get_grpc_channel(self, port):
        '''setup grpc to use tls client authentication'''
        with open(TEST_TLS_CA, 'rb') as ca_file, open(TEST_TLS_CLIENT_KEY, 'rb') as key_file, open(TEST_TLS_CLIENT_CERT,
                                                                                                   'rb') as cert_file:
            ca_bytes = ca_file.read()
            key_bytes = key_file.read()
            cert_bytes = cert_file.read()
        tls_credentials = grpc.ssl_channel_credentials(ca_bytes, key_bytes, cert_bytes)
        return grpc.secure_channel('localhost:{}'.format(port), tls_credentials)

    def grpc_encrypt_request(self, port, client_id, data):
        with self.get_grpc_channel(port) as channel:
            stub = api_pb2_grpc.WriterStub(channel)
            try:
                response = stub.Encrypt(api_pb2.EncryptRequest(
                    client_id=client_id.encode('ascii'), data=data),
                    timeout=SOCKET_CONNECT_TIMEOUT)
            except grpc.RpcError as exc:
                logging.info(exc)
                return b''
            return response.acrastruct

    def grpc_decrypt_request(self, port, client_id, acrastruct, raise_exception_on_failure=False):
        with self.get_grpc_channel(port) as channel:
            stub = api_pb2_grpc.ReaderStub(channel)
            try:
                response = stub.Decrypt(api_pb2.DecryptRequest(
                    client_id=client_id.encode('ascii'), acrastruct=acrastruct),
                    timeout=SOCKET_CONNECT_TIMEOUT)
            except grpc.RpcError as exc:
                logging.info(exc)
                if raise_exception_on_failure:
                    raise
                return b''
            return response.data


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
        redis_hostport = os.environ.get('TEST_REDIS_HOSTPORT', 'localhost:6379')
        redis_host, redis_port = redis_hostport.split(':')
        self.redis_keys_client = redis.Redis(
            host=redis_host, port=int(redis_port), db=self.TEST_REDIS_KEYS_DB,
            ssl=TEST_WITH_TLS, ssl_keyfile=TEST_TLS_CLIENT_KEY, ssl_certfile=TEST_TLS_CLIENT_CERT,
            ssl_ca_certs=TEST_TLS_CA, socket_timeout=SOCKET_CONNECT_TIMEOUT)
        self.redis_tokens_client = redis.Redis(
            host=redis_host, port=int(redis_port), db=self.TEST_REDIS_TOKEN_DB,
            ssl=TEST_WITH_TLS, ssl_keyfile=TEST_TLS_CLIENT_KEY, ssl_certfile=TEST_TLS_CLIENT_CERT,
            ssl_ca_certs=TEST_TLS_CA, socket_timeout=SOCKET_CONNECT_TIMEOUT)
        super().setUp()

    def tearDown(self):
        self.redis_keys_client.flushall()
        self.redis_keys_client.close()
        self.redis_tokens_client.flushall()
        self.redis_tokens_client.close()
        super().tearDown()


class BaseBinaryPostgreSQLTestCase(AsyncpgExecutorMixin, BaseTestCase):
    """Setup test fixture for testing PostgreSQL extended protocol."""

    def checkSkip(self):
        super().checkSkip()
        if not TEST_POSTGRESQL:
            self.skipTest("test only PostgreSQL")

    FORMAT = AsyncpgExecutor.BinaryFormat

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
        param_counter = 1
        for placeholder, value in parameters.items():
            # SQLAlchemy default dialect has placeholders of form ":name".
            # PostgreSQL syntax is "$n", with 1-based sequential parameters.
            saPlaceholder = ':' + placeholder
            # SQLAlchemy has placeholders of form ":name_1" for literal value
            # https://docs.sqlalchemy.org/en/14/core/tutorial.html#operators
            saPlaceholderIndex = saPlaceholder + '_' + str(param_counter)
            if saPlaceholderIndex in query:
                saPlaceholder = saPlaceholderIndex
                param_counter += 1
            # Replace and keep values only for those placeholders which
            # are actually used in the query.
            if saPlaceholder in query:
                pgPlaceholder = '$' + str(len(values) + 1)
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
        # INSERT INTO test_table (id, nullable_column, empty) VALUES (:id, :nullable_column, :empty)
        pattern_string = r'(INSERT INTO) (\S+).*\((.*?)\).*(VALUES).*\((.*?)\)(.*\;?)'

        res = re.findall(pattern_string, query, re.IGNORECASE | re.DOTALL)
        if len(res) > 0:
            # regexp matching result should look like this:
            # `id, nullable_column, empty`
            intos = str(res[0][2])
            count = 1
            for idx, params in enumerate(parameters):
                # each value in bulk insert has unique suffix like ':id_m0'
                suffix = '_m' + str(idx)
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
        # INSERT INTO test_table (id, nullable_column, empty) VALUES (:id, :nullable_column, :empty)
        pattern_string = r'(INSERT INTO) (\S+).*\((.*?)\).*(VALUES).*\((.*?)\)(.*\;?)'

        res = re.findall(pattern_string, query, re.IGNORECASE | re.DOTALL)
        if len(res) > 0:
            # regexp matching result should look like this:
            # `id, nullable_column, empty`
            intos = str(res[0][2])
            count = 1
            # so we need to split it by comma value to iterate over
            for into_value in intos.split(', '):
                values.append(parameters[into_value])
                query = query.replace(':' + into_value, '$' + str(count))
                count += 1
        return query, tuple(values)


class BaseBinaryMySQLTestCase(MysqlExecutorMixin, BaseTestCase):
    """Setup test fixture for testing MySQL extended protocol."""

    def checkSkip(self):
        super().checkSkip()
        if not TEST_MYSQL:
            self.skipTest("test only MySQL")

    def compileInsertQuery(self, query, parameters={}, literal_binds=False):
        """
        Compile SQLAlchemy insert query and parameter dictionary into SQL text and parameter list for the executor.
        It is used regexp parsing to get the correct order of insert params, values are stored in tuple with the same order.
        """
        compile_kwargs = {"literal_binds": literal_binds}
        query = str(query.compile(compile_kwargs=compile_kwargs))
        values = []
        # example of the insert string:
        # INSERT INTO test_table (id, nullable_column, empty) VALUES (:id, :nullable_column, :empty)
        pattern_string = r'(INSERT INTO) (\S+).*\((.*?)\).*(VALUES).*\((.*?)\)(.*\;?)'

        res = re.findall(pattern_string, query, re.IGNORECASE | re.DOTALL)
        if len(res) > 0:
            # regexp matching result should look like this:
            # `id, nullable_column, empty`
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
        # INSERT INTO test_table (id, nullable_column, empty) VALUES (:id, :nullable_column, :empty)
        pattern_string = r'(INSERT INTO) (\S+).*\((.*?)\).*(VALUES).*\((.*?)\)(.*\;?)'

        res = re.findall(pattern_string, query, re.IGNORECASE | re.DOTALL)
        if len(res) > 0:
            # regexp matching result should look like this:
            # `id, nullable_column, empty`
            intos = str(res[0][2])
            for idx, params in enumerate(parameters):
                # each value in bulk insert contains unique suffix like ':id_m0'
                suffix = '_m' + str(idx)
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
        param_counter = 1
        if len(res) > 0:
            for placeholder in res:
                # parameters map contain values where keys without ':' so we need trim the placeholder before
                key = placeholder.lstrip(':')
                if key not in parameters.keys():
                    index_suffix = '_' + str(param_counter)
                    if index_suffix in key:
                        key = key.rstrip(index_suffix)
                        param_counter += 1
                values.append(parameters[key])
                query = query.replace(placeholder, '?')
        return query, tuple(values)


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

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
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


class BaseCensorTest(BaseTestCase):
    CENSOR_CONFIG_FILE = 'default.yaml'

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
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
            self.assertNotIn(expectedMessage.lower(), stderr.decode('utf-8').lower(),
                             "Has message that should not to be in")
        except:
            raise
        finally:
            process.kill()


class TLSAuthenticationDirectlyToAcraMixin:
    """Start acra-server TLS mode and use clientID from certificates
    self.engine1 uses TEST_TLS_CLIENT_* and self.engine2 uses TEST_TLS_CLIENT_2_* values as TLS credentials"""

    def setUp(self):
        if not TEST_WITH_TLS:
            self.skipTest("Test works only with TLS support on db side")
        self.acra_writer_id = extract_client_id_from_cert(tls_cert=TEST_TLS_CLIENT_CERT,
                                                          extractor=self.get_identifier_extractor_type())
        self.assertEqual(create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_CERT,
                                                                extractor=self.get_identifier_extractor_type(),
                                                                keys_dir=KEYS_FOLDER.name), 0)
        # generate encryption keys for second certificate too
        self.assertEqual(create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_2_CERT,
                                                                extractor=self.get_identifier_extractor_type(),
                                                                keys_dir=KEYS_FOLDER.name), 0)
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
        self.assertEqual(
            create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_CERT, keys_dir=KEYS_FOLDER.name), 0)
        # generate encryption keys for second certificate too
        self.assertEqual(
            create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_2_CERT, keys_dir=KEYS_FOLDER.name), 0)
        with self.assertRaises(Exception) as exc:
            self.fork_acra(
                tls_key=abs_path(TEST_TLS_SERVER_KEY),
                tls_cert=abs_path(TEST_TLS_SERVER_CERT),
                # specify explicitly that it is not specified to override default value
                tls_client_auth=-1,
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
        self.assertEqual(
            create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_CERT, keys_dir=KEYS_FOLDER.name), 0)
        # generate encryption keys for second certificate too
        self.assertEqual(
            create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_2_CERT, keys_dir=KEYS_FOLDER.name), 0)
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


class AcraTranslatorTest(AcraTranslatorMixin, BaseTestCase):

    # override BaseTestCase's methods to not start acra-server
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def apiEncryptionTest(self, request_func, use_http=False, use_grpc=False):
        # one is set
        self.assertTrue(use_http or use_grpc)
        # two is not acceptable
        self.assertFalse(use_http and use_grpc)
        translator_port = 3456
        key_folder = tempfile.TemporaryDirectory()
        try:
            client_id = extract_client_id_from_cert(tls_cert=TEST_TLS_CLIENT_CERT,
                                                    extractor=self.get_identifier_extractor_type())
            self.assertEqual(create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_CERT,
                                                                    extractor=self.get_identifier_extractor_type(),
                                                                    keys_dir=key_folder.name), 0)
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
                response = request_func(translator_port, incorrect_client_id, data)
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
            client_id = extract_client_id_from_cert(tls_cert=TEST_TLS_CLIENT_CERT,
                                                    extractor=self.get_identifier_extractor_type())
            self.assertEqual(create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_CERT,
                                                                    extractor=self.get_identifier_extractor_type(),
                                                                    keys_dir=key_folder.name), 0)
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
                response = request_func(translator_port, incorrect_client_id, acrastruct)
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
        fake_offset = (3 + 45 + 84) - 4
        fake_acra_struct = create_acrastruct(
            incorrect_data.encode('ascii'), server_public1)[:fake_offset]
        inner_acra_struct = create_acrastruct(
            correct_data.encode('ascii'), server_public1)
        data = fake_acra_struct + inner_acra_struct + suffix_data.encode('ascii')
        correct_data = correct_data + suffix_data
        row_id = get_random_id()

        self.log(storage_client_id=client_id,
                 data=data,
                 expected=fake_acra_struct + correct_data.encode('ascii'))

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


class TestEnableCachedOnStartupTest(HexFormatTest):

    def checkSkip(self):
        super().checkSkip()
        if KEYSTORE_VERSION == 'v2':
            self.skipTest("test only for keystore Version v1")

    def setUp(self):
        super().setUp()

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        acra_kwargs['keystore_cache_on_start_enable'] = 'true'
        return super(TestEnableCachedOnStartupTest, self).fork_acra(
            popen_kwargs, **acra_kwargs)

    def testReadAcrastructInAcrastruct(self):
        super().testReadAcrastructInAcrastruct()

    def testClientIDRead(self):
        super().testClientIDRead()


class TestKeyRotation(BaseTestCase):
    """Verify key rotation without data reencryption."""

    def read_rotation_public_key(self, extra_kwargs: dict = None):
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


class TestAcraTranslatorClientIDFromTLSByDistinguishedName(TLSAuthenticationByDistinguishedNameMixin,
                                                           AcraTranslatorTest):
    pass


class TestAcraTranslatorClientIDFromTLSBySerialNumber(TLSAuthenticationBySerialNumberMixin,
                                                      TestAcraTranslatorClientIDFromTLSByDistinguishedName):
    pass


class TestTranslatorDisableCachedOnStartup(AcraTranslatorMixin, BaseTestCase):
    def checkSkip(self):
        super().checkSkip()
        if KEYSTORE_VERSION == 'v2':
            self.skipTest("test only for keystore Version v1")

    def setUp(self):
        self.cached_dir = tempfile.TemporaryDirectory()
        # fill temp dir with all keys
        copy_tree(KEYS_FOLDER.name, self.cached_dir.name)
        super().setUp()

    def fork_translator(self, translator_kwargs, popen_kwargs=None):
        args = {
            'keystore_cache_on_start_enable': 'false',
            'keys_dir': self.cached_dir.name
        }
        translator_kwargs.update(args)
        return super().fork_translator(translator_kwargs, popen_kwargs)

    def testApiEncryptionDisableCacheWithoutKeysDir(self):
        translator_port = 3456

        client_id = extract_client_id_from_cert(tls_cert=TEST_TLS_CLIENT_CERT,
                                                extractor=self.get_identifier_extractor_type())
        self.assertEqual(create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_CERT,
                                                                extractor=self.get_identifier_extractor_type(),
                                                                keys_dir=self.cached_dir.name), 0)
        data = get_pregenerated_random_data().encode('ascii')
        client_id_private_key = read_storage_private_key(self.cached_dir.name, client_id)
        connection_string = 'tcp://127.0.0.1:{}'.format(translator_port)
        translator_kwargs = {
            'incoming_connection_http_string': connection_string,
            'tls_key': abs_path(TEST_TLS_SERVER_KEY),
            'tls_cert': abs_path(TEST_TLS_SERVER_CERT),
            'tls_ca': TEST_TLS_CA,
            'keys_dir': self.cached_dir.name,
            'tls_identifier_extractor_type': self.get_identifier_extractor_type(),
            'acratranslator_client_id_from_connection_enable': 'true',
            'tls_ocsp_from_cert': 'ignore',
            'tls_crl_from_cert': 'ignore',
        }

        incorrect_client_id = TLS_CERT_CLIENT_ID_2
        with ProcessContextManager(self.fork_translator(translator_kwargs)):
            self.cached_dir.cleanup()
            response = self.http_encrypt_request(translator_port, incorrect_client_id, data)
            # we cant encrypt data because AcraServer doest have access to encryption key with disabled keystore caching
            self.assertEqual(response, b"Can't encrypt data")
            with self.assertRaises(ValueError):
                deserialize_and_decrypt_acrastruct(response, client_id_private_key, client_id)
