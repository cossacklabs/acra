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
import contextlib
import socket
import json
import logging
import http
import tempfile
import time
import os
import random
import subprocess
import traceback
import unittest
import re
import stat
import uuid
import signal
import ssl
from base64 import b64decode, b64encode
from tempfile import NamedTemporaryFile
from urllib.request import urlopen
from urllib.parse import urlparse
import collections
import collections.abc
import shutil

import requests
import psycopg2
import psycopg2.extras
import pymysql
import semver
import sqlalchemy as sa
import api_pb2_grpc
import api_pb2
import grpc
import asyncpg
import mysql.connector
from prometheus_client.parser import text_string_to_metric_families
from mysql.connector.cursor import MySQLCursorPrepared
from requests.auth import HTTPBasicAuth
from sqlalchemy.exc import DatabaseError
from sqlalchemy.dialects.postgresql import BYTEA
from sqlalchemy.dialects import mysql as mysql_dialect
from sqlalchemy.dialects import postgresql as postgresql_dialect

from utils import (read_storage_public_key, read_storage_private_key,
                   read_zone_public_key, read_zone_private_key,
                   read_poison_public_key, read_poison_private_key,
                   decrypt_acrastruct,
                   load_random_data_config, get_random_data_files,
                   clean_test_data, safe_string, prepare_encryptor_config,
                   get_encryptor_config, abs_path, get_test_encryptor_config, send_signal_by_process_name,
                   load_yaml_config, dump_yaml_config)

import sys
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
TEST_TLS_SERVER_CERT = abs_path(os.environ.get('TEST_TLS_SERVER_CERT', 'tests/ssl/acra-server/acra-server.crt'))
TEST_TLS_SERVER_KEY = abs_path(os.environ.get('TEST_TLS_SERVER_KEY', 'tests/ssl/acra-server/acra-server.key'))
# keys copied to tests/* with modified rights to 0400 because keys in docker/ssl/ has access from groups/other but some
# db drivers prevent usage of keys with global rights
TEST_TLS_CLIENT_CERT = abs_path(os.environ.get('TEST_TLS_CLIENT_CERT', 'tests/ssl/acra-writer/acra-writer.crt'))
TEST_TLS_CLIENT_KEY = abs_path(os.environ.get('TEST_TLS_CLIENT_KEY', 'tests/ssl/acra-writer/acra-writer.key'))
TEST_WITH_TLS = os.environ.get('TEST_TLS', 'off').lower() == 'on'

TEST_WITH_TRACING = os.environ.get('TEST_TRACE', 'off').lower() == 'on'
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
master_keys = None
KEYS_FOLDER = None
ACRA_MASTER_KEY_VAR_NAME = 'ACRA_MASTER_KEY'
ACRA_MASTER_ENCRYPTION_KEY_VAR_NAME = 'ACRA_MASTER_ENCRYPTION_KEY'
ACRA_MASTER_SIGNATURE_KEY_VAR_NAME = 'ACRA_MASTER_SIGNATURE_KEY'
MASTER_KEY_PATH = '/tmp/acra-test-master.key'
MASTER_ENCRYPTION_KEY_PATH = '/tmp/acra-test-master-encryption.key'
MASTER_SIGNATURE_KEY_PATH = '/tmp/acra-test-master-signature.key'

ACRAWEBCONFIG_HTTP_PORT = 8022
ACRAWEBCONFIG_AUTH_DB_PATH = 'auth.keys'
ACRAWEBCONFIG_BASIC_AUTH = dict(
    user='test_user',
    password='test_user_password'
)
ACRAWEBCONFIG_STATIC_PATH = 'cmd/acra-webconfig/static/'
ACRAWEBCONFIG_HTTP_TIMEOUT = 3

POISON_KEY_PATH = '.poison_key/poison_key'

STATEMENT_TIMEOUT = 5 * 1000 # 5 sec
SETUP_SQL_COMMAND_TIMEOUT = 0.1
FORK_FAIL_SLEEP = 0.5
CONNECTION_FAIL_SLEEP = 0.1
SOCKET_CONNECT_TIMEOUT = 3
KILL_WAIT_TIMEOUT = 10
CONNECT_TRY_COUNT = 3
SQL_EXECUTE_TRY_COUNT = 5
# http://docs.python-requests.org/en/master/user/advanced/#timeouts
# use only for requests.* methods
REQUEST_TIMEOUT = (5, 5)  # connect_timeout, read_timeout
PG_UNIX_HOST = '/tmp'

DB_USER = os.environ.get('TEST_DB_USER', 'postgres')
DB_USER_PASSWORD = os.environ.get('TEST_DB_USER_PASSWORD', 'postgres')
SSLMODE = os.environ.get('TEST_SSL_MODE', 'require' if TEST_WITH_TLS else 'disable')
TEST_MYSQL = bool(os.environ.get('TEST_MYSQL', False))
if TEST_MYSQL:
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
        ssl_context = ssl.create_default_context(cafile=TEST_TLS_CA)
        ssl_context.load_cert_chain(TEST_TLS_CLIENT_CERT, TEST_TLS_CLIENT_KEY)
        ssl_context.check_hostname = False
        asyncpg_connect_args['ssl'] = ssl_context


def get_random_id():
    return random.randint(1, 100000)


def get_pregenerated_random_data():
    data_file = random.choice(TEST_RANDOM_DATA_FILES)
    with open(data_file, 'r') as f:
        return f.read()


def create_acrastruct_with_client_id(data, client_id='keypair1'):
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


def get_master_keys():
    """Returns master key variable map: variable name => base64-encoded value."""
    def obtain_key(env_var, key_file, keystore):
        key = os.environ.get(env_var)
        if not key:
            subprocess.check_output([
                './acra-keymaker', '--keystore={}'.format(keystore),
                '--generate_master_key={}'.format(key_file)])
            with open(key_file, 'rb') as f:
                key = b64encode(f.read()).decode('ascii')
        return env_var, key

    global master_keys
    if not master_keys:
        master_keys = dict([
            obtain_key(ACRA_MASTER_KEY_VAR_NAME, MASTER_KEY_PATH, 'v1'),
            obtain_key(ACRA_MASTER_ENCRYPTION_KEY_VAR_NAME, MASTER_ENCRYPTION_KEY_PATH, 'v2'),
            obtain_key(ACRA_MASTER_SIGNATURE_KEY_VAR_NAME, MASTER_SIGNATURE_KEY_PATH, 'v2'),
        ])
    return master_keys


def get_poison_record():
    """generate one poison record for speed up tests and don't create subprocess
    for new records"""
    global poison_record
    if not poison_record:
        poison_record = b64decode(subprocess.check_output([
            './acra-poisonrecordmaker', '--keys_dir={}'.format(KEYS_FOLDER.name),
            '--keystore={}'.format(KEYSTORE_VERSION)],
            timeout=PROCESS_CALL_TIMEOUT))
    return poison_record


def create_client_keypair(name, only_server=False, only_client=False):
    args = ['./acra-keymaker', '-client_id={}'.format(name),
            '-keys_output_dir={}'.format(KEYS_FOLDER.name),
            '--keys_public_output_dir={}'.format(KEYS_FOLDER.name),
            '--keystore={}'.format(KEYSTORE_VERSION)]
    if only_server:
        args.append('-acra-server')
    elif only_client:
        args.append('-acra-connector')
    return subprocess.call(args, cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT)

def manage_basic_auth_user(action, user_name, user_password):
    args = ['./acra-authmanager', '--{}'.format(action),
            '--file={}'.format(ACRAWEBCONFIG_AUTH_DB_PATH),
            '--user={}'.format(user_name),
            '--keys_dir={}'.format(KEYS_FOLDER.name),
            '--keystore={}'.format(KEYSTORE_VERSION),
            '--password={}'.format(user_password)]
    return subprocess.call(args, cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT)


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
    raise Exception("can't wait connection")


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
        return get_postgresql_unix_connection_string(port, dbname)

def get_postgresql_unix_connection_string(port, dbname):
    return '{}:///{}?host={}'.format(DB_DRIVER, dbname, PG_UNIX_HOST)

def get_postgresql_tcp_connection_string(port, dbname):
    return '{}://{}:{}/{}'.format(DB_DRIVER, get_db_host(), port, dbname)

def get_acraserver_unix_connection_string(port):
    return "unix://{}".format("{}/unix_socket_{}".format(PG_UNIX_HOST, port))

def get_acraserver_tcp_connection_string(port):
    return get_tcp_connection_string(port)

def get_connector_connection_string(port):
    if TEST_MYSQL:
        return get_tcp_connection_string(port)
    else:
        if TEST_WITH_TLS:
            return get_tcp_connection_string(port)
        else:
            return 'unix://{}/.s.PGSQL.{}'.format(PG_UNIX_HOST, port)

def get_tcp_connection_string(port):
    return 'tcp://127.0.0.1:{}'.format(port)

def socket_path_from_connection_string(connection_string):
    if '://' in connection_string:
        return connection_string.split('://')[1]
    else:
        return connection_string

def acra_api_connection_string(port):
    return "unix://{}".format("{}/acra_api_unix_socket_{}".format(PG_UNIX_HOST, port+1))



DEFAULT_VERSION = '1.8.0'
DEFAULT_BUILD_ARGS = []
ACRAROLLBACK_MIN_VERSION = "1.8.0"
Binary = collections.namedtuple(
    'Binary', ['name', 'from_version', 'build_args'])


BINARIES = [
    Binary(name='acra-connector', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    # compile with Test=true to disable golang tls client server verification
    Binary(name='acra-server', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-addzone', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-keymaker', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-migrate-keys', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-read-key', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-poisonrecordmaker', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-rollback', from_version=ACRAROLLBACK_MIN_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-authmanager', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-webconfig', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-translator', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-rotate', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS)
]

def clean_binaries():
    for i in BINARIES:
        try:
            os.remove(i.name)
        except:
            pass

def clean_misc():
    try:
        os.unlink('./{}'.format(ACRAWEBCONFIG_AUTH_DB_PATH))
    except:
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


def setUpModule():
    global zones
    global KEYS_FOLDER
    clean_binaries()
    clean_misc()
    KEYS_FOLDER = tempfile.TemporaryDirectory()
    # build binaries
    builds = [
        (binary.from_version, ['go', 'build'] + binary.build_args + ['github.com/cossacklabs/acra/cmd/{}'.format(binary.name)])
        for binary in BINARIES
    ]
    go_version = get_go_version()
    GREATER, EQUAL, LESS = (1, 0, -1)
    for version, build in builds:
        if semver.compare(go_version, version) == LESS:
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

    # must be before any call of key generators or forks of acra/proxy servers
    for key_var, value in get_master_keys().items():
        os.environ.setdefault(key_var, value)

    # first keypair for using without zones
    assert create_client_keypair('keypair1') == 0
    assert create_client_keypair('keypair2') == 0
    # add two zones
    zones.append(json.loads(subprocess.check_output(
        ['./acra-addzone', '--keys_output_dir={}'.format(KEYS_FOLDER.name)],
        cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT).decode('utf-8')))
    zones.append(json.loads(subprocess.check_output(
        ['./acra-addzone', '--keys_output_dir={}'.format(KEYS_FOLDER.name)],
        cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT).decode('utf-8')))
    socket.setdefaulttimeout(SOCKET_CONNECT_TIMEOUT)
    drop_tables()


def tearDownModule():
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


ConnectionArgs = collections.namedtuple(
    "ConnectionArgs", ["user", "password", "host", "port", "dbname",
                       "ssl_ca", "ssl_key", "ssl_cert"])


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
        if not args:
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
        if not args:
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


class AsyncpgExecutor(QueryExecutor):
    def _connect(self, loop):
        return loop.run_until_complete(
            asyncpg.connect(
                host=self.connection_args.host, port=self.connection_args.port,
                user=self.connection_args.user, password=self.connection_args.password,
                database=self.connection_args.dbname,
                **asyncpg_connect_args))

    def execute_prepared_statement(self, query, args=None):
        if not args:
            args = []
        loop = asyncio.get_event_loop()
        conn = self._connect(loop)
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
                self.memoryview_to_bytes(data)
                return data

    def memoryview_to_bytes(self, data):
        for row in data:
            items = row.items()
            for key, value in items:
                if hasattr(value, 'tobytes'):
                    row[key] = value.tobytes()

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
                self.memoryview_to_bytes(data)
                return data


class KeyMakerTest(unittest.TestCase):
    def test_key_length(self):
        key_size = 32
        short_key = b64encode((key_size - 1)*b'a')
        short_master_keys = {var: short_key for var in get_master_keys().keys()}
        standard_key = b64encode(key_size * b'a')
        standard_master_keys = {var: standard_key for var in get_master_keys().keys()}
        long_key = b64encode((key_size * 2) * b'a')
        long_master_keys = {var: long_key for var in get_master_keys().keys()}

        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(subprocess.CalledProcessError) as exc:
                subprocess.check_output(
                    ['./acra-keymaker', '--keystore={}'.format(KEYSTORE_VERSION),
                     '--keys_output_dir={}'.format(folder),
                     '--keys_public_output_dir={}'.format(folder)],
                    env=short_master_keys)

        with tempfile.TemporaryDirectory() as folder:
            subprocess.check_output(
                    ['./acra-keymaker', '--keystore={}'.format(KEYSTORE_VERSION),
                     '--keys_output_dir={}'.format(folder),
                     '--keys_public_output_dir={}'.format(folder)],
                    env=standard_master_keys)

        with tempfile.TemporaryDirectory() as folder:
            subprocess.check_output(
                    ['./acra-keymaker', '--keystore={}'.format(KEYSTORE_VERSION),
                     '--keys_output_dir={}'.format(folder),
                     '--keys_public_output_dir={}'.format(folder)],
                    env=long_master_keys)


class PrometheusMixin(object):
    _prometheus_addresses_field_name = 'prometheus_addresses'
    LOG_METRICS = os.environ.get('TEST_LOG_METRICS', False)

    def get_prometheus_address(self, port):
        addr = 'tcp://127.0.0.1:{}'.format(port)
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


class BaseTestCase(PrometheusMixin, unittest.TestCase):
    DEBUG_LOG = os.environ.get('DEBUG_LOG', True)

    CONNECTOR_PORT_1 = int(os.environ.get('TEST_CONNECTOR_PORT', 9595))
    CONNECTOR_PROMETHEUS_PORT_1 = int(os.environ.get('TEST_CONNECTOR_PORT', CONNECTOR_PORT_1+1))

    CONNECTOR_PORT_2 = CONNECTOR_PORT_1 + 200
    CONNECTOR_PROMETHEUS_PORT_2 = int(os.environ.get('TEST_CONNECTOR_PORT', CONNECTOR_PORT_2+1))

    CONNECTOR_API_PORT_1 = int(os.environ.get('TEST_CONNECTOR_API_PORT', 9696))
    ACRAWEBCONFIG_HTTP_PORT = int(os.environ.get('TEST_CONFIG_UI_HTTP_PORT', ACRAWEBCONFIG_HTTP_PORT))
    # for debugging with manually runned acra-server
    EXTERNAL_ACRA = False
    ACRASERVER_PORT = int(os.environ.get('TEST_ACRASERVER_PORT', 10003))
    ACRASERVER_PROMETHEUS_PORT = int(os.environ.get('TEST_ACRASERVER_PROMETHEUS_PORT', 10004))
    ACRA_BYTEA = 'pgsql_hex_bytea'
    DB_BYTEA = 'hex'
    WHOLECELL_MODE = False
    ACRAWEBCONFIG_AUTH_KEYS_PATH = os.environ.get('TEST_CONFIG_UI_AUTH_DB_PATH', ACRAWEBCONFIG_AUTH_DB_PATH)
    ZONE = False
    TEST_DATA_LOG = False
    CONNECTOR_TLS_TRANSPORT = False

    # hack to simplify handling errors on forks and don't check `if hasattr(self, 'connector_1')`
    connector_1 = ProcessStub()
    connector_2 = ProcessStub()
    acra = ProcessStub()

    def checkSkip(self):
        if TEST_WITH_TLS:
            self.skipTest("running tests with TLS")

    def fork(self, func):
        process = func()
        count = 0
        while count <= 3:
            if process.poll() is None:
                print('forked')
                return process
            count += 1
            time.sleep(FORK_FAIL_SLEEP)
        stop_process(process)
        raise Exception("Can't fork")

    def wait_acraserver_connection(self, connection_string: str, *args, **kwargs):
        if connection_string.startswith('unix'):
            return wait_unix_socket(
                socket_path_from_connection_string(connection_string),
                *args, **kwargs)
        else:
            return wait_connection(connection_string.split(':')[-1])

    def fork_webconfig(self, connector_port: int, http_port: int):
        logging.info("fork acra-webconfig")
        args = [
            './acra-webconfig',
            '-incoming_connection_port={}'.format(http_port),
            '-destination_host=127.0.0.1',
            '-destination_port={}'.format(connector_port),
            '-static_path={}'.format(ACRAWEBCONFIG_STATIC_PATH)
        ]
        if self.DEBUG_LOG:
            args.append('-d=true')
        process = self.fork(lambda: subprocess.Popen(args))
        wait_connection(http_port)
        return process

    def get_connector_tls_params(self):
        return {
            'acraserver_tls_transport_enable': True,
            'tls_acraserver_sni': 'acraserver',
        }

    def get_connector_prometheus_port(self, port):
        return port+1

    def fork_connector(self, connector_port: int, acraserver_port: int,
                       client_id: str, api_port: int=None,
                       zone_mode: bool=False, check_connection: bool=True,
                       **extra_options: dict):
        logging.info("fork connector with port {} and client_id={}".format(connector_port, client_id))

        acraserver_connection = self.get_acraserver_connection_string(acraserver_port)
        acraserver_api_connection = self.get_acraserver_api_connection_string(acraserver_port)
        connector_connection = self.get_connector_connection_string(connector_port)
        if zone_mode:
            # because standard library can send http requests only through tcp and cannot through unix socket
            connector_api_connection = "tcp://127.0.0.1:{}".format(api_port)
        else:
            # now it's no matter, so just +100
            connector_api_connection = self.get_connector_api_connection_string(api_port if api_port else connector_port + 100)

        for path in [socket_path_from_connection_string(connector_connection), socket_path_from_connection_string(connector_api_connection)]:
            try:
                os.remove(path)
            except:
                pass
        args = {
            'acraserver_connection_string': acraserver_connection,
            'acraserver_api_connection_string': acraserver_api_connection,
            'client_id': client_id,
            'incoming_connection_string': connector_connection,
            'incoming_connection_api_string': connector_api_connection,
            'user_check_disable': 'true',
            'keys_dir': KEYS_FOLDER.name,
            'logging_format': 'cef',
        }
        if self.LOG_METRICS:
            args['incoming_connection_prometheus_metrics_string'] = \
                self.get_prometheus_address(
                    self.get_connector_prometheus_port(connector_port))
        if TEST_WITH_TRACING:
            args['tracing_log_enable'] = True
            if TEST_TRACE_TO_JAEGER:
                args['tracing_jaeger_enable'] = True
        if self.DEBUG_LOG:
            args['d'] = True
        if zone_mode:
            args['http_api_enable'] = True
        if self.CONNECTOR_TLS_TRANSPORT:
            args.update(self.get_connector_tls_params())
        if extra_options:
            args.update(extra_options)

        cli_args = sorted(['--{}={}'.format(k, v) for k, v in args.items()])
        print('connector args: {}'.format(' '.join(cli_args)))

        process = self.fork(lambda: subprocess.Popen(['./acra-connector'] + cli_args))
        if check_connection:
            print('check connection {}'.format(connector_connection))
            try:
                if connector_connection.startswith('tcp'):
                    wait_connection(connector_port)
                else:
                    wait_unix_socket(socket_path_from_connection_string(connector_connection))
            except:
                stop_process(process)
                raise
        logging.info("fork connector finished [pid={}]".format(process.pid))
        return process

    def get_acraserver_connection_string(self, port=None):
        if not port:
            port = self.ACRASERVER_PORT
        return get_acraserver_unix_connection_string(port)

    def get_acraserver_api_connection_string(self, port=None):
        if not port:
            port = self.ACRASERVER_PORT
        return acra_api_connection_string(port)

    def get_connector_connection_string(self, port=None):
        if not port:
            port = self.CONNECTOR_PORT_1
        return get_connector_connection_string(port)

    def get_connector_api_connection_string(self, port=None):
        if not port:
            port = self.CONNECTOR_API_PORT_1
        return get_connector_connection_string(port)

    def get_acrawebconfig_connection_url(self):
        return 'http://{}:{}'.format('127.0.0.1', ACRAWEBCONFIG_HTTP_PORT)

    def get_acraserver_bin_path(self):
        return './acra-server'

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
            'incoming_connection_string': connection_string,
            'incoming_connection_api_string': api_connection_string,
            'acrastruct_wholecell_enable': 'true' if self.WHOLECELL_MODE else 'false',
            'acrastruct_injectedcell_enable': 'false' if self.WHOLECELL_MODE else 'true',
            'd': 'true' if self.DEBUG_LOG else 'false',
            'zonemode_enable': 'true' if self.ZONE else 'false',
            'http_api_enable': 'true' if self.ZONE else 'true',
            'auth_keys': self.ACRAWEBCONFIG_AUTH_KEYS_PATH,
            'keys_dir': KEYS_FOLDER.name,
        }
        if TEST_WITH_TRACING:
            args['tracing_log_enable'] = 'true'
            if TEST_TRACE_TO_JAEGER:
                args['tracing_jaeger_enable'] = 'true'
        if self.LOG_METRICS:
            args['incoming_connection_prometheus_metrics_string'] = self.get_prometheus_address(
                self.ACRASERVER_PROMETHEUS_PORT)
        if self.CONNECTOR_TLS_TRANSPORT:
            args['acraconnector_tls_transport_enable'] = 'true'
        if self.with_tls():
            args['tls_key'] = TEST_TLS_SERVER_KEY
            args['tls_cert'] = TEST_TLS_SERVER_CERT
            args['tls_ca'] = TEST_TLS_CA
            args['tls_auth'] = ACRA_TLS_AUTH
        if TEST_MYSQL:
            args['mysql_enable'] = 'true'
            args['postgresql_enable'] = 'false'
        args.update(acra_kwargs)
        if not popen_kwargs:
            popen_kwargs = {}
        cli_args = sorted(['--{}={}'.format(k, v) for k, v in args.items() if v is not None])
        print("acra-server args: {}".format(' '.join(cli_args)))

        process = self.fork(lambda: subprocess.Popen([self.get_acraserver_bin_path()] + cli_args,
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

        translator = self.fork(lambda: subprocess.Popen(['./acra-translator'] + cli_args,
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
            self.connector_1 = self.fork_connector(self.CONNECTOR_PORT_1, self.ACRASERVER_PORT, 'keypair1')
            self.connector_2 = self.fork_connector(self.CONNECTOR_PORT_2, self.ACRASERVER_PORT, 'keypair2')

            self.engine1 = sa.create_engine(
                get_engine_connection_string(self.get_connector_connection_string(self.CONNECTOR_PORT_1), DB_NAME), connect_args=get_connect_args(port=self.CONNECTOR_PORT_1))
            self.engine2 = sa.create_engine(
                get_engine_connection_string(
                    self.get_connector_connection_string(self.CONNECTOR_PORT_2), DB_NAME), connect_args=get_connect_args(port=self.CONNECTOR_PORT_2))
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
                    except Exception:
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
        processes = [getattr(self, 'connector_1', ProcessStub()),
                     getattr(self, 'connector_2', ProcessStub()),
                     getattr(self, 'acra', ProcessStub())]
        stop_process(processes)
        send_signal_by_process_name('acra-server', signal.SIGKILL)
        send_signal_by_process_name('acra-connector', signal.SIGKILL)

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
            'master_keys': get_master_keys(),
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


class HexFormatTest(BaseTestCase):

    def testConnectorRead(self):
        """test decrypting with correct acra-connector and not decrypting with
        incorrect acra-connector or using direct connection to db"""
        client_id = 'keypair1'
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
        client_id = 'keypair1'
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
        # doesn't need to start acra-server/acra-connector and connections
        pass

    def tearDown(self):
        # doesn't need to stop acra-server/acra-connector and connections
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
        connection_args = ConnectionArgs(host=get_db_host(), port=self.CONNECTOR_PORT_1,
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
        connection_args = ConnectionArgs(host=get_db_host(), port=self.CONNECTOR_PORT_1,
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

    def testConnectorRead(self):
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

        # without zone in another connector, in the same connector and without any connector
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


class ZoneEscapeFormatTest(ZoneHexFormatTest):
    ACRA_BYTEA = 'pgsql_escape_bytea'
    DB_BYTEA = 'escape'


class WholeCellMixinTest(object):
    def testReadAcrastructInAcrastruct(self):
        return


class HexFormatWholeCellTest(WholeCellMixinTest, HexFormatTest):
    WHOLECELL_MODE = True


class ZoneHexFormatWholeCellTest(WholeCellMixinTest, ZoneHexFormatTest):
    WHOLECELL_MODE = True


class EscapeFormatWholeCellTest(WholeCellMixinTest, EscapeFormatTest):
    WHOLECELL_MODE = True


class ZoneEscapeFormatWholeCellTest(WholeCellMixinTest, ZoneEscapeFormatTest):
    WHOLECELL_MODE = True


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
            self.connector_1 = self.fork_connector(
                self.CONNECTOR_PORT_1, self.ACRASERVER_PORT, 'keypair1')
            if not self.EXTERNAL_ACRA:
                self.acra = self.fork_acra()
        except:
            self.tearDown()
            raise

    def get_connection(self):
        count = CONNECT_TRY_COUNT
        while True:
            try:
                if TEST_MYSQL:
                    return TestConnectionClosing.mysql_closing(
                        pymysql.connect(**get_connect_args(port=self.CONNECTOR_PORT_1)))
                else:
                    return TestConnectionClosing.mysql_closing(psycopg2.connect(
                        host=get_db_host(), **get_connect_args(port=self.CONNECTOR_PORT_1)))
            except:
                count -= 1
                if count == 0:
                    raise
                time.sleep(CONNECTION_FAIL_SLEEP)

    def tearDown(self):
        procs = []
        if hasattr(self, 'connector_1'):
            procs.append(self.connector_1)
        if not self.EXTERNAL_ACRA and hasattr(self, 'acra'):
            procs.append(self.acra)
        stop_process(procs)
        send_signal_by_process_name('acra-server', signal.SIGKILL)
        send_signal_by_process_name('acra-connector', signal.SIGKILL)

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
        try_count = SQL_EXECUTE_TRY_COUNT
        for i in range(try_count):
            try:
                self.assertEqual(self.getActiveConnectionCount(cursor), expected)
                break
            except AssertionError:
                if i == (try_count - 1):
                    raise
                # some wait for closing. chosen manually
                time.sleep(1)

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


class TestKeyNonExistence(BaseTestCase):
    def setUp(self):
        self.checkSkip()
        # FIXME(ilammy, 2020-03-20): implement key removal for v2
        if KEYSTORE_VERSION == 'v2':
            self.skipTest('key store v2 does not support key removal')
        try:
            if not self.EXTERNAL_ACRA:
                self.acra = self.fork_acra()
            self.dsn = get_connect_args(port=self.CONNECTOR_PORT_1, host=get_db_host())
        except:
            self.tearDown()
            raise

    def tearDown(self):
        if hasattr(self, 'acra'):
            stop_process(self.acra)
        send_signal_by_process_name('acra-server', signal.SIGKILL)
        send_signal_by_process_name('acra-connector', signal.SIGKILL)

    def delete_key(self, filename):
        os.remove('{dir}{sep}{name}'.format(
            dir=KEYS_FOLDER.name, sep=os.path.sep, name=filename))

    def test_without_acraconnector_public(self):
        """acra-server without acra-connector public key should drop connection
        from acra-connector than acra-connector should drop connection from psycopg2"""
        keyname = 'without_acra-connector_public_test'
        result = create_client_keypair(keyname)
        if result != 0:
            self.fail("can't create keypairs")
        self.delete_key(keyname + '.pub')
        engine = None
        if TEST_MYSQL:
            expected_exception = pymysql.err.OperationalError
        elif TEST_POSTGRESQL:
            expected_exception = psycopg2.OperationalError

        try:
            self.connector = self.fork_connector(
                self.CONNECTOR_PORT_1, self.ACRASERVER_PORT, keyname)
            self.assertIsNone(self.connector.poll())
            with self.assertRaises(sa.exc.OperationalError) as exc:
                engine = sa.create_engine(
                    get_engine_connection_string(self.get_connector_connection_string(self.CONNECTOR_PORT_1), DB_NAME),
                    connect_args=get_connect_args(port=self.CONNECTOR_PORT_1))
                with engine.connect() as connection:
                    connection.execute('select 1 from dual')

            self.assertTrue(isinstance(exc.exception.orig, expected_exception))
        finally:
            if engine:
                engine.dispose()
            stop_process(self.connector)

    def checkShutdownAcraConnector(self, process):
        total_wait_time = 2  # sec
        poll_interval = 0.1
        retry = total_wait_time / poll_interval
        while retry:
            retry -= 1
            if process.poll() == 1:
                return
            time.sleep(poll_interval)

    def test_without_acraconnector_private(self):
        """acra-connector shouldn't start without private key"""
        keyname = 'without_acra-connector_private_test'
        result = create_client_keypair(keyname)
        if result != 0:
            self.fail("can't create keypairs")
        self.delete_key(keyname)
        try:
            self.connector = self.fork_connector(
                self.CONNECTOR_PORT_1, self.ACRASERVER_PORT, keyname,
                check_connection=False)
            self.checkShutdownAcraConnector(self.connector)
        finally:
            try:
                stop_process(self.connector)
            except OSError:  # pid not found
                pass

    def test_without_acraserver_private(self):
        """acra-server without private key should drop connection
        from acra-connector than acra-connector should drop connection from psycopg2"""
        keyname = 'without_acraserver_private_test'
        result = create_client_keypair(keyname)
        if result != 0:
            self.fail("can't create keypairs")
        self.delete_key(keyname + '_server')
        if TEST_MYSQL:
            expected_exception = pymysql.err.OperationalError
        elif TEST_POSTGRESQL:
            expected_exception = psycopg2.OperationalError
        engine = None
        try:
            self.connector = self.fork_connector(
                self.CONNECTOR_PORT_1, self.ACRASERVER_PORT, keyname)
            self.assertIsNone(self.connector.poll())
            with self.assertRaises(sa.exc.OperationalError) as exc:
                engine = sa.create_engine(
                    get_engine_connection_string(self.get_connector_connection_string(self.CONNECTOR_PORT_1), DB_NAME),
                    connect_args=get_connect_args(port=self.CONNECTOR_PORT_1))
                with engine.connect() as connection:
                    connection.execute('select 1 from dual')
            self.assertTrue(isinstance(exc.exception.orig, expected_exception))
        finally:
            if engine:
                engine.dispose()
            stop_process(self.connector)

    def test_without_acraserver_public(self):
        """acra-connector shouldn't start without acra-server public key"""
        keyname = 'without_acraserver_public_test'
        result = create_client_keypair(keyname)
        if result != 0:
            self.fail("can't create keypairs")
        self.delete_key(keyname + '_server.pub')
        try:
            self.connector = self.fork_connector(
                self.CONNECTOR_PORT_1, self.ACRASERVER_PORT, keyname,
                check_connection=False)
            # time for start up connector and validation file existence.
            self.checkShutdownAcraConnector(self.connector)
        finally:
            try:
                stop_process(self.connector)
            except OSError:  # pid not found
                pass


class BasePoisonRecordTest(BaseTestCase):
    SHUTDOWN = True
    TEST_DATA_LOG = True
    DETECT_POISON_RECORDS = True

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
        }

        if hasattr(self, 'poisonscript'):
            args['poison_run_script_file'] = self.poisonscript

        return super(BasePoisonRecordTest, self).fork_acra(popen_kwargs, **args)


class TestPoisonRecordShutdown(BasePoisonRecordTest):
    SHUTDOWN = True

    def testShutdown(self):
        row_id = get_random_id()
        data = get_poison_record()
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

    def testShutdown2(self):
        """check working poison record callback on full select"""
        row_id = get_random_id()
        data = get_poison_record()
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

    def testShutdown3(self):
        """check working poison record callback on full select inside another data"""
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


class TestPoisonRecordOffStatus(BasePoisonRecordTest):
    SHUTDOWN = True
    DETECT_POISON_RECORDS = False

    def testShutdown(self):
        row_id = get_random_id()
        data = get_poison_record()
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

    def testShutdown2(self):
        """check working poison record callback on full select"""
        row_id = get_random_id()
        data = get_poison_record()
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

    def testShutdown3(self):
        """check working poison record callback on full select inside another data"""
        row_id = get_random_id()
        poison_record = get_poison_record()
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


class TestShutdownPoisonRecordWithZone(TestPoisonRecordShutdown):
    ZONE = True
    WHOLECELL_MODE = False
    SHUTDOWN = True

    def testShutdown(self):
        """check callback with select by id and zone"""
        row_id = get_random_id()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': get_poison_record(), 'raw_data': 'poison_record'})
        with self.assertRaises(DatabaseError):
            zone = zones[0][ZONE_ID].encode('ascii')
            result = self.engine1.execute(
                sa.select([sa.cast(zone, BYTEA), test_table])
                    .where(test_table.c.id == row_id))
            print(result.fetchall())

    def testShutdown2(self):
        """check callback with select by id and without zone"""
        row_id = get_random_id()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': get_poison_record(), 'raw_data': 'poison_record'})
        with self.assertRaises(DatabaseError):
            result = self.engine1.execute(
                sa.select([test_table]).where(test_table.c.id == row_id))
            print(result.fetchall())

    def testShutdown3(self):
        """check working poison record callback on full select"""
        row_id = get_random_id()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': get_poison_record(), 'raw_data': 'poison_record'})
        with self.assertRaises(DatabaseError):
            result = self.engine1.execute(
                sa.select([test_table]))
            print(result.fetchall())

    def testShutdown4(self):
        """check working poison record callback on full select inside another data"""
        row_id = get_random_id()
        poison_record = get_poison_record()
        begin_tag = poison_record[:4]
        # test with extra long begin tag
        data = os.urandom(100) + begin_tag + poison_record + os.urandom(100)
        self.log(poison_key=True, data=data, expected=data)
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': data, 'raw_data': 'poison_record'})

        with self.assertRaises(DatabaseError):
            result = self.engine1.execute(
                sa.select([test_table]))
            # here shouldn't execute code and it's debug info
            print(result.fetchall())


class TestShutdownPoisonRecordWithZoneOffStatus(TestPoisonRecordShutdown):
    ZONE = True
    WHOLECELL_MODE = False
    SHUTDOWN = True
    DETECT_POISON_RECORDS = False

    def testShutdown(self):
        """check callback with select by id and zone"""
        row_id = get_random_id()
        poison_record = get_poison_record()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': poison_record, 'raw_data': 'poison_record'})

        zone = zones[0][ZONE_ID].encode('ascii')
        result = self.engine1.execute(
            sa.select([sa.cast(zone, BYTEA), test_table])
                .where(test_table.c.id == row_id))
        for zone, _, data, raw_data, _, _ in result:
            self.assertEqual(zone, zone)
            self.assertEqual(data, poison_record)

    def testShutdown2(self):
        """check callback with select by id and without zone"""
        row_id = get_random_id()
        poison_record = get_poison_record()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': poison_record, 'raw_data': 'poison_record'})

        result = self.engine1.execute(
            sa.select([test_table])
                .where(test_table.c.id == row_id))
        for _, data, raw_data, _, _ in result:
            self.assertEqual(data, poison_record)

    def testShutdown3(self):
        """check working poison record callback on full select"""
        row_id = get_random_id()
        poison_record = get_poison_record()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': poison_record, 'raw_data': 'poison_record'})

        result = self.engine1.execute(
            sa.select([test_table]))
        for _, data, raw_data, _, _ in result:
            self.assertEqual(data, poison_record)

    def testShutdown4(self):
        """check working poison record callback on full select inside another data"""
        row_id = get_random_id()
        poison_record = get_poison_record()
        begin_tag = poison_record[:4]
        # test with extra long begin tag
        testData = os.urandom(100) + begin_tag + poison_record + os.urandom(100)
        self.log(poison_key=True, data=testData, expected=testData)
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': testData, 'raw_data': 'poison_record'})

        result = self.engine1.execute(
            sa.select([test_table]))
        for _, data, raw_data, _, _ in result:
            self.assertEqual(testData, data)


class TestPoisonRecordWholeCell(TestPoisonRecordShutdown):
    WHOLECELL_MODE = True
    SHUTDOWN = True

    def testShutdown3(self):
        return

class TestPoisonRecordWholeCellStatusOff(TestPoisonRecordOffStatus):
    WHOLECELL_MODE = True
    SHUTDOWN = True

    def testShutdown3(self):
        return



class TestShutdownPoisonRecordWithZoneWholeCell(TestShutdownPoisonRecordWithZone):
    WHOLECELL_MODE = True
    SHUTDOWN = True

    def testShutdown4(self):
        return


class TestShutdownPoisonRecordWithZoneWholeCellOffStatus(TestShutdownPoisonRecordWithZoneOffStatus):
    WHOLECELL_MODE = True
    SHUTDOWN = True

    def testShutdown4(self):
        return


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
            'close_fds': True
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


class TestNoCheckPoisonRecord(AcraCatchLogsMixin, BasePoisonRecordTest):
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
        self.assertNotIn('Check poison records', log)
        result = self.engine1.execute(
            sa.select([test_table]))
        for _, data, raw_data, _, _ in result:
            self.assertEqual(poison_record, data)


class TestNoCheckPoisonRecordWithZone(TestNoCheckPoisonRecord):
    ZONE = True


class TestNoCheckPoisonRecordWholeCell(TestNoCheckPoisonRecord):
    WHOLECELL_MODE = True


class TestNoCheckPoisonRecordWithZoneWholeCell(TestNoCheckPoisonRecordWithZone):
    WHOLECELL_MODE = True


class TestCheckLogPoisonRecord(AcraCatchLogsMixin, BasePoisonRecordTest):
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

        self.assertIn('Check poison records', self.read_log(self.acra))


class TestKeyStorageClearing(BaseTestCase):
    def setUp(self):
        self.checkSkip()
        # FIXME(ilammy, 2020-03-20): implement key removal for v2
        if KEYSTORE_VERSION == 'v2':
            self.skipTest('key store v2 does not support key removal')
        try:
            self.key_name = 'clearing_keypair'
            create_client_keypair(self.key_name)
            self.connector_1 = self.fork_connector(
                self.CONNECTOR_PORT_1, self.ACRASERVER_PORT, self.key_name, self.CONNECTOR_API_PORT_1,
                zone_mode=True)
            if not self.EXTERNAL_ACRA:
                self.acra = self.fork_acra(
                    zonemode_enable='true', http_api_enable='true')

            self.engine1 = sa.create_engine(
                get_engine_connection_string(self.get_connector_connection_string(self.CONNECTOR_PORT_1), DB_NAME),
                connect_args=get_connect_args(port=self.CONNECTOR_PORT_1))

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
        if hasattr(self, 'connector_1'):
            processes.append(self.connector_1)
        if not self.EXTERNAL_ACRA and hasattr(self, 'acra'):
            processes.append(self.acra)

        stop_process(processes)
        send_signal_by_process_name('acra-server', signal.SIGKILL)
        send_signal_by_process_name('acra-connector', signal.SIGKILL)

    def test_clearing(self):
        # execute any query for loading key by acra
        result = self.engine1.execute(sa.select([1]).limit(1))
        result.fetchone()
        with urlopen('http://127.0.0.1:{}/resetKeyStorage'.format(self.CONNECTOR_API_PORT_1)) as response:
            self.assertEqual(response.status, 200)
        # delete key for excluding reloading from FS
        os.remove('{}/{}.pub'.format(KEYS_FOLDER.name, self.key_name))
        # close connections in pool and reconnect to reinitiate secure session
        self.engine1.dispose()
        # acra-server should close connection when doesn't find key
        with self.assertRaises(DatabaseError):
            result = self.engine1.execute(test_table.select().limit(1))


class TestKeyStoreMigration(BaseTestCase):
    """Test acra-migrate-keys utility."""

    # We need to test different key store formats so we can't touch
    # the global KEYS_FOLDER. We need to launch service instances
    # with particular key store configuration. Ignore the usual
    # setup and teardown routines that start Acra services.

    def setUp(self):
        self.checkSkip()
        self.test_dir = tempfile.TemporaryDirectory()
        self.engine_raw = sa.create_engine(
            '{}://{}:{}/{}'.format(DB_DRIVER, DB_HOST, DB_PORT, DB_NAME),
            connect_args=get_connect_args(DB_PORT))
        metadata.create_all(self.engine_raw)
        self.engine_raw.execute(test_table.delete())

    def tearDown(self):
        self.engine_raw.execute(test_table.delete())
        self.engine_raw.dispose()
        self.test_dir.cleanup()

    # Instead, use these methods according to individual test needs.

    def create_key_store(self, version):
        """Create new key store of given version."""
        # Start with service transport keys and client storage keys.
        self.client_id = 'test-client-please-ignore'
        subprocess.check_call([
                './acra-keymaker',
                '--generate_acraconnector_keys',
                '--generate_acraserver_keys',
                '--generate_acrawriter_keys',
                '--client_id={}'.format(self.client_id),
                '--keys_output_dir={}'.format(self.current_key_store_path()),
                '--keys_public_output_dir={}'.format(self.current_key_store_path()),
                '--keystore={}'.format(version),
            ],
            timeout=PROCESS_CALL_TIMEOUT)

        # Then add some zones that we're going to test with.
        zone_output = subprocess.check_output([
                './acra-addzone',
                '--keys_output_dir={}'.format(self.current_key_store_path()),
            ],
            timeout=PROCESS_CALL_TIMEOUT)
        zone_config = json.loads(zone_output.decode('utf-8'))
        self.zone_id = zone_config[ZONE_ID]

        # Keep the current version around, we'll need it for migration.
        self.keystore_version = version

    def migrate_key_store(self, new_version):
        """Migrate key store from current to given new version."""
        # Run the migration tool. New key store is in a new directory.
        subprocess.check_call([
                './acra-migrate-keys',
                '--src_keys_dir={}'.format(self.current_key_store_path()),
                '--src_keys_dir_public={}'.format(self.current_key_store_path()),
                '--src_keystore={}'.format(self.keystore_version),
                '--dst_keys_dir={}'.format(self.new_key_store_path()),
                '--dst_keys_dir_public={}'.format(self.new_key_store_path()),
                '--dst_keystore={}'.format(new_version),
            ],
            timeout=PROCESS_CALL_TIMEOUT)

        # Finalize the migration, replacing old key store with the new one.
        # We assume the services to be not running at this moment.
        os.rename(self.current_key_store_path(), self.old_key_store_path())
        os.rename(self.new_key_store_path(), self.current_key_store_path())
        self.keystore_version = new_version

    def start_services(self, zone_mode=False):
        """Start Acra services required for testing."""
        self.acra_server = self.fork_acra(
            zonemode_enable='true' if zone_mode else 'false',
            keys_dir=self.current_key_store_path())

        self.acra_connector = self.fork_connector(
            client_id=self.client_id,
            zone_mode=zone_mode,
            api_port=self.CONNECTOR_API_PORT_1,
            connector_port=self.CONNECTOR_PORT_1,
            acraserver_port=self.ACRASERVER_PORT,
            keys_dir=self.current_key_store_path())

        self.engine = sa.create_engine(
            get_engine_connection_string(
                self.get_connector_connection_string(self.CONNECTOR_PORT_1),
                DB_NAME),
            connect_args=get_connect_args(port=self.CONNECTOR_PORT_1))

        # Remember whether we're running in zone mode. We need to know this
        # to store and retrieve the data correctly.
        self.zone_mode = zone_mode

    def stop_services(self):
        """Gracefully stop Acra services being tested."""
        self.engine.dispose()
        stop_process(self.acra_connector)
        stop_process(self.acra_server)

    @contextlib.contextmanager
    def running_services(self, **kwargs):
        self.start_services(**kwargs)
        try:
            yield
        finally:
            self.stop_services()

    def insert_via_connector(self, data):
        """Encrypt and insert data via Acra Connector."""
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

        row_id = get_random_id()
        self.engine.execute(test_table.insert(), {
            'id': row_id, 'data': acra_struct, 'raw_data': data,
        })
        return row_id

    def select_via_connector(self, row_id):
        """Select decrypted data via Acra Connector."""
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
        """Verify v1 -> v2 key store migration."""
        data_1 = get_pregenerated_random_data()
        data_2 = get_pregenerated_random_data()

        self.create_key_store('v1')

        # Try saving some data with default zone
        with self.running_services():
            row_id_1 = self.insert_via_connector(data_1)

            # Check that we're able to put and get data via Connector.
            selected = self.select_via_connector(row_id_1)
            self.assertEquals(selected['data'], data_1.encode('ascii'))
            self.assertEquals(selected['raw_data'], data_1)

            # Get encrypted data. It should really be encrypted.
            encrypted_1 = self.select_directly(row_id_1)
            self.assertNotEquals(encrypted_1['data'], data_1.encode('ascii'))

        # Now do the same with a specific zone
        with self.running_services(zone_mode=True):
            row_id_1_zoned = self.insert_via_connector(data_1)

            # Check that we're able to put and get data via Connector.
            selected = self.select_via_connector(row_id_1_zoned)
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
            # Old data should still be there, accessible via Connector.
            selected = self.select_via_connector(row_id_1)
            self.assertEquals(selected['data'], data_1.encode('ascii'))
            self.assertEquals(selected['raw_data'], data_1)

            # Key migration does not change encrypted data.
            encrypted_1_migrated = self.select_directly(row_id_1)
            self.assertEquals(encrypted_1_migrated['data'],
                              encrypted_1['data'])

            # We're able to put some new data into the table and get it back.
            row_id_2 = self.insert_via_connector(data_2)
            selected = self.select_via_connector(row_id_2)
            self.assertEquals(selected['data'], data_2.encode('ascii'))
            self.assertEquals(selected['raw_data'], data_2)

        # And again, this time with zones.
        with self.running_services(zone_mode=True):
            # Old data should still be there, accessible via Connector.
            selected = self.select_via_connector(row_id_1_zoned)
            self.assertEquals(selected['data'], data_1.encode('ascii'))
            self.assertEquals(selected['raw_data'], data_1)

            # Key migration does not change encrypted data.
            encrypted_1_zoned_migrated = self.select_directly(row_id_1_zoned)
            self.assertEquals(encrypted_1_zoned_migrated['data'],
                              encrypted_1_zoned['data'])

            # We're able to put some new data into the table and get it back.
            row_id_2_zoned = self.insert_via_connector(data_2)
            selected = self.select_via_connector(row_id_2_zoned)
            self.assertEquals(selected['data'], data_2.encode('ascii'))
            self.assertEquals(selected['raw_data'], data_2)


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
        args = ['./acra-rollback'] + self.default_acrarollback_args + extra_args
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
        server_public1 = read_storage_public_key('keypair1', KEYS_FOLDER.name)

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
        server_public1 = read_storage_public_key('keypair1', KEYS_FOLDER.name)

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
        args = ['./acra-rollback',
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


class TestAcraKeyMakers(unittest.TestCase):
    def test_only_alpha_client_id(self):
        # call with directory separator in key name
        self.assertEqual(create_client_keypair(POISON_KEY_PATH), 1)


class TestAcraWebconfigAcraAuthManager(unittest.TestCase):
    def testUIGenAuth(self):
        self.assertEqual(manage_basic_auth_user('set', 'test', 'test'), 0)
        self.assertEqual(manage_basic_auth_user('set', ACRAWEBCONFIG_BASIC_AUTH['user'], ACRAWEBCONFIG_BASIC_AUTH['password']), 0)
        self.assertEqual(manage_basic_auth_user('remove', 'test', 'test'), 0)
        self.assertEqual(manage_basic_auth_user('remove', 'test_unknown', 'test_unknown'), 1)


class TestAcraWebconfigWeb(AcraCatchLogsMixin, BaseTestCase):
    def get_acraserver_connection_string(self, port=None):
        return get_tcp_connection_string(port or self.ACRASERVER_PORT)

    def get_acraserver_api_connection_string(self, port=None):
        if not port:
            port = self.ACRASERVER_PORT
        return get_tcp_connection_string(port+1)

    def setUp(self):
        try:
            base_config = load_yaml_config('configs/acra-server.yaml')
            base_config['zonemode_enable'] = True
            base_config['http_api_enable'] = True
            base_config['db_host'] = DB_HOST
            base_config['db_port'] = DB_PORT
            self.config = NamedTemporaryFile(delete=False)
            with self.config as f:
                dump_yaml_config(base_config, f.name)

            # create auth file with default correct user
            manage_basic_auth_user('set', ACRAWEBCONFIG_BASIC_AUTH['user'], ACRAWEBCONFIG_BASIC_AUTH['password'])
            # don't pass these args as cli params because they will have higher priority than config file
            # so pass them with None value which will exclude them in fork_acra method
            empty_overridable_args = {
                i: None for i in ('db_host', 'db_port', 'zonemode_enable',  'incoming_connection_api_port',
                                'd', 'poison_run_script_file', 'poison_shutdown_enable')
            }
            self.acra = self.fork_acra(
                popen_kwargs={'stderr': subprocess.STDOUT, 'stdout': subprocess.PIPE, 'close_fds': True},
                config_file=self.config.name, **empty_overridable_args)
            self.connector_1 = self.fork_connector(
                self.CONNECTOR_PORT_1, self.ACRASERVER_PORT, 'keypair1', zone_mode=True, api_port=self.CONNECTOR_API_PORT_1)
            self.webconfig = self.fork_webconfig(connector_port=self.CONNECTOR_API_PORT_1, http_port=self.ACRAWEBCONFIG_HTTP_PORT)
        except Exception:
            self.tearDown()
            raise

    def tearDown(self):
        self.config.close()
        os.remove(self.config.name)
        super(TestAcraWebconfigWeb, self).tearDown()
        stop_process(getattr(self, 'webconfig', ProcessStub()))
        send_signal_by_process_name('acra-webconfig', signal.SIGKILL)

    def testAuthAndSubmitSettings(self):
        base_config = load_yaml_config('configs/acra-server.yaml')
        shutil.copy('configs/acra-server.yaml', 'configs/acra-server.yaml.backup')
        try:
            # test wrong auth
            with requests.post(
                    self.get_acrawebconfig_connection_url(), data={}, timeout=ACRAWEBCONFIG_HTTP_TIMEOUT,
                    auth=HTTPBasicAuth('wrong_user_name', 'wrong_password')) as req:
                self.assertEqual(req.status_code, 401)


            # test correct auth
            with requests.post(
                    self.get_acrawebconfig_connection_url(), data={}, timeout=ACRAWEBCONFIG_HTTP_TIMEOUT,
                    auth=HTTPBasicAuth(ACRAWEBCONFIG_BASIC_AUTH['user'], ACRAWEBCONFIG_BASIC_AUTH['password'])) as req:
                self.assertEqual(req.status_code, 200)

            # test settings that inverse or extend existing values to diff changes after
            new_settings = dict(
                db_host=base_config.get('db_host') or '' + 'test',
                db_port=int(base_config['db_port'])+1,
                incoming_connection_api_port=int(base_config['incoming_connection_api_port'])+1,
                debug=not base_config['d'],
                poison_run_script_file=base_config.get('poison_run_script_file') or '' + 'test',
                poison_shutdown_enable=base_config['poison_shutdown_enable'],
                zonemode_enable=base_config['zonemode_enable']
            )
            with requests.post(
                    "{}/acra-server/submit_setting".format(self.get_acrawebconfig_connection_url()),
                    data=new_settings,
                    timeout=ACRAWEBCONFIG_HTTP_TIMEOUT,
                    auth=HTTPBasicAuth(ACRAWEBCONFIG_BASIC_AUTH['user'], ACRAWEBCONFIG_BASIC_AUTH['password'])) as req:
                self.assertEqual(req.status_code, 200)

            connection_string = self.get_acraserver_connection_string(self.ACRASERVER_PORT)
            # wait restarted acra-server after submitting new config
            self.wait_acraserver_connection(connection_string)
            # check for new config after acra-server's graceful restart
            with requests.post(
                    self.get_acrawebconfig_connection_url(), data={}, timeout=ACRAWEBCONFIG_HTTP_TIMEOUT,
                    auth=HTTPBasicAuth(ACRAWEBCONFIG_BASIC_AUTH['user'], ACRAWEBCONFIG_BASIC_AUTH['password'])) as req:
                self.assertEqual(req.status_code, 200)
                config_regex = r'currentConfig\s*=\s*(.+?);'
                match = re.search(config_regex, req.text)
                if not match:
                    self.fail("Can't find config in output html")
                loaded_config = json.loads(match.group(1))
                for key in new_settings.keys():
                    self.assertEqual(new_settings[key], loaded_config[key])
        finally:
            # search pid of forked acra-server process to kill
            out = self.read_log(self.acra)
            print(out)
            # acra-server process forked to PID: 56946
            if out and 'process forked to PID' in out:
                pids = re.findall(r'process forked to PID: (\d+)', out)
                if pids:
                    pid = pids[0]
                    try:
                        os.kill(int(pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            send_signal_by_process_name('acra-server', signal.SIGKILL)

            # restore changed config
            os.rename('configs/acra-server.yaml.backup',
                      'configs/acra-server.yaml')


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
            self.assertIn('To support TLS connections you must pass TLS key '
                          'and certificate for AcraServer that will be used',
                          self.read_log(self.acra2))
        finally:
            engine.dispose()

    def setUp(self):
        self.checkSkip()
        """don't fork connector, connect directly to acra, use sslmode=require in connections and tcp protocol on acra side
        because postgresql support tls only over tcp
        """
        try:
            if not self.EXTERNAL_ACRA:
                self.acra = self.fork_acra(
                    tls_key=abs_path(TEST_TLS_SERVER_KEY),
                    tls_cert=abs_path(TEST_TLS_SERVER_CERT),
                    tls_ca=TEST_TLS_CA,
                    acraconnector_transport_encryption_disable=True, client_id='keypair1')
                # create second acra without settings for tls to check that
                # connection will be closed on tls handshake
                self.acra2 = self.fork_acra(
                    acraconnector_transport_encryption_disable=True, client_id='keypair1',
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


class TLSBetweenConnectorAndServerMixin(object):
    TLS_ON = True
    def fork_acra(self, popen_kwargs: dict=None, **acra_kwargs: dict):
        return self._fork_acra({'client_id': 'keypair1'}, popen_kwargs)

    def get_connector_tls_params(self):
        base_params = super(TLSBetweenConnectorAndServerMixin, self).get_connector_tls_params()
        # client side need CA cert to verify server's
        base_params.update('tls_ca', TEST_TLS_CA)
        return base_params

    def setUp(self):
        super(TLSBetweenConnectorAndServerMixin, self).setUp()
        # acra works with one client id and no matter from which proxy connection come
        self.engine2.dispose()
        self.engine2 = self.engine_raw


class TLSBetweenConnectorAndServerTest(TLSBetweenConnectorAndServerMixin, HexFormatTest):
    pass


class TLSBetweenConnectorAndServerWithZonesTest(TLSBetweenConnectorAndServerMixin, ZoneHexFormatTest):
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
        """don't fork connector, connect directly to acra, use ssl for connections and tcp protocol on acra side
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
                    acraconnector_transport_encryption_disable=True, client_id='keypair1')
                # create second acra without settings for tls to check that
                # connection will be closed on tls handshake
                self.acra2 = self.fork_acra(
                    acraconnector_transport_encryption_disable=True, client_id='keypair1',
                    incoming_connection_port=self.ACRASERVER2_PORT,
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

    def testConnectorRead(self):
        """test decrypting with correct acra-connector and not decrypting with
        incorrect acra-connector or using direct connection to db"""
        client_id = 'keypair1'
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
        client_id = 'keypair1'
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
            if self.WHOLECELL_MODE:
                self.assertEqual(row['data'], data)
            else:
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

    def executePreparedStatement(self, query):
        return PyMysqlExecutor(
            ConnectionArgs(host=get_db_host(), port=self.CONNECTOR_PORT_1,
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

    def executePreparedStatement(self, query):
        return MysqlExecutor(
            ConnectionArgs(host=get_db_host(), port=self.CONNECTOR_PORT_1,
                           user=DB_USER, password=DB_USER_PASSWORD,
                           dbname=DB_NAME, ssl_ca=TEST_TLS_CA,
                           ssl_key=TEST_TLS_CLIENT_KEY,
                           ssl_cert=TEST_TLS_CLIENT_CERT)
        ).execute_prepared_statement(query)


class TestMysqlBinaryPreparedStatementWholeCell(TestMysqlBinaryPreparedStatement):
    WHOLECELL_MODE = True


class TestPostgresqlTextPreparedStatement(BasePrepareStatementMixin, BaseTestCase):
    def checkSkip(self):
        if not TEST_POSTGRESQL:
            self.skipTest("run test only for postgresql")

    def executePreparedStatement(self, query, args=None):
        if not args:
            args = []
        return Psycopg2Executor(ConnectionArgs(host=get_db_host(), port=self.CONNECTOR_PORT_1,
                           user=DB_USER, password=DB_USER_PASSWORD,
                           dbname=DB_NAME, ssl_ca=TEST_TLS_CA,
                           ssl_key=TEST_TLS_CLIENT_KEY,
                           ssl_cert=TEST_TLS_CLIENT_CERT)
                                ).execute_prepared_statement(query, args)


class TestPostgresqlTextPreparedStatementWholeCell(TestPostgresqlTextPreparedStatement):
    WHOLECELL_MODE = True


class TestPostgresqlBinaryPreparedStatement(BasePrepareStatementMixin, BaseTestCase):
    def checkSkip(self):
        if not TEST_POSTGRESQL:
            self.skipTest("run test only for postgresql")

    def executePreparedStatement(self, query):
        return AsyncpgExecutor(
            ConnectionArgs(host=get_db_host(), # asyncpg doesn't support ssl with unix socket
                           port=self.CONNECTOR_PORT_1,
                           user=DB_USER, password=DB_USER_PASSWORD,
                           dbname=DB_NAME,
                           ssl_ca=TEST_TLS_CA,
                           ssl_key=TEST_TLS_CLIENT_KEY,
                           ssl_cert=TEST_TLS_CLIENT_CERT)
        ).execute_prepared_statement(query)


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


class AcraTranslatorMixin(object):

    def fork_connector_for_translator(self, connector_port: int, server_port: int, client_id: str, check_connection: bool=True):
        logging.info("fork connector for translator")
        server_connection = get_tcp_connection_string(server_port)
        connector_connection = get_tcp_connection_string(connector_port)
        args = [
            './acra-connector',
            '-acratranslator_connection_string={}'.format(server_connection),
            '-mode=acratranslator',
            '-client_id={}'.format(client_id),
            '-incoming_connection_string={}'.format(connector_connection),
            '-user_check_disable=true',
            '-keys_dir={}'.format(KEYS_FOLDER.name),
        ]
        if self.DEBUG_LOG:
            args.append('-v=true')
        process = self.fork(lambda: subprocess.Popen(args))
        assert process
        if check_connection:
            try:
                wait_connection(connector_port)
            except:
                stop_process(process)
                raise
        return process


class AcraTranslatorTest(AcraTranslatorMixin, BaseTestCase):

    def checkSkip(self):
        return

    def setUp(self):
        self.checkSkip()

    def grpc_decrypt_request(self, port, client_id, zone_id, acrastruct):
        channel = grpc.insecure_channel('127.0.0.1:{}'.format(port))
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
        except grpc.RpcError:
            return b''
        return response.data

    def http_decrypt_request(self, port, client_id, zone_id, acrastruct):
        api_url = 'http://127.0.0.1:{}/v1/decrypt'.format(port)
        if zone_id:
            api_url = '{}?zone_id={}'.format(api_url, zone_id)
        with requests.post(api_url, data=acrastruct, timeout=REQUEST_TIMEOUT) as response:
            return response.content

    def grpc_encrypt_request(self, port, client_id, zone_id, data):
        channel = grpc.insecure_channel('127.0.0.1:{}'.format(port))
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
        except grpc.RpcError:
            return b''
        return response.acrastruct

    def http_encrypt_request(self, port, client_id, zone_id, data):
        api_url = 'http://127.0.0.1:{}/v1/encrypt'.format(port)
        if zone_id:
            api_url = '{}?zone_id={}'.format(api_url, zone_id)
        with requests.post(api_url, data=data, timeout=REQUEST_TIMEOUT) as response:
            return response.content

    def _testApiEncryption(self, request_func, use_http=False, use_grpc=False):
        # one is set
        self.assertTrue(use_http or use_grpc)
        # two is not acceptable
        self.assertFalse(use_http and use_grpc)
        translator_port = 3456
        connector_port = 12345
        connector_port2 = connector_port+1
        client_id = "keypair1"
        data = get_pregenerated_random_data().encode('ascii')
        client_id_private_key = read_storage_private_key(KEYS_FOLDER.name, 'keypair1')
        zone = zones[0]
        zone_private_key = read_zone_private_key(KEYS_FOLDER.name, zone['id'])
        connection_string = 'tcp://127.0.0.1:{}'.format(translator_port)
        translator_kwargs = {
            'incoming_connection_http_string': connection_string if use_http else '',
            # turn off grpc to avoid check connection to it without acra-connector
            'incoming_connection_grpc_string': connection_string if use_grpc else '',}

        correct_client_id = 'keypair1'
        incorrect_client_id = 'keypair2'
        with ProcessContextManager(self.fork_translator(translator_kwargs)):
            with ProcessContextManager(self.fork_connector_for_translator(connector_port, translator_port, client_id)):
                response = request_func(connector_port, correct_client_id, None, data)
                decrypted = decrypt_acrastruct(response, client_id_private_key, 'keypair1')
                self.assertEqual(data, decrypted)
                # test with correct zone id
                print("encrypt with zone {}".format(zone['id']))
                response = request_func(
                    connector_port, client_id, zone['id'], data)
                print("decrypt with zone {}".format(zone['id']))
                decrypted = decrypt_acrastruct(response, zone_private_key, zone_id=zone['id'].encode('ascii'))
                self.assertEqual(data, decrypted)
            # wait decryption error with incorrect client id
            with ProcessContextManager(self.fork_connector_for_translator(connector_port2, translator_port, incorrect_client_id)):
                response = request_func(connector_port2, incorrect_client_id, None, None)
                self.assertNotEqual(data, response)

    def _testApiDecryption(self, request_func, use_http=False, use_grpc=False):
        # one is set
        self.assertTrue(use_http or use_grpc)
        # two is not acceptable
        self.assertFalse(use_http and use_grpc)
        translator_port = 3456
        connector_port = 12345
        connector_port2 = connector_port+1
        client_id = "keypair1"
        data = get_pregenerated_random_data().encode('ascii')
        encryption_key = read_storage_public_key(
            client_id, keys_dir=KEYS_FOLDER.name)
        acrastruct = create_acrastruct(data, encryption_key)

        zone = zones[0]
        incorrect_zone = zones[1]
        zone_public = b64decode(zone['public_key'].encode('ascii'))
        acrastruct_with_zone = create_acrastruct(
            data, zone_public, context=zone['id'].encode('ascii'))
        connection_string = 'tcp://127.0.0.1:{}'.format(translator_port)
        translator_kwargs = {
            'incoming_connection_http_string': connection_string if use_http else '',
            # turn off grpc to avoid check connection to it without acra-connector
            'incoming_connection_grpc_string': connection_string if use_grpc else '',}

        correct_client_id = 'keypair1'
        incorrect_client_id = 'keypair2'
        with ProcessContextManager(self.fork_translator(translator_kwargs)):
            with ProcessContextManager(self.fork_connector_for_translator(connector_port, translator_port, client_id)):
                response = request_func(connector_port, correct_client_id, None, acrastruct)
                self.assertEqual(data, response)

                # test with correct zone id
                response = request_func(
                    connector_port, client_id, zone['id'], acrastruct_with_zone)
                self.assertEqual(data, response)

                # test with incorrect zone id
                response = request_func(
                    connector_port, client_id, incorrect_zone['id'],
                    acrastruct_with_zone)
                self.assertNotEqual(data, response)

            # wait decryption error with incorrect client id
            with ProcessContextManager(self.fork_connector_for_translator(connector_port2, translator_port, incorrect_client_id)):
                response = request_func(connector_port2, incorrect_client_id, None, acrastruct)
                self.assertNotEqual(data, response)

    def testHTTPApiResponses(self):
        translator_port = 3456
        connector_port = 8000
        data = get_pregenerated_random_data().encode('ascii')
        encryption_key = read_storage_public_key(
            'keypair1', keys_dir=KEYS_FOLDER.name)
        acrastruct = create_acrastruct(data, encryption_key)
        connection_string = 'tcp://127.0.0.1:{}'.format(translator_port)
        translator_kwargs = {
            'incoming_connection_http_string': connection_string ,
        }
        api_url = 'http://127.0.0.1:{}/v1/decrypt'.format(connector_port)
        with ProcessContextManager(self.fork_translator(translator_kwargs)):
            with ProcessContextManager(self.fork_connector_for_translator(connector_port, translator_port, 'keypair1')):
                # test incorrect HTTP method
                response = requests.get(api_url, data=acrastruct,
                                        timeout=REQUEST_TIMEOUT)
                self.assertEqual(
                    response.status_code, http.HTTPStatus.METHOD_NOT_ALLOWED)
                self.assertIn('HTTP method is not allowed, expected POST, got'.lower(),
                              response.text.lower())
                self.assertEqual(response.headers['Content-Type'], 'text/plain')

                # test without api version
                without_version_api_url = api_url.replace('v1/', '')
                response = requests.post(
                    without_version_api_url, data=acrastruct,
                    timeout=REQUEST_TIMEOUT)
                self.assertEqual(response.status_code,
                                 http.HTTPStatus.BAD_REQUEST)
                self.assertIn('Malformed URL, expected /<version>/<endpoint>, got'.lower(),
                              response.text.lower())
                self.assertEqual(response.headers['Content-Type'], 'text/plain')

                # incorrect version
                without_version_api_url = api_url.replace('v1/', 'v2/')
                response = requests.post(
                    without_version_api_url, data=acrastruct,
                    timeout=REQUEST_TIMEOUT)
                self.assertEqual(response.status_code,
                                 http.HTTPStatus.BAD_REQUEST)
                self.assertIn('HTTP request version is not supported: expected v1, got'.lower(),
                              response.text.lower())
                self.assertEqual(response.headers['Content-Type'], 'text/plain')

                # incorrect url
                incorrect_url = 'http://127.0.0.1:{}/v1/someurl'.format(connector_port)
                response = requests.post(
                    incorrect_url, data=acrastruct, timeout=REQUEST_TIMEOUT)
                self.assertEqual(
                    response.status_code, http.HTTPStatus.BAD_REQUEST)
                self.assertEqual('HTTP endpoint not supported'.lower(),
                                 response.text.lower())
                self.assertEqual(response.headers['Content-Type'], 'text/plain')


                # without acrastruct (http body), pass empty byte array as data
                response = requests.post(api_url, data=b'',
                                         timeout=REQUEST_TIMEOUT)
                self.assertEqual(response.status_code,
                                 http.HTTPStatus.UNPROCESSABLE_ENTITY)
                self.assertIn("Can't decrypt AcraStruct".lower(),
                              response.text.lower())
                self.assertEqual(response.headers['Content-Type'], 'text/plain')


                # test with correct acrastruct
                response = requests.post(api_url, data=acrastruct,
                                         timeout=REQUEST_TIMEOUT)
                self.assertEqual(data, response.content)
                self.assertEqual(response.status_code, http.HTTPStatus.OK)
                self.assertEqual(response.headers['Content-Type'],
                                 'application/octet-stream')

    def testGRPCApi(self):
        self._testApiDecryption(self.grpc_decrypt_request, use_grpc=True)
        self._testApiEncryption(self.grpc_encrypt_request, use_grpc=True)

    def testHTTPApi(self):
        self._testApiDecryption(self.http_decrypt_request, use_http=True)
        self._testApiEncryption(self.http_encrypt_request, use_http=True)


class TestAcraRotateWithZone(BaseTestCase):
    ZONE = True

    def checkSkip(self):
        return

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
                        ['./acra-addzone',
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
                        ['./acra-rotate', '--keys_dir={}'.format(keys_folder),
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
                            decrypted_rotated = decrypt_acrastruct(
                                rotated_acrastruct, zone_private,
                                zone_id=zone_id.encode('ascii'))
                            if dryRun:
                                self.assertEqual(
                                    rotated_acrastruct,
                                    acrastructs[path].acrastruct)
                            else:
                                self.assertNotEqual(
                                    rotated_acrastruct,
                                    acrastructs[path].acrastruct)
                            # data should be unchanged
                            self.assertEqual(
                                decrypted_rotated, acrastructs[path].data)

    def testDatabaseRotation(self):
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
                    ['./acra-addzone',
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
                './acra-rotate',
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
                ['./acra-keymaker',
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
                        ['./acra-rotate', '--keys_dir={}'.format(keys_folder),
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
                            decrypted_rotated = decrypt_acrastruct(
                                rotated_acrastruct, client_id_private)
                            if dryRun:
                                self.assertEqual(
                                    rotated_acrastruct,
                                    acrastructs[path].acrastruct)
                            else:
                                self.assertNotEqual(
                                    rotated_acrastruct,
                                    acrastructs[path].acrastruct)
                            # data should be unchanged
                            self.assertEqual(
                                decrypted_rotated, acrastructs[path].data)

    def testDatabaseRotation(self):
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
        )
        metadata.create_all(self.engine_raw)
        self.engine_raw.execute(sa.delete(rotate_test_table))

        data_before_rotate = {}

        data = get_pregenerated_random_data()
        client_id = 'keypair1'
        acra_struct = create_acrastruct_with_client_id(data.encode('ascii'), client_id)
        row_id = get_random_id()
        data_before_rotate[row_id] = acra_struct
        self.engine_raw.execute(
            rotate_test_table.insert(),
            {'id': row_id, 'data': acra_struct, 'raw_data': data,
             'key_id': client_id.encode('ascii')})

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
                './acra-rotate',
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

    def checkSkip(self):
        return

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
        HexFormatTest.testConnectorRead(self)
        labels = {
            # acra-connector keypair1 + keypair2
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
        self.checkMetrics('http://127.0.0.1:{}/metrics'.format(
            self.ACRASERVER_PROMETHEUS_PORT), labels)

    def testAcraConnector(self):
        # connector should has some values in counter after connections checks
        # on setUp
        labels = {
            'acraconnector_connections_total': {'min_value': 2},

            'acraconnector_connections_processing_seconds_bucket': {'min_value': 0},
            'acraconnector_connections_processing_seconds_sum': {'min_value': TestPrometheusMetrics.MIN_EXECUTION_TIME},
            'acraconnector_connections_processing_seconds_count': {'min_value': 1},

            'acraconnector_version_major': {'min_value': 0},
            'acraconnector_version_minor': {'min_value': 0},
            'acraconnector_version_patch': {'min_value': 0},

            'acraconnector_build_info': {'min_value': 1},
        }
        self.checkMetrics('http://127.0.0.1:{}/metrics'.format(
            self.get_connector_prometheus_port(self.CONNECTOR_PORT_1)), labels)

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
        connector_port = 8000
        data = get_pregenerated_random_data().encode('ascii')
        client_id = 'keypair1'
        encryption_key = read_storage_public_key(
            client_id, keys_dir=KEYS_FOLDER.name)
        acrastruct = create_acrastruct(data, encryption_key)

        prometheus_metrics_address = 'tcp://127.0.0.1:{}'.format(metrics_port)
        connection_string = 'tcp://127.0.0.1:{}'.format(translator_port)
        translator_kwargs = {
            'incoming_connection_http_string': connection_string,
            'incoming_connection_prometheus_metrics_string': prometheus_metrics_address,
        }
        metrics_url = 'http://127.0.0.1:{}/metrics'.format(metrics_port)
        api_url = 'http://127.0.0.1:{}/v1/decrypt'.format(connector_port)
        with ProcessContextManager(self.fork_translator(translator_kwargs)):
            with ProcessContextManager(self.fork_connector_for_translator(connector_port, translator_port, client_id)):
                # test with correct acrastruct
                response = requests.post(api_url, data=acrastruct,
                                         timeout=REQUEST_TIMEOUT)
                self.assertEqual(response.status_code, http.HTTPStatus.OK)
                self.checkMetrics(metrics_url, labels)

        translator_kwargs = {
            'incoming_connection_grpc_string': connection_string,
            'incoming_connection_prometheus_metrics_string': prometheus_metrics_address,
        }
        with ProcessContextManager(self.fork_translator(translator_kwargs)):
            with ProcessContextManager(self.fork_connector_for_translator(connector_port, translator_port, client_id)):
                AcraTranslatorTest.grpc_decrypt_request(
                    self, connector_port, client_id, None, acrastruct)
                self.checkMetrics(metrics_url, labels)


class TestTransparentEncryption(BaseTestCase):
    WHOLECELL_MODE = True
    encryptor_table = sa.Table('test_transparent_encryption', metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('specified_client_id',
                  sa.LargeBinary(length=COLUMN_DATA_SIZE)),
        sa.Column('default_client_id',
                  sa.LargeBinary(length=COLUMN_DATA_SIZE)),

        sa.Column('zone_id', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
        sa.Column('raw_data', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
        sa.Column('nullable', sa.Text, nullable=True),
        sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
    )
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/encryptor_config.yaml')

    def checkSkip(self):
        return

    def setUp(self):
        prepare_encryptor_config(zones[0][ZONE_ID], self.ENCRYPTOR_CONFIG)
        super(TestTransparentEncryption, self).setUp()

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
            'zone_id': get_pregenerated_random_data().encode('ascii'),
            'specified_client_id': get_pregenerated_random_data().encode('ascii'),
            'raw_data': get_pregenerated_random_data().encode('ascii'),
            'zone': zones[0],
            'empty': b'',
        }
        return context

    def checkDefaultIdEncryption(self, id, default_client_id,
                                 specified_client_id, zone_id, zone, raw_data,
                                 *args, **kwargs):
        result = self.engine2.execute(
            sa.select([self.encryptor_table])
            .where(self.encryptor_table.c.id == id))
        row = result.fetchone()
        self.assertIsNotNone(row)

        # should be decrypted
        self.assertEqual(row['default_client_id'], default_client_id)
        # should be as is
        self.assertEqual(row['raw_data'], raw_data)
        # other data should be encrypted
        self.assertNotEqual(row['specified_client_id'], specified_client_id)
        self.assertNotEqual(row['zone_id'], zone_id)
        self.assertEqual(row['empty'], b'')

    def checkSpecifiedIdEncryption(
            self, id, default_client_id, specified_client_id, zone_id,
            zone, raw_data, *args, **kwargs):
        # fetch using another acra-connector that will authenticated as keypair1
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
        # send through acra-connector that authenticates as client_id=keypair2
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
        # use same id
        new_context['id'] = context['id']
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
                       self.encryptor_table.c.zone_id,
                       self.encryptor_table.c.raw_data,
                       self.encryptor_table.c.nullable,
                       self.encryptor_table.c.empty])
            .where(self.encryptor_table.c.id == context['id']))
        data = result.fetchone()
        return data


class TestTransparentEncryptionWithZone(TestTransparentEncryption):
    ZONE = True

    def testSearch(self):
        self.skipTest("searching with encryption with zones not supported yet")

    def testSearchWithEncryptedData(self):
        self.skipTest("searching with encryption with zones not supported yet")

    def checkZoneIdEncryption(self, zone, id, default_client_id,
                              specified_client_id, zone_id, raw_data,
                              *args, **kwargs):
        result = self.engine1.execute(
            sa.select([self.encryptor_table.c.default_client_id,
                       self.encryptor_table.c.specified_client_id,
                       sa.cast(zone[ZONE_ID].encode('ascii'), BYTEA),
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
        self.assertEqual(row['raw_data'], raw_data)
        # other data should be encrypted
        self.assertNotEqual(row['default_client_id'], default_client_id)
        self.assertNotEqual(row['specified_client_id'], specified_client_id)
        self.assertEqual(row['empty'], b'')

    def check_all_decryptions(self, **context):
        self.checkZoneIdEncryption(**context)


class TestSetupCustomApiPort(BaseTestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def get_acraserver_api_connection_string(self, port=None):
        # use tcp instead unix socket which set as default in tests
        return 'tcp://127.0.0.1:{}'.format(port)

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


class TestSetupCustomApiPort(BaseTestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def get_acraserver_api_connection_string(self, port=None):
        # use tcp instead unix socket which set as default in tests
        return 'tcp://127.0.0.1:{}'.format(port)

    def testCustomPort(self):
        custom_port = 7373
        acra = self.fork_acra(
            None, incoming_connection_api_port=custom_port)
        try:
            wait_connection(custom_port)
        finally:
            stop_process(acra)


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
        self.assertIsNone(row['text'])
        self.assertIsNone(row['binary'])

        # check empty values
        result = self.engine1.execute(sa.select([self.temp_table]).where(self.temp_table.c.id == empty_value_id))
        row = result.fetchone()
        self.assertEqual(row['text'], '')
        self.assertEqual(row['binary'], b'')


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
            subprocess.check_output(['configs/regenerate.sh', tmp_dir])

            for service in services:
                self.remove_version_from_config(os.path.join(tmp_dir, service + '.yaml'))

            default_args = {
                'acra-server': ['-db_host=127.0.0.1'],
                'acra-connector': ['-user_check_disable', '-acraserver_connection_host=127.0.0.1', '-client_id=keypair1'],
                'acra-migrate-keys': ['--dry_run', '--src_keys_dir={}'.format(KEYS_FOLDER.name)],
                'acra-read-key': ['--keys_dir={}'.format(KEYS_FOLDER.name)],
            }
            for service in services:
                config_param = '-config_file={}'.format(os.path.join(tmp_dir, '{}.yaml'.format(service)))
                args = ['./' + service, config_param] + default_args.get(service, [])
                stderr = self.getOutputFromProcess(args)
                self.assertIn('error="config hasn\'t version key"', stderr)

    def testStartupWithOutdatedConfigVersion(self):
        files = os.listdir('cmd/')
        services = [i for i in files if os.path.isdir(os.path.join('cmd', i))]
        self.assertTrue(services)

        with tempfile.TemporaryDirectory() as tmp_dir:
            # generate configs for tests
            subprocess.check_output(['configs/regenerate.sh', tmp_dir])

            for service in services:
                self.replace_version_in_config('0.0.0', os.path.join(tmp_dir, service + '.yaml'))

            default_args = {
                'acra-server': ['-db_host=127.0.0.1'],
                'acra-connector': ['-user_check_disable', '-acraserver_connection_host=127.0.0.1', '-client_id=keypair1'],
                'acra-migrate-keys': ['--dry_run', '--src_keys_dir={}'.format(KEYS_FOLDER.name)],
                'acra-read-key': ['--keys_dir={}'.format(KEYS_FOLDER.name)],
            }
            for service in services:
                config_param = '-config_file={}'.format(os.path.join(tmp_dir, '{}.yaml'.format(service)))
                args = ['./' + service, config_param] + default_args.get(service, [])
                stderr = self.getOutputFromProcess(args)
                self.assertRegexpMatches(stderr, r'code=508 error="config version \\"0.0.0\\" is not supported, expects \\"[\d.]+\\" version')

    def testStartupWithDifferentConfigsPatchVersion(self):
        files = os.listdir('cmd/')
        services = [i for i in files if os.path.isdir(os.path.join('cmd/', i))]
        self.assertTrue(services)

        with tempfile.TemporaryDirectory() as tmp_dir:
            # generate configs for tests
            subprocess.check_output(['configs/regenerate.sh', tmp_dir])

            for service in services:
                config_path = os.path.join(tmp_dir, service + '.yaml')
                config = load_yaml_config(config_path)
                version = semver.parse(config['version'])
                version['patch'] = 100500
                config['version'] = semver.format_version(**version)
                dump_yaml_config(config, config_path)

            default_args = {
                'acra-addzone': ['-keys_output_dir={}'.format(KEYS_FOLDER.name)],
                'acra-authmanager': {'args': ['-keys_dir={}'.format(KEYS_FOLDER.name)],
                                     'status': 1},
                'acra-connector': {'connection': 'connection_string',
                                   'args': ['-keys_dir={}'.format(KEYS_FOLDER.name)],
                                   'status': 1},
                'acra-keymaker': ['-keys_output_dir={}'.format(tmp_dir),
                                  '-keys_public_output_dir={}'.format(tmp_dir),
                                  '--keystore={}'.format(KEYSTORE_VERSION)],
                'acra-migrate-keys': ['--dry_run', '--src_keys_dir={}'.format(KEYS_FOLDER.name)],
                'acra-read-key': ['--keys_dir={}'.format(KEYS_FOLDER.name)],
                'acra-poisonrecordmaker': ['-keys_dir={}'.format(tmp_dir),
                                           '--keystore={}'.format(KEYSTORE_VERSION)],
                'acra-rollback': {'args': ['-keys_dir={}'.format(tmp_dir),
                                           '--keystore={}'.format(KEYSTORE_VERSION)],
                                  'status': 1},
                'acra-rotate': {'args': ['-keys_dir={}'.format(tmp_dir),
                                         '--keystore={}'.format(KEYSTORE_VERSION)],
                                'status': 0},
                'acra-translator': {'connection': 'connection_string',
                                   'args': ['-keys_dir={}'.format(KEYS_FOLDER.name),
                                            # empty id to raise error
                                            '--securesession_id=""'],
                                   'status': 1},
                'acra-server': {'args': ['-keys_dir={}'.format(KEYS_FOLDER.name)],
                                'status': 1},
                'acra-webconfig': {'args': ['-static_path={}'.format('/not/existed/path')],
                                   'status': 1},
            }

            for service in services:
                test_data = default_args.get(service)
                expected_status_code = 0
                if isinstance(test_data, dict):
                    expected_status_code = test_data['status']
                    service_args = test_data['args']
                else:
                    service_args = test_data

                config_param = '-config_file={}'.format(os.path.join(tmp_dir, '{}.yaml'.format(service)))
                args = ['./' + service, config_param] + service_args
                stderr = self.getOutputFromProcess(args)
                self.assertNotRegex(stderr, r'code=508 error="config version \\"[\d.+]\\" is not supported, expects \\"[\d.]+\\" version')

    def testStartupWithoutConfig(self):
        files = os.listdir('cmd/')
        services = [i for i in files if os.path.isdir(os.path.join('cmd/', i))]
        self.assertTrue(services)

        with tempfile.TemporaryDirectory() as tmp_dir:
            default_args = {
                'acra-addzone': ['-keys_output_dir={}'.format(KEYS_FOLDER.name)],
                'acra-authmanager': {'args': ['-keys_dir={}'.format(KEYS_FOLDER.name)],
                                     'status': 1},
                'acra-connector': {'connection': 'connection_string',
                                   'args': ['-keys_dir={}'.format(KEYS_FOLDER.name)],
                                   'status': 1},
                'acra-keymaker': ['-keys_output_dir={}'.format(tmp_dir),
                                  '-keys_public_output_dir={}'.format(tmp_dir),
                                  '--keystore={}'.format(KEYSTORE_VERSION)],
                'acra-migrate-keys': ['--dry_run', '--src_keys_dir={}'.format(KEYS_FOLDER.name)],
                'acra-read-key': ['--keys_dir={}'.format(KEYS_FOLDER.name)],
                'acra-poisonrecordmaker': ['-keys_dir={}'.format(tmp_dir),
                                           '--keystore={}'.format(KEYSTORE_VERSION)],
                'acra-rollback': {'args': ['-keys_dir={}'.format(tmp_dir),
                                           '--keystore={}'.format(KEYSTORE_VERSION)],
                                  'status': 1},
                'acra-rotate': {'args': ['-keys_dir={}'.format(tmp_dir),
                                         '--keystore={}'.format(KEYSTORE_VERSION)],
                                'status': 0},
                'acra-translator': {'connection': 'connection_string',
                                    'args': ['-keys_dir={}'.format(KEYS_FOLDER.name),
                                             # empty id to raise error
                                             '--securesession_id=""'],
                                    'status': 1},
                'acra-server': {'args': ['-keys_dir={}'.format(KEYS_FOLDER.name)],
                                'status': 1},
                'acra-webconfig': {'args': ['-static_path={}'.format('/not/existed/path')],
                                   'status': 1},
            }

            for service in services:
                test_data = default_args.get(service)
                expected_status_code = 0
                if isinstance(test_data, dict):
                    expected_status_code = test_data['status']
                    service_args = test_data['args']
                else:
                    service_args = test_data

                args = ['./' + service, '-config_file=""'] + service_args
                stderr = self.getOutputFromProcess(args)
                self.assertNotRegex(stderr, r'code=508 error="config version \\"[\d.]\\" is not supported, expects \\"[\d.]+\\" version')


class TestPgPlaceholders(BaseTestCase):
    def checkSkip(self):
        if TEST_MYSQL or not TEST_POSTGRESQL:
            self.skipTest("test only for postgresql")

    def testPgPlaceholders(self):
        connection_args = ConnectionArgs(host=get_db_host(), port=self.CONNECTOR_PORT_1,
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


if __name__ == '__main__':
    import xmlrunner
    output_path = os.environ.get('TEST_XMLOUTPUT', '')
    if output_path:
        with open(output_path, 'wb') as output:
            unittest.main(testRunner=xmlrunner.XMLTestRunner(output=output))
    else:
        unittest.main()
