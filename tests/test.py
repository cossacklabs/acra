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
from base64 import b64decode, b64encode
from tempfile import NamedTemporaryFile
from urllib.request import urlopen
from urllib.parse import urlparse
import collections
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
from mysql.connector.cursor import MySQLCursorPrepared
from requests.auth import HTTPBasicAuth
from sqlalchemy.exc import DatabaseError
from sqlalchemy.dialects.postgresql import BYTEA

from utils import (read_storage_public_key, decrypt_acrastruct,
                   decrypt_private_key, read_zone_public_key,
                   load_random_data_config, get_random_data_files,
                   clean_test_data, safe_string, prepare_encryptor_config,
                   ENCRYPTOR_TEST_CONFIG)

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

DB_HOST = os.environ.get('TEST_DB_HOST', '127.0.0.1')
DB_NAME = os.environ.get('TEST_DB_NAME', 'postgres')
DB_PORT = os.environ.get('TEST_DB_PORT', 5432)


TEST_RANDOM_DATA_CONFIG = load_random_data_config()
TEST_RANDOM_DATA_FILES = get_random_data_files()

# 200 is overhead of encryption (chosen manually)
# multiply 2 because tested acrastruct in acrastruct
COLUMN_DATA_SIZE = (TEST_RANDOM_DATA_CONFIG['data_max_size'] + 200) * 2
metadata = sa.MetaData()
test_table = sa.Table('test', metadata,
    sa.Column('id', sa.Integer, primary_key=True),
    sa.Column('data', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
    sa.Column('raw_data', sa.Text),
    sa.Column('nullable_column', sa.Text, nullable=True),
)

acrarollback_output_table = sa.Table('acrarollback_output', metadata,
                                     sa.Column('data', sa.LargeBinary),
                                     )
# keys of json objects that return acra-addzone tool
ZONE_ID = 'id'
ZONE_PUBLIC_KEY = 'public_key'

zones = []
poison_record = None
master_key = None
KEYS_FOLDER = None
ACRA_MASTER_KEY_VAR_NAME = 'ACRA_MASTER_KEY'
MASTER_KEY_PATH = '/tmp/acra-test-master.key'

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

TEST_WITH_TLS = os.environ.get('TEST_TLS', 'off').lower() == 'on'
TEST_WITH_TRACING = os.environ.get('TEST_TRACE', 'off').lower() == 'on'
TEST_TRACE_TO_JAEGER = os.environ.get('TEST_TRACE_JAEGER', 'off').lower() == 'on'

PG_UNIX_HOST = '/tmp'

DB_USER = os.environ.get('TEST_DB_USER', 'postgres')
DB_USER_PASSWORD = os.environ.get('TEST_DB_USER_PASSWORD', 'postgres')
SSLMODE = os.environ.get('TEST_SSL_MODE', 'require')
TEST_MYSQL = bool(os.environ.get('TEST_MYSQL', False))
if TEST_MYSQL:
    TEST_POSTGRESQL = False
    DB_DRIVER = "mysql+pymysql"
    TEST_MYSQL = True
    connect_args = {
        'user': DB_USER, 'password': DB_USER_PASSWORD
    }
else:
    TEST_POSTGRESQL = True
    DB_DRIVER = "postgresql"
    connect_args = {
        'connect_timeout': SOCKET_CONNECT_TIMEOUT,
        'user': DB_USER, 'password': DB_USER_PASSWORD,
        "options": "-c statement_timeout={}".format(STATEMENT_TIMEOUT),
        'sslmode': SSLMODE}
    asyncpg_connect_args = {
        'timeout': SOCKET_CONNECT_TIMEOUT,
        'user': DB_USER, 'password': DB_USER_PASSWORD,
        'ssl': TEST_WITH_TLS
    }


def get_random_id():
    return random.randint(1, 100000)


def get_random_data():
    data_file = random.choice(TEST_RANDOM_DATA_FILES)
    with open(data_file, 'r') as f:
        return f.read()


def stop_process(process):
    """stop process if exists by terminate and kill at end to be sure
    that process will not alive as zombi-process"""
    if not isinstance(process, collections.Iterable):
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
        except:
            traceback.print_exc()


def get_connect_args(port=5432, sslmode=None, **kwargs):
    args = connect_args.copy()
    args['port'] = int(port)
    if TEST_POSTGRESQL:
        args['sslmode'] = sslmode if sslmode else SSLMODE
    args.update(kwargs)
    return args


def get_master_key():
    """
    return master key in base64 format if generated or generate and return
    """
    global master_key
    if not master_key:
        master_key = os.environ.get(ACRA_MASTER_KEY_VAR_NAME)
        if not master_key:
            subprocess.check_output([
                './acra-keymaker', '--generate_master_key={}'.format(MASTER_KEY_PATH),
                '--keys_output_dir={}'.format(KEYS_FOLDER.name),
                '--keys_public_output_dir={}'.format(KEYS_FOLDER.name)])
            with open(MASTER_KEY_PATH, 'rb') as f:
                master_key = b64encode(f.read()).decode('ascii')
    return master_key


def get_poison_record():
    """generate one poison record for speed up tests and don't create subprocess
    for new records"""
    global poison_record
    if not poison_record:
        poison_record = b64decode(subprocess.check_output(
            ['./acra-poisonrecordmaker', '--keys_dir={}'.format(KEYS_FOLDER.name)], timeout=PROCESS_CALL_TIMEOUT))
    return poison_record


def create_client_keypair(name, only_server=False, only_client=False):
    args = ['./acra-keymaker', '-client_id={}'.format(name),
            '-keys_output_dir={}'.format(KEYS_FOLDER.name),
            '--keys_public_output_dir={}'.format(KEYS_FOLDER.name)]
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
            '--password={}'.format(user_password)]
    return subprocess.call(args, cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT)


def wait_connection(port, count=1000, sleep=0.001):
    """try connect to 127.0.0.1:port and close connection
    if can't then sleep on and try again (<count> times)
    if <count> times is failed than raise Exception
    """
    while count:
        try:
            connection = socket.create_connection(('127.0.0.1', port),
                                                  timeout=1)
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
        connection = socket.socket(socket.AF_UNIX)
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
    if TEST_POSTGRESQL:
        return PG_UNIX_HOST
    else:
        return '127.0.0.1'


def get_unix_connection_string(port, dbname):
    if TEST_MYSQL:
        return get_postgresql_tcp_connection_string(port, dbname)
    else:
        return get_postgresql_unix_connection_string(port, dbname)

def get_postgresql_unix_connection_string(port, dbname):
    return '{}:///{}?host={}'.format(DB_DRIVER, dbname, PG_UNIX_HOST)

def get_postgresql_tcp_connection_string(port, dbname):
    return '{}://127.0.0.1:{}/{}'.format(DB_DRIVER, port, dbname)

def get_acraserver_unix_connection_string(port):
    return "unix://{}".format("{}/unix_socket_{}".format(PG_UNIX_HOST, port))

def get_connector_connection_string(port):
    if TEST_MYSQL:
        connection_string = get_postgresql_tcp_connection_string(port, '')
        url = urlparse(connection_string)
        return 'tcp://{}'.format(url.netloc)
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
           build_args=['-ldflags', '-X main.TestOnly=true']),
    Binary(name='acra-addzone', from_version=DEFAULT_VERSION,
           build_args=DEFAULT_BUILD_ARGS),
    Binary(name='acra-keymaker', from_version=DEFAULT_VERSION,
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
    os.environ.setdefault(ACRA_MASTER_KEY_VAR_NAME, get_master_key())

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


def tearDownModule():
    clean_binaries()
    clean_misc()
    KEYS_FOLDER.cleanup()
    clean_test_data()
    for path in [MASTER_KEY_PATH, ENCRYPTOR_TEST_CONFIG]:
        try:
            os.remove(path)
        except:
            pass


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
        with contextlib.closing(pymysql.connect(
                host=self.connection_args.host, port=self.connection_args.port,
                user=self.connection_args.user,
                password=self.connection_args.password,
                db=self.connection_args.dbname,
                cursorclass=pymysql.cursors.DictCursor)) as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, args)
                return cursor.fetchall()

    def execute_prepared_statement(self, query, args=None):
        with contextlib.closing(pymysql.connect(
                host=self.connection_args.host, port=self.connection_args.port,
                user=self.connection_args.user,
                password=self.connection_args.password,
                db=self.connection_args.dbname,
                cursorclass=pymysql.cursors.DictCursor)) as connection:
            with connection.cursor() as cursor:
                cursor.execute("PREPARE test_statement FROM '{}'".format(query))
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
                cursor.execute(query)
                data = cursor.fetchall()
                result = self._result_to_dict(cursor.description, data)
        return result

    def execute_prepared_statement(self, query, args=None):
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

            with contextlib.closing(connection.cursor(
                    cursor_class=MySQLCursorPrepared)) as cursor:
                cursor.execute(query)
                data = cursor.fetchall()
                result = self._result_to_dict(cursor.description, data)
        return result


class AsyncpgExecutor(QueryExecutor):
    def _connect(self, loop):
        return loop.run_until_complete(
            asyncpg.connect(
                host=self.connection_args.host, port=self.connection_args.port,
                user=self.connection_args.user, password=self.connection_args.password,
                ssl=TEST_WITH_TLS, timeout=STATEMENT_TIMEOUT,
                statement_cache_size=0,
                command_timeout=STATEMENT_TIMEOUT))

    def execute_prepared_statement(self, query, args=None):
        loop = asyncio.get_event_loop()
        conn = self._connect(loop)
        try:
            stmt = loop.run_until_complete(
                conn.prepare(query, timeout=STATEMENT_TIMEOUT))
            result = loop.run_until_complete(
                stmt.fetch(timeout=STATEMENT_TIMEOUT))
            return result
        finally:
            conn.terminate()

    def execute(self, query, args=None):
        loop = asyncio.get_event_loop()
        conn = self._connect(loop)
        try:
            result = loop.run_until_complete(
                conn.execute(query, timeout=STATEMENT_TIMEOUT))
            result = loop.run_until_complete(
                result.fetch(timeout=STATEMENT_TIMEOUT))
            return result
        finally:
            loop.run_until_complete(conn.close(timeout=STATEMENT_TIMEOUT))


class Psycopg2Executor(QueryExecutor):
    def execute(self, query, args=None):
        args = get_connect_args(self.connection_args.port)
        with psycopg2.connect(
                host=self.connection_args.host,
                dbname=self.connection_args.dbname, **args) as connection:
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
        with tempfile.TemporaryDirectory() as folder:
            key_size = 32
            short_key = b64encode((key_size - 1)*b'a')
            standard_key = b64encode(key_size * b'a')
            long_key = b64encode((key_size * 2) * b'a')

            with self.assertRaises(subprocess.CalledProcessError) as exc:
                subprocess.check_output(
                    ['./acra-keymaker', '--keys_output_dir={}'.format(folder),
                     '--keys_public_output_dir={}'.format(folder)],
                    env={'ACRA_MASTER_KEY': short_key})

            subprocess.check_output(
                    ['./acra-keymaker', '--keys_output_dir={}'.format(folder),
                     '--keys_public_output_dir={}'.format(folder)],
                    env={'ACRA_MASTER_KEY': standard_key})
            subprocess.check_output(
                    ['./acra-keymaker', '--keys_output_dir={}'.format(folder),
                     '--keys_public_output_dir={}'.format(folder)],
                    env={'ACRA_MASTER_KEY': long_key})


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
    ACRAWEBCONFIG_ACRASERVER_PARAMS = dict(
        db_host=DB_HOST,
        db_port=DB_PORT,
        incoming_connection_api_port=9090,
        debug=DEBUG_LOG,
        poison_run_script_file="",
        poison_shutdown_enable=False,
        zonemode_enable=False
    )
    ZONE = False
    TEST_DATA_LOG = False
    TLS_ON = False

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

    def wait_acraserver_connection(self, *args, **kwargs):
        return wait_unix_socket(*args, **kwargs)

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
        return [
            '--acraserver_tls_transport_enable',
            '--tls_acraserver_sni=acraserver',
        ]

    def get_connector_prometheus_port(self, port):
        return port+1

    def fork_connector(self, connector_port: int, acraserver_port: int, client_id: str, api_port: int=None, zone_mode: bool=False, check_connection: bool=True):
        logging.info("fork connector")

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
        args = [
            './acra-connector',
            '-acraserver_connection_string={}'.format(acraserver_connection),
            '-acraserver_api_connection_string={}'.format(acraserver_api_connection),
             '-client_id={}'.format(client_id),
            '-incoming_connection_string={}'.format(connector_connection),
            '-incoming_connection_api_string={}'.format(connector_api_connection),
            '-user_check_disable=true',
            '-keys_dir={}'.format(KEYS_FOLDER.name),
            '-logging_format=cef',
        ]
        if self.LOG_METRICS:
            args.append('-incoming_connection_prometheus_metrics_string={}'.format(
                self.get_prometheus_address(
                    self.get_connector_prometheus_port(connector_port))))
        if TEST_WITH_TRACING:
            args.append('--tracing_log_enable')
            if TEST_TRACE_TO_JAEGER:
                args.append('--tracing_jaeger_enable')
        if self.DEBUG_LOG:
            args.append('-v=true')
        if zone_mode:
            args.append('--http_api_enable=true')
        if self.TLS_ON:
            args.extend(self.get_connector_tls_params())
        process = self.fork(lambda: subprocess.Popen(args))
        if check_connection:
            try:
                if TEST_MYSQL:
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

    def _fork_acra(self, acra_kwargs, popen_kwargs):
        logging.info("fork acra")
        connection_string = self.get_acraserver_connection_string(
            acra_kwargs.get('incoming_connection_port'))
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
        if self.TLS_ON:
            args['acraconnector_tls_transport_enable'] = 'true'
            args['tls_key'] = 'tests/server.key'
            args['tls_cert'] = 'tests/server.crt'
            args['tls_ca'] = 'tests/server.crt'
            args['tls_auth'] = 0
        if TEST_MYSQL:
            args['mysql_enable'] = 'true'
            args['postgresql_enable'] = 'false'
        args.update(acra_kwargs)
        if not popen_kwargs:
            popen_kwargs = {}
        cli_args = ['--{}={}'.format(k, v) for k, v in args.items()]

        process = self.fork(lambda: subprocess.Popen([self.get_acraserver_bin_path()] + cli_args,
                                                     **popen_kwargs))
        try:
            self.wait_acraserver_connection(socket_path_from_connection_string(connection_string))
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
                get_unix_connection_string(self.CONNECTOR_PORT_1, DB_NAME), connect_args=get_connect_args(port=self.CONNECTOR_PORT_1))
            self.engine2 = sa.create_engine(
                get_unix_connection_string(
                    self.CONNECTOR_PORT_2, DB_NAME), connect_args=get_connect_args(port=self.CONNECTOR_PORT_2))
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
        processes = [getattr(self, 'connector_1', ProcessStub()),
                     getattr(self, 'connector_2', ProcessStub()),
                     getattr(self, 'acra', ProcessStub())]
        stop_process(processes)
        try:
            self.engine_raw.execute('delete from test;')
        except:
            pass
        for engine in getattr(self, 'engines', []):
            engine.dispose()

    def log(self, acra_key_name, data, expected):
        """this function for printing data which used in test and for
        reproducing error with them if any error detected"""
        if not self.TEST_DATA_LOG:
            return
        with open('{}/{}_zone'.format(KEYS_FOLDER.name, zones[0][ZONE_ID]), 'rb') as f:
            zone_private = f.read()
        with open('{}/{}'.format(KEYS_FOLDER.name, acra_key_name), 'rb') as f:
            private_key = f.read()
        with open('{}/{}.pub'.format(KEYS_FOLDER.name, acra_key_name), 'rb') as f:
            public_key = f.read()
        logging.debug("test log: {}".format(json.dumps(
            {
                'master_key': get_master_key(),
                'key_name': acra_key_name,
                'private_key': b64encode(private_key).decode('ascii'),
                'public_key': b64encode(public_key).decode('ascii'),
                'data': b64encode(data).decode('ascii'),
                'expected': b64encode(expected).decode('ascii'),
                'zone_private': b64encode(zone_private).decode('ascii'),
                'zone_public': zones[0][ZONE_PUBLIC_KEY],
                'zone_id': zones[0][ZONE_ID],
                'poison_record': b64encode(get_poison_record()).decode('ascii'),
            }
        )))


class HexFormatTest(BaseTestCase):

    def testConnectorRead(self):
        """test decrypting with correct acra-connector and not decrypting with
        incorrect acra-connector or using direct connection to db"""
        keyname = 'keypair1_storage'
        with open('{}/{}.pub'.format(KEYS_FOLDER.name, keyname), 'rb') as f:
            server_public1 = f.read()
        data = get_random_data()
        acra_struct = create_acrastruct(
            data.encode('ascii'), server_public1)
        row_id = get_random_id()

        self.log(keyname, acra_struct, data.encode('ascii'))

        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': acra_struct, 'raw_data': data})
        result = self.engine1.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertEqual(row['data'], row['raw_data'].encode('utf-8'))

        result = self.engine2.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'].decode('ascii', errors='ignore'),
                            row['raw_data'])

        result = self.engine_raw.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'].decode('ascii', errors='ignore'),
                            row['raw_data'])

    def testReadAcrastructInAcrastruct(self):
        """test correct decrypting acrastruct when acrastruct concatenated to
        partial another acrastruct"""
        keyname = 'keypair1_storage'
        with open('{}/{}.pub'.format(KEYS_FOLDER.name, keyname), 'rb') as f:
            server_public1 = f.read()
        incorrect_data = get_random_data()
        correct_data = get_random_data()
        fake_offset = (3+45+84) - 4
        fake_acra_struct = create_acrastruct(
            incorrect_data.encode('ascii'), server_public1)[:fake_offset]
        inner_acra_struct = create_acrastruct(
            correct_data.encode('ascii'), server_public1)
        data = fake_acra_struct + inner_acra_struct
        row_id = get_random_id()

        self.log(keyname, data, fake_acra_struct+correct_data.encode('ascii'))

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

        result = self.engine_raw.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'][fake_offset:].decode('ascii', errors='ignore'),
                            row['raw_data'])


class BaseCensorTest(BaseTestCase):
    CENSOR_CONFIG_FILE = 'default.yaml'
    def fork_acra(self, popen_kwargs: dict=None, **acra_kwargs: dict):
        acra_kwargs['acracensor_config_file'] = self.CENSOR_CONFIG_FILE
        return self._fork_acra(acra_kwargs, popen_kwargs)


class CensorBlacklistTest(BaseCensorTest):
    CENSOR_CONFIG_FILE = 'tests/acra-censor_configs/acra-censor_blacklist.yaml'
    def testBlacklist(self):

        connection_args = ConnectionArgs(host=get_db_host(), port=self.CONNECTOR_PORT_1,
                           user=DB_USER, password=DB_USER_PASSWORD,
                           dbname=DB_NAME, ssl_ca='tests/server.crt',
                           ssl_key='tests/client.key',
                           ssl_cert='tests/client.crt')
        if TEST_MYSQL:
            expectedException = (pymysql.err.OperationalError,
                                 mysql.connector.errors.DatabaseError)
            executors = [PyMysqlExecutor(connection_args),
                         MysqlExecutor(connection_args)]
        if TEST_POSTGRESQL:
            expectedException = (psycopg2.ProgrammingError,
                                 asyncpg.exceptions.SyntaxOrAccessError)
            executors = [Psycopg2Executor(connection_args),
                         AsyncpgExecutor(connection_args)]

        for executor in executors:
            #test block by query
            with self.assertRaises(expectedException):
                result = executor.execute(
                    "select data from test where id='1'")
            #test block by query in prepared statement
            with self.assertRaises(expectedException):
                result = executor.execute_prepared_statement(
                    "select data from test where id='1'")

            #test block by table
            with self.assertRaises(expectedException):
                result = executor.execute("select data_raw from test")

            #test block by table in prepared statement
            with self.assertRaises(expectedException):
                result = executor.execute_prepared_statement(
                    "select data_raw from test")

            #test block by pattern
            with self.assertRaises(expectedException):
                result = executor.execute(
                    "select * from acrarollback_output")

            #test block by pattern in prepared statement
            with self.assertRaises(expectedException):
                result = executor.execute_prepared_statement(
                    "select * from acrarollback_output")


class CensorWhitelistTest(BaseCensorTest):
    CENSOR_CONFIG_FILE = 'tests/acra-censor_configs/acra-censor_whitelist.yaml'
    def testWhitelist(self):
        connection_args = ConnectionArgs(host=get_db_host(), port=self.CONNECTOR_PORT_1,
                           user=DB_USER, password=DB_USER_PASSWORD,
                           dbname=DB_NAME, ssl_ca='tests/server.crt',
                           ssl_key='tests/client.key',
                           ssl_cert='tests/client.crt')
        if TEST_MYSQL:
            expectedException = (pymysql.err.OperationalError,
                                 mysql.connector.errors.DatabaseError)
            executors = [PyMysqlExecutor(connection_args),
                         MysqlExecutor(connection_args)]
        if TEST_POSTGRESQL:
            expectedException = (psycopg2.ProgrammingError,
                                 asyncpg.exceptions.SyntaxOrAccessError)
            executors = [Psycopg2Executor(connection_args),
                         AsyncpgExecutor(connection_args)]

        for executor in executors:

            #test block by table
            with self.assertRaises(expectedException):
                result = executor.execute("select * from acrarollback_output")
            #test block by table with prepared statement
            with self.assertRaises(expectedException):
                result = executor.execute_prepared_statement("select * from acrarollback_output")

            #test block by pattern
            with self.assertRaises(expectedException):
                result = executor.execute("insert into test (a, b, c) values ('x', 'y', 'z')")
            #test block by pattern with prepared statement
            with self.assertRaises(expectedException):
                result = executor.execute_prepared_statement("insert into test (a, b, c) values ('x', 'y', 'z')")


class ZoneHexFormatTest(BaseTestCase):
    ZONE = True

    def testConnectorRead(self):
        data = get_random_data()
        zone_public = b64decode(zones[0][ZONE_PUBLIC_KEY].encode('ascii'))
        acra_struct = create_acrastruct(
            data.encode('ascii'), zone_public,
            context=zones[0][ZONE_ID].encode('ascii'))
        row_id = get_random_id()
        self.log(zones[0][ZONE_ID]+'_zone', acra_struct, data.encode('ascii'))
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': acra_struct, 'raw_data': data})

        zone = zones[0][ZONE_ID].encode('ascii')
        result = self.engine1.execute(
            sa.select([sa.cast(zone, BYTEA), test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertEqual(row['data'], row['raw_data'].encode('utf-8'))

        # without zone in another connector, in the same connector and without any connector
        for engine in self.engines:
            result = engine.execute(
                sa.select([test_table])
                .where(test_table.c.id == row_id))
            row = result.fetchone()
            self.assertNotEqual(row['data'].decode('ascii', errors='ignore'), row['raw_data'])

    def testReadAcrastructInAcrastruct(self):
        incorrect_data = get_random_data()
        correct_data = get_random_data()
        zone_public = b64decode(zones[0][ZONE_PUBLIC_KEY].encode('ascii'))
        fake_offset = (3+45+84) - 1
        fake_acra_struct = create_acrastruct(
            incorrect_data.encode('ascii'), zone_public, context=zones[0][ZONE_ID].encode('ascii'))[:fake_offset]
        inner_acra_struct = create_acrastruct(
            correct_data.encode('ascii'), zone_public, context=zones[0][ZONE_ID].encode('ascii'))
        data = fake_acra_struct + inner_acra_struct
        self.log(zones[0][ZONE_ID]+'_zone', data, fake_acra_struct+correct_data.encode('ascii'))
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
                         row['raw_data'].encode('utf-8'))

        result = self.engine2.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'][fake_offset:].decode('ascii', errors='ignore'),
                            row['raw_data'])

        result = self.engine_raw.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'][fake_offset:].decode('ascii', errors='ignore'),
                            row['raw_data'])


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
            except (AssertionError):
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
        connection = None
        try:
            self.connector = self.fork_connector(
                self.CONNECTOR_PORT_1, self.ACRASERVER_PORT, keyname)
            self.assertIsNone(self.connector.poll())
            with self.assertRaises(psycopg2.OperationalError) as exc:
                connection = psycopg2.connect(**self.dsn)

        finally:
            stop_process(self.connector)
            if connection:
                connection.close()

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
        connection = None
        try:
            self.connector = self.fork_connector(
                self.CONNECTOR_PORT_1, self.ACRASERVER_PORT, keyname)
            self.assertIsNone(self.connector.poll())
            with self.assertRaises(psycopg2.OperationalError):
                connection = psycopg2.connect(**self.dsn)
        finally:
            stop_process(self.connector)
            if connection:
                connection.close()

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
            self.log(POISON_KEY_PATH, get_poison_record(),
                     b'no matter because poison record')
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
        self.log(POISON_KEY_PATH, data, data)
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
        for zone, _, data, raw_data, _ in result:
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
        for _, data, raw_data, _ in result:
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
        for _, data, raw_data, _ in result:
            self.assertEqual(data, poison_record)

    def testShutdown4(self):
        """check working poison record callback on full select inside another data"""
        row_id = get_random_id()
        poison_record = get_poison_record()
        begin_tag = poison_record[:4]
        # test with extra long begin tag
        testData = os.urandom(100) + begin_tag + poison_record + os.urandom(100)
        self.log(POISON_KEY_PATH, testData, testData)
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': testData, 'raw_data': 'poison_record'})

        result = self.engine1.execute(
            sa.select([test_table]))
        for _, data, raw_data, _ in result:
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
            #print(log.encode(encoding='utf-8', errors='replace'))
            print(log)
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
        for process, log_file in self.log_files.items():
            log_file.close()
            try:
                os.remove(log_file.name)
            except:
                pass
            stop_process(process)

        super(AcraCatchLogsMixin, self).tearDown(*args, **kwargs)


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
        for _, data, raw_data, _ in result:
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
                get_unix_connection_string(self.CONNECTOR_PORT_1, DB_NAME),
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
        processes = []
        if hasattr(self, 'connector_1'):
            processes.append(self.connector_1)
        if not self.EXTERNAL_ACRA and hasattr(self, 'acra'):
            processes.append(self.acra)

        stop_process(processes)

        try:
            self.engine_raw.execute('delete from test;')
        except:
            pass

        for engine in getattr(self, 'engines', []):
            engine.dispose()

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
        keyname = 'keypair1_storage'
        with open('{}/{}.pub'.format(KEYS_FOLDER.name, keyname), 'rb') as f:
            server_public1 = f.read()

        rows = []
        for _ in range(self.DATA_COUNT):
            data = get_random_data()
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
            data = get_random_data()
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
        keyname = 'keypair1_storage'
        with open('{}/{}.pub'.format(KEYS_FOLDER.name, keyname), 'rb') as f:
            server_public1 = f.read()

        rows = []
        for _ in range(self.DATA_COUNT):
            data = get_random_data()
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
            data = get_random_data()
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
    def setUp(self):
        try:
            # create auth file with default correct user
            manage_basic_auth_user('set', ACRAWEBCONFIG_BASIC_AUTH['user'], ACRAWEBCONFIG_BASIC_AUTH['password'])
            self.acra = self.fork_acra(
                popen_kwargs={'stderr': subprocess.STDOUT, 'stdout': subprocess.PIPE, 'close_fds': True},
                zonemode_enable='true', http_api_enable='true')
            self.connector_1 = self.fork_connector(
                self.CONNECTOR_PORT_1, self.ACRASERVER_PORT, 'keypair1', zone_mode=True, api_port=self.CONNECTOR_API_PORT_1)
            self.webconfig = self.fork_webconfig(connector_port=self.CONNECTOR_API_PORT_1, http_port=self.ACRAWEBCONFIG_HTTP_PORT)
        except Exception:
            self.tearDown()
            raise

    def tearDown(self):
        stop_process(getattr(self, 'webconfig', ProcessStub()))
        super(TestAcraWebconfigWeb, self).tearDown()

    def testAuthAndSubmitSettings(self):
        shutil.copy('configs/acra-server.yaml', 'configs/acra-server.yaml.backup')
        try:
            # test wrong auth
            req = requests.post(
                self.get_acrawebconfig_connection_url(), data={}, timeout=ACRAWEBCONFIG_HTTP_TIMEOUT,
                auth=HTTPBasicAuth('wrong_user_name', 'wrong_password'))
            self.assertEqual(req.status_code, 401)
            req.close()

            # test correct auth
            req = requests.post(
                self.get_acrawebconfig_connection_url(), data={}, timeout=ACRAWEBCONFIG_HTTP_TIMEOUT,
                auth=HTTPBasicAuth(ACRAWEBCONFIG_BASIC_AUTH['user'], ACRAWEBCONFIG_BASIC_AUTH['password']))
            self.assertEqual(req.status_code, 200)
            req.close()

            # test submit settings
            settings = self.ACRAWEBCONFIG_ACRASERVER_PARAMS
            settings['poison_run_script_file'] = str(uuid.uuid4())
            print(settings)
            req = requests.post(
                "{}/acra-server/submit_setting".format(self.get_acrawebconfig_connection_url()),
                data=settings,
                timeout=ACRAWEBCONFIG_HTTP_TIMEOUT,
                auth=HTTPBasicAuth(ACRAWEBCONFIG_BASIC_AUTH['user'], ACRAWEBCONFIG_BASIC_AUTH['password']))
            self.assertEqual(req.status_code, 200)
            req.close()

            # check for new config after acra-server's graceful restart
            req = requests.post(
                self.get_acrawebconfig_connection_url(), data={}, timeout=ACRAWEBCONFIG_HTTP_TIMEOUT,
                auth=HTTPBasicAuth(ACRAWEBCONFIG_BASIC_AUTH['user'], ACRAWEBCONFIG_BASIC_AUTH['password']))
            self.assertEqual(req.status_code, 200)
            self.assertIn(settings['poison_run_script_file'], req.text)
            req.close()
        finally:
            # search pid of forked acra-server process to kill
            out = self.read_log(self.acra)
            # acra-server process forked to PID: 56946
            if out and 'process forked to PID' in out:
                pids = re.findall(r'process forked to PID: (\d+)', out)
                if pids:
                    pid = pids[0]
                    try:
                        os.kill(int(pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

            # restore changed config
            os.rename('configs/acra-server.yaml.backup',
                      'configs/acra-server.yaml')


class SSLPostgresqlMixin(AcraCatchLogsMixin):
    ACRASERVER2_PORT = BaseTestCase.ACRASERVER_PORT + 1000
    ACRASERVER2_PROMETHEUS_PORT = BaseTestCase.ACRASERVER_PROMETHEUS_PORT + 1000
    DEBUG_LOG = True

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
                    tls_key='tests/server.key', tls_cert='tests/server.crt',
                    tls_ca='tests/server.crt',
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
        base_params.append('--tls_ca=tests/server.crt')
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
                    tls_key='tests/server.key',
                    tls_cert='tests/server.crt',
                    tls_ca='tests/server.crt',
                    tls_auth=0,
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
                'ca': 'tests/server.crt',
                #'cert': 'tests/client.crt',
                #'key': 'tests/client.key',
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

    def fork_acra(self, popen_kwargs: dict=None, **acra_kwargs: dict):
        if TEST_WITH_TLS:
            acra_kwargs['tls_key'] = 'tests/server.key'
            acra_kwargs['tls_cert'] = 'tests/server.crt'
            acra_kwargs['tls_ca'] = 'tests/server.crt'
        return super(BasePrepareStatementMixin, self).fork_acra(
            popen_kwargs, **acra_kwargs)

    def executePreparedStatement(self, query):
        raise NotImplementedError

    def testConnectorRead(self):
        """test decrypting with correct acra-connector and not decrypting with
        incorrect acra-connector or using direct connection to db"""
        keyname = 'keypair1_storage'
        with open('{}/{}.pub'.format(KEYS_FOLDER.name, keyname), 'rb') as f:
            server_public1 = f.read()
        data = get_random_data()
        acra_struct = create_acrastruct(
            data.encode('ascii'), server_public1)
        row_id = get_random_id()

        self.log(keyname, acra_struct, data.encode('ascii'))

        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': acra_struct, 'raw_data': data})

        query = sa.select([test_table]).where(test_table.c.id == row_id).compile(compile_kwargs={"literal_binds": True}).string
        row = self.executePreparedStatement(query)[0]

        self.assertEqual(row['data'], safe_string(row['raw_data']).encode('utf-8'))

        result = self.engine2.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'].decode('ascii', errors='ignore'),
                            row['raw_data'])

        result = self.engine_raw.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'].decode('ascii', errors='ignore'),
                            row['raw_data'])

    def testReadAcrastructInAcrastruct(self):
        """test correct decrypting acrastruct when acrastruct concatenated to
        partial another acrastruct"""
        keyname = 'keypair1_storage'
        with open('{}/{}.pub'.format(KEYS_FOLDER.name, keyname), 'rb') as f:
            server_public1 = f.read()
        incorrect_data = get_random_data()
        correct_data = get_random_data()
        fake_offset = (3+45+84) - 4
        fake_acra_struct = create_acrastruct(
            incorrect_data.encode('ascii'), server_public1)[:fake_offset]
        inner_acra_struct = create_acrastruct(
            correct_data.encode('ascii'), server_public1)
        data = fake_acra_struct + inner_acra_struct
        row_id = get_random_id()

        self.log(keyname, data, fake_acra_struct+correct_data.encode('ascii'))

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

        result = self.engine_raw.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'][fake_offset:].decode('ascii', errors='ignore'),
                            row['raw_data'])


class TestMysqlTextPreparedStatement(BasePrepareStatementMixin, BaseTestCase):
    def checkSkip(self):
        if not TEST_MYSQL:
            self.skipTest("run test only for mysql")

    def executePreparedStatement(self, query):
        return PyMysqlExecutor(
            ConnectionArgs(host=get_db_host(), port=self.CONNECTOR_PORT_1,
                           user=DB_USER, password=DB_USER_PASSWORD,
                           dbname=DB_NAME, ssl_ca='tests/server.crt',
                           ssl_key='tests/client.key',
                           ssl_cert='tests/client.crt')
        ).execute_prepared_statement(query)


class TestMysqlBinaryPreparedStatement(BasePrepareStatementMixin, BaseTestCase):
    def checkSkip(self):
        if not TEST_MYSQL:
            self.skipTest("run test only for mysql")

    def executePreparedStatement(self, query):
        return MysqlExecutor(
            ConnectionArgs(host=get_db_host(), port=self.CONNECTOR_PORT_1,
                           user=DB_USER, password=DB_USER_PASSWORD,
                           dbname=DB_NAME, ssl_ca='tests/server.crt',
                           ssl_key='tests/client.key',
                           ssl_cert='tests/client.crt')
        ).execute_prepared_statement(query)


class TestPostgresqlTextPreparedStatement(BasePrepareStatementMixin, BaseTestCase):
    def checkSkip(self):
        if not TEST_POSTGRESQL:
            self.skipTest("run test only for postgresql")

    def executePreparedStatement(self, query):
        return Psycopg2Executor(ConnectionArgs(host=get_db_host(), port=self.CONNECTOR_PORT_1,
                           user=DB_USER, password=DB_USER_PASSWORD,
                           dbname=DB_NAME, ssl_ca='tests/server.crt',
                           ssl_key='tests/client.key',
                           ssl_cert='tests/client.crt')
                                ).execute_prepared_statement(query)


class TestPostgresqlBinaryPreparedStatement(BasePrepareStatementMixin,
                                            BaseTestCase):
    def checkSkip(self):
        if not TEST_POSTGRESQL or TEST_WITH_TLS:
            self.skipTest("run test only for postgresql")

    def executePreparedStatement(self, query):
        return AsyncpgExecutor(
            ConnectionArgs(host=get_db_host(), port=self.CONNECTOR_PORT_1,
                           user=DB_USER, password=DB_USER_PASSWORD,
                           dbname=DB_NAME, ssl_ca='tests/server.crt',
                           ssl_key='tests/client.key',
                           ssl_cert='tests/client.crt')
        ).execute_prepared_statement(query)


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

    def _testApiDecryption(self, request_func, use_http=False, use_grpc=False):
        # one is set
        self.assertTrue(use_http or use_grpc)
        # two is not acceptable
        self.assertFalse(use_http and use_grpc)
        translator_port = 3456
        connector_port = 12345
        connector_port2 = connector_port+1
        client_id = "keypair1"
        data = get_random_data().encode('ascii')
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
        data = get_random_data().encode('ascii')
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

    def testHTTPApi(self):
        self._testApiDecryption(self.http_decrypt_request, use_http=True)


class TestAcraRotate(BaseTestCase):
    ZONE = True

    def checkSkip(self):
        return

    def fork_acra(self, popen_kwargs: dict=None, **acra_kwargs: dict):
        acra_kwargs['keystore_cache_size'] = -1  # no cache
        return super(TestAcraRotate, self).fork_acra(
            popen_kwargs, **acra_kwargs)

    def isSameZonePublicKeys(self, keys_folder, zone_data):
        """check is equal zone public key on filesystem and from zone_data"""
        for zone_id, public_key in zone_data.items():
            current_public = read_zone_public_key(zone_id, keys_folder)
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
                    data = get_random_data().encode('ascii')
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
                            self.isSameZonePublicKeys(
                                keys_folder, zones_before_rotate))
                    else:
                        # keys on filesystem must be changed
                        self.assertFalse(
                            self.isSameZonePublicKeys(
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
                            zone_private_key_path = '{}/{}_zone'.format(
                                keys_folder, zone_id)
                            with open(zone_private_key_path, 'rb') as f:
                                zone_private = decrypt_private_key(
                                    f.read(), zone_id.encode("ascii"),
                                    b64decode(get_master_key()))
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
                output[id] = b64encode(read_zone_public_key(id, keys_folder))
            return output

        rotate_test_table = sa.Table(
            'rotate_test',
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
                data = get_random_data()
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
                sql_update = "update rotate_test set data=? where id=?;"
            elif TEST_POSTGRESQL:
                sql_update = "update rotate_test set data=$1 where id=$2;"
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
                    '--sql_select=select id, zone_id, data from rotate_test order by id;',
                    '--sql_update={}'.format(sql_update)
                ]
            )
            if dry_run:
                self.assertTrue(
                    self.isSameZonePublicKeys(KEYS_FOLDER.name, zone_map))
            else:
                self.assertFalse(
                    self.isSameZonePublicKeys(KEYS_FOLDER.name, zone_map))

            result = self.engine1.execute(sa.select([rotate_test_table]))
            self.check_decrypted_data(result)
            result = self.engine_raw.execute(sa.select([rotate_test_table]))
            self.check_rotation(result, data_before_rotate, dry_run)

            # chose any id to operate with specific row
            if TEST_MYSQL:
                sql_update = "update rotate_test set data=? where id={};"
            elif TEST_POSTGRESQL:
                sql_update = "update rotate_test set data=$1 where id={};"
            else:
                self.fail("unsupported settings of tested db")
            some_id = list(data_before_rotate.keys())[0]
            sql_update = sql_update.format(some_id)


            zone_map = load_zones_from_folder(KEYS_FOLDER.name, zone_ids)
            # rotate with select without extra arg
            subprocess.check_output(
                default_args + [
                    '--sql_select=select zone_id, data from rotate_test where id={};'.format(some_id),
                    '--sql_update={}'.format(sql_update)
                 ]
            )

            if dry_run:
                self.assertTrue(
                    self.isSameZonePublicKeys(KEYS_FOLDER.name, zone_map))
            else:
                self.assertFalse(
                    self.isSameZonePublicKeys(KEYS_FOLDER.name, zone_map))

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


class TestPrometheusMetrics(AcraTranslatorMixin, BaseTestCase):
    LOG_METRICS = True

    def checkSkip(self):
        return

    def checkMetrics(self, url, labels=None):
        """
        check that output of prometheus exporter contains all labels
        """
        labels = labels if labels else []
        response = requests.get(url)
        self.assertEqual(response.status_code, http.HTTPStatus.OK)
        for label in labels:
            self.assertIn(label, response.text)

    def testAcraServer(self):
        # run some queries to set some values for counters
        HexFormatTest.testConnectorRead(self)
        labels = [
            'acraserver_connections_total',
            'acraserver_connections_processing_seconds_bucket',
            'acraserver_response_processing_seconds_bucket',
            'acraserver_request_processing_seconds_bucket',
            'acra_acrastruct_decryptions_total',
        ]
        self.checkMetrics('http://127.0.0.1:{}/metrics'.format(
            self.ACRASERVER_PROMETHEUS_PORT), labels)

    def testAcraConnector(self):
        # connector should has some values in counter after connections checks
        # on setUp
        labels = [
            'acraconnector_connections_total',
            'acraconnector_connections_processing_seconds_bucket',
        ]
        self.checkMetrics('http://127.0.0.1:{}/metrics'.format(
            self.get_connector_prometheus_port(self.CONNECTOR_PORT_1)), labels)

    def testAcraTranslator(self):
        labels = [
            'acratranslator_connections_total',
            'acratranslator_connections_processing_seconds_bucket',
            'translator_request_processing_seconds_bucket',
        ]
        translator_port = 3456
        metrics_port = translator_port+1
        connector_port = 8000
        data = get_random_data().encode('ascii')
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
    encryptor_table = sa.Table('test_transparent_encryption', metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('specified_client_id',
                  sa.LargeBinary(length=COLUMN_DATA_SIZE)),
        sa.Column('default_client_id',
                  sa.LargeBinary(length=COLUMN_DATA_SIZE)),

        sa.Column('zone_id', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
        sa.Column('raw_data', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
        sa.Column('nullable', sa.Text, nullable=True),
    )

    def checkSkip(self):
        return

    def setUp(self):
        prepare_encryptor_config(zones[0][ZONE_ID])
        super(TestTransparentEncryption, self).setUp()

    def tearDown(self):
        self.engine_raw.execute(self.encryptor_table.delete())
        super(TestTransparentEncryption, self).tearDown()

    def fork_acra(self, popen_kwargs: dict=None, **acra_kwargs: dict):
        acra_kwargs['encryptor_config_file'] = ENCRYPTOR_TEST_CONFIG
        return super(TestTransparentEncryption, self).fork_acra(
            popen_kwargs, **acra_kwargs)

    def get_context_data(self):
        context = {}
        context['id'] = get_random_id()
        context['default_client_id'] = get_random_data().encode('ascii')
        context['zone_id'] = get_random_data().encode('ascii')
        context['specified_client_id'] = get_random_data().encode('ascii')
        context['raw_data'] = get_random_data().encode('ascii')
        context['zone'] = zones[0]
        return context

    def checkDefaultIdEncryption(self, id, default_client_id, specified_client_id,
                                 zone_id, zone, raw_data):
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

    def checkSpecifiedIdEncryption(self, id, default_client_id, specified_client_id,
                                 zone_id, zone, raw_data):
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

    def insert_row(self, context):
        # send through acra-connector that authenticates as client_id=keypair2
        self.engine2.execute(
            self.encryptor_table.insert(),
            {'id': context['id'],
             'default_client_id': context['default_client_id'],
             'specified_client_id': context['specified_client_id'],
             'raw_data': context['raw_data'],
             'zone_id': context['zone_id']})

    def check_all_decryptions(self, **context):
        self.checkDefaultIdEncryption(**context)
        self.checkSpecifiedIdEncryption(**context)

    def testEncryptedInsert(self):
        context = self.get_context_data()
        self.insert_row(context)
        self.check_all_decryptions(**context)

        encrypted_data = self.fetch_raw_data(context)

        # update with acrastructs and AcraServer should not
        # re-encrypt
        data_fields = ['default_client_id', 'specified_client_id', 'zone_id',
                       'raw_data']
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
                       self.encryptor_table.c.nullable])
            .where(self.encryptor_table.c.id == context['id']))
        data = result.fetchone()
        return data

    def insert_row_with_quotes(self, context):
        if TEST_MYSQL:
            quote_char = '`'
        else:
            quote_char = '"'

        wrap_identifier = lambda x: '{}{}{}'.format(quote_char, x, quote_char)
        columns = ["id", "default_client_id", "specified_client_id", "raw_data", "zone_id"]
        # create list of wrapped columns: "col1", "col2", "col3" or `col1`, `col2`, `col3`
        table_columns = ', '.join([wrap_identifier(i) for i in columns])
        # use %s as placeholder which will be used by engine
        column_placeholders = ', '.join(['%s' for _ in range(len(columns))])

        # add double quotes around table name and columns
        # use raw sql to avoid processing sql by sqlalchemy
        query = (
            "insert into {} "
            "({}) "
            "values ({})"
            ).format(
            wrap_identifier(self.encryptor_table.name),
            table_columns,
            column_placeholders)
        with self.engine2.connect() as connection:
            connection.execute(
                query,
                (context['id'], context['default_client_id'],
                 context['specified_client_id'], context['raw_data'],
                 context['zone_id']))

    def test_quoted_identifiers(self):
        context = self.get_context_data()
        self.insert_row_with_quotes(context)
        self.check_all_decryptions(**context)


class TestTransparentEncryptionWithZone(TestTransparentEncryption):
    ZONE = True

    def checkZoneIdEncryption(self, zone, id, default_client_id,
                              specified_client_id, zone_id, raw_data):
        result = self.engine1.execute(
            sa.select([self.encryptor_table.c.default_client_id,
                       self.encryptor_table.c.specified_client_id,
                       sa.cast(zone[ZONE_ID].encode('ascii'), BYTEA),
                       self.encryptor_table.c.zone_id,
                       self.encryptor_table.c.raw_data,
                       self.encryptor_table.c.nullable])
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


if __name__ == '__main__':
    unittest.main()