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
import socket
import json
import time
import os
import random
import string
import subprocess
import traceback
import unittest
import stat
import collections
from base64 import b64decode, b64encode
from tempfile import NamedTemporaryFile
from urllib.request import urlopen
from urllib.parse import urlparse

import psycopg2
import pymysql
import sqlalchemy as sa
from sqlalchemy.exc import DatabaseError
from sqlalchemy.dialects.postgresql import BYTEA

import sys
# add to path our wrapper until not published to PYPI
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'wrappers/python'))

from acrawriter import create_acrastruct

DATA_MAX_SIZE = 10000
# 200 is overhead of encryption (chosen manually)
COLUMN_DATA_SIZE = DATA_MAX_SIZE + 200
metadata = sa.MetaData()
test_table = sa.Table('test', metadata,
    sa.Column('id', sa.Integer, primary_key=True),
    sa.Column('data', sa.LargeBinary(length=COLUMN_DATA_SIZE)),
    sa.Column('raw_data', sa.String(length=COLUMN_DATA_SIZE)),
)

rollback_output_table = sa.Table('acra_rollback_output', metadata,
    sa.Column('data', sa.LargeBinary),
)

zones = []
poison_record = None
POISON_KEY_PATH = '.poison_key/poison_key'

SETUP_SQL_COMMAND_TIMEOUT = 0.1
FORK_FAIL_SLEEP = 0.1
CONNECTION_FAIL_SLEEP = 0.1
SOCKET_CONNECT_TIMEOUT = 10
KILL_WAIT_TIMEOUT = 10

TEST_WITH_TLS = os.environ.get('TEST_TLS', 'on').lower() == 'on'

PG_UNIX_HOST = '/tmp'

DB_USER = os.environ.get('TEST_DB_USER', 'postgres')
DB_USER_PASSWORD = os.environ.get('TEST_DB_USER_PASSWORD', 'postgres')
SSLMODE = os.environ.get('TEST_SSL_MODE', 'allow')
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
        "options": "-c statement_timeout=1000", 'sslmode': SSLMODE}


def stop_process(process):
    """stop process if exists by terminate and kill at end to be sure
    that process will not alive as zombi-process"""
    if not isinstance(process, collections.Iterable):
        process = [process]
    # send signal to each. they can handle it asynchronously
    for p in process:
        try:
            p.terminate()
        except:
            traceback.print_exc()
    # synchronously wait termination or kill
    for p in process:
        try:
            p.wait(timeout=KILL_WAIT_TIMEOUT)
        except:
            traceback.print_exc()
        try:
            p.kill()
        except:
            traceback.print_exc()


def get_connect_args(port=5432, sslmode=None, **kwargs):
    args = connect_args.copy()
    args['port'] = port
    if TEST_POSTGRESQL:
        args['sslmode'] = sslmode if sslmode else SSLMODE
    args.update(kwargs)
    return args

def get_poison_record():
    """generate one poison record for speed up tests and don't create subprocess
    for new records"""
    global poison_record
    if not poison_record:
        poison_record = b64decode(subprocess.check_output(
            ['./acra_genpoisonrecord'], timeout=PROCESS_CALL_TIMEOUT))
    return poison_record


def create_client_keypair(name, only_server=False, only_client=False):
    args = ['./acra_genkeys', '-client_id={}'.format(name)]
    if only_server:
        args.append('-acraserver')
    elif only_client:
        args.append('-acraproxy')
    return subprocess.call(args, cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT)


def wait_connection(port, count=10, sleep=0.1):
    """try connect to 127.0.0.1:port and close connection
    if can't then sleep on and try again (<count> times)
    if <count> times is failed than raise Exception
    """
    while count:
        try:
            connection = socket.create_connection(('127.0.0.1', port),
                                                  timeout=10)
            connection.close()
            return
        except ConnectionRefusedError:
            pass
        count -= 1
        time.sleep(sleep)
    raise Exception("can't wait connection")


def wait_unix_socket(socket_path, count=10, sleep=0.1):
    while count:
        try:
            connection = socket.socket(socket.AF_UNIX)
            connection.connect(socket_path)
            return
        except:
            pass
        finally:
            connection.close()
        count -= 1
        time.sleep(sleep)
    raise Exception("can't wait connection")

def get_unix_connection_string(port, dbname):
    if TEST_MYSQL:
        return get_postgresql_tcp_connection_string(port, dbname)
    else:
        return get_postgresql_unix_connection_string(port, dbname)

def get_postgresql_unix_connection_string(port, dbname):
    return '{}:///{}?host={}'.format(DB_DRIVER, dbname, PG_UNIX_HOST)

def get_postgresql_tcp_connection_string(port, dbname):
    return '{}://127.0.0.1:{}/{}'.format(DB_DRIVER, port, dbname)

def get_acra_unix_connection_string(port):
    return "unix://{}".format("{}/unix_socket_{}".format(PG_UNIX_HOST, port))

def get_proxy_connection_string(port):
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

BINARIES = ['acraproxy', 'acraserver', 'acra_addzone', 'acra_genkeys',
            'acra_genpoisonrecord', 'acra_rollback']

def clean_binaries():
    for i in BINARIES:
        try:
            os.remove(i)
        except:
            pass

PROCESS_CALL_TIMEOUT = 120

def setUpModule():
    global zones
    clean_binaries()
    # build binaries
    builds = [
        ['go', 'build', 'github.com/cossacklabs/acra/cmd/{}'.format(binary)]
        for binary in BINARIES
    ]
    for build in builds:
        # try to build 3 times with timeout
        build_count = 3
        for i in range(build_count):
            try:
                assert subprocess.call(build, cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT) == 0
                break
            except (AssertionError, subprocess.TimeoutExpired):
                if i == (build_count-1):
                    raise
                continue

    # first keypair for using without zones
    assert create_client_keypair('keypair1') == 0
    assert create_client_keypair('keypair2') == 0
    # add two zones
    zones.append(json.loads(subprocess.check_output(
        ['./acra_addzone'], cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT).decode('utf-8')))
    zones.append(json.loads(subprocess.check_output(
        ['./acra_addzone'], cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT).decode('utf-8')))
    socket.setdefaulttimeout(SOCKET_CONNECT_TIMEOUT)

def tearDownModule():
    import shutil
    shutil.rmtree('.acrakeys')
    clean_binaries()

class ProcessStub(object):
    pid = 'stub'
    def kill(self, *args, **kwargs):
        pass
    def wait(self, *args, **kwargs):
        pass
    def terminate(self, *args, **kwargs):
        pass


class BaseTestCase(unittest.TestCase):
    DB_HOST = os.environ.get('TEST_DB_HOST', '127.0.0.1')
    DB_NAME = os.environ.get('TEST_DB_NAME', 'postgres')
    DB_PORT = os.environ.get('TEST_DB_PORT', 5432)

    PROXY_PORT_1 = int(os.environ.get('TEST_PROXY_PORT', 9595))
    PROXY_PORT_2 = PROXY_PORT_1 + 200
    PROXY_COMMAND_PORT_1 = int(os.environ.get('TEST_PROXY_COMMAND_PORT', 9696))
    # for debugging with manually runned acra server
    EXTERNAL_ACRA = False
    ACRA_PORT = int(os.environ.get('TEST_ACRA_PORT', 10003))
    ACRA_BYTEA = 'hex_bytea'
    DB_BYTEA = 'hex'
    WHOLECELL_MODE = False
    ZONE = False
    DEBUG_LOG = True
    TEST_DATA_LOG = False
    TLS_ON = False
    maxDiff = None
    # hack to simplify handling errors on forks and don't check `if hasattr(self, 'proxy_1')`
    proxy_1 = ProcessStub()
    proxy_2 = ProcessStub()
    acra = ProcessStub()

    def checkSkip(self):
        if TEST_WITH_TLS:
            self.skipTest("running tests with TLS")

    def fork(self, func):
        process = func()
        count = 0
        while count <= 3:
            if process.poll() is None:
                return process
            count += 1
            time.sleep(FORK_FAIL_SLEEP)
        stop_process(process)
        self.fail("can't fork")

    def wait_acra_connection(self, *args, **kwargs):
        return wait_unix_socket(*args, **kwargs)

    def fork_proxy(self, proxy_port: int, acra_port: int, client_id: str, commands_port: int=None, zone_mode: bool=False, check_connection: bool=True):
        acra_connection = self.get_acra_connection_string(acra_port)
        acra_api_connection = self.get_acra_api_connection_string(acra_port)
        proxy_connection = self.get_proxy_connection_string(proxy_port)
        if zone_mode:
            # because standard library can send http requests only through tcp and cannot through unix socket
            proxy_api_connection = "tcp://127.0.0.1:{}".format(commands_port)
        else:
            # now it's no matter, so just +100
            proxy_api_connection = self.get_proxy_api_connection_string(commands_port if commands_port else proxy_port + 100)

        for path in [socket_path_from_connection_string(proxy_connection), socket_path_from_connection_string(proxy_api_connection)]:
            try:
                os.remove(path)
            except:
                pass
        args = [
            './acraproxy',
            '-acra_connection_string={}'.format(acra_connection),
            '-acra_api_connection_string={}'.format(acra_api_connection),
             '-client_id={}'.format(client_id),
            '-connection_string={}'.format(proxy_connection),
            '-connection_api_string={}'.format(proxy_api_connection),
            '-disable_user_check=true'
        ]
        if self.DEBUG_LOG:
            args.append('-v=true')
        if zone_mode:
            args.append('--zonemode=true')
        if self.TLS_ON:
            args.append('--tls')
            args.append('--tls_ca=tests/server.crt')
            args.append('--tls_key=tests/client.key')
            args.append('--tls_cert=tests/client.crt')
            args.append('--tls_sni=acraserver')
        process = self.fork(lambda: subprocess.Popen(args))
        if check_connection:
            try:
                if TEST_MYSQL:
                    wait_connection(proxy_port)
                else:
                    wait_unix_socket(socket_path_from_connection_string(proxy_connection))
            except:
                stop_process(process)
                raise
        return process

    def get_acra_connection_string(self, port=None):
        if not port:
            port = self.ACRA_PORT
        return get_acra_unix_connection_string(port)

    def get_acra_api_connection_string(self, port=None):
        if not port:
            port = self.ACRA_PORT
        return acra_api_connection_string(port)

    def get_proxy_connection_string(self, port=None):
        if not port:
            port = self.PROXY_PORT_1
        return get_proxy_connection_string(port)

    def get_proxy_api_connection_string(self, port=None):
        if not port:
            port = self.PROXY_COMMAND_PORT_1
        return get_proxy_connection_string(port)

    def _fork_acra(self, acra_kwargs, popen_kwargs):
        connection_string = self.get_acra_connection_string()
        api_connection_string = self.get_acra_api_connection_string()
        for path in [socket_path_from_connection_string(connection_string), socket_path_from_connection_string(api_connection_string)]:
            try:
                os.remove(path)
            except:
                pass

        args = {
            'db_host': self.DB_HOST,
            'db_port': self.DB_PORT,
            self.ACRA_BYTEA: 'true',
            'connection_string': connection_string,
            'connection_api_string': api_connection_string,
            'wholecell': 'true' if self.WHOLECELL_MODE else 'false',
            'injectedcell': 'false' if self.WHOLECELL_MODE else 'true',
            'd': 'true' if self.DEBUG_LOG else 'false',
            'zonemode': 'true' if self.ZONE else 'false',
            'disable_http_api': 'false' if self.ZONE else 'true',
        }
        if self.TLS_ON:
            args['tls'] = 'true'
            args['tls_key'] = 'tests/server.key'
            args['tls_cert'] = 'tests/server.crt'
            args['tls_ca'] = 'tests/server.crt'
            args['tls_sni'] = 'acraserver'
        if TEST_MYSQL:
            args['mysql'] = 'true'
            args['postgresql'] = 'false'
        args.update(acra_kwargs)
        if not popen_kwargs:
            popen_kwargs = {}
        cli_args = ['--{}={}'.format(k, v) for k, v in args.items()]

        process = self.fork(lambda: subprocess.Popen(['./acraserver'] + cli_args,
                                                     **popen_kwargs))
        try:
            self.wait_acra_connection(socket_path_from_connection_string(connection_string))
        except:
            stop_process(process)
            raise
        return process

    def fork_acra(self, popen_kwargs: dict=None, **acra_kwargs: dict):
        return self._fork_acra(acra_kwargs, popen_kwargs)

    def setUp(self):
        self.checkSkip()
        try:
            self.proxy_1 = self.fork_proxy(self.PROXY_PORT_1, self.ACRA_PORT, 'keypair1')
            self.proxy_2 = self.fork_proxy(self.PROXY_PORT_2, self.ACRA_PORT, 'keypair2')
            if not self.EXTERNAL_ACRA:
                self.acra = self.fork_acra()

            self.engine1 = sa.create_engine(
                get_unix_connection_string(self.PROXY_PORT_1, self.DB_NAME), connect_args=get_connect_args(port=self.PROXY_PORT_1))
            self.engine2 = sa.create_engine(
                get_unix_connection_string(
                    self.PROXY_PORT_2, self.DB_NAME), connect_args=get_connect_args(port=self.PROXY_PORT_2))
            self.engine_raw = sa.create_engine(
                '{}://{}:{}/{}'.format(DB_DRIVER, self.DB_HOST, self.DB_PORT, self.DB_NAME),
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
                            engine.execute(
                                "select 1;")
                        else:
                            engine.execute(
                                "UPDATE pg_settings SET setting = '{}' "
                                "WHERE name = 'bytea_output'".format(self.DB_BYTEA))
                        break
                    except Exception:
                        time.sleep(SETUP_SQL_COMMAND_TIMEOUT)
                        count += 1
                        if count == 3:
                            raise
        except:
            self.tearDown()
            raise

    def tearDown(self):
        processes = [getattr(self, 'proxy_1', ProcessStub()),
                     getattr(self, 'proxy_2', ProcessStub()),
                     getattr(self, 'acra', ProcessStub())]
        stop_process(processes)
        try:
            self.engine_raw.execute('delete from test;')
        except:
            pass
        for engine in getattr(self, 'engines', []):
            engine.dispose()

    def get_random_data(self):
        size = random.randint(100, DATA_MAX_SIZE)
        return ''.join(random.choice(string.ascii_letters)
                       for _ in range(size))

    def get_random_id(self):
        return random.randint(1, 100000)

    def log(self, acra_key_name, data, expected):
        """this function for printing data which used in test and for
        reproducing error with them if any error detected"""
        if not self.TEST_DATA_LOG:
            return
        with open('.acrakeys/{}_zone'.format(zones[0]['id']), 'rb') as f:
            zone_private = f.read()
        with open('.acrakeys/{}'.format(acra_key_name), 'rb') as f:
            private_key = f.read()
        with open('.acrakeys/{}.pub'.format(acra_key_name), 'rb') as f:
            public_key = f.read()
        print(json.dumps(
            {
                'private_key': b64encode(private_key).decode('ascii'),
                'public_key': b64encode(public_key).decode('ascii'),
                'data': b64encode(data).decode('ascii'),
                'expected': b64encode(expected).decode('ascii'),
                'zone_private': b64encode(zone_private).decode('ascii'),
                'zone_public': zones[0]['public_key'],
                'zone_id': zones[0]['id'],
                'poison_record': b64encode(get_poison_record()).decode('ascii'),
            }
        ))


class HexFormatTest(BaseTestCase):

    def testProxyRead(self):
        """test decrypting with correct acraproxy and not decrypting with
        incorrect acraproxy or using direct connection to db"""
        keyname = 'keypair1_storage'
        with open('.acrakeys/{}.pub'.format(keyname), 'rb') as f:
            server_public1 = f.read()
        data = self.get_random_data()
        acra_struct = create_acrastruct(
            data.encode('ascii'), server_public1)
        row_id = self.get_random_id()

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
        with open('.acrakeys/{}.pub'.format(keyname), 'rb') as f:
            server_public1 = f.read()
        incorrect_data = self.get_random_data()
        correct_data = self.get_random_data()
        fake_offset = (3+45+84) - 4
        fake_acra_struct = create_acrastruct(
            incorrect_data.encode('ascii'), server_public1)[:fake_offset]
        inner_acra_struct = create_acrastruct(
            correct_data.encode('ascii'), server_public1)
        data = fake_acra_struct + inner_acra_struct
        row_id = self.get_random_id()

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
        except UnicodeDecodeError:
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


class ZoneHexFormatTest(BaseTestCase):
    ZONE = True

    def testProxyRead(self):
        data = self.get_random_data()
        zone_public = b64decode(zones[0]['public_key'].encode('ascii'))
        acra_struct = create_acrastruct(
            data.encode('ascii'), zone_public,
            context=zones[0]['id'].encode('ascii'))
        row_id = self.get_random_id()
        self.log(zones[0]['id']+'_zone', acra_struct, data.encode('ascii'))
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': acra_struct, 'raw_data': data})

        zone = zones[0]['id'].encode('ascii')
        result = self.engine1.execute(
            sa.select([sa.cast(zone, BYTEA), test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertEqual(row['data'], row['raw_data'].encode('utf-8'))

        # without zone in another proxy, in the same proxy and without any proxy
        for engine in self.engines:
            result = engine.execute(
                sa.select([test_table])
                .where(test_table.c.id == row_id))
            row = result.fetchone()
            self.assertNotEqual(row['data'].decode('ascii', errors='ignore'), row['raw_data'])

    def testReadAcrastructInAcrastruct(self):
        incorrect_data = self.get_random_data()
        correct_data = self.get_random_data()
        zone_public = b64decode(zones[0]['public_key'].encode('ascii'))
        fake_offset = (3+45+84) - 1
        fake_acra_struct = create_acrastruct(
            incorrect_data.encode('ascii'), zone_public, context=zones[0]['id'].encode('ascii'))[:fake_offset]
        inner_acra_struct = create_acrastruct(
            correct_data.encode('ascii'), zone_public, context=zones[0]['id'].encode('ascii'))
        data = fake_acra_struct + inner_acra_struct
        self.log(zones[0]['id']+'_zone', data, fake_acra_struct+correct_data.encode('ascii'))
        row_id = self.get_random_id()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': data, 'raw_data': correct_data})
        zone = zones[0]['id'].encode('ascii')
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
    ACRA_BYTEA = 'escape_bytea'
    DB_BYTEA = 'escape'


class ZoneEscapeFormatTest(ZoneHexFormatTest):
    ACRA_BYTEA = 'escape_bytea'
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
    def setUp(self):
        self.checkSkip()
        try:
            self.proxy_1 = self.fork_proxy(
                self.PROXY_PORT_1, self.ACRA_PORT, 'keypair1')
            if not self.EXTERNAL_ACRA:
                self.acra = self.fork_acra()
        except:
            self.tearDown()
            raise

    def get_connection(self):
        if TEST_MYSQL:
            return pymysql.connect(**get_connect_args(port=self.PROXY_PORT_1))
        else:
            return psycopg2.connect(host=PG_UNIX_HOST, **get_connect_args(port=self.PROXY_PORT_1))

    def tearDown(self):
        procs = []
        if hasattr(self, 'proxy_1'):
            procs.append(self.proxy_1)
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
            cursor = connection.cursor()
            cursor.execute(query)
            return int(cursor.fetchone()[1])

        else:
            cursor = connection.cursor()
            cursor.execute('select setting from pg_settings where name=\'max_connections\';')
            pg_max_connections = int(cursor.fetchone()[0])
            cursor.execute('select rolconnlimit from pg_roles where rolname = current_user;')
            pg_rolconnlimit = int(cursor.fetchone()[0])
            cursor.close()
            if created_connection:
                connection.close()
            if pg_rolconnlimit <= 0:
                return pg_max_connections
            return min(pg_max_connections, pg_rolconnlimit)

    def check_count(self, cursor, expected):
        # give a time to close connections via postgresql
        # because performance where tests will run not always constant,
        # we wait try_count times. in best case it will not need to sleep
        try_count = 5
        for i in range(try_count):
            try:
                self.assertEqual(self.getActiveConnectionCount(cursor), expected)
            except (AssertionError):
                if i == (try_count - 1):
                    raise
                # some wait for closing. chosen manually
                time.sleep(1)

    def checkConnectionLimit(self, connection_limit):
        connections = []
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
                'FATAL:  sorry, too many clients already']
            for message in correct_messages:
                if message in exception.args[0]:
                    is_correct_exception_message = True
                    break

        self.assertIsInstance(exception, exception_type)
        self.assertTrue(is_correct_exception_message)
        return connections


    def testClosingPostgreslConnections(self):
        connection = self.get_connection()

        connection.autocommit = True
        cursor = connection.cursor()
        current_connection_count = self.getActiveConnectionCount(cursor)

        connection2 = self.get_connection()
        self.assertEqual(self.getActiveConnectionCount(cursor),
                         current_connection_count+1)
        connection_limit = self.getConnectionLimit(connection)
        connections = [connection2]

        created_connections = self.checkConnectionLimit(connection_limit)

        for conn in connections + created_connections:
            conn.close()

        self.check_count(cursor, current_connection_count)

        # try create new connection
        connection2 = self.get_connection()
        self.check_count(cursor, current_connection_count + 1)

        connection2.close()
        self.check_count(cursor, current_connection_count)
        cursor.close()
        connection.close()




class TestKeyNonExistence(BaseTestCase):
    # 0.05 empirical selected
    PROXY_STARTUP_DELAY = 0.05

    def setUp(self):
        self.checkSkip()
        try:
            if not self.EXTERNAL_ACRA:
                self.acra = self.fork_acra()
            self.dsn = get_connect_args(port=self.PROXY_PORT_1, host=PG_UNIX_HOST)
        except:
            self.tearDown()
            raise

    def tearDown(self):
        if hasattr(self, 'acra'):
            stop_process(self.acra)

    def delete_key(self, filename):
        os.remove('.acrakeys{sep}{name}'.format(sep=os.path.sep, name=filename))

    def test_without_acraproxy_public(self):
        """acraserver without acraproxy public key should drop connection
        from acraproxy than acraproxy should drop connection from psycopg2"""
        keyname = 'without_acraproxy_public_test'
        result = create_client_keypair(keyname)
        if result != 0:
            self.fail("can't create keypairs")
        self.delete_key(keyname + '.pub')
        connection = None
        try:
            self.proxy = self.fork_proxy(
                self.PROXY_PORT_1, self.ACRA_PORT, keyname)
            self.assertIsNone(self.proxy.poll())
            with self.assertRaises(psycopg2.OperationalError) as exc:
                connection = psycopg2.connect(**self.dsn)

        finally:
            stop_process(self.proxy)
            if connection:
                connection.close()

    def test_without_acraproxy_private(self):
        """acraproxy shouldn't start without private key"""
        keyname = 'without_acraproxy_private_test'
        result = create_client_keypair(keyname)
        if result != 0:
            self.fail("can't create keypairs")
        self.delete_key(keyname)
        try:
            self.proxy = self.fork_proxy(
                self.PROXY_PORT_1, self.ACRA_PORT, keyname,
                check_connection=False)
            # time for start up proxy and validation file existence.
            time.sleep(self.PROXY_STARTUP_DELAY)
            self.assertEqual(self.proxy.poll(), 1)
        finally:
            try:
                stop_process(self.proxy)
            except OSError:  # pid not found
                pass

    def test_without_acraserver_private(self):
        """acraserver without private key should drop connection
        from acraproxy than acraproxy should drop connection from psycopg2"""
        keyname = 'without_acraserver_private_test'
        result = create_client_keypair(keyname)
        if result != 0:
            self.fail("can't create keypairs")
        self.delete_key(keyname + '_server')
        connection = None
        try:
            self.proxy = self.fork_proxy(
                self.PROXY_PORT_1, self.ACRA_PORT, keyname)
            self.assertIsNone(self.proxy.poll())
            with self.assertRaises(psycopg2.OperationalError):
                connection = psycopg2.connect(**self.dsn)
        finally:
            stop_process(self.proxy)
            if connection:
                connection.close()

    def test_without_acraserver_public(self):
        """acraproxy shouldn't start without acraserver public key"""
        keyname = 'without_acraserver_public_test'
        result = create_client_keypair(keyname)
        if result != 0:
            self.fail("can't create keypairs")
        self.delete_key(keyname + '_server.pub')
        try:
            self.proxy = self.fork_proxy(
                self.PROXY_PORT_1, self.ACRA_PORT, keyname,
                check_connection=False)
            # time for start up proxy and validation file existence.
            time.sleep(self.PROXY_STARTUP_DELAY)
            self.assertEqual(self.proxy.poll(), 1)
        finally:
            try:
                stop_process(self.proxy)
            except OSError:  # pid not found
                pass


class BasePoisonRecordTest(BaseTestCase):
    SHUTDOWN = True

    def setUp(self):
        super(BasePoisonRecordTest, self).setUp()
        self.log(POISON_KEY_PATH, get_poison_record(),
                 b'no matter because poison record')

    def fork_acra(self, popen_kwargs: dict=None, **acra_kwargs: dict):
        args = {
            'poisonshutdown': 'true' if self.SHUTDOWN else 'false',
        }

        if hasattr(self, 'poisonscript'):
            args['poisonscript'] = self.poisonscript

        return super(BasePoisonRecordTest, self).fork_acra(popen_kwargs, **args)


class TestPoisonRecordShutdown(BasePoisonRecordTest):
    SHUTDOWN = True

    def testShutdown(self):
        row_id = self.get_random_id()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': get_poison_record(), 'raw_data': 'poison_record'})
        with self.assertRaises(DatabaseError):
            self.engine1.execute(
                sa.select([test_table])
                .where(test_table.c.id == row_id))

    def testShutdown2(self):
        """check working poison record callback on full select"""
        row_id = self.get_random_id()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': get_poison_record(), 'raw_data': 'poison_record'})
        with self.assertRaises(DatabaseError):
            self.engine1.execute(
                sa.select([test_table]))

    def testShutdown3(self):
        """check working poison record callback on full select inside another data"""
        row_id = self.get_random_id()
        data = os.urandom(100) + get_poison_record() + os.urandom(100)
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': data, 'raw_data': 'poison_record'})
        with self.assertRaises(DatabaseError):
            self.engine1.execute(
                sa.select([test_table]))


class TestShutdownPoisonRecordWithZone(TestPoisonRecordShutdown):
    ZONE = True
    WHOLECELL_MODE = False
    SHUTDOWN = True

    def testShutdown(self):
        """check callback with select by id and zone"""
        row_id = self.get_random_id()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': get_poison_record(), 'raw_data': 'poison_record'})
        with self.assertRaises(DatabaseError):
            zone = zones[0]['id'].encode('ascii')
            result = self.engine1.execute(
                sa.select([sa.cast(zone, BYTEA), test_table])
                    .where(test_table.c.id == row_id))
            print(result.fetchall())

    def testShutdown2(self):
        """check callback with select by id and without zone"""
        row_id = self.get_random_id()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': get_poison_record(), 'raw_data': 'poison_record'})
        with self.assertRaises(DatabaseError):
            result = self.engine1.execute(
                sa.select([test_table])
                    .where(test_table.c.id == row_id))
            print(result.fetchall())

    def testShutdown3(self):
        """check working poison record callback on full select"""
        row_id = self.get_random_id()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': get_poison_record(), 'raw_data': 'poison_record'})
        with self.assertRaises(DatabaseError):
            result = self.engine1.execute(
                sa.select([test_table]))
            print(result.fetchall())

    def testShutdown4(self):
        """check working poison record callback on full select inside another data"""
        row_id = self.get_random_id()
        data = os.urandom(100) + get_poison_record() + os.urandom(100)
        self.log(POISON_KEY_PATH, data, data)
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': data, 'raw_data': 'poison_record'})

        with self.assertRaises(DatabaseError):
            result = self.engine1.execute(
                sa.select([test_table]))
            # here shouldn't execute code and it's debug info
            print(result.fetchall())


class TestPoisonRecordWholeCell(TestPoisonRecordShutdown):
    WHOLECELL_MODE = True
    SHUTDOWN = True

    def testShutdown3(self):
        return


class TestShutdownPoisonRecordWithZoneWholeCell(TestShutdownPoisonRecordWithZone):
    WHOLECELL_MODE = True
    SHUTDOWN = True

    def testShutdown4(self):
        return


class AcraCatchLogsMixin(object):
    def fork_acra(self, popen_kwargs: dict=None, **acra_kwargs: dict):
        popen_args = {
            'stdout': subprocess.PIPE, 'stderr': subprocess.STDOUT,
            'close_fds': True
        }
        return super(AcraCatchLogsMixin, self).fork_acra(
            popen_args, **acra_kwargs
        )


class TestNoCheckPoisonRecord(AcraCatchLogsMixin, BasePoisonRecordTest):
    WHOLECELL_MODE = False
    SHUTDOWN = False
    DEBUG_LOG = True

    def testNoDetect(self):
        row_id = self.get_random_id()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': get_poison_record(), 'raw_data': 'poison_record'})
        result = self.engine1.execute(test_table.select())
        result.fetchall()
        # super() tearDown without killink acra
        super(TestNoCheckPoisonRecord, self).tearDown()

        try:
            out, er_ = self.acra.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        self.assertNotIn(b'Debug: check poison records', out)


class TestNoCheckPoisonRecordWithZone(TestNoCheckPoisonRecord):
    ZONE = True


class TestNoCheckPoisonRecordWholeCell(TestNoCheckPoisonRecord):
    WHOLECELL_MODE = True


class TestNoCheckPoisonRecordWithZoneWholeCell(TestNoCheckPoisonRecordWithZone):
    WHOLECELL_MODE = True


class TestCheckLogPoisonRecord(AcraCatchLogsMixin, BasePoisonRecordTest):
    SHUTDOWN = True
    DEBUG_LOG = True

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
        row_id = self.get_random_id()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': get_poison_record(), 'raw_data': 'poison_record'})
        try:
            with self.assertRaises(DatabaseError):
                self.engine1.execute(test_table.select())
        finally:
            # super() tearDown without killink acra
            super(TestCheckLogPoisonRecord, self).tearDown()

        try:
            out, _ = self.acra.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        self.assertIn(b'check poison records', out)


class TestKeyStorageClearing(BaseTestCase):
    def setUp(self):
        self.checkSkip()
        try:
            self.key_name = 'clearing_keypair'
            create_client_keypair(self.key_name)
            self.proxy_1 = self.fork_proxy(
                self.PROXY_PORT_1, self.ACRA_PORT, self.key_name, self.PROXY_COMMAND_PORT_1,
                zone_mode=True)
            if not self.EXTERNAL_ACRA:
                self.acra = self.fork_acra(
                    zonemode='true', disable_http_api='false')

            self.engine1 = sa.create_engine(
                get_unix_connection_string(self.PROXY_PORT_1, self.DB_NAME),
                connect_args=get_connect_args(port=self.PROXY_PORT_1))

            self.engine_raw = sa.create_engine(
                '{}://{}:{}/{}'.format(DB_DRIVER, self.DB_HOST, self.DB_PORT, self.DB_NAME),
                connect_args=connect_args)

            self.engines = [self.engine1, self.engine_raw]

            metadata.create_all(self.engine_raw)
            self.engine_raw.execute('delete from test;')
        except:
            self.tearDown()
            raise

    def tearDown(self):
        processes = []
        if hasattr(self, 'proxy_1'):
            processes.append(self.proxy_1)
        if not self.EXTERNAL_ACRA and hasattr(self, 'acra'):
            processes.append(self.acra)

        stop_process(processes)

        try:
            self.engine_raw.execute('delete from test;')
        except:
            pass

        for engine in self.engines:
            engine.dispose()

    def test_clearing(self):
        # execute any query for loading key by acra
        result = self.engine1.execute(sa.select([1]).limit(1))
        result.fetchone()
        with urlopen('http://127.0.0.1:{}/resetKeyStorage'.format(self.PROXY_COMMAND_PORT_1)) as response:
            self.assertEqual(response.status, 200)
        # delete key for excluding reloading from FS
        os.remove('.acrakeys/{}.pub'.format(self.key_name))
        # close connections in pool and reconnect to reinitiate secure session
        self.engine1.dispose()
        # acraserver should close connection when doesn't find key
        with self.assertRaises(DatabaseError):
            result = self.engine1.execute(test_table.select().limit(1))


class TestAcraRollback(BaseTestCase):
    DATA_COUNT = 5

    def setUp(self):
        self.checkSkip()
        self.engine_raw = sa.create_engine(
            '{}://{}:{}/{}'.format(DB_DRIVER, self.DB_HOST, self.DB_PORT,
                                   self.DB_NAME),
            connect_args=connect_args)

        self.output_filename = 'acra_rollback_output.txt'
        rollback_output_table.create(self.engine_raw, checkfirst=True)
        if self.TLS_ON:
            self.sslmode='require'
        else:
            self.sslmode='disable'
        if TEST_MYSQL:
            # https://github.com/go-sql-driver/mysql/
            connection_string = "{user}:{password}@tcp({host}:{port})/{dbname}".format(
                user=DB_USER, password=DB_USER_PASSWORD, dbname=self.DB_NAME,
                port=self.DB_PORT, host=self.DB_HOST
            )

            # https://github.com/ziutek/mymysql
            # connection_string = "tcp:{host}:{port}*{dbname}/{user}/{password}".format(
            #     user=DB_USER, password=DB_USER_PASSWORD, dbname=self.DB_NAME,
            #     port=self.DB_PORT, host=self.DB_HOST
            # )
        else:
            connection_string = (
                'dbname={dbname} user={user} '
                'sslmode={sslmode} password={password} host={host} '
                'port={port}').format(
                     sslmode=self.sslmode, dbname=self.DB_NAME,
                     user=DB_USER, port=self.DB_PORT,
                     password=DB_USER_PASSWORD, host=self.DB_HOST
            )

        if TEST_MYSQL:
            self.placeholder = "?"
            DB_ARGS = ['--mysql']
        else:
            self.placeholder = "$1"
            DB_ARGS = ['--postgresql']

        self.default_rollback_args = [
            '--client_id=keypair1',
             '--connection_string={}'.format(connection_string),
             '--output_file={}'.format(self.output_filename),
        ] + DB_ARGS

    def tearDown(self):
        try:
            self.engine_raw.execute(rollback_output_table.delete())
            self.engine_raw.execute(test_table.delete())
        except Exception as exc:
            print(exc)
        self.engine_raw.dispose()
        if os.path.exists(self.output_filename):
            os.remove(self.output_filename)

    def run_rollback(self, extra_args):
        args = ['./acra_rollback'] + self.default_rollback_args + extra_args
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
        with open('.acrakeys/{}.pub'.format(keyname), 'rb') as f:
            server_public1 = f.read()

        rows = []
        for _ in range(self.DATA_COUNT):
            data = self.get_random_data()
            row = {
                'raw_data': data,
                'data': create_acrastruct(data.encode('ascii'), server_public1),
                'id': self.get_random_id()
            }
            rows.append(row)
        self.engine_raw.execute(test_table.insert(), rows)
        args = [
            '--select=select data from {};'.format(test_table.name),
            '--insert=insert into {} values({});'.format(
                 rollback_output_table.name, self.placeholder)
        ]
        self.run_rollback(args)

        # execute file
        with open(self.output_filename, 'r') as f:
            for line in f:
                self.engine_raw.execute(line)

        source_data = set([i['raw_data'].encode('ascii') for i in rows])
        result = self.engine_raw.execute(rollback_output_table.select())
        result = result.fetchall()
        for data in result:
            self.assertIn(data[0], source_data)

    def test_with_zone_to_file(self):
        zone_public = b64decode(zones[0]['public_key'].encode('ascii'))
        rows = []
        for _ in range(self.DATA_COUNT):
            data = self.get_random_data()
            row = {
                'raw_data': data,
                'data': create_acrastruct(
                    data.encode('ascii'), zone_public,
                    context=zones[0]['id'].encode('ascii')),
                'id': self.get_random_id()
            }
            rows.append(row)
        self.engine_raw.execute(test_table.insert(), rows)
        if TEST_MYSQL:
            select_query = '--select=select \'{id}\', data from {table};'.format(
                 id=zones[0]['id'], table=test_table.name)
        else:
            select_query = '--select=select \'{id}\'::bytea, data from {table};'.format(
                 id=zones[0]['id'], table=test_table.name)
        args = [
             select_query,
             '--zonemode=true',
             '--insert=insert into {} values({});'.format(
                 rollback_output_table.name, self.placeholder)
        ]
        self.run_rollback(args)

        # execute file
        with open(self.output_filename, 'r') as f:
            for line in f:
                self.engine_raw.execute(line)

        source_data = set([i['raw_data'].encode('ascii') for i in rows])
        result = self.engine_raw.execute(rollback_output_table.select())
        result = result.fetchall()
        for data in result:
            self.assertIn(data[0], source_data)

    def test_without_zone_execute(self):
        keyname = 'keypair1_storage'
        with open('.acrakeys/{}.pub'.format(keyname), 'rb') as f:
            server_public1 = f.read()

        rows = []
        for _ in range(self.DATA_COUNT):
            data = self.get_random_data()
            row = {
                'raw_data': data,
                'data': create_acrastruct(data.encode('ascii'), server_public1),
                'id': self.get_random_id()
            }
            rows.append(row)
        self.engine_raw.execute(test_table.insert(), rows)

        args = [
            '--execute=true',
            '--select=select data from {};'.format(test_table.name),
            '--insert=insert into {} values({});'.format(
                rollback_output_table.name, self.placeholder)
        ]
        self.run_rollback(args)

        source_data = set([i['raw_data'].encode('ascii') for i in rows])
        result = self.engine_raw.execute(rollback_output_table.select())
        result = result.fetchall()
        for data in result:
            self.assertIn(data[0], source_data)

    def test_with_zone_execute(self):
        zone_public = b64decode(zones[0]['public_key'].encode('ascii'))
        rows = []
        for _ in range(self.DATA_COUNT):
            data = self.get_random_data()
            row = {
                'raw_data': data,
                'data': create_acrastruct(
                    data.encode('ascii'), zone_public,
                    context=zones[0]['id'].encode('ascii')),
                'id': self.get_random_id()
            }
            rows.append(row)
        self.engine_raw.execute(test_table.insert(), rows)

        if TEST_MYSQL:
            select_query = '--select=select \'{id}\', data from {table};'.format(
                 id=zones[0]['id'], table=test_table.name)
        else:
            select_query = '--select=select \'{id}\'::bytea, data from {table};'.format(
                 id=zones[0]['id'], table=test_table.name)
        args = [
            '--execute=true',
            select_query,
            '--zonemode=true',
            '--insert=insert into {} values({});'.format(
                rollback_output_table.name, self.placeholder)
        ]
        self.run_rollback(args)

        source_data = set([i['raw_data'].encode('ascii') for i in rows])
        result = self.engine_raw.execute(rollback_output_table.select())
        result = result.fetchall()
        for data in result:
            self.assertIn(data[0], source_data)


class TestAcraGenKeys(unittest.TestCase):
    def test_only_alpha_client_id(self):
        # call with directory separator in key name
        self.assertEqual(create_client_keypair(POISON_KEY_PATH), 1)


class SSLPostgresqlConnectionTest(HexFormatTest):
    def get_acra_connection_string(self):
        return get_tcp_connection_string(self.ACRA_PORT)

    def wait_acra_connection(self, *args, **kwargs):
        wait_connection(self.ACRA_PORT)

    def checkSkip(self):
        if not TEST_WITH_TLS:
            self.skipTest("running tests without TLS")

    def setUp(self):
        self.checkSkip()
        """don't fork proxy, connect directly to acra, use sslmode=require in connections and tcp protocol on acra side
        because postgresql support tls only over tcp
        """
        try:
            if not self.EXTERNAL_ACRA:
                self.acra = self.fork_acra(
                    tls_key='tests/server.key', tls_cert='tests/server.crt', no_encryption=True, client_id='keypair1')
            self.engine1 = sa.create_engine(
                get_postgresql_tcp_connection_string(self.ACRA_PORT, self.DB_NAME), connect_args=get_connect_args(port=self.ACRA_PORT))
            self.engine_raw = sa.create_engine(
                '{}://{}:{}/{}'.format(DB_DRIVER, self.DB_HOST, self.DB_PORT, self.DB_NAME),
                connect_args=get_connect_args(self.DB_PORT))
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
                        if count == 3:
                            raise
        except:
            self.tearDown()
            raise

    def tearDown(self):
        if not self.EXTERNAL_ACRA:
            if hasattr(self, 'acra'):
                stop_process(self.acra)

        try:
            self.engine_raw.execute('delete from test;')
            for engine in self.engines:
                engine.dispose()
        except:
            pass


class SSLPostgresqlConnectionWithZoneTest(ZoneHexFormatTest,
                                          SSLPostgresqlConnectionTest):
    pass


class TLSBetweenProxyAndServerTest(HexFormatTest):
    TLS_ON = True
    def fork_acra(self, popen_kwargs: dict=None, **acra_kwargs: dict):
        return self._fork_acra({'client_id': 'keypair1'}, popen_kwargs)

    def setUp(self):
        super(TLSBetweenProxyAndServerTest, self).setUp()
        # acra works with one client id and no matter from which proxy connection come
        self.engine2.dispose()
        self.engine2 = self.engine_raw


class TLSBetweenProxyAndServerWithZonesTest(ZoneHexFormatTest,
                                            TLSBetweenProxyAndServerTest):
    pass


if __name__ == '__main__':
    unittest.main()
