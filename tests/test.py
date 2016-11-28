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
import sys
import unittest
from base64 import b64decode
from os.path import expanduser

import psycopg2
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import BYTEA

from acra import create_acra_struct, ZONE_BEGIN

__author__ = 'Lagovas <lagovas.lagovas@gmail.com>'

metadata = sa.MetaData()
test_table = sa.Table('test', metadata,
    sa.Column('id', sa.Integer, primary_key=True),
    sa.Column('data', sa.LargeBinary),
    sa.Column('raw_data', sa.String),
)

zones = []


def create_client_keypair(name, server_pair=False):
    if server_pair:
        name += '_server'
    return subprocess.call(
        ['./acra_genkeys', '-key_name={}'.format(name)], cwd=os.getcwd())


def setUpModule():
    global zones
    os.environ['GOPATH'] = '/home/lagovas/development/GOPATH'
    # build binaries
    assert subprocess.call(['go', 'build', 'github.com/cossacklabs/acra/cmd/acraproxy'], cwd=os.getcwd()) == 0
    assert subprocess.call(['go', 'build', 'github.com/cossacklabs/acra/cmd/acra_addzone'], cwd=os.getcwd()) == 0
    assert subprocess.call(
        ['go', 'build', 'github.com/cossacklabs/acra/cmd/acra_genkeys'], cwd=os.getcwd()) == 0
    assert subprocess.call(['go', 'build', 'github.com/cossacklabs/acra/cmd/acraserver'], cwd=os.getcwd()) == 0
    # first keypair for using without zones
    assert create_client_keypair('keypair1') == 0
    assert create_client_keypair('keypair1', server_pair=True) == 0
    assert create_client_keypair('keypair2') == 0
    assert create_client_keypair('keypair2', server_pair=True) == 0
    # add two zones
    zones.append(json.loads(subprocess.check_output(
        ['./acra_addzone'], cwd=os.getcwd()).decode('utf-8')))
    zones.append(json.loads(subprocess.check_output(
        ['./acra_addzone'], cwd=os.getcwd()).decode('utf-8')))


def tearDownModule():
    # delete builded binaries and keypairs
    home = expanduser('~')
    files = []
    for i in range(1, 3):
        files.append('.acrakeys/keypair{}'.format(i))
        files.append('.acrakeys/keypair{}.pub'.format(i))
        files.append('.acrakeys/keypair{}_server'.format(i))
        files.append('.acrakeys/keypair{}_server.pub'.format(i))
    for zone in zones:
        files.append('.acrakeys/{}_zone'.format(zone['id']))
        files.append('.acrakeys/{}_zone.pub'.format(zone['id']))

    for i in ['acraproxy', 'acraserver', 'acra_addzone', 'acra_genkeys'] + files:
        try:
            os.remove(i)
        except:
            pass


class TestCompilation(unittest.TestCase):
    def testCompileAll(self):
        self.assertFalse(subprocess.call(['go', 'build', 'github.com/cossacklabs/acra/cmd/acraproxy'], cwd=os.getcwd()))
        self.assertFalse(subprocess.call(['go', 'build', 'github.com/cossacklabs/acra/cmd/acraserver'], cwd=os.getcwd()))
        self.assertFalse(subprocess.call(['go', 'build', 'github.com/cossacklabs/acra/cmd/acra_addzone'], cwd=os.getcwd()))
        self.assertFalse(subprocess.call(['go', 'build', 'github.com/cossacklabs/acra/cmd/acra_genkeys'], cwd=os.getcwd()))
        self.assertFalse(subprocess.call(['go', 'build', 'github.com/cossacklabs/acra/cmd/acra_genpoisonrecord'], cwd=os.getcwd()))


class BaseTestCase(unittest.TestCase):
    DB_HOST = '127.0.0.1'
    DB_USER = 'postgres'
    DB_USER_PASSWORD = 'postgres'
    PROXY_PORT_1 = 9090
    PROXY_PORT_2 = 9091
    ACRA_PORT = 10003
    PG_PORT = 5433
    DB_NAME = 'postgres'
    ACRA_BYTEA = 'hex_bytea'
    DB_BYTEA = 'hex'
    ZONE = False
    DEBUG = False

    def fork(self, func):
        popen = func()
        count = 0
        while count <= 3:
            if popen.poll() is None:
                return popen
            count += 1
            time.sleep(0.01)
        self.fail("can't fork")

    def fork_proxy(self, proxy_port: int, acra_port: int, client_id: str):
        return self.fork(lambda: subprocess.Popen(
            ['./acraproxy', '-acra_host=127.0.0.1', '-acra_port={}'.format(acra_port),
             '-client_id={}'.format(client_id), '-port={}'.format(proxy_port), '-v',
             # now it's no matter, so just +100
             '-command_port={}'.format(proxy_port+100),
             '-disable_user_check']))

    def fork_acra(self, db_host: str, db_port: int, format: str, acra_port,
                  with_zone=False):
        return self.fork(lambda: subprocess.Popen(
            ['./acraserver', '-db_host='+db_host, '-db_port={}'.format(db_port),
             '-{}'.format(format), '-host=127.0.0.1', '-port={}'.format(acra_port),
             '-zonemode' if with_zone else '', '-v', '-d' if self.DEBUG else ''],
            stdout=sys.stdout))

    def setUp(self):
        self.proxy_1 = self.fork_proxy(
            self.PROXY_PORT_1, self.ACRA_PORT, 'keypair1')
        self.proxy_2 = self.fork_proxy(
            self.PROXY_PORT_2, self.ACRA_PORT, 'keypair2')
        self.acra = self.fork_acra(
            self.DB_HOST, self.PG_PORT, self.ACRA_BYTEA, self.ACRA_PORT, self.ZONE)

        self.engine1 = sa.create_engine(
            'postgresql://{}:{}@{}:{}/{}'.format(
                self.DB_USER, self.DB_USER_PASSWORD, self.DB_HOST, self.PROXY_PORT_1,
                self.DB_NAME))
        self.engine2 = sa.create_engine(
            'postgresql://{}:{}@{}:{}/{}'.format(
                self.DB_USER, self.DB_USER_PASSWORD, self.DB_HOST, self.PROXY_PORT_2,
                self.DB_NAME))
        self.engine_raw = sa.create_engine(
            'postgresql://{}:{}@{}:{}/{}'.format(
                self.DB_USER, self.DB_USER_PASSWORD, self.DB_HOST, self.PG_PORT, self.DB_NAME))

        self.engines = [self.engine1, self.engine2, self.engine_raw]

        metadata.create_all(self.engine_raw)
        self.engine_raw.execute('delete from test;')
        for engine in self.engines:
            engine.execute(
                "UPDATE pg_settings SET setting = '{}' "
                "WHERE name = 'bytea_output'".format(self.DB_BYTEA))

    def tearDown(self):
        for engine in self.engines:
            engine.execute(
                "UPDATE pg_settings SET setting = 'hex' "
                "WHERE name = 'bytea_output'")
        self.proxy_1.kill()
        self.proxy_2.kill()
        self.acra.kill()
        for p in [self.proxy_1, self.proxy_2, self.acra]:
            p.wait()
        self.engine_raw.execute('delete from test;')
        for engine in self.engines:
            engine.dispose()

    def get_random_data(self):
        size = random.randint(100, 10000)
        return ''.join(random.choice(string.ascii_letters)
                       for _ in range(size))

    def get_random_id(self):
        return random.randint(1, 100000)


class HexFormatTest(BaseTestCase):

    def testProxyRead(self):
        """test decrypting with correct acraproxy and not decrypting with
        incorrect acraproxy or using direct connection to db"""
        with open('.acrakeys/keypair1_server.pub', 'rb') as f:
            server_public1 = f.read()
        data = self.get_random_data()
        acra_struct = create_acra_struct(
            data.encode('ascii'), server_public1)
        row_id = self.get_random_id()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': acra_struct, 'raw_data': data})
        result = self.engine1.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertEqual(row['data'].decode('ascii'),
                         row['raw_data'])

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
        with open('.acrakeys/keypair1_server.pub', 'rb') as f:
            server_public1 = f.read()
        incorrect_data = self.get_random_data()
        correct_data = self.get_random_data()
        fake_offset = (3+45+84) - 1
        fake_acra_struct = create_acra_struct(
            incorrect_data.encode('ascii'), server_public1)[:fake_offset]
        inner_acra_struct = create_acra_struct(
            correct_data.encode('ascii'), server_public1)
        data = fake_acra_struct + inner_acra_struct
        row_id = self.get_random_id()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': data, 'raw_data': correct_data})
        result = self.engine1.execute(
            sa.select([test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        try:
            self.assertEqual(row['data'][fake_offset:].decode('ascii'),
                             row['raw_data'])
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
        acra_struct = create_acra_struct(
            data.encode('ascii'), zone_public,
            context=zones[0]['id'].encode('ascii'))
        row_id = self.get_random_id()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': acra_struct, 'raw_data': data})

        zone = ZONE_BEGIN+zones[0]['id'].encode('ascii')
        result = self.engine1.execute(
            sa.select([sa.cast(zone, BYTEA), test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertEqual(row['data'].decode('ascii'),
                         row['raw_data'])

        # without zone in another proxy, in the same proxy and without any proxy
        for engine in self.engines:
            result = engine.execute(
                sa.select([test_table])
                .where(test_table.c.id == row_id))
            row = result.fetchone()
            self.assertNotEqual(row['data'].decode('ascii', errors='ignore'),
                                row['raw_data'])

    def testReadAcrastructInAcrastruct(self):
        incorrect_data = self.get_random_data()
        correct_data = self.get_random_data()
        zone_public = b64decode(zones[0]['public_key'].encode('ascii'))
        fake_offset = (3+45+84) - 1
        fake_acra_struct = create_acra_struct(
            incorrect_data.encode('ascii'), zone_public, context=zones[0]['id'].encode('ascii'))[:fake_offset]
        inner_acra_struct = create_acra_struct(
            correct_data.encode('ascii'), zone_public, context=zones[0]['id'].encode('ascii'))
        data = fake_acra_struct + inner_acra_struct
        row_id = self.get_random_id()
        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': data, 'raw_data': correct_data})
        zone = ZONE_BEGIN+zones[0]['id'].encode('ascii')
        result = self.engine1.execute(
            sa.select([sa.cast(zone, BYTEA), test_table])
            .where(test_table.c.id == row_id))
        row = result.fetchone()
        self.assertEqual(row['data'][fake_offset:].decode('ascii'),
                         row['raw_data'])

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


class TestConnectionClosing(BaseTestCase):
    def setUp(self):
        self.proxy_1 = self.fork_proxy(
            self.PROXY_PORT_1, self.ACRA_PORT, 'keypair1')
        self.acra = self.fork_acra(
            self.DB_HOST, self.PG_PORT, self.ACRA_BYTEA, self.ACRA_PORT, self.ZONE)
        self.dsn = 'postgresql://{}:{}@{}:{}'.format(
            self.DB_USER, self.DB_USER_PASSWORD, self.DB_HOST, self.PROXY_PORT_1)

    def tearDown(self):
        self.proxy_1.kill()
        self.acra.kill()
        for p in [self.proxy_1, self.acra]:
            p.wait()

    def getActiveConnectionCount(self, cursor):
        cursor.execute('select count(*) from pg_stat_activity;')
        return int(cursor.fetchone()[0])

    def getConnectionLimit(self, connection=None):
        created_connection = False
        if connection is None:
            connection = psycopg2.connect(self.dsn)
            created_connection = True
        cursor = connection.cursor()
        cursor.execute('select setting from pg_settings where name=\'max_connections\';')
        limit = int(cursor.fetchone()[0])
        cursor.close()
        if created_connection:
            connection.close()
        return limit

    def checkConnection(self):
        """check that proxy and acra ready to accept connections"""
        count = 0
        while count <= 3:
            try:
                con = socket.create_connection(('127.0.0.1', self.ACRA_PORT), 1)
                con.close()
                con = socket.create_connection(('127.0.0.1', self.PROXY_PORT_1), 1)
                con.close()
                return
            except:
                pass
            count += 1
            time.sleep(0.1)
        self.fail("can't connect to acra or proxy")

    def testClosingConnections(self):
        self.checkConnection()
        connection = psycopg2.connect(self.dsn)

        connection.autocommit = True
        cursor = connection.cursor()
        current_connection_count = self.getActiveConnectionCount(cursor)

        connection2 = psycopg2.connect(self.dsn)
        self.assertEqual(self.getActiveConnectionCount(cursor),
                         current_connection_count+1)
        connection_limit = self.getConnectionLimit(connection)
        connections = [connection2]
        with self.assertRaises(psycopg2.OperationalError) as context_manager:
            for i in range(connection_limit):
                connections.append(psycopg2.connect(self.dsn))
        exception = context_manager.exception
        self.assertEqual(exception.args[0], 'FATAL:  sorry, too many clients already\n')

        for conn in connections:
            conn.close()
        # some wait for closing
        time.sleep(0.5)

        self.assertEqual(self.getActiveConnectionCount(cursor),
                         current_connection_count)

        # try create new connection
        connection2 = psycopg2.connect(self.dsn)
        self.assertEqual(self.getActiveConnectionCount(cursor),
                         current_connection_count + 1)

        connection2.close()
        self.assertEqual(self.getActiveConnectionCount(cursor),
                         current_connection_count)


class TestKeyNonExistence(BaseTestCase):
    # 0.05 empirical selected
    PROXY_STARTUP_DELAY = 0.05

    def setUp(self):
        self.acra = self.fork_acra(
            self.DB_HOST, self.PG_PORT, self.ACRA_BYTEA, self.ACRA_PORT, self.ZONE)
        self.dsn = 'postgresql://{}:{}@{}:{}'.format(
            self.DB_USER, self.DB_USER_PASSWORD, self.DB_HOST, self.PROXY_PORT_1)

    def tearDown(self):
        self.acra.kill()
        self.acra.wait()

    def delete_key(self, filename):
        os.remove('.acrakeys{sep}{name}'.format(sep=os.path.sep, name=filename))

    def test_without_acraproxy_public(self):
        """acraserver without acraproxy public key should drop connection
        from acraproxy than acraproxy should drop connection from psycopg2"""
        keyname = 'without_acraproxy_public_test'
        result = create_client_keypair(keyname)
        result |= create_client_keypair(keyname, server_pair=True)
        if result != 0:
            self.fail("Can't create keypairs")
        self.delete_key(keyname + '.pub')
        try:
            self.proxy = self.fork_proxy(
                self.PROXY_PORT_1, self.ACRA_PORT, keyname)
            self.assertIsNone(self.proxy.poll())
            with self.assertRaises(psycopg2.OperationalError) as exc:
                psycopg2.connect(self.dsn)
        finally:
            self.proxy.kill()
            self.proxy.wait()

    def test_without_acraproxy_private(self):
        """acraproxy shouldn't start without private key"""
        keyname = 'without_acraproxy_private_test'
        result = create_client_keypair(keyname)
        result |= create_client_keypair(keyname, server_pair=True)
        if result != 0:
            self.fail("Can't create keypairs")
        self.delete_key(keyname)
        try:
            self.proxy = self.fork_proxy(
                self.PROXY_PORT_1, self.ACRA_PORT, keyname)
            # time for start up proxy and validation file existence.
            time.sleep(self.PROXY_STARTUP_DELAY)
            self.assertEqual(self.proxy.poll(), 1)
        finally:
            self.proxy.kill()
            self.proxy.wait()

    def test_without_acraserver_private(self):
        """acraserver without private key should drop connection
        from acraproxy than acraproxy should drop connection from psycopg2"""
        keyname = 'without_acraserver_private_test'
        result = create_client_keypair(keyname)
        result |= create_client_keypair(keyname, server_pair=True)
        if result != 0:
            self.fail("Can't create keypairs")
        self.delete_key(keyname + '_server')
        try:
            self.proxy = self.fork_proxy(
                self.PROXY_PORT_1, self.ACRA_PORT, keyname)
            self.assertIsNone(self.proxy.poll())
            with self.assertRaises(psycopg2.OperationalError):
                psycopg2.connect(self.dsn)
        finally:
            self.proxy.kill()
            self.proxy.wait()

    def test_without_acraserver_public(self):
        """acraproxy shouldn't start without acraserver public key"""
        keyname = 'without_acraserver_public_test'
        result = create_client_keypair(keyname)
        result |= create_client_keypair(keyname, server_pair=True)
        if result != 0:
            self.fail("Can't create keypairs")
        self.delete_key(keyname + '_server.pub')
        try:
            self.proxy = self.fork_proxy(
                self.PROXY_PORT_1, self.ACRA_PORT, keyname)
            # time for start up proxy and validation file existence.
            time.sleep(self.PROXY_STARTUP_DELAY)
            self.assertEqual(self.proxy.poll(), 1)
        finally:
            self.proxy.kill()
            self.proxy.wait()


if __name__ == '__main__':
    unittest.main()