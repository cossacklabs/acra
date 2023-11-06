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
import collections.abc
import os.path
import stat
from tempfile import NamedTemporaryFile
from urllib.request import urlopen

import asyncpg.exceptions
import mysql.connector
import psycopg2.errors
import psycopg2.extras
from ddt import ddt, data
from prometheus_client.parser import text_string_to_metric_families
from sqlalchemy.exc import DatabaseError, OperationalError

from base import *
from test_common import *
from test_searchable_transparent_encryption import *
from test_tokenization import *
from test_type_aware import *

# add to path our wrapper until not published to PYPI
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'wrappers/python'))
from acrawriter import create_acrastruct


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
        connection_args = ConnectionArgs(host='localhost', port=self.ACRASERVER_PORT,
                                         user=DB_USER, password=DB_USER_PASSWORD, raw=True,
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
                                 asyncpg.exceptions.SyntaxOrAccessError,
                                 # https://github.com/MagicStack/asyncpg/issues/240
                                 AttributeError)
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
    if TEST_MYSQL:
        CENSOR_CONFIG_FILE = abs_path('tests/acra-censor_configs/acra-censor_whitelist_mysql.yaml')

    if TEST_POSTGRESQL:
        CENSOR_CONFIG_FILE = abs_path('tests/acra-censor_configs/acra-censor_whitelist_pgsql.yaml')

    def testWhitelist(self):
        connection_args = ConnectionArgs(host='localhost', port=self.ACRASERVER_PORT,
                                         user=DB_USER, password=DB_USER_PASSWORD, raw=True,
                                         dbname=DB_NAME, ssl_ca=TEST_TLS_CA,
                                         ssl_key=TEST_TLS_CLIENT_KEY,
                                         ssl_cert=TEST_TLS_CLIENT_CERT)
        if TEST_MYSQL:
            expectedException = (pymysql.err.OperationalError,
                                 mysql.connector.errors.DatabaseError)
            expectedExceptionInPreparedStatement = (pymysql.err.OperationalError, mysql.connector.errors.DatabaseError)
            executors = [PyMysqlExecutor(connection_args),
                         MysqlExecutor(connection_args)]
        if TEST_POSTGRESQL:
            expectedException = (psycopg2.ProgrammingError,
                                 asyncpg.exceptions.SyntaxOrAccessError)
            expectedExceptionInPreparedStatement = (
                asyncpg.exceptions.SyntaxOrAccessError,
                # due to https://github.com/MagicStack/asyncpg/issues/240
                AttributeError)
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
                    self.assertIn("AcraCensor blocked this query", str(e))
                except expectedExceptionInPreparedStatement:
                    return


class TestEnableCachedOnStartupServerV2ErrorExit(BaseTestCase):
    def checkSkip(self):
        if KEYSTORE_VERSION == 'v1':
            self.skipTest("test only for keystore Version v2")

    def setUp(self):
        self.log_file = tempfile.NamedTemporaryFile('w+', encoding='utf-8')

    def testRun(self):
        self.checkSkip()
        acra_kwargs = {
            'log_to_file': self.log_file.name,
            'keystore_cache_on_start_enable': 'true',
        }
        try:
            self.fork_acra(**acra_kwargs)
        except Exception as exc:
            self.assertEqual(str(exc), WAIT_CONNECTION_ERROR_MESSAGE)
            with open(self.log_file.name, 'r') as f:
                log = f.read()
                self.assertIn("Can't cache on start with disabled cache", log)
            self.tearDown()


class TestEnableCachedOnStartupTranslatorSV2ErrorExit(AcraTranslatorMixin, BaseTestCase):
    def checkSkip(self):
        if KEYSTORE_VERSION == 'v1':
            self.skipTest("test only for keystore Version v2")

    def setUp(self):
        self.log_file = tempfile.NamedTemporaryFile('w+', encoding='utf-8')

    def testRun(self):
        translator_kwargs = {
            'log_to_file': self.log_file.name,
            'keystore_cache_on_start_enable': 'true',
        }

        with ProcessContextManager(self.fork_translator(translator_kwargs)):
            with self.assertRaises(Exception):
                with open(self.log_file.name, 'r') as f:
                    log = f.read()
                    self.assertIn("Can't cache on start with disabled cache", log)
                self.tearDown()


class TestDisableCachedOnStartupTest(HexFormatTest):

    def setUp(self):
        self.non_cached_dir = tempfile.TemporaryDirectory()
        # fill temp dir with all keys
        copy_tree(base.KEYS_FOLDER.name, self.non_cached_dir.name)
        super().setUp()

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        # keystore_cache_on_start_enable is false by default in super().fork_acra()
        acra_kwargs['keys_dir'] = self.non_cached_dir.name
        return super(TestDisableCachedOnStartupTest, self).fork_acra(
            popen_kwargs, **acra_kwargs)

    def testReadAcrastructInAcrastruct(self):
        self.non_cached_dir.cleanup()
        with self.assertRaises(Exception):
            super().testReadAcrastructInAcrastruct()

    def testClientIDRead(self):
        self.non_cached_dir.cleanup()
        with self.assertRaises(Exception):
            super().testClientIDRead()


class EscapeFormatTest(HexFormatTest):
    ACRA_BYTEA = 'pgsql_escape_bytea'
    DB_BYTEA = 'escape'

    def checkSkip(self):
        if TEST_MYSQL:
            self.skipTest("useful only for postgresql")
        elif not TEST_WITH_TLS:
            self.skipTest("running tests only with TLS")


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
                        pymysql.connect(host='localhost', **get_connect_args(port=self.ACRASERVER_PORT)))
                else:
                    return TestConnectionClosing.mysql_closing(psycopg2.connect(
                        host='localhost', **get_connect_args(port=self.ACRASERVER_PORT)))
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
            query = "select count(*) from information_schema.processlist where db=%s;"
            cursor.execute(query, [DB_NAME])
            return int(cursor.fetchone()[0])
        else:
            cursor.execute('SELECT numbackends FROM pg_stat_database where datname=%s;', [DB_NAME])
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
                                     current_connection_count + 1)
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


class TestPoisonRecordOffStatus(BasePoisonRecordTest):
    SHUTDOWN = True
    DETECT_POISON_RECORDS = False

    def testShutdown(self):
        """case with select by specifying row id, checks that acra-server doesn't initialize poison record detection
        and any callbacks, and returns data as is on decryption failure even if it's valid poison record
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

    def testShutdownTranslatorHTTP(self):
        """check poison record ignoring via acra-translator using HTTP v1 API, omitting initialization poison
        record detection and any callbacks, returning data as is on decryption failure even if it's valid poison
        record
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
                response = self.http_decrypt_request(http_port, base.TLS_CERT_CLIENT_ID_1, data)
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
                    response = self.grpc_decrypt_request(grpc_port, base.TLS_CERT_CLIENT_ID_1, data,
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


class TestKeyStorageClearing(AcraCatchLogsMixin, BaseTestCase):
    def setUp(self):
        self.checkSkip()
        try:
            self.init_key_stores()
            if not self.EXTERNAL_ACRA:
                self.acra = self.fork_acra(
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

        create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_CERT, keys_dir=self.server_keys_dir,
                                               only_storage=True)

    def test_clearing(self):
        # execute any query for loading key by acra
        result = self.engine1.execute(sa.select([1]).limit(1))
        result.fetchone()

        ssl_context = ssl.create_default_context(cafile=base.TEST_TLS_CA)
        ssl_context.load_cert_chain(base.TEST_TLS_CLIENT_CERT, base.TEST_TLS_CLIENT_KEY)
        ssl_context.check_hostname = True
        with urlopen('https://localhost:{}/resetKeyStorage'.format(self.ACRASERVER_PORT + 1),
                     context=ssl_context) as response:
            self.assertEqual(response.status, 200)
        acra_logs = self.read_log(self.acra)
        self.assertNotIn("OCSP: Verifying", acra_logs)
        self.assertNotIn("CRL: Verifying", acra_logs)


class TestKeyStorageClearingWithTLSSpecificCLIAndConfig(TestKeyStorageClearing):
    def setUp(self):
        self.checkSkip()
        try:
            self.init_key_stores()
            if not self.EXTERNAL_ACRA:
                config = load_yaml_config('configs/acra-server.yaml')
                # explicitly set specific CLI config options as prefer and pass CLI with `ignore` because the extract flow is the following:
                # Specific param CLI -> Specific CLI Config -> General CLI -> General CLI Config
                config['tls_ocsp_client_from_cert'] = 'prefer'
                config['tls_crl_client_from_cert'] = 'prefer'
                config['tls_ocsp_database_from_cert'] = 'prefer'
                config['tls_crl_database_from_cert'] = 'prefer'
                temp_config = tempfile.NamedTemporaryFile()
                dump_yaml_config(config, temp_config.name)
                # using general CLI
                self.acra = self.fork_acra(
                    http_api_enable='true',
                    # pass 'ignore` values as specific params to make sure Specific CLI is in priority
                    tls_ocsp_client_from_cert='ignore',
                    tls_crl_client_from_cert='ignore',
                    tls_ocsp_database_from_cert='ignore',
                    tls_crl_database_from_cert='ignore',
                    tls_ocsp_url='',
                    tls_crl_url='',
                    config_file=temp_config.name,
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


class TestKeyStorageClearingWithTLSConfigSpecificCLI(TestKeyStorageClearing):
    def setUp(self):
        self.checkSkip()
        try:
            self.init_key_stores()
            if not self.EXTERNAL_ACRA:
                config = load_yaml_config('configs/acra-server.yaml')
                # explicitly set specific CLI config options and not pass CLI because the extract flow is the following:
                # Specific param CLI -> Specific CLI Config -> General CLI -> General CLI Config
                config['tls_ocsp_client_from_cert'] = 'ignore'
                config['tls_crl_client_from_cert'] = 'ignore'
                config['tls_ocsp_database_from_cert'] = 'ignore'
                config['tls_crl_database_from_cert'] = 'ignore'
                temp_config = tempfile.NamedTemporaryFile()
                dump_yaml_config(config, temp_config.name)
                # using general CLI
                self.acra = self.fork_acra(
                    http_api_enable='true',
                    # pass 'prefer` values as general params to make sure config is in priority
                    tls_ocsp_from_cert='prefer',
                    tls_crl_from_cert='prefer',
                    tls_ocsp_url='',
                    tls_crl_url='',
                    config_file=temp_config.name,
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


class TestKeyStorageClearingWithTLSGeneralCLI(TestKeyStorageClearing):
    def setUp(self):
        self.checkSkip()
        try:
            self.init_key_stores()
            if not self.EXTERNAL_ACRA:
                config = load_yaml_config('configs/acra-server.yaml')
                # explicitly delete specific CLI options to use general CLI because the extract flow is the following:
                # Specific param CLI -> Specific CLI Config -> General CLI -> General CLI Config
                del config['tls_ocsp_client_from_cert']
                del config['tls_crl_client_from_cert']
                del config['tls_ocsp_database_from_cert']
                del config['tls_crl_database_from_cert']
                temp_config = tempfile.NamedTemporaryFile()
                dump_yaml_config(config, temp_config.name)
                # using general CLI
                self.acra = self.fork_acra(
                    http_api_enable='true',
                    tls_ocsp_from_cert='ignore',
                    tls_crl_from_cert='ignore',
                    tls_ocsp_url='',
                    tls_crl_url='',
                    config_file=temp_config.name,
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
        self.client_id = base.TLS_CERT_CLIENT_ID_1
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

    def start_services(self):
        """Start Acra services required for testing."""
        master_key = self.get_master_key(self.keystore_version)
        master_key_env = {ACRA_MASTER_KEY_VAR_NAME: master_key}

        self.acra_server = self.fork_acra(
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

        # Try saving some data with defaults
        with self.running_services():
            row_id_1 = self.insert_as_client(data_1)

            # Check that we're able to put and get data via AcraServer.
            selected = self.select_as_client(row_id_1)
            self.assertEquals(selected['data'], data_1.encode('ascii'))
            self.assertEquals(selected['raw_data'], data_1)

            # Get encrypted data. It should really be encrypted.
            encrypted_1 = self.select_directly(row_id_1)
            self.assertNotEquals(encrypted_1['data'], data_1.encode('ascii'))

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


class TestAcraKeysWithRotatedKeys(unittest.TestCase):
    def setUp(self):
        self.master_key = get_master_key()
        self.dir_with_distinguished_name_client_id = tempfile.TemporaryDirectory()
        self.time_to_rotate = 3
        self.create_key_store_with_client_id_from_cert(TLS_CLIENT_ID_SOURCE_DN,
                                                       self.dir_with_distinguished_name_client_id.name)

    def test_keys_rotation(self):
        extract_resp = self.extrac_client_id(TLS_CLIENT_ID_SOURCE_DN)

        if KEYSTORE_VERSION == 'v1':
            key_ids = [
                'poison_key',
                'poison_key.pub',
                'poison_key_sym',
                'secure_log_key',
                '{}_storage_sym'.format(extract_resp['client_id']),
                '{}_storage.pub'.format(extract_resp['client_id']),
                '{}_storage'.format(extract_resp['client_id']),
                '{}_hmac'.format(extract_resp['client_id']),
            ]
        else:
            key_ids = [
                'audit-log',
                'poison-record-sym',
                'poison-record',
                'client/{}/storage-sym'.format(extract_resp['client_id']),
                'client/{}/hmac-sym'.format(extract_resp['client_id']),
                'client/{}/storage-sym'.format(extract_resp['client_id']),
            ]

        expected_keys_count = len(key_ids) * (self.time_to_rotate + 1)
        for _x in range(self.time_to_rotate):
            self.create_key_store_with_client_id_from_cert(TLS_CLIENT_ID_SOURCE_DN,
                                                           self.dir_with_distinguished_name_client_id.name)

        resp = self.list_key_store_keys_in_json(self.dir_with_distinguished_name_client_id.name)
        self.assertEqual(len(resp), expected_keys_count)

        key_id_count = {}
        for entry in resp:
            self.assertTrue(entry['Purpose'])
            self.assertTrue(entry['KeyID'])
            if entry['Index'] == 1:
                self.assertEqual(entry['State'], 'current')
            else:
                self.assertEqual(entry['State'], 'rotated')
                self.assertTrue(entry['CreationTime'])

            if entry['KeyID'] not in key_id_count:
                key_id_count[entry['KeyID']] = 1
            else:
                key_id_count[entry['KeyID']] += 1

        for key_id in key_ids:
            self.assertEqual(key_id_count[key_id], self.time_to_rotate + 1)

        # try destroy invalid key by index
        with self.assertRaises(Exception) as ctx:
            self.destroy_rotated_key(index=self.time_to_rotate + 5,
                                     dir_name=self.dir_with_distinguished_name_client_id.name, key_id=key_ids[0])

        # destroy first rotated key
        self.destroy_rotated_key(index=2, dir_name=self.dir_with_distinguished_name_client_id.name,
                                 key_id='poison-record-symmetric')

        resp = self.list_key_store_keys_in_json(self.dir_with_distinguished_name_client_id.name)
        # w/o one destroyed key
        self.assertEqual(len(resp), expected_keys_count - 1)

        if KEYSTORE_VERSION == 'v1':
            purpose = 'poison_sym_key'
        else:
            purpose = 'poison record symmetric key'

        # check indexes shifter after destroy
        expected_idx = 1
        for entry in resp:
            if entry['Purpose'] == purpose:
                self.assertEqual(entry['Index'], expected_idx)
                expected_idx += 1

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

    def destroy_rotated_key(self, index, dir_name, key_id):
        subprocess.check_call([
            os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'),
            'destroy',
            '--index={}'.format(index),
            '--keys_dir={}'.format(dir_name),
            '{}'.format(key_id),
        ],
            env={ACRA_MASTER_KEY_VAR_NAME: self.master_key},
            timeout=PROCESS_CALL_TIMEOUT)

    def extrac_client_id(self, extractor):
        cmd_output = json.loads(subprocess.check_output([
            os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'),
            'extract-client-id',
            '--tls_identifier_extractor_type={}'.format(extractor),
            '--tls_cert={}'.format(TEST_TLS_SERVER_CERT),
            '--print_json'
        ],
            cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT).decode('utf-8'))
        return cmd_output

    def list_key_store_keys_in_json(self, dir_name):
        """List all keys from keystore in JSON format."""
        cmd_output = json.loads(subprocess.check_output([
            os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'),
            'list',
            '--rotated-keys',
            '--json',
            '--keys_dir={}'.format(dir_name),
        ],
            cwd=os.getcwd(), timeout=PROCESS_CALL_TIMEOUT).decode('utf-8'))
        return cmd_output


class TestAcraKeysWithClientIDGeneration(unittest.TestCase):
    def setUp(self):
        self.master_key = get_master_key()
        self.dir_with_distinguished_name_client_id = tempfile.TemporaryDirectory()
        self.dir_with_serial_number_client_id = tempfile.TemporaryDirectory()

        self.create_key_store_with_client_id_from_cert(TLS_CLIENT_ID_SOURCE_DN,
                                                       self.dir_with_distinguished_name_client_id.name)
        self.create_key_store_with_client_id_from_cert(TLS_CLIENT_ID_SOURCE_SERIAL,
                                                       self.dir_with_serial_number_client_id.name)

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
        self.assertIn("--client_id or --tls_cert is required to generate keys".lower(),
                      exc.exception.output.decode('utf8').lower())
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
        tls_args = []
        redis_hostport = os.environ.get('TEST_REDIS_HOSTPORT', 'localhost:6379')
        if TEST_WITH_TLS:
            tls_args.extend([
                '--redis_tls_client_auth=4',
                '--redis_tls_client_ca=' + TEST_TLS_CA,
                '--redis_tls_client_cert=' + TEST_TLS_CLIENT_CERT,
                '--redis_tls_client_key=' + TEST_TLS_CLIENT_KEY,
                '--redis_tls_enable=true'
            ])

        subprocess.check_call(
            [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keymaker'),
             '--client_id={}'.format(client_id),
             '--generate_acrawriter_keys',
             '--generate_symmetric_storage_key',
             '--redis_host_port=' + redis_hostport,
             '--keystore={}'.format(KEYSTORE_VERSION)
             ] + tls_args,
            env={ACRA_MASTER_KEY_VAR_NAME: master_key},
            timeout=PROCESS_CALL_TIMEOUT)

        subprocess.check_call([
                                  os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'),
                                  'read',
                                  '--public',
                                  '--redis_host_port=' + redis_hostport,
                              ] + tls_args + ['client/keypair1/storage'],
                              env={ACRA_MASTER_KEY_VAR_NAME: master_key},
                              timeout=PROCESS_CALL_TIMEOUT)

        subprocess.check_call([
                                  os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'),
                                  'read',
                                  '--redis_host_port=' + redis_hostport,
                              ] + tls_args + ['client/keypair1/symmetric'],
                              env={ACRA_MASTER_KEY_VAR_NAME: master_key},
                              timeout=PROCESS_CALL_TIMEOUT)

        subprocess.check_call([
                                  os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keys'),
                                  'read',
                                  '--private',
                                  '--redis_host_port=' + redis_hostport,
                              ] + tls_args + ['client/keypair1/storage'],
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
            host='localhost', port=self.ACRASERVER_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_USER_PASSWORD, raw=True,
            format=AsyncpgExecutor.BinaryFormat,
            ssl_ca=TEST_TLS_CA,
            ssl_key=TEST_TLS_CLIENT_KEY,
            ssl_cert=TEST_TLS_CLIENT_CERT
        )).execute_prepared_statement(query=query)

    def read_public_key(self, extra_kwargs: dict = None):
        return read_storage_public_key(base.TLS_CERT_CLIENT_ID_1, base.KEYS_FOLDER.name, extra_kwargs=extra_kwargs)

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
            host='localhost', port=self.ACRASERVER_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_USER_PASSWORD, raw=True,
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
            self.sslmode = 'verify-full'
            TLS_ARGS = [
                '--tls_database_enabled=true',
                '--tls_database_ca={}'.format(base.TEST_TLS_CA),
                '--tls_database_key={}'.format(base.TEST_TLS_CLIENT_KEY),
                '--tls_database_cert={}'.format(base.TEST_TLS_CLIENT_CERT),
                '--tls_ocsp_database_from_cert=ignore',
                '--tls_crl_database_from_cert=ignore',
            ]

        else:
            self.sslmode = 'disable'
            TLS_ARGS = []
        if TEST_MYSQL:
            # https://github.com/go-sql-driver/mysql/
            connection_string = "{user}:{password}@tcp({host}:{port})/{dbname}?tls=skip-verify".format(
                user=DB_USER, password=DB_USER_PASSWORD, dbname=DB_NAME,
                port=DB_PORT, host=DB_HOST
            )

            # https://github.com/ziutek/mymysql
            # connection_string = "tcp:{host}:{port}*{dbname}/{user}/{password}".format(
            #     user=DB_USER, password=DB_USER_PASSWORD, dbname=DB_NAME,
            #     port=DB_PORT, host=DB_HOST
            # )
        else:
            connection_string = "postgresql://{user}:{password}@{host}:{port}/{dbname}?sslmode={sslmode}".format(
                user=DB_USER, password=DB_USER_PASSWORD, dbname=DB_NAME,
                port=DB_PORT, host=DB_HOST, sslmode=self.sslmode
            )

        if TEST_MYSQL:
            self.placeholder = "?"
            DB_ARGS = ['--mysql_enable']
        else:
            self.placeholder = "$1"
            DB_ARGS = ['--postgresql_enable']

        self.default_acrarollback_args = [
                                             '--client_id={}'.format(base.TLS_CERT_CLIENT_ID_1),
                                             '--connection_string={}'.format(connection_string),
                                             '--output_file={}'.format(self.output_filename),
                                             '--keys_dir={}'.format(base.KEYS_FOLDER.name),
                                         ] + DB_ARGS

        if TEST_WITH_TLS:
            self.default_acrarollback_args = self.default_acrarollback_args + TLS_ARGS

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

    def test_to_file(self):
        server_public1 = read_storage_public_key(base.TLS_CERT_CLIENT_ID_1, base.KEYS_FOLDER.name)

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
        self.assertEqual(len(result), len(rows))
        for data in result:
            self.assertIn(data[0], source_data)

    def test_execute(self):
        server_public1 = read_storage_public_key(base.TLS_CERT_CLIENT_ID_1, base.KEYS_FOLDER.name)

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
        self.assertEqual(len(result), len(rows))
        for data in result:
            self.assertIn(data[0], source_data)

    def test_without_placeholder(self):
        args = [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-rollback'),
                '--execute=true',
                '--select=select data from {};'.format(test_table.name),
                '--insert=query without placeholders;',
                '--postgresql_enable',
                '--keys_dir={}'.format(base.KEYS_FOLDER.name),
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
        def insert_random_data():
            rows = []
            public_key = read_storage_public_key(base.TLS_CERT_CLIENT_ID_1, base.KEYS_FOLDER.name)
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
        create_client_keypair(base.TLS_CERT_CLIENT_ID_1, only_storage=True)

        # Insert some more data encrypted with new key
        rows = rows + insert_random_data()

        # Run acra-rollback for the test table
        self.run_acrarollback([
            '--execute=true',
            '--select=select data from {};'.format(test_table.name),
            '--insert=insert into {} values({});'.format(
                acrarollback_output_table.name, self.placeholder)
        ])

        # Rollback should successfully use previous keys to decrypt data
        source_data = set([i['raw_data'].encode('ascii') for i in rows])
        result = self.engine_raw.execute(acrarollback_output_table.select())
        result = result.fetchall()
        self.assertEqual(len(result), len(rows))
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
            get_postgresql_tcp_connection_string(self.ACRASERVER2_PORT, DB_NAME, 'localhost'),
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
                    client_id=base.TLS_CERT_CLIENT_ID_1)
                # create second acra without settings for tls to check that
                # connection will be closed on tls handshake
                self.acra2 = self.fork_acra(
                    client_id=base.TLS_CERT_CLIENT_ID_1,
                    incoming_connection_api_string=self.get_acraserver_api_connection_string(
                        port=self.ACRASERVER2_PORT + 5),
                    incoming_connection_port=self.ACRASERVER2_PORT,
                    incoming_connection_prometheus_metrics_string=self.get_prometheus_address(
                        self.ACRASERVER2_PROMETHEUS_PORT))
            self.engine1 = sa.create_engine(
                get_postgresql_tcp_connection_string(self.ACRASERVER_PORT, DB_NAME, 'localhost'),
                connect_args=get_connect_args(port=self.ACRASERVER_PORT))
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


class SSLMysqlMixin(SSLPostgresqlMixin):
    def checkSkip(self):
        if not (TEST_WITH_TLS and TEST_MYSQL):
            self.skipTest("running tests without TLS")

    def get_ssl_engine(self):
        return sa.create_engine(
            get_postgresql_tcp_connection_string(self.ACRASERVER2_PORT, DB_NAME, 'localhost'),
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
                    # tls_db_sni="127.0.0.1",
                    client_id=base.TLS_CERT_CLIENT_ID_1)
                # create second acra without settings for tls to check that
                # connection will be closed on tls handshake
                self.acra2 = self.fork_acra(
                    client_id=base.TLS_CERT_CLIENT_ID_1,
                    incoming_connection_port=self.ACRASERVER2_PORT,
                    incoming_connection_api_string=self.get_acraserver_api_connection_string(
                        port=self.ACRASERVER2_PORT + 5),
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
                get_postgresql_tcp_connection_string(self.ACRASERVER_PORT, DB_NAME, host='localhost'),
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


class BasePrepareStatementMixin:
    def checkSkip(self):
        return

    def executePreparedStatement(self, query):
        raise NotImplementedError

    def testClientRead(self):
        """test decrypting with correct client_id and not decrypting with
        incorrect client_id or using direct connection to db"""
        client_id = base.TLS_CERT_CLIENT_ID_1
        server_public1 = read_storage_public_key(client_id, base.KEYS_FOLDER.name)
        data = get_pregenerated_random_data()
        acra_struct = create_acrastruct(
            data.encode('ascii'), server_public1)
        row_id = get_random_id()

        self.log(storage_client_id=client_id,
                 data=acra_struct, expected=data.encode('ascii'))

        self.engine1.execute(
            test_table.insert(),
            {'id': row_id, 'data': acra_struct, 'raw_data': data})

        query = sa.select([test_table]).where(test_table.c.id == row_id).compile(
            compile_kwargs={"literal_binds": True}).string
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
        client_id = base.TLS_CERT_CLIENT_ID_1
        server_public1 = read_storage_public_key(client_id, base.KEYS_FOLDER.name)
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
            ConnectionArgs(host='localhost', port=self.ACRASERVER_PORT,
                           user=DB_USER, password=DB_USER_PASSWORD,
                           dbname=DB_NAME, ssl_ca=TEST_TLS_CA,
                           ssl_key=TEST_TLS_CLIENT_KEY,
                           raw=True,
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
            ConnectionArgs(host='localhost', port=self.ACRASERVER_PORT,
                           user=DB_USER, password=DB_USER_PASSWORD,
                           dbname=DB_NAME, ssl_ca=TEST_TLS_CA,
                           ssl_key=TEST_TLS_CLIENT_KEY,
                           raw=True,
                           ssl_cert=TEST_TLS_CLIENT_CERT)
        ).execute_prepared_statement(query, args=args)


class TestMariaDBBinaryPreparedStatement(BasePrepareStatementMixin, BaseTestCase):
    def checkSkip(self):
        if not TEST_MARIADB:
            self.skipTest("run test only for MariaDB")
        elif not TEST_WITH_TLS:
            self.skipTest("running tests only with TLS")

    def executePreparedStatement(self, query, args=None):
        # MariaDB used socket auth by default and in case of localhost trying to connect to unix socket
        return MariaDBExecutor(
            ConnectionArgs(host='127.0.0.1', port=self.ACRASERVER_PORT,
                           user=DB_USER, password=DB_USER_PASSWORD,
                           dbname=DB_NAME, ssl_ca=TEST_TLS_CA,
                           ssl_key=TEST_TLS_CLIENT_KEY,
                           raw=True,
                           ssl_cert=TEST_TLS_CLIENT_CERT)
        ).execute_prepared_statement(query, args=args)


class TestMysqlConnectorCBinaryPreparedStatement(BasePrepareStatementMixin, BaseTestCase):
    def checkSkip(self):
        if not TEST_MYSQL:
            self.skipTest("run test only for mysql")
        elif not TEST_WITH_TLS:
            self.skipTest("running tests only with TLS")

    def executePreparedStatement(self, query, args=None):
        return MysqlConnectorCExecutor(
            ConnectionArgs(host='localhost', port=self.ACRASERVER_PORT,
                           user=DB_USER, password=DB_USER_PASSWORD,
                           dbname=DB_NAME, ssl_ca=TEST_TLS_CA,
                           ssl_key=TEST_TLS_CLIENT_KEY,
                           raw=True,
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
        return Psycopg2Executor(ConnectionArgs(host='localhost', port=self.ACRASERVER_PORT,
                                               user=DB_USER, password=DB_USER_PASSWORD,
                                               dbname=DB_NAME, ssl_ca=TEST_TLS_CA, raw=True,
                                               ssl_key=TEST_TLS_CLIENT_KEY,
                                               ssl_cert=TEST_TLS_CLIENT_CERT)).execute_prepared_statement(query, args)


class TestPostgresqlTextPreparedStatementWholeCell(TestPostgresqlTextPreparedStatement):
    WHOLECELL_MODE = True


class TestPostgresqlBinaryPreparedStatement(BaseBinaryPostgreSQLTestCase, BasePrepareStatementMixin):

    def executePreparedStatement(self, query):
        return self.executor1.execute_prepared_statement(query)


class TestPostgresqlBinaryPreparedStatementWholeCell(TestPostgresqlBinaryPreparedStatement):
    WHOLECELL_MODE = True


class TestTranslatorEnableCachedOnStartup(AcraTranslatorMixin, BaseTestCase):
    def checkSkip(self):
        super().checkSkip()
        if KEYSTORE_VERSION == 'v2':
            self.skipTest("test only for keystore Version v1")

    def setUp(self):
        self.cached_dir = tempfile.TemporaryDirectory()
        # fill temp dir with all keys
        copy_tree(base.KEYS_FOLDER.name, self.cached_dir.name)
        super().setUp()

    def fork_translator(self, translator_kwargs, popen_kwargs=None):
        args = {
            'keystore_cache_on_start_enable': 'true',
            'keys_dir': self.cached_dir.name
        }
        translator_kwargs.update(args)
        return super().fork_translator(translator_kwargs, popen_kwargs)

    def testApiEncryptionEnabledCacheWithoutKeysDir(self):
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

        incorrect_client_id = base.TLS_CERT_CLIENT_ID_2
        with ProcessContextManager(self.fork_translator(translator_kwargs)):
            self.cached_dir.cleanup()
            response = self.http_encrypt_request(translator_port, incorrect_client_id, data)
            decrypted = deserialize_and_decrypt_acrastruct(response, client_id_private_key, client_id)
            self.assertEqual(data, decrypted)


@ddt
class TestAcraRotate(BaseTestCase):
    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        acra_kwargs['keystore_cache_size'] = -1  # no cache
        return super(TestAcraRotate, self).fork_acra(
            popen_kwargs, **acra_kwargs)

    def isSamePublicKeys(self, keys_folder, keys_data):
        """check is equal public key on filesystem and from key_data"""
        for key_id, public_key in keys_data.items():
            current_public = self.read_public_key(key_id, keys_folder)
            if b64decode(public_key) != current_public:
                return False
        return True

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
                         '--dry-run={}'.format(1 if dryRun else 0)])
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
        client_id = base.TLS_CERT_CLIENT_ID_1
        acra_struct = create_acrastruct_with_client_id(data.encode('ascii'), client_id)
        row_id = get_random_id()
        data_before_rotate[row_id] = acra_struct
        self.engine_raw.execute(
            rotate_test_table.insert(),
            {'id': row_id, 'data': acra_struct, 'raw_data': data,
             'key_id': client_id.encode('ascii')})

        if rotate_storage_keys:
            create_client_keypair(client_id, only_storage=True)

        if TEST_WITH_TLS:
            TLS_ARGS = [
                '--tls_database_enabled=true',
                '--tls_database_ca={}'.format(base.TEST_TLS_CA),
                '--tls_database_key={}'.format(base.TEST_TLS_CLIENT_KEY),
                '--tls_database_cert={}'.format(base.TEST_TLS_CLIENT_CERT),
                '--tls_ocsp_database_from_cert=ignore',
                '--tls_crl_database_from_cert=ignore',
            ]
        else:
            TLS_ARGS = []

        if TEST_MYSQL:
            # test:test@tcp(127.0.0.1:3306)/test
            connection_string = "{user}:{password}@tcp({host}:{port})/{db_name}?tls=skip-verify".format(
                user=DB_USER, password=DB_USER_PASSWORD, host=DB_HOST,
                port=DB_PORT, db_name=DB_NAME)
            mode_arg = '--mysql_enable'
        elif TEST_POSTGRESQL:
            if TEST_WITH_TLS:
                sslmode = 'verify-full'
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
                sql_select = "select id, '{}'::bytea, data from {} order by id;".format(client_id,
                                                                                        rotate_test_table.name)
            else:
                self.fail("unsupported settings of tested db")

            default_args = [
                os.path.join(BINARY_OUTPUT_FOLDER, 'acra-rotate'),
                '--keys_dir={}'.format(base.KEYS_FOLDER.name),
                '--db_connection_string={}'.format(connection_string),
                '--dry-run={}'.format(1 if dry_run else 0),
                mode_arg
            ]

            keys_map = load_keys_from_folder(base.KEYS_FOLDER.name, [client_id])
            try:
                args = default_args + [
                    "--sql_select={}".format(sql_select),
                    '--sql_update={}'.format(sql_update),
                ] + TLS_ARGS

                # use extra arg in select and update
                subprocess.check_output(args)
            except subprocess.CalledProcessError as exc:
                print(exc.output)
                raise
            if dry_run:
                self.assertTrue(
                    self.isSamePublicKeys(base.KEYS_FOLDER.name, keys_map))
            else:
                self.assertFalse(
                    self.isSamePublicKeys(base.KEYS_FOLDER.name, keys_map))

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
                sql_select = "select '{}'::bytea, data from {} where id={};".format(client_id, rotate_test_table.name,
                                                                                    some_id)
            else:
                self.fail("unsupported settings of tested db")
            sql_update = sql_update.format(some_id)

            keys_map = load_keys_from_folder(base.KEYS_FOLDER.name, [client_id])
            # rotate with select without extra arg

            args = default_args + [
                "--sql_select={}".format(sql_select),
                '--sql_update={}'.format(sql_update)
            ] + TLS_ARGS

            subprocess.check_output(args)
            if dry_run:
                self.assertTrue(
                    self.isSamePublicKeys(base.KEYS_FOLDER.name, keys_map))
            else:
                self.assertFalse(
                    self.isSamePublicKeys(base.KEYS_FOLDER.name, keys_map))

            result = self.engine1.execute(
                sa.select([rotate_test_table],
                          whereclause=rotate_test_table.c.id == some_id))
            self.check_decrypted_data(result)
            # check that after rotation we can read actual data
            result = self.engine_raw.execute(
                sa.select([rotate_test_table],
                          whereclause=rotate_test_table.c.id == some_id))
            self.check_rotation(result, data_before_rotate, dry_run)


class TestPrometheusMetrics(AcraTranslatorMixin, BaseTestCase):
    LOG_METRICS = True
    # some small value but greater than 0 to compare with metrics value of time of processing
    MIN_EXECUTION_TIME = 0.0000001
    ENCRYPTOR_CONFIG = base.get_encryptor_config('tests/encryptor_configs/ee_encryptor_config_prometheus.yaml')

    def setUp(self):
        super().setUp()

        # init searchable transparent encryption test
        self.searchableTransparentTest = TestSearchableTransparentEncryption()
        self.searchableTransparentTest.engine_raw = self.engine_raw
        self.searchableTransparentTest.engine1 = self.engine1
        self.searchableTransparentTest.engine2 = self.engine2
        self.searchableTransparentTest.encryptor_table = BaseSearchableTransparentEncryption().get_encryptor_table()
        base.metadata.create_all(self.engine_raw, [self.searchableTransparentTest.encryptor_table])

        # init tokenization test
        self.tokenizationTest = TestTokenization()
        self.tokenizationTest.engine_raw = self.engine_raw
        self.tokenizationTest.engine1 = self.engine1
        self.tokenizationTest.engine2 = self.engine2

    def tearDown(self):
        base.metadata.drop_all(self.engine_raw, [self.searchableTransparentTest.encryptor_table])
        super().tearDown()

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        acra_kwargs.update(encryptor_config_file=self.ENCRYPTOR_CONFIG)
        return super(TestPrometheusMetrics, self).fork_acra(popen_kwargs, **acra_kwargs)

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

        self.tokenizationTest.testTokenizationDefaultClientID()
        self.searchableTransparentTest.testSearch()
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

            'acra_tokenizations_total': {'min_value': 1},
            'acra_detokenizations_total': {'min_value': 1},

            'acra_encryptions_total': {'min_value': 1},
            'acra_decryptions_total': {'min_value': 1},

            'acraserver_build_info': {'min_value': 1},
        }
        self.checkMetrics('http://localhost:{}/metrics'.format(
            self.ACRASERVER_PROMETHEUS_PORT), labels)

    def testAcraTranslator(self):
        # TODO: added more metrics tracking when support /v2 translator queries
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
            'acra_decryptions_total': {'min_value': 1},

            'acratranslator_build_info': {'min_value': 1},
        }
        translator_port = 3456
        metrics_port = translator_port + 1
        data = get_pregenerated_random_data().encode('ascii')
        client_id = base.TLS_CERT_CLIENT_ID_1
        encryption_key = read_storage_public_key(
            client_id, keys_dir=base.KEYS_FOLDER.name)
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
                self, translator_port, client_id, acrastruct)
            self.checkMetrics(metrics_url, labels)


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
            read_storage_public_key(base.TLS_CERT_CLIENT_ID_1, base.KEYS_FOLDER.name)
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
            }
            for service in services:
                config_param = '-config_file={}'.format(os.path.join(tmp_dir, '{}.yaml'.format(service)))
                args = [os.path.join(BINARY_OUTPUT_FOLDER, service), config_param] + default_args.get(service, [])
                stderr = self.getOutputFromProcess(args)
                self.assertRegexpMatches(stderr,
                                         r'code=508 error="config version \\"0.0.0\\" is not supported, expects \\"[\d.]+\\" version')

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
                                    'args': ['-keys_dir={}'.format(base.KEYS_FOLDER.name),
                                             # empty id to raise error
                                             '--securesession_id=""'],
                                    'status': 1},
                'acra-server': {'args': ['-keys_dir={}'.format(base.KEYS_FOLDER.name)],
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
                self.assertNotRegex(stderr,
                                    r'code=508 error="config version \\"[\d.+]\\" is not supported, expects \\"[\d.]+\\" version')

    def testStartupWithoutConfig(self):
        files = os.listdir('cmd/')
        services = [i for i in files if os.path.isdir(os.path.join('cmd/', i))]
        self.assertTrue(services)

        with tempfile.TemporaryDirectory() as tmp_dir:
            default_args = {
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
                                    'args': ['-keys_dir={}'.format(base.KEYS_FOLDER.name),
                                             # empty id to raise error
                                             '--securesession_id=""'],
                                    'status': 1},
                'acra-server': {'args': ['-keys_dir={}'.format(base.KEYS_FOLDER.name)],
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
                self.assertNotRegex(stderr,
                                    r'code=508 error="config version \\"[\d.]\\" is not supported, expects \\"[\d.]+\\" version')


class TestPgPlaceholders(BaseTestCase):
    def checkSkip(self):
        if TEST_MYSQL or not TEST_POSTGRESQL:
            self.skipTest("test only for postgresql")
        elif not TEST_WITH_TLS:
            self.skipTest("running tests only with TLS")

    def testPgPlaceholders(self):
        connection_args = ConnectionArgs(host='localhost', port=self.ACRASERVER_PORT,
                                         user=DB_USER, password=DB_USER_PASSWORD, raw=True,
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


class TestTLSAuthenticationDirectlyToAcraByDistinguishedName(TLSAuthenticationDirectlyToAcraMixin,
                                                             TLSAuthenticationByDistinguishedNameMixin, BaseTestCase):
    """
    Tests environment when client's app connect to db through acra-server with TLS and acra-server extracts clientID from client's certificate
    instead using from --clientID CLI param
    """

    def testServerRead(self):
        """test decrypting with correct client_id and not decrypting with
        incorrect client_id or using direct connection to db"""
        self.assertEqual(create_client_keypair_from_certificate(tls_cert=TEST_TLS_CLIENT_CERT,
                                                                extractor=self.get_identifier_extractor_type(),
                                                                keys_dir=base.KEYS_FOLDER.name), 0)
        server_public1 = read_storage_public_key(self.acra_writer_id, base.KEYS_FOLDER.name)
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
        server_public1 = read_storage_public_key(self.acra_writer_id, base.KEYS_FOLDER.name)
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

        self.log(storage_client_id=self.acra_writer_id,
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


class TestTLSAuthenticationDirectlyToAcraBySerialNumber(TLSAuthenticationBySerialNumberMixin,
                                                        TestTLSAuthenticationDirectlyToAcraByDistinguishedName):
    pass


class TestTLSAuthenticationDirectlyToAcraBySerialNumberConnectionsClosed(AcraCatchLogsMixin,
                                                                         TLSAuthenticationBySerialNumberMixin,
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


class TestAcraIgnoresLegacyKeys(AcraCatchLogsMixin, BaseTestCase):
    """
    Ensure AcraServer won't exit with error when started with flags for key caching,
    while keystore contains legacy keys (Connector<->Server, Connector<->Translator)
    """

    legacy_key_files = [
        'auth_key',
        'testclientid',
        'testclientid.pub',
        'testclientid_server',
        'testclientid_server.pub',
        'testclientid_translator',
        'testclientid_translator.pub',
    ]

    def checkSkip(self):
        super().checkSkip()

        if KEYSTORE_VERSION != 'v1':
            self.skipTest("test only for keystore v1")

    def setUp(self):
        try:
            for key_file in self.legacy_key_files:
                open(f"{base.KEYS_FOLDER.name}/{key_file}", "w").close()
        except:
            self.tearDown()
            raise

        super().setUp()

    def tearDown(self):
        for key_file in self.legacy_key_files:
            try:
                os.remove(f"{base.KEYS_FOLDER.name}/{key_file}")
            except:
                pass

        super().tearDown()

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        args = {
            'keystore_cache_size': 0,
            'keystore_cache_on_start_enable': 'true',
        }
        acra_kwargs.update(args)
        return super().fork_acra(popen_kwargs, **acra_kwargs)

    def testKeysCachedSuccessfully(self):
        self.assertIn("Cached keystore on start successfully".lower(), self.read_log(self.acra).lower())

    def testLegacyKeysIgnored(self):
        self.assertIn("Ignoring legacy key".lower(), self.read_log(self.acra).lower())


class TestReturningProcessingMixing:
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

    def delete_and_return_data_with_star(self, id):
        raise NotImplementedError

    def delete_and_return_data_with_enum(self, id):
        raise NotImplementedError

    def update_and_return_data_with_enum(self, date):
        raise NotImplementedError

    def update_and_return_data_with_star(self, date):
        raise NotImplementedError

    def test_returning_with_col_enum(self):
        source, hidden, data = self.insert_with_enum_and_return_data()
        self.assertEqual(source['token_str'], data['token_str'])
        self.assertEqual(source['token_i64'], data['token_i64'])
        self.assertEqual(source['token_email'], data['token_email'])
        self.assertEqual(source['token_i32'], data['token_i32'])
        self.assertNotEqual(hidden['token_str'], data['token_str'])
        self.assertNotEqual(hidden['token_i64'], data['token_i64'])
        self.assertNotEqual(hidden['token_email'], data['token_email'])
        self.assertNotEqual(hidden['token_i32'], data['token_i32'])
        source = self.delete_and_return_data_with_enum(source['id'])
        self.assertEqual(source['token_i32'], data['token_i32'])
        self.assertEqual(source['token_i64'], data['token_i64'])
        self.assertEqual(source['token_str'], data['token_str'])
        self.assertEqual(source['token_email'], data['token_email'])
        if TEST_POSTGRESQL:
            data['token_i32'] = random_int32()
            data['token_i64'] = random_int64()
            data['token_str'] = random_str()
            data['token_bytes'] = random_bytes()
            data['token_email'] = random_email()
            source = self.update_and_return_data_with_enum(data)
            self.assertEqual(source['token_i32'], data['token_i32'])
            self.assertEqual(source['token_i64'], data['token_i64'])
            self.assertEqual(source['token_str'], data['token_str'])
            self.assertEqual(source['token_email'], data['token_email'])

    def test_returning_with_star(self):
        source, hidden, data = self.insert_with_star_and_return_data()
        self.assertEqual(source['token_i32'], data['token_i32'])
        self.assertEqual(source['token_i64'], data['token_i64'])
        self.assertEqual(source['token_str'], data['token_str'])
        self.assertEqual(source['token_email'], data['token_email'])
        self.assertNotEqual(hidden['token_i32'], data['token_i32'])
        self.assertNotEqual(hidden['token_i64'], data['token_i64'])
        self.assertNotEqual(hidden['token_str'], data['token_str'])
        self.assertNotEqual(hidden['token_email'], data['token_email'])
        source = self.delete_and_return_data_with_star(source['id'])
        self.assertEqual(source['token_i32'], data['token_i32'])
        self.assertEqual(source['token_i64'], data['token_i64'])
        self.assertEqual(source['token_str'], data['token_str'])
        self.assertEqual(source['token_email'], data['token_email'])
        if TEST_POSTGRESQL:
            data['token_i32'] = random_int32()
            data['token_i64'] = random_int64()
            data['token_str'] = random_str()
            data['token_bytes'] = random_bytes()
            data['token_email'] = random_email()
            source = self.update_and_return_data_with_star(data)
            self.assertEqual(source['token_i32'], data['token_i32'])
            self.assertEqual(source['token_i64'], data['token_i64'])
            self.assertEqual(source['token_str'], data['token_str'])
            self.assertEqual(source['token_email'], data['token_email'])


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
        if not TEST_MARIADB:
            self.skipTest("Only for MariaDB")
        super().checkSkip()

    def build_raw_query_with_enum(self):
        id = get_random_id()
        # TODO(zhars, 2021-5-20): rewrite query when sqlalchemy will support RETURNING statements
        # include literals 0, 1, null to be sure that we support non-column values too
        return 'INSERT INTO test_tokenization_specific_client_id ' \
               '(id, empty, token_bytes, token_i32, token_i64, token_str, token_email) ' \
               'VALUES ({}, {}, {}, {}, {}, \'{}\', \'{}\') ' \
               'RETURNING 0, 1 as literal, test_tokenization_specific_client_id.id, test_tokenization_specific_client_id.token_str,' \
               ' test_tokenization_specific_client_id.token_i64, test_tokenization_specific_client_id.token_email, ' \
               'test_tokenization_specific_client_id.token_i32, NULL'.format(id, self.data['empty'], self.data['empty'],
                                                                             self.data['token_i32'],
                                                                             self.data['token_i64'],
                                                                             self.data['token_str'],
                                                                             self.data['token_email'])

    def build_raw_query_with_star(self):
        id = get_random_id()
        # TODO(zhars, 2021-5-20): rewrite query when sqlalchemy will support RETURNING statements
        return 'INSERT INTO test_tokenization_specific_client_id ' \
               '(id, empty, token_bytes, token_i32, token_i64, token_str, token_email) ' \
               'VALUES ({}, {}, {}, {}, {}, \'{}\', \'{}\') ' \
               'RETURNING *'.format(id, self.data['empty'], self.data['empty'], self.data['token_i32'],
                                    self.data['token_i64'], self.data['token_str'], self.data['token_email'])

    def build_delete_query_with_star_returning(self, id):
        # TODO(zhars, 2021-5-20): rewrite query when sqlalchemy will support RETURNING statements
        return 'DELETE FROM test_tokenization_specific_client_id ' \
               'WHERE id = {} ' \
               'RETURNING *'.format(id)

    def build_delete_query_with_enum_returning(self, id):
        # TODO(zhars, 2021-5-20): rewrite query when sqlalchemy will support RETURNING statements
        return 'DELETE FROM test_tokenization_specific_client_id ' \
               'WHERE id = {} ' \
               'RETURNING 0, 1 as literal, test_tokenization_specific_client_id.id, test_tokenization_specific_client_id.token_str,' \
               'test_tokenization_specific_client_id.token_i64, test_tokenization_specific_client_id.token_email, ' \
               'test_tokenization_specific_client_id.token_i32, NULL'.format(id, self.data['empty'], self.data['empty'],
                                                                             self.data['token_i32'],
                                                                             self.data['token_i64'],
                                                                             self.data['token_str'],
                                                                             self.data['token_email'])

    def insert_with_enum_and_return_data(self):
        metadata.create_all(self.engine_raw, [self.specific_client_id_table])
        self.fetch_from_2(sa.select([self.specific_client_id_table]).where(self.specific_client_id_table.c.id == id))

        source = self.fetch_from_2(self.build_raw_query_with_enum())[0]
        hidden = self.fetch_from_1(self.build_raw_query_with_enum())[0]
        return source, hidden, self.data

    def delete_and_return_data_with_star(self, id):
        metadata.create_all(self.engine_raw, [self.specific_client_id_table])
        self.fetch_from_2(sa.select([self.specific_client_id_table]).where(self.specific_client_id_table.c.id == id))

        source = self.execute_via_2(self.build_delete_query_with_star_returning(id))[0]
        row = self.fetch_from_2(
            sa.select([self.specific_client_id_table]).where(self.specific_client_id_table.c.id == id))
        self.assertEqual(len(row), 0)

        return source

    def delete_and_return_data_with_enum(self, id):
        metadata.create_all(self.engine_raw, [self.specific_client_id_table])
        self.fetch_from_2(sa.select([self.specific_client_id_table]).where(self.specific_client_id_table.c.id == id))

        source = self.execute_via_2(self.build_delete_query_with_enum_returning(id))[0]
        row = self.fetch_from_2(
            sa.select([self.specific_client_id_table]).where(self.specific_client_id_table.c.id == id))
        self.assertEqual(len(row), 0)

        return source

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
        # include literals 0, 1, null to be sure that we support non-column values too
        return self.specific_client_id_table.insert(). \
            returning(0, sa.literal('1').label('literal'),
                      self.specific_client_id_table.c.id, self.specific_client_id_table.c.token_str,
                      self.specific_client_id_table.c.token_i64,
                      self.specific_client_id_table.c.token_email, self.specific_client_id_table.c.token_i32,
                      sa.text('null')), self.data

    def build_raw_query_with_star(self):
        self.data['id'] = get_random_id()
        return self.specific_client_id_table.insert().returning(sa.literal_column('*')), self.data

    def build_delete_query_with_star_returning(self, id):
        return self.specific_client_id_table.delete().where(self.specific_client_id_table.c.id == id).returning(
            sa.literal_column('*'))

    def build_delete_query_with_enum_returning(self, id):
        return self.specific_client_id_table.delete().where(self.specific_client_id_table.c.id == id). \
            returning(0, sa.literal('1').label('literal'),
                      self.specific_client_id_table.c.id, self.specific_client_id_table.c.token_str,
                      self.specific_client_id_table.c.token_i64,
                      self.specific_client_id_table.c.token_email, self.specific_client_id_table.c.token_i32,
                      sa.text('null'))

    def build_update_query_with_star_returning(self, data):
        return self.specific_client_id_table.update().where(self.specific_client_id_table.c.id == data['id']).returning(
            sa.literal_column('*'))

    def build_update_query_with_enum_returning(self, data):
        return self.specific_client_id_table.update().where(self.specific_client_id_table.c.id == data['id']). \
            returning(0, sa.literal('1').label('literal'),
                      self.specific_client_id_table.c.id, self.specific_client_id_table.c.token_str,
                      self.specific_client_id_table.c.token_i64,
                      self.specific_client_id_table.c.token_email, self.specific_client_id_table.c.token_i32,
                      sa.text('null'))

    def insert_with_enum_and_return_data(self):
        metadata.create_all(self.engine_raw, [self.specific_client_id_table])
        self.fetch_from_2(
            sa.select([self.specific_client_id_table]).where(self.specific_client_id_table.c.id == get_random_id()))

        source_query, source_data = self.build_raw_query_with_enum()
        source = self.engine2.execute(source_query, source_data).fetchone()

        hidden_query, hidden_data = self.build_raw_query_with_enum()
        hidden = self.engine1.execute(hidden_query, hidden_data).fetchone()
        return source, hidden, self.data

    def insert_with_star_and_return_data(self):
        metadata.create_all(self.engine_raw, [self.specific_client_id_table])
        self.fetch_from_2(
            sa.select([self.specific_client_id_table]).where(self.specific_client_id_table.c.id == get_random_id()))

        source_query, data = self.build_raw_query_with_star()
        with self.engine2.connect() as connection:
            source = connection.execute(source_query, data).fetchone()

        hidden_query, data = self.build_raw_query_with_star()
        with self.engine1.connect() as connection:
            hidden = connection.execute(hidden_query, data).fetchone()
        return source, hidden, self.data

    def delete_and_return_data_with_star(self, id):
        metadata.create_all(self.engine_raw, [self.specific_client_id_table])
        self.fetch_from_2(sa.select([self.specific_client_id_table]).where(self.specific_client_id_table.c.id == id))

        source = self.engine2.execute(self.build_delete_query_with_star_returning(id)).fetchone()
        return source

    def delete_and_return_data_with_enum(self, id):
        metadata.create_all(self.engine_raw, [self.specific_client_id_table])
        self.fetch_from_2(sa.select([self.specific_client_id_table]).where(self.specific_client_id_table.c.id == id))

        source = self.engine2.execute(self.build_delete_query_with_enum_returning(id)).fetchone()
        return source

    def update_and_return_data_with_enum(self, data):
        source_query = self.build_update_query_with_enum_returning(data)
        with self.engine2.connect() as connection:
            source = connection.execute(source_query, data).fetchone()
        return source

    def update_and_return_data_with_star(self, data):
        source_query = self.build_update_query_with_star_returning(data)
        with self.engine2.connect() as connection:
            source = connection.execute(source_query, data).fetchone()
        return source


class TestEmptyPreparedStatementQueryPostgresql(BaseTestCase):
    def checkSkip(self):
        if not TEST_POSTGRESQL:
            self.skipTest("Only for postgresql")
        super().checkSkip()

    def testPassedEmptyQuery(self):
        # no matter which connector to use
        executor = AsyncpgExecutor(ConnectionArgs(
            host='localhost', port=self.ACRASERVER_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_USER_PASSWORD, raw=True,
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
            host='localhost', port=self.ACRASERVER_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_USER_PASSWORD, raw=True,
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
            host='localhost', port=self.ACRASERVER_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_USER_PASSWORD, raw=True,
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
            self.assertIn("You can either specify identifier for keys".lower(),
                          exc.exception.output.decode('utf8').lower())
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
            key_id = extract_client_id_from_cert(tls_cert=TEST_TLS_CLIENT_CERT,
                                                 extractor=self.get_identifier_extractor_type())

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


class TestInvalidCryptoEnvelope(unittest.TestCase):
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/encryptor_configs/ee_encryptor_config.yaml')

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
        # self.engine_raw.execute(default_client_id_table.insert(), data)

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


class TestPostgresqlConnectWithTLSPrefer(BaseTestCase):
    def checkSkip(self):
        if TEST_WITH_TLS or not TEST_POSTGRESQL:
            self.skipTest("running tests with TLS")

    def with_tls(self):
        return False

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        kwargs = {
            'client_id': base.TLS_CERT_CLIENT_ID_1,
            'tls_client_id_from_cert': False,
        }
        acra_kwargs.update(kwargs)
        return super().fork_acra(popen_kwargs, **acra_kwargs)

    def setUp(self):
        self.checkSkip()
        try:
            if not self.EXTERNAL_ACRA:
                self.acra = self.fork_acra()

        except:
            self.tearDown()
            raise

    def testPlainConnectionAfterDeny(self):
        async def _testPlainConnectionAfterDeny():
            # We use raw connections to specify ssl='prefer'
            # which would ask for ssl connection first.
            # And then after receiving a deny, it would ask for a plain connection
            conn = await asyncpg.connect(
                host='localhost', port=self.ACRASERVER_PORT, database=DB_NAME,
                user=DB_USER, password=DB_USER_PASSWORD,
                ssl='prefer',
                **asyncpg_connect_args
            )
            await conn.fetch('SELECT 1', timeout=STATEMENT_TIMEOUT)
            await conn.close()

        loop = asyncio.new_event_loop()  # create new to avoid concurrent usage of the loop in the current thread and allow parallel execution in the future
        loop.run_until_complete(_testPlainConnectionAfterDeny())


class TestDbFlushingOnError(BaseTransparentEncryption):
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/encryptor_configs/transparent_type_aware_decryption.yaml')

    def get_encryptor_table(self):
        encryptor_table = sa.Table(
            'test_proper_db_flushing_on_error', self.get_metadata(),
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('value_bytes', sa.LargeBinary),
        )
        return encryptor_table

    def checkSkip(self):
        if not TEST_WITH_TLS:
            self.skipTest("Test only with TLS")

    def testConnectionIsNotAborted(self):
        """
        Test that connection is not closed in case of "encoding error". Test
        that we can reuse connection for queries after.
        """

        self.encryptor_table.create(bind=self.engine_raw, checkfirst=True)
        # Insert data that will trigger decryption error
        corrupted_data = {
            'id': get_random_id(),
            'value_bytes': random_bytes(),
        }
        self.engine_raw.execute(self.encryptor_table.insert(), corrupted_data)

        with self.engine1.connect() as conn:
            # Insert some data
            data = {
                'id': get_random_id(),
                'value_bytes': random_bytes(),
            }
            conn.execute(self.encryptor_table.insert(), data)

            query = sa \
                .select([self.encryptor_table]) \
                .where(self.encryptor_table.c.id == data['id'])
            row = conn.execute(query).fetchone()
            self.assertEqual(data['value_bytes'], row['value_bytes'])

            # Expect "encoding error"
            ids = (data['id'], corrupted_data['id'])
            query = sa \
                .select([self.encryptor_table]) \
                .where(self.encryptor_table.c.id.in_(ids))

            with self.assertRaisesRegex((OperationalError, DatabaseError),
                                        'encoding error in column "value_bytes"'):
                conn.execute(query).fetchall()

            # Insert and select new data using the same connection to be sure
            # it doesn't close or get out of sync
            data = {
                'id': get_random_id(),
                'value_bytes': random_bytes(),
            }
            conn.execute(self.encryptor_table.insert(), data)

            query = sa \
                .select([self.encryptor_table]) \
                .where(self.encryptor_table.c.id == data['id'])
            row = conn.execute(query).fetchone()
            self.assertEqual(data['value_bytes'], row['value_bytes'])

    def testTransactionRollback(self):
        """
        Test that connection is not closed in case of "encoding error" and
        sqlaclchemy can do rollback in transaction after that.
        """

        self.encryptor_table.create(bind=self.engine_raw, checkfirst=True)
        # Insert data that will trigger decryption error
        corrupted_data = {
            'id': get_random_id(),
            'value_bytes': random_bytes(),
        }
        self.engine_raw.execute(self.encryptor_table.insert(), corrupted_data)
        data = {
            'id': get_random_id(),
            'value_bytes': random_bytes(),
        }
        select_data = sa \
            .select([self.encryptor_table]) \
            .where(self.encryptor_table.c.id == data['id'])

        with self.assertRaisesRegex((OperationalError, DatabaseError),
                                    'encoding error in column "value_bytes"'):
            with self.engine1.begin() as conn:
                conn.execute(self.encryptor_table.insert(), data)

                row = conn.execute(select_data).fetchone()
                self.assertEqual(data['value_bytes'], row['value_bytes'])

                # Expect "encoding error"
                ids = (data['id'], corrupted_data['id'])
                query = sa \
                    .select([self.encryptor_table]) \
                    .where(self.encryptor_table.c.id.in_(ids))

                conn.execute(query).fetchall()

        # Most db-drivers do a rollback after an exception, so check
        # that our data is not saved due to the rollback.
        row = self.engine1.execute(select_data).fetchone()
        self.assertEqual(row, None)


class TestPostgresqlDbFlushingOnError(BaseTransparentEncryption):
    ENCRYPTOR_CONFIG = get_encryptor_config(
        'tests/encryptor_configs/transparent_type_aware_decryption.yaml')

    def get_encryptor_table(self):
        encryptor_table = sa.Table(
            'test_proper_db_flushing_on_error', self.get_metadata(),
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('value_bytes', sa.LargeBinary),
        )
        return encryptor_table

    def checkSkip(self):
        if not (TEST_POSTGRESQL and TEST_WITH_TLS):
            self.skipTest("Test only for Postgres with TLS")

    def setUp(self):
        super().setUp()

        def executor_with_ssl(ssl_key, ssl_cert, port=self.ACRASERVER_PORT):
            args = ConnectionArgs(
                host='localhost', port=port, dbname=DB_NAME,
                user=DB_USER, password=DB_USER_PASSWORD,
                ssl_ca=TEST_TLS_CA,
                ssl_key=ssl_key,
                ssl_cert=ssl_cert,
                format=AsyncpgExecutor.BinaryFormat,
                raw=True,
            )
            return AsyncpgExecutor(args)

        self.executor = executor_with_ssl(
            TEST_TLS_CLIENT_KEY, TEST_TLS_CLIENT_CERT)

    def testPreparedStatementIsNotAborted(self):
        """
        Test that connection is not closed in case of "encoding error" when we
        use prepared statements.
        """

        async def test():
            self.encryptor_table.create(bind=self.engine_raw, checkfirst=True)
            # Insert data that will trigger decryption error
            corrupted_data = {
                'id': get_random_id(),
                'value_bytes': random_bytes(),
            }
            self.engine_raw.execute(
                self.encryptor_table.insert(), corrupted_data)

            conn = await self.executor.connect()
            data = {
                'id': get_random_id(),
                'value_bytes': random_bytes(),
            }
            insert_query = """
                INSERT INTO test_proper_db_flushing_on_error(id, value_bytes)
                VALUES ($1, $2)
            """
            select_query = """
                SELECT value_bytes
                FROM test_proper_db_flushing_on_error
                WHERE id = $1
            """

            await conn.execute(insert_query, data['id'], data['value_bytes'])

            row = await conn.fetchrow(select_query, data['id'])
            self.assertEqual(data['value_bytes'], row['value_bytes'])

            # Expect "encoding error"
            select_two_query = """
                SELECT value_bytes
                FROM test_proper_db_flushing_on_error
                WHERE id = $1 OR id = $2
            """

            stmt = await conn.prepare(select_two_query)

            with self.assertRaisesRegex(asyncpg.exceptions.SyntaxOrAccessError,
                                        'encoding error in column "value_bytes"'):
                await stmt.fetch(corrupted_data['id'], data['id'])

            # Insert and select new data using the same connection to be sure
            # it doesn't close or get out of sync
            data = {
                'id': get_random_id(),
                'value_bytes': random_bytes(),
            }
            await conn.execute(insert_query, data['id'], data['value_bytes'])
            row = await conn.fetchrow(select_query, data['id'])
            self.assertEqual(data['value_bytes'], row['value_bytes'])
            await conn.close()

        loop = asyncio.new_event_loop()
        loop.run_until_complete(test())

    def testTransactionPreparedRollback(self):
        """
        Test that connection is not closed in case of "encoding error" with
        prepared statement and a driver can do rollback in transaction after
        that.
        """

        async def test():
            self.encryptor_table.create(bind=self.engine_raw, checkfirst=True)
            # Insert data that will trigger decryption error
            corrupted_data = {
                'id': get_random_id(),
                'value_bytes': random_bytes(),
            }
            self.engine_raw.execute(
                self.encryptor_table.insert(), corrupted_data)
            data = {
                'id': get_random_id(),
                'value_bytes': random_bytes(),
            }

            conn = await self.executor.connect()

            insert_query = """
                INSERT INTO test_proper_db_flushing_on_error(id, value_bytes)
                VALUES ($1, $2)
            """
            select_query = """
                SELECT value_bytes
                FROM test_proper_db_flushing_on_error
                WHERE id = $1
            """

            with self.assertRaisesRegex(asyncpg.exceptions.SyntaxOrAccessError,
                                        'encoding error in column "value_bytes"'):
                async with conn.transaction():
                    await conn.execute(insert_query, data['id'], data['value_bytes'])

                    row = await conn.fetchrow(select_query, data['id'])
                    self.assertEqual(data['value_bytes'], row['value_bytes'])

                    stmt = await conn.prepare(select_query)
                    # Expect encoding error
                    await stmt.fetch(corrupted_data['id'])

            # Most db-drivers do a rollback after an exception, so check
            # that our data is not saved due to the rollback.
            row = await conn.fetchrow(select_query, data['id'])
            self.assertEqual(row, None)
            await conn.close()

        loop = asyncio.new_event_loop()
        loop.run_until_complete(test())

    def testPreparedCursor(self):
        """
        Test that connection is not closed in case of "encoding error" with
        cursor that fetches `n` rows at a time and then flushes the
        `PortalSuspended` awaiting the client response.
        """

        async def test():
            self.encryptor_table.create(bind=self.engine_raw, checkfirst=True)
            # Insert data that will trigger decryption error
            corrupted_data = {
                'id': get_random_id(),
                'value_bytes': random_bytes(),
            }
            self.engine_raw.execute(
                self.encryptor_table.insert(), corrupted_data)
            data = {
                'id': get_random_id(),
                'value_bytes': random_bytes(),
            }

            conn = await self.executor.connect()

            insert_query = """
                INSERT INTO test_proper_db_flushing_on_error(id, value_bytes)
                VALUES ($1, $2)
            """
            select_query = """
                SELECT value_bytes
                FROM test_proper_db_flushing_on_error
                WHERE id = $1
            """

            with self.assertRaisesRegex(asyncpg.exceptions.SyntaxOrAccessError,
                                        'encoding error in column "value_bytes"'):
                async with conn.transaction():
                    await conn.execute(insert_query, data['id'], data['value_bytes'])
                    row = await conn.fetchrow(select_query, data['id'])
                    self.assertEqual(data['value_bytes'], row['value_bytes'])

                    # Also insert a bunch of random values
                    for _ in range(10):
                        tmp_data = {
                            'id': get_random_id(),
                            'value_bytes': random_bytes(),
                        }
                        await conn.execute(insert_query, tmp_data['id'], tmp_data['value_bytes'])

                    stmt = await conn.prepare("""
                        SELECT id, value_bytes
                        FROM test_proper_db_flushing_on_error
                        ORDER BY random()
                    """)

                    # Expect encoding error
                    cursor = await stmt.cursor()
                    while True:
                        rows = await cursor.fetch(2)
                        if len(rows) == 0:
                            break

            row = await conn.fetchrow(select_query, data['id'])
            self.assertEqual(row, None)
            await conn.close()

        loop = asyncio.new_event_loop()
        loop.run_until_complete(test())


class TestDifferentCaseTableIdentifiersPostgreSQL(BaseTransparentEncryption):
    # Testing behavior of PostgreSQL parser: before comparing with things in encryptor config
    # - raw identifiers (table, column names) should be converted to lowercase
    # - if wrapped with double quotes, should be taken as is
    # see https://www.postgresql.org/docs/current/sql-syntax-lexical.html

    ENCRYPTOR_CONFIG = get_encryptor_config('tests/encryptor_configs/postgresql_identifiers.yaml')

    def checkSkip(self):
        if not TEST_WITH_TLS or not TEST_POSTGRESQL:
            self.skipTest("this test is only for PostgreSQL")

    def setUp(self):
        super().setUp()
        self.engine1.execute(
            'CREATE TABLE IF NOT EXISTS "lowercase_table" (id SERIAL PRIMARY KEY, "data" BYTEA, "DATA" BYTEA);')
        self.engine1.execute(
            'CREATE TABLE IF NOT EXISTS "LOWERCASE_TABLE" (id SERIAL PRIMARY KEY, "data" BYTEA, "DATA" BYTEA);')
        self.engine1.execute(
            'CREATE TABLE IF NOT EXISTS "uppercase_table" (id SERIAL PRIMARY KEY, "data" BYTEA, "DATA" BYTEA);')
        self.engine1.execute(
            'CREATE TABLE IF NOT EXISTS "UPPERCASE_TABLE" (id SERIAL PRIMARY KEY, "data" BYTEA, "DATA" BYTEA);')

    def tearDown(self):
        self.engine1.execute('DROP TABLE "lowercase_table";')
        self.engine1.execute('DROP TABLE "LOWERCASE_TABLE";')
        self.engine1.execute('DROP TABLE "uppercase_table";')
        self.engine1.execute('DROP TABLE "UPPERCASE_TABLE";')
        super().tearDown()

    def runTestCase(self,
                    table_name: str,
                    quoted_table_name: bool,
                    column_name: str,
                    quoted_column_name: bool,
                    should_match: bool):
        test_string = "test"

        if quoted_table_name:
            table_name = '"' + table_name + '"'

        if quoted_column_name:
            row_name = column_name
            column_name = '"' + column_name + '"'
        else:
            row_name = column_name.lower()

        # generate random id
        id = get_random_id()

        def check():
            # ensure it is encrypted (if should_match) or ensure it's not encrypted (if not should_match)
            if should_match:
                # ensure decrypted data matches what was inserted

                result = self.engine1.execute(f"SELECT {column_name} FROM {table_name} WHERE id={id};")
                row = result.fetchone()

                self.assertEqual(
                    bytes(row[row_name]),
                    bytes(test_string, "UTF-8"),
                    f"Table identifier {table_name}, column identifier {column_name}, did not match (decryption failed?)"
                )

                # ensure database does not contain plaintext

                result = self.engine2.execute(f"SELECT {column_name} FROM {table_name} WHERE id={id};")
                row = result.fetchone()

                self.assertNotEqual(
                    bytes(row[row_name]),
                    bytes(test_string, "UTF-8"),
                    f"Table identifier {table_name}, column identifier {column_name}, did not match (DB contains plaintext)"
                )

                result = self.engine_raw.execute(f"SELECT {column_name} FROM {table_name} WHERE id={id};")
                row = result.fetchone()

                self.assertNotEqual(
                    bytes(row[row_name]),
                    bytes(test_string, "UTF-8"),
                    f"Table identifier {table_name}, column identifier {column_name}, did not match (DB contains plaintext)"
                )
            else:
                # ensure database contains plaintext

                result = self.engine2.execute(f"SELECT {column_name} FROM {table_name} WHERE id={id};")
                row = result.fetchone()

                self.assertEqual(
                    bytes(row[row_name]),
                    bytes(test_string, "UTF-8"),
                    f"Table identifier {table_name}, column identifier {column_name}, matched (no plaintext in DB)"
                )

                result = self.engine_raw.execute(f"SELECT {column_name} FROM {table_name} WHERE id={id};")
                row = result.fetchone()

                self.assertEqual(
                    bytes(row[row_name]),
                    bytes(test_string, "UTF-8"),
                    f"Table identifier {table_name}, column identifier {column_name}, matched (no plaintext in DB)"
                )

        # insert a record
        self.engine1.execute(f"INSERT INTO {table_name} (id, {column_name}) VALUES ({id}, '{test_string}');")
        check()

        # update a record
        self.engine1.execute(f"UPDATE {table_name} SET {column_name}='{test_string}' WHERE id={id};")
        check()

    def testLowerConfigLowerQuery(self):
        # table should match, lowercase config identifier == lowercase SQL identifier
        # column should only match in quoted "DATA" case
        QUOTED, NOT_QUOTED = (True, False)
        SHOULD_MATCH, SHOULD_NOT_MATCH = (True, False)
        self.runTestCase("lowercase_table", NOT_QUOTED, "data", NOT_QUOTED, SHOULD_NOT_MATCH)
        self.runTestCase("lowercase_table", NOT_QUOTED, "data", QUOTED, SHOULD_NOT_MATCH)
        self.runTestCase("lowercase_table", NOT_QUOTED, "DATA", NOT_QUOTED, SHOULD_NOT_MATCH)
        self.runTestCase("lowercase_table", NOT_QUOTED, "DATA", QUOTED, SHOULD_MATCH)

    def testLowerConfigLowerQuotedQuery(self):
        # should match, lowercase config identifier == lowercase SQL identifier
        QUOTED, NOT_QUOTED = (True, False)
        SHOULD_MATCH, SHOULD_NOT_MATCH = (True, False)
        self.runTestCase("lowercase_table", QUOTED, "DATA", QUOTED, SHOULD_MATCH)

    def testLowerConfigUpperQuery(self):
        # should match, lowercase config identifier == lowercase SQL identifier (converted)
        QUOTED, NOT_QUOTED = (True, False)
        SHOULD_MATCH, SHOULD_NOT_MATCH = (True, False)
        self.runTestCase("LOWERCASE_TABLE", NOT_QUOTED, "DATA", QUOTED, SHOULD_MATCH)

    def testLowerConfigUpperQuotedQuery(self):
        # should NOT match, lowercase config identifier != uppercase SQL identifier
        QUOTED, NOT_QUOTED = (True, False)
        SHOULD_MATCH, SHOULD_NOT_MATCH = (True, False)
        self.runTestCase("LOWERCASE_TABLE", QUOTED, "DATA", QUOTED, SHOULD_NOT_MATCH)

    def testUpperConfigLowerQuery(self):
        # should NOT match, uppercase config identifier != lowercase SQL identifier
        QUOTED, NOT_QUOTED = (True, False)
        SHOULD_MATCH, SHOULD_NOT_MATCH = (True, False)
        self.runTestCase("uppercase_table", NOT_QUOTED, "data", NOT_QUOTED, SHOULD_NOT_MATCH)

    def testUpperConfigLowerQuotedQuery(self):
        # should NOT match, uppercase config identifier != lowercase SQL identifier
        QUOTED, NOT_QUOTED = (True, False)
        SHOULD_MATCH, SHOULD_NOT_MATCH = (True, False)
        self.runTestCase("uppercase_table", QUOTED, "data", NOT_QUOTED, SHOULD_NOT_MATCH)

    def testUpperConfigUpperQuery(self):
        # should NOT match, uppercase config identifier != lowercase SQL identifier (converted)
        QUOTED, NOT_QUOTED = (True, False)
        SHOULD_MATCH, SHOULD_NOT_MATCH = (True, False)
        self.runTestCase("UPPERCASE_TABLE", NOT_QUOTED, "data", NOT_QUOTED, SHOULD_NOT_MATCH)

    def testUpperConfigUpperQuotedQuery(self):
        # should match, uppercase config identifier == uppercase SQL identifier
        # column should match in all cases except quoted "DATA"
        QUOTED, NOT_QUOTED = (True, False)
        SHOULD_MATCH, SHOULD_NOT_MATCH = (True, False)
        self.runTestCase("UPPERCASE_TABLE", QUOTED, "data", NOT_QUOTED, SHOULD_MATCH)
        self.runTestCase("UPPERCASE_TABLE", QUOTED, "data", QUOTED, SHOULD_MATCH)
        self.runTestCase("UPPERCASE_TABLE", QUOTED, "DATA", NOT_QUOTED, SHOULD_MATCH)
        self.runTestCase("UPPERCASE_TABLE", QUOTED, "DATA", QUOTED, SHOULD_NOT_MATCH)


class TestDifferentCaseTableIdentifiersMySQL(BaseTransparentEncryption):
    # Testing behavior of MySQL parser: before comparing with things in encryptor config
    # - column identifiers should be converted to lowercase
    # - table identifiers should be used as is (in this test, as config enables case sensitivity)
    # - backquotes should have no effect on case sensitivity
    # see https://dev.mysql.com/doc/refman/8.0/en/identifier-case-sensitivity.html

    ENCRYPTOR_CONFIG = get_encryptor_config('tests/encryptor_configs/mysql_identifiers.yaml')

    def checkSkip(self):
        if not TEST_WITH_TLS or not (TEST_MYSQL or TEST_MARIADB):
            self.skipTest("this test is only for MySQL/MariaDB")

    def setUp(self):
        super().setUp()
        self.engine1.execute(
            f"CREATE TABLE IF NOT EXISTS lowercase_table (id INT PRIMARY KEY AUTO_INCREMENT, data BLOB);")
        self.engine1.execute(
            f"CREATE TABLE IF NOT EXISTS LOWERCASE_TABLE (id INT PRIMARY KEY AUTO_INCREMENT, data BLOB);")
        self.engine1.execute(
            f"CREATE TABLE IF NOT EXISTS uppercase_table (id INT PRIMARY KEY AUTO_INCREMENT, data BLOB);")
        self.engine1.execute(
            f"CREATE TABLE IF NOT EXISTS UPPERCASE_TABLE (id INT PRIMARY KEY AUTO_INCREMENT, data BLOB);")

    def tearDown(self):
        self.engine1.execute(f"DROP TABLE lowercase_table;")
        self.engine1.execute(f"DROP TABLE LOWERCASE_TABLE;")
        self.engine1.execute(f"DROP TABLE uppercase_table;")
        self.engine1.execute(f"DROP TABLE UPPERCASE_TABLE;")
        super().tearDown()

    def runTestCase(self,
                    table_name: str,
                    quoted_table_name: bool,
                    column_name: str,
                    quoted_column_name: bool,
                    should_match: bool):
        test_string = "test"

        if quoted_table_name:
            table_name = '`' + table_name + '`'

        row_name = column_name

        if quoted_column_name:
            column_name = '`' + column_name + '`'

        # generate random id
        id = get_random_id()

        def check():
            # ensure it is encrypted (if should_match) or ensure it's not encrypted (if not should_match)
            if should_match:
                # ensure decrypted data matches what was inserted

                result = self.engine1.execute(f"SELECT {column_name} FROM {table_name} WHERE id={id};")
                row = result.fetchone()

                self.assertEqual(
                    bytes(row[row_name]),
                    bytes(test_string, "UTF-8"),
                    f"Table identifier {table_name}, column identifier {column_name}, did not match (decryption failed?)"
                )

                # ensure database does not contain plaintext

                result = self.engine2.execute(f"SELECT {column_name} FROM {table_name} WHERE id={id};")
                row = result.fetchone()

                self.assertNotEqual(
                    bytes(row[row_name]),
                    bytes(test_string, "UTF-8"),
                    f"Table identifier {table_name}, column identifier {column_name} did not match (DB contains plaintext)"
                )

                result = self.engine_raw.execute(f"SELECT {column_name} FROM {table_name} WHERE id={id};")
                row = result.fetchone()

                self.assertNotEqual(
                    bytes(row[row_name]),
                    bytes(test_string, "UTF-8"),
                    f"Table identifier {table_name}, column identifier {column_name}, did not match (DB contains plaintext)"
                )
            else:
                # ensure database contains plaintext

                result = self.engine2.execute(f"SELECT {column_name} FROM {table_name} WHERE id={id};")
                row = result.fetchone()

                self.assertEqual(
                    bytes(row[row_name]),
                    bytes(test_string, "UTF-8"),
                    f"Table identifier {table_name}, column identifier {column_name}, matched (no plaintext in DB)"
                )

                result = self.engine_raw.execute(f"SELECT {column_name} FROM {table_name} WHERE id={id};")
                row = result.fetchone()

                self.assertEqual(
                    bytes(row[row_name]),
                    bytes(test_string, "UTF-8"),
                    f"Table identifier {table_name}, column identifier {column_name}, matched (no plaintext in DB)"
                )

        # insert a record
        self.engine1.execute(f"INSERT INTO {table_name} (id, {column_name}) VALUES ({id}, \"{test_string}\");")
        check()

        # update a record
        self.engine1.execute(f"UPDATE {table_name} SET {column_name}=\"{test_string}\" WHERE id={id};")
        check()

    def testLowerConfigLowerQuery(self):
        # should match, lowercase config identifier == lowercase SQL identifier
        # column identifiers are always case-insensitive in MySQL and backquotes do not affect this,
        # see https://dev.mysql.com/doc/refman/8.0/en/identifier-case-sensitivity.html
        QUOTED, NOT_QUOTED = (True, False)
        SHOULD_MATCH, SHOULD_NOT_MATCH = (True, False)
        self.runTestCase("lowercase_table", NOT_QUOTED, "data", NOT_QUOTED, SHOULD_MATCH)
        self.runTestCase("lowercase_table", NOT_QUOTED, "Data", NOT_QUOTED, SHOULD_MATCH)
        self.runTestCase("lowercase_table", QUOTED, "DATA", NOT_QUOTED, SHOULD_MATCH)
        self.runTestCase("lowercase_table", NOT_QUOTED, "data", QUOTED, SHOULD_MATCH)
        self.runTestCase("lowercase_table", QUOTED, "Data", QUOTED, SHOULD_MATCH)
        self.runTestCase("lowercase_table", NOT_QUOTED, "DATA", QUOTED, SHOULD_MATCH)

    def testLowerConfigUpperQuery(self):
        # should NOT match, lowercase config identifier == lowercase SQL identifier
        QUOTED, NOT_QUOTED = (True, False)
        SHOULD_MATCH, SHOULD_NOT_MATCH = (True, False)
        self.runTestCase("LOWERCASE_TABLE", NOT_QUOTED, "data", NOT_QUOTED, SHOULD_NOT_MATCH)

    def testUpperConfigLowerQuery(self):
        # should NOT match, uppercase config identifier != lowercase SQL identifier
        QUOTED, NOT_QUOTED = (True, False)
        SHOULD_MATCH, SHOULD_NOT_MATCH = (True, False)
        self.runTestCase("uppercase_table", NOT_QUOTED, "data", NOT_QUOTED, SHOULD_NOT_MATCH)

    def testUpperConfigUpperQuery(self):
        # should match, uppercase config identifier == uppercase SQL identifier
        QUOTED, NOT_QUOTED = (True, False)
        SHOULD_MATCH, SHOULD_NOT_MATCH = (True, False)
        self.runTestCase("UPPERCASE_TABLE", NOT_QUOTED, "data", NOT_QUOTED, SHOULD_MATCH)


class TestSigHUPHandler(AcraTranslatorMixin, BaseTestCase):
    def setUp(self):
        pass

    def copy_keystore(self):
        new_keystore = tempfile.mkdtemp()
        # we don't use shutil.copytree(..., dirs_exist_ok=True) due to unsupported in default python on centos 7, 8
        # so we remove folder and then copy
        shutil.rmtree(new_keystore)
        return shutil.copytree(base.KEYS_FOLDER.name, new_keystore)

    def find_forked_pid(self, filepath):
        with open(filepath, 'r') as f:
            for line in f:
                # CEF:0|cossacklabs|acra-translator|0.93.0|100|acra-translator process forked to PID: 914350|1|unixTime=1659577578.966
                if 'process forked to PID' in line:
                    pid = re.search(r'PID: (\d+)', line).group(1)
                    return int(pid)

    def testAcraServerReload(self):
        '''verify keys_dir changing on SIGHUP after changing config file and keep PORT same due to re-use of socket
        descriptors
        '''
        acra_args = self.get_acra_cli_args({})
        temp_keystore = self.copy_keystore()
        config = load_yaml_config('configs/acra-server.yaml')
        config.update(acra_args)
        config['keys_dir'] = temp_keystore
        config['log_to_file'] = tempfile.NamedTemporaryFile().name
        temp_config = tempfile.NamedTemporaryFile()
        dump_yaml_config(config, temp_config.name)

        acra = fork(lambda: subprocess.Popen([
            self.get_acraserver_bin_path(), '--config_file={}'.format(temp_config.name)]))
        try:
            self.wait_acraserver_connection(config['incoming_connection_string'])
        except:
            stop_process(acra)
            shutil.rmtree(temp_keystore)
            raise
        test_engine = None
        try:
            # copied from BaseTestCase._fork_acra
            base_args = get_connect_args(port=self.ACRASERVER_PORT, sslmode=SSLMODE)
            tls_args = base_args.copy()
            if TEST_WITH_TLS:
                tls_args.update(get_tls_connection_args(TEST_TLS_CLIENT_KEY, TEST_TLS_CLIENT_CERT))
            connect_str = get_engine_connection_string(
                self.get_acraserver_connection_string(self.ACRASERVER_PORT), DB_NAME)
            test_engine = sa.create_engine(connect_str, connect_args=tls_args)

            result = test_engine.execute('select 1').fetchone()
            self.assertEqual(1, result[0])

            # use another keystore and delete previous
            shutil.rmtree(temp_keystore)
            config['keys_dir'] = base.KEYS_FOLDER.name
            # turn off due to unsupported for keystore v2
            config['keystore_cache_on_start_enable'] = False
            config['keystore_cache_size'] = -1
            test_port = get_free_port()
            connection_string = self.get_acraserver_connection_string(test_port)
            config['incoming_connection_string'] = connection_string
            dump_yaml_config(config, temp_config.name)
            acra.send_signal(signal.SIGHUP)
            # close current connections
            test_engine.dispose()

            connect_str = get_engine_connection_string(
                self.get_acraserver_connection_string(self.ACRASERVER_PORT), DB_NAME)
            tls_args['port'] = self.ACRASERVER_PORT
            test_engine = sa.create_engine(connect_str, connect_args=tls_args)

            result = test_engine.execute('select 1').fetchone()
            self.assertEqual(1, result[0])

            with self.assertRaises(Exception) as exc:
                wait_connection(test_port, 1)
            self.assertEqual(exc.exception.args[0], WAIT_CONNECTION_ERROR_MESSAGE)
        finally:
            pid = self.find_forked_pid(config['log_to_file'])
            if pid:
                os.kill(pid, signal.SIGKILL)
            os.remove(config['log_to_file'])
            if test_engine:
                test_engine.dispose()
            stop_process(acra)

    def testAcraTranslatorReload(self):
        '''verify keys_dir changing on SIGHUP after changing config file and keep PORT same due to re-use of socket
        descriptors
        '''
        grpc_port = get_free_port()
        temp_keystore = self.copy_keystore()
        default_args = self.get_base_translator_args()
        default_args.update({
            'd': 1,
            'incoming_connection_close_timeout': 0,
            'logging_format': 'cef',
            'incoming_connection_grpc_string': 'tcp://127.0.0.1:{}'.format(grpc_port),
            'keys_dir': temp_keystore,
            'log_to_file': tempfile.NamedTemporaryFile().name,
            # turn off due to unsupported for keystore v2
            'keystore_cache_size': -1,
            'keystore_cache_on_start_enable': False,
        })
        config = load_yaml_config('configs/acra-translator.yaml')
        config.update(default_args)
        temp_config = tempfile.NamedTemporaryFile()
        dump_yaml_config(config, temp_config.name)

        translator = fork(lambda: subprocess.Popen([os.path.join(BINARY_OUTPUT_FOLDER, 'acra-translator'),
                                                    '--config_file={}'.format(temp_config.name)]))
        try:
            wait_connection(grpc_port)
        except:
            stop_process(translator)
            shutil.rmtree(temp_keystore)
            raise
        test_data = b'test data'
        try:
            ciphertext = self.grpc_encrypt_request(grpc_port, base.TLS_CERT_CLIENT_ID_1, test_data)
            self.assertNotEqual(ciphertext, b'')
            # load default config
            shutil.rmtree(temp_keystore)
            config['keys_dir'] = base.KEYS_FOLDER.name
            new_grpc_port = get_free_port()
            config['incoming_connection_grpc_string'] = 'tcp://127.0.0.1:{}'.format(new_grpc_port)
            dump_yaml_config(config, temp_config.name)
            translator.send_signal(signal.SIGHUP)
            try:
                wait_connection(grpc_port)
            except:
                stop_process(translator)
                raise

            plaintext = self.grpc_decrypt_request(grpc_port, base.TLS_CERT_CLIENT_ID_1, ciphertext)
            self.assertEqual(plaintext, test_data)

            with self.assertRaises(Exception) as exc:
                wait_connection(new_grpc_port, 1)
            self.assertEqual(exc.exception.args[0], WAIT_CONNECTION_ERROR_MESSAGE)
        finally:
            pid = self.find_forked_pid(config['log_to_file'])
            if pid:
                os.kill(pid, signal.SIGKILL)
            stop_process(translator)
            os.remove(config['log_to_file'])


class LimitOffsetQueryTest(BaseTransparentEncryption):
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/encryptor_configs/ee_encryptor_config.yaml')

    def get_encryptor_table(self):
        encryptor_table = sa.Table(
            'test_searchable_limit_offset', self.get_metadata(),
            sa.Column('id', sa.Integer, primary_key=True, autoincrement=False),
            sa.Column('data',
                      sa.LargeBinary(length=COLUMN_DATA_SIZE)),
            sa.Column('raw_data', sa.Text),
            sa.Column('empty', sa.LargeBinary(length=COLUMN_DATA_SIZE), nullable=False, default=b''),
        )
        return encryptor_table

    def setUp(self):
        # should be before setUp and fork_acra
        self.log_file = tempfile.NamedTemporaryFile()
        super().setUp()
        self.engine_raw.execute(sa.delete(self.encryptor_table))
        self.engine_raw.execute(sa.delete(test_table))

    def tearDown(self):
        super().tearDown()
        os.remove(self.log_file.name)

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        acra_kwargs['encryptor_config_file'] = get_test_encryptor_config(
            self.ENCRYPTOR_CONFIG)
        acra_kwargs['log_to_file'] = self.log_file.name
        return super(BaseTransparentEncryption, self).fork_acra(
            popen_kwargs, **acra_kwargs)

    def testSearchableQueries(self):
        limit_count = 3
        offset_index = 3
        searchable_data = 'searchable data'
        data_amount = 10
        testCase = collections.namedtuple('TestCase', ['query', 'limit', 'offset'])
        test_cases = [
            testCase(
                query="select id, data, raw_data, empty from {table_name} where data='{data}' "
                      "order by id LIMIT {limit}".format(
                    limit=limit_count, table_name=self.encryptor_table.name, data=searchable_data),
                limit=limit_count,
                offset=0,
            ),
            testCase(
                query="select id, data, raw_data, empty from {table_name} where data='{data}' order by id "
                      "LIMIT {limit} OFFSET {offset}".format(
                    limit=limit_count, table_name=self.encryptor_table.name, offset=offset_index, data=searchable_data),
                limit=limit_count,
                offset=offset_index,
            ),
        ]
        mysql_cases = [
            testCase(
                query="select id, data, raw_data, empty from {table_name} where data='{data}' order by id "
                      "LIMIT {offset}, {limit}".format(
                    limit=limit_count, table_name=self.encryptor_table.name, offset=offset_index, data=searchable_data),
                limit=limit_count,
                offset=offset_index,
            ),
        ]
        postgresql_cases = [
            testCase(
                query="select id, data, raw_data, empty from {table_name} where data='{data}' order by id "
                      "LIMIT ALL".format(
                    table_name=self.encryptor_table.name, data=searchable_data),
                limit=data_amount,
                offset=0,
            ),
            testCase(
                query="select id, data, raw_data, empty from {table_name} where data='{data}' order by id "
                      "LIMIT ALL OFFSET {offset}".format(
                    table_name=self.encryptor_table.name, offset=offset_index, data=searchable_data),
                limit=data_amount,
                offset=offset_index,
            ),
        ]
        if TEST_MYSQL:
            test_cases += mysql_cases
        elif TEST_POSTGRESQL:
            test_cases += postgresql_cases
        data_set = []

        for i in range(data_amount):
            if i % 2 == 0:
                row = {'id': i, 'data': searchable_data.encode('ascii'), 'raw_data': searchable_data}
            else:
                data = get_pregenerated_random_data().encode('ascii')
                row = {'id': i, 'data': data, 'raw_data': data}
            data_set.append(row)
            self.engine1.execute(self.encryptor_table.insert(), row)

        for test_case in test_cases:
            result = self.engine1.execute(sa.text(test_case.query)).fetchall()
            # simulate search logic
            expected_data_slice = [i
                                   for i in data_set
                                   if i['id'] % 2 == 0]
            expected_data_slice = expected_data_slice[test_case.offset:test_case.offset + test_case.limit]
            self.assertEqual(len(expected_data_slice), len(result))
            for i, row in enumerate(result):
                self.assertEqual(row['id'], expected_data_slice[i]['id'])
                self.assertEqual(memoryview_to_bytes(row['data']),
                                 expected_data_slice[i]['raw_data'].encode('ascii'))
                self.assertEqual(row['raw_data'], expected_data_slice[i]['raw_data'])
                self.assertEqual(row['empty'], b'')

        for test_case in test_cases:
            result = self.engine2.execute(sa.text(test_case.query)).fetchall()
            self.assertEqual(len(result), 0)

    def get_testcases(self, data_amount):
        # randomly chosen
        limit_count = 3
        offset_index = 3
        testCase = collections.namedtuple('TestCase', ['query', 'limit', 'offset'])
        test_cases = [
            testCase(
                query='select id, data, raw_data, empty from {table_name} order by id LIMIT {limit}'.format(
                    limit=limit_count, table_name=test_table.name),
                limit=limit_count,
                offset=0,
            ),
            testCase(
                query='select id, data, raw_data, empty from {table_name} order by id LIMIT {limit} OFFSET {offset}'.format(
                    limit=limit_count, table_name=test_table.name, offset=offset_index),
                limit=limit_count,
                offset=offset_index,
            ),
        ]
        failure_cases = []
        mysql_cases = [
            testCase(
                query='select id, data, raw_data, empty from {table_name} order by id LIMIT {offset}, {limit}'.format(
                    limit=limit_count, table_name=test_table.name, offset=offset_index),
                limit=limit_count,
                offset=offset_index,
            ),
        ]
        postgresql_cases = [
            testCase(
                query='select id, data, raw_data, empty from {table_name} order by id LIMIT ALL'.format(
                    table_name=test_table.name),
                limit=data_amount,
                offset=0,
            ),
            testCase(
                query='select id, data, raw_data, empty from {table_name} order by id LIMIT ALL OFFSET {offset}'.format(
                    table_name=test_table.name, offset=offset_index),
                limit=data_amount,
                offset=offset_index,
            ),
        ]
        if TEST_MYSQL:
            test_cases += mysql_cases
            failure_cases += postgresql_cases
        elif TEST_POSTGRESQL:
            test_cases += postgresql_cases
            failure_cases += mysql_cases
        return test_cases, failure_cases

    def testAcrastructRead(self):
        client_id = base.TLS_CERT_CLIENT_ID_1
        server_public1 = read_storage_public_key(client_id, base.KEYS_FOLDER.name)
        data_set = []
        for i in range(10):
            data = get_pregenerated_random_data()
            acra_struct = create_acrastruct(
                data.encode('ascii'), server_public1)
            self.log(storage_client_id=client_id,
                     data=acra_struct, expected=data.encode('ascii'))
            row = {'id': i, 'data': acra_struct, 'raw_data': data}
            data_set.append(row)
            self.engine1.execute(test_table.insert(), row)

        test_cases, _ = self.get_testcases(len(data_set))
        for test_case in test_cases:
            result = self.engine1.execute(sa.text(test_case.query)).fetchall()
            expected_data_slice = data_set[test_case.offset:test_case.offset + test_case.limit]
            self.assertEqual(len(expected_data_slice), len(result))
            for i, row in enumerate(result):
                self.assertEqual(row['id'], expected_data_slice[i]['id'])
                self.assertEqual(memoryview_to_bytes(row['data']),
                                 expected_data_slice[i]['raw_data'].encode('ascii'))
                self.assertEqual(row['raw_data'], expected_data_slice[i]['raw_data'])
                self.assertEqual(row['empty'], b'')

        # requests by another client without permissions
        for test_case in test_cases:
            result = self.engine2.execute(sa.text(test_case.query)).fetchall()
            expected_data_slice = data_set[test_case.offset:test_case.offset + test_case.limit]
            self.assertEqual(len(expected_data_slice), len(result))
            for i, row in enumerate(result):
                self.assertEqual(row['id'], expected_data_slice[i]['id'])
                self.assertNotEqual(
                    memoryview_to_bytes(row['data']), expected_data_slice[i]['raw_data'].encode('ascii'))
                self.assertEqual(row['raw_data'], expected_data_slice[i]['raw_data'])
                self.assertEqual(row['empty'], b'')

    def testReadAcrastructInAcrastruct(self):
        client_id = base.TLS_CERT_CLIENT_ID_1
        server_public1 = read_storage_public_key(client_id, base.KEYS_FOLDER.name)

        # use one sample of outer invalid acrastruct
        fake_offset = (3 + 45 + 84) - 4
        incorrect_data = get_pregenerated_random_data()
        suffix_data = get_pregenerated_random_data()[:10]
        fake_acra_struct = create_acrastruct(
            incorrect_data.encode('ascii'), server_public1)[:fake_offset]
        data_set = []
        for i in range(10):
            correct_data = get_pregenerated_random_data()
            inner_acra_struct = create_acrastruct(
                correct_data.encode('ascii'), server_public1)
            data = fake_acra_struct + inner_acra_struct + suffix_data.encode('ascii')
            correct_data = correct_data + suffix_data
            self.log(storage_client_id=client_id,
                     data=data,
                     expected=fake_acra_struct + correct_data.encode('ascii'))
            row = {'id': i, 'data': data, 'raw_data': correct_data}
            data_set.append(row)
            self.engine1.execute(test_table.insert(), row)

        test_cases, _ = self.get_testcases(len(data_set))
        for test_case in test_cases:
            result = self.engine1.execute(sa.text(test_case.query)).fetchall()
            expected_data_slice = data_set[test_case.offset:test_case.offset + test_case.limit]
            self.assertEqual(len(expected_data_slice), len(result))
            for i, row in enumerate(result):
                self.assertEqual(memoryview_to_bytes(row['data'][fake_offset:]), row['raw_data'].encode('utf-8'))
                self.assertEqual(memoryview_to_bytes(row['data'][:fake_offset]), fake_acra_struct[:fake_offset])

                self.assertEqual(row['id'], expected_data_slice[i]['id'])
                self.assertEqual(row['raw_data'], expected_data_slice[i]['raw_data'])
                self.assertEqual(row['empty'], b'')

        for test_case in test_cases:
            result = self.engine2.execute(sa.text(test_case.query)).fetchall()
            expected_data_slice = data_set[test_case.offset:test_case.offset + test_case.limit]
            self.assertEqual(len(expected_data_slice), len(result))
            for i, row in enumerate(result):
                self.assertNotEqual(
                    memoryview_to_bytes(row['data'][fake_offset:]).decode('ascii', errors='ignore'),
                    row['raw_data'])

                self.assertEqual(row['id'], expected_data_slice[i]['id'])
                self.assertEqual(row['raw_data'], expected_data_slice[i]['raw_data'])
                self.assertEqual(row['empty'], b'')

    def testFailureQueries(self):
        _, failure_cases = self.get_testcases(10)
        for test_case in failure_cases:
            # clear all previous log entries
            self.log_file.truncate(0)
            with self.assertRaises(sa.exc.ProgrammingError) as exc:
                # check that database doesn't pass it too
                self.engine1.execute(sa.text(test_case.query))
            if TEST_POSTGRESQL:
                self.assertIsInstance(exc.exception.orig, psycopg2.errors.SyntaxError)
            elif TEST_MYSQL:
                self.assertIsInstance(exc.exception.orig, pymysql.err.ProgrammingError)
                self.assertIn("You have an error in your SQL syntax;", exc.exception.orig.args[1])
            else:
                raise exc.exception

            # check that acra-server didn't parse it too
            # find our query in the log output
            # next after the query should be log entry about parsing error
            success = False
            has_break = False
            with open(self.log_file.name, 'r', encoding='utf8') as f:
                while True:
                    line = f.readline()
                    if not line:
                        break
                    if test_case.query in line:
                        # search expected query until ReadyForQueryPacket that means that command lifecycle is finished
                        while True:
                            new_line = f.readline()
                            if not new_line:
                                break
                            self.assertNotIn('ReadyForQueryPacket', new_line)
                            if 'ignoring error of non parsed sql statement' in new_line:
                                if TEST_POSTGRESQL:
                                    self.assertIn(
                                        "PostgreSQL dialect doesn't allow 'LIMIT offset, limit' syntax of LIMIT "
                                        "statements", new_line)
                                elif TEST_MYSQL:
                                    self.assertIn("MySQL dialect doesn't allow 'LIMIT ALL' syntax of LIMIT statements",
                                                  new_line)
                                else:
                                    self.fail('Unexpected test environment')
                                success = True
                                break
                        break
            if not success:
                self.fail('Not found expected log entry in the acra-server\'s log output')


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
        pass


class TestPoisonRecordShutdown(BasePoisonRecordTest):
    SHUTDOWN = True

    def testShutdown(self):
        """fetch data from table by specifying row id

        acra-server should find poison record on data decryption failure
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

        acra-server should find poison record on data decryption failure
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

        acra-server should find poison record on data decryption failure
        """
        row_id = get_random_id()
        poison_record = self.get_poison_record_data()
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

    def testShutdownTranslatorHTTP(self):
        """check poison record decryption via acra-translator using HTTP v1 API

        acra-translator should match poison record on data decryption failure
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
                response = self.http_decrypt_request(http_port, base.TLS_CERT_CLIENT_ID_1, data)
        self.assertEqual(exc.exception.args[0].args[0], 'Connection aborted.')

        # check that port not listening anymore
        with self.assertRaises(Exception) as exc:
            wait_connection(http_port, count=1, sleep=0)
        self.assertEqual(exc.exception.args[0], WAIT_CONNECTION_ERROR_MESSAGE)

    def testShutdownTranslatorgRPC(self):
        """check poison record decryption via acra-translator using gRPC API

        acra-translator should match poison record on data decryption failure
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
                response = self.grpc_decrypt_request(grpc_port, base.TLS_CERT_CLIENT_ID_1, data,
                                                     raise_exception_on_failure=True)
        self.assertEqual(exc.exception.code(), grpc.StatusCode.UNAVAILABLE)

        # check that port not listening anymore
        with self.assertRaises(Exception) as exc:
            wait_connection(grpc_port, count=1, sleep=0)
        self.assertEqual(exc.exception.args[0], WAIT_CONNECTION_ERROR_MESSAGE)


class TestPoisonRecordShutdownWithAcraBlock(TestPoisonRecordShutdown):
    def get_poison_record_data(self):
        return get_poison_record_with_acrablock()


class TestEncryptorSettingReset(SeparateMetadataMixin, AcraCatchLogsMixin, BaseTokenization):

    def checkSkip(self):
        pass

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        acra_kwargs.update({
            # no need to switch between users
            # we can run with and without TLS
            'client_id': base.TLS_CERT_CLIENT_ID_1,
            'tls_client_id_from_cert': False,
        })
        return super().fork_acra(popen_kwargs, **acra_kwargs)

    def setUp(self):
        super().setUp()
        self.engine_raw.execute(sa.text('create table if not exists empty_table(id integer);'))
        self.engine_raw.execute(sa.text('insert into empty_table values (1);'))
        # create with sqlalchemy to encapsulate db specific differences
        self.test_table = sa.Table(
            'test_tokenization_default_client_id', self.get_metadata(),
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('nullable_column', sa.Text, nullable=True),
            sa.Column('empty', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('token_i32', sa.Integer()),
            sa.Column('token_i64', sa.BigInteger()),
            sa.Column('token_str', sa.Text),
            sa.Column('token_bytes', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('token_email', sa.Text),
        )
        self.get_metadata().create_all(self.engine_raw, [self.test_table])

    def tearDown(self):
        if hasattr(self, 'test_table'):
            self.get_metadata().drop_all(self.engine_raw, [self.test_table])
        logs = self.read_log(self.acra)
        print(logs)
        super().tearDown()

    def test_select(self):
        """verify that after valid SELECT query over transparently encrypted data same config will not be applied
        for the next query and will be cleared"""
        encrypted_row = {'nullable_column': None, 'empty': b'', 'token_i32': random_int32(),
                         'token_i64': random_int64(),
                         'token_str': random_str(), 'token_bytes': random_bytes(), 'token_email': random_email()}
        with self.engine1.begin() as connection:
            connection.execute(self.test_table.insert(encrypted_row))
            result = connection.execute(sa.select(self.test_table)).fetchall()
            self.assertEqual(len(result), 1)
            for row in result:
                for k, v in encrypted_row.items():
                    self.assertEqual(row[k], v)
            sql = ("select 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h' from empty_table join ("
                   "select 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h' from empty_table) t on true;")
            connection.execute(sa.text(sql)).fetchall()
            logs = self.read_log(self.acra)
            self.assertIn("can't extract columns from select statement", logs.lower())
        raw_data = self.engine_raw.execute(sa.select(self.test_table)).fetchall()
        for row in raw_data:
            for k, v in encrypted_row.items():
                # skip empty and nullable
                if not v:
                    continue
                self.assertNotEqual(row[k], v)

    def test_insert_returning(self):
        """verify that after valid INSERT query with RETURNING over transparently encrypted data same config will not
        be applied for the next query and will be cleared
        """

        if not (base.TEST_POSTGRESQL or TEST_MARIADB):
            self.skipTest("MySQL doesn't support returning statement for insert")

        encrypted_row = {'nullable_column': None, 'empty': b'', 'token_i32': random_int32(),
                         'token_i64': random_int64(),
                         'token_str': random_str(), 'token_bytes': random_bytes(), 'token_email': random_email()}
        with self.engine1.begin() as connection:
            if TEST_POSTGRESQL:
                result = connection.execute(
                    sa.insert(self.test_table).values(encrypted_row).returning(self.test_table)).fetchall()
            elif TEST_MARIADB:
                # use raw sql due to only sqlalchemy 2.x supports returning for mariadb
                # TODO use sqlalchemy core after upgrading from 1.x to 2.x version
                columns = ','.join(['nullable_column', 'empty', 'token_i32', 'token_i64', 'token_str',
                                    'token_bytes', 'token_email'])
                result = connection.execute(sa.text(
                    "insert into {} ({}) values ( :nullable_column, :empty, :token_i32, :token_i64, :token_str, :token_bytes, :token_email) returning {};".format(
                        self.test_table.name, columns, columns)), encrypted_row
                ).fetchall()
            else:
                self.fail("Invalid environment")
            self.assertEqual(len(result), 1)
            for row in result:
                for k, v in encrypted_row.items():
                    self.assertEqual(row[k], v)
            sql = ("select 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h' from empty_table join ("
                   "select 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h' from empty_table) t on true;")
            connection.execute(sa.text(sql)).fetchall()
            logs = self.read_log(self.acra)
            self.assertIn("can't extract columns from select statement", logs.lower())
        raw_data = self.engine_raw.execute(sa.select(self.test_table)).fetchall()
        for row in raw_data:
            for k, v in encrypted_row.items():
                # skip empty and nullable
                if not v:
                    continue
                self.assertNotEqual(row[k], v)


class TestSQLPreparedStatements(AcraCatchLogsMixin):
    ENCRYPTOR_CONFIG = base.get_encryptor_config('tests/encryptor_configs/ee_prepared_statements_sql.yaml')

    prepared_sql_statements_table_data_types = {
        'id': 'int',
        'default_client_id': 'bytea',
        'number': 'int',
        'specified_client_id': 'bytea',
        'raw_data': 'bytea',
        'searchable': 'bytea',
        'empty': 'bytea',
        'nullable': 'text',
        'masking': 'bytea',
        'token_bytes': 'bytea',
        'token_email': 'text',
        'token_str': 'text',
        'token_i32': 'int4',
        'token_i64': 'int8',
    }

    test_prepared_sql_statements_table = sa.Table(
        'test_prepared_sql_statements', base.metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('specified_client_id',
                  sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),
        sa.Column('default_client_id',
                  sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),

        sa.Column('number', sa.Integer),
        sa.Column('raw_data', sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),
        sa.Column('nullable', sa.Text, nullable=True),
        sa.Column('searchable', sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),
        sa.Column('empty', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False, default=b''),
        sa.Column('token_i32', sa.Integer(), nullable=False, default=1),
        sa.Column('token_i64', sa.BigInteger(), nullable=False, default=1),
        sa.Column('token_str', sa.Text, nullable=False, default=''),
        sa.Column('token_bytes', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False, default=b''),
        sa.Column('token_email', sa.Text, nullable=False, default=''),
        sa.Column('masking', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False, default=b''),
    )

    default_client_id_table = sa.Table(
        'test_tokenization_default_client_id', base.metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('nullable_column', sa.Text, nullable=True),
        sa.Column('empty', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False, default=b''),
        sa.Column('token_i32', sa.Integer()),
        sa.Column('token_i64', sa.BigInteger()),
        sa.Column('token_str', sa.Text),
        sa.Column('token_bytes', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False, default=b''),
        sa.Column('token_email', sa.Text),
        extend_existing=True,
    )

    def tearDown(self):
        self.engine_raw.execute(self.test_prepared_sql_statements_table.delete())
        base.metadata.remove(self.test_prepared_sql_statements_table)

        self.engine_raw.execute(self.default_client_id_table.delete())
        base.metadata.remove(self.default_client_id_table)

        super(TestSQLPreparedStatements, self).tearDown()

    def get_test_prepared_sql_statements_table_context(self):
        return {
            'id': base.get_random_id(),
            'default_client_id': base.get_pregenerated_random_data().encode('ascii'),
            'number': base.get_random_id(),
            'specified_client_id': base.get_pregenerated_random_data().encode('ascii'),
            'raw_data': base.get_pregenerated_random_data().encode('ascii'),
            'searchable': base.get_pregenerated_random_data().encode('ascii'),
            'empty': b'',
            'nullable': None,
            'masking': base.get_pregenerated_random_data().encode('ascii'),
            'token_bytes': base.get_pregenerated_random_data().encode('ascii'),
            'token_email': base.get_pregenerated_random_data(),
            'token_str': base.get_pregenerated_random_data(),
            'token_i32': base.random.randint(0, 2 ** 16),
            'token_i64': base.random.randint(0, 2 ** 32),
        }

    def get_specified_client_id(self):
        return base.TLS_CERT_CLIENT_ID_1

    def testSearchableTokenizationDefaultClientID(self):
        base.metadata.create_all(self.engine_raw, [self.default_client_id_table])
        self.engine1.execute(self.default_client_id_table.delete())

        row_id = 1
        data = {
            'id': row_id,
            'nullable_column': None,
            'empty': b'',
            'token_i32': random_int32(),
            'token_i64': random_int64(),
            'token_str': random_str(),
            'token_bytes': random_bytes(),
            'token_email': random_email(),
        }
        data_types = {
            'id': 'int',
            'nullable_column': 'text',
            'empty': 'bytea',
            'token_i32': 'int4',
            'token_i64': 'int8',
            'token_str': 'text',
            'token_bytes': 'bytea',
            'token_email': 'text',
        }

        # create SQL prepared statements in DB with name `insert_data` with engine1
        self.prepare(prepared_name='insert_data', engine=self.engine1, query=self.default_client_id_table.insert(),
                     data_types=data_types)

        # expect fail on the prepare query with the same name
        try:
            self.prepare(prepared_name='insert_data', engine=self.engine1, query=self.default_client_id_table.insert(),
                         data_types=data_types)
        except Exception:
            self.assertIn("PreparedStatement already stored in registry", self.read_log(self.acra))
            pass

        self.execute_prepared(prepared_name='insert_data', engine=self.engine1, data=data)

        # create SQL prepared statements in DB with name `select_all_data` with engine1
        self.prepare(prepared_name='select_all_data', engine=self.engine1, query=self.default_client_id_table.select())
        rows = self.execute_prepared_fetch(prepared_name='select_all_data', engine=self.engine1)
        self.assertEqual(len(rows), 1)

        for k in ('token_i32', 'token_i64', 'token_str', 'token_bytes', 'token_email'):
            if isinstance(rows[0][k], memoryview) and isinstance(data[k], bytes):
                self.assertEqual(bytes(rows[0][k]), data[k])
            else:
                self.assertEqual(rows[0][k], data[k])

        columns = {
            'token_i32': self.default_client_id_table.c.token_i32,
            'token_i64': self.default_client_id_table.c.token_i64,
            'token_str': self.default_client_id_table.c.token_str,
            'token_bytes': self.default_client_id_table.c.token_bytes,
            'token_email': self.default_client_id_table.c.token_email,
        }

        query = sa.select(self.default_client_id_table).where(columns['token_i64'] == data['token_i64'])

        self.prepare(prepared_name='select_data_by_field', query=query, engine=self.engine1, data_types={
            'token_i64': 'int8'
        }, literal_binds=False)
        rows = self.execute_prepared_fetch(prepared_name='select_data_by_field', engine=self.engine1, data={
            'token_i64': data['token_i64']
        })
        self.assertEqual(len(rows), 1)

        for k in ('token_i32', 'token_i64', 'token_str', 'token_bytes', 'token_email'):
            if isinstance(rows[0][k], memoryview) and isinstance(data[k], bytes):
                self.assertEqual(bytes(rows[0][k]), data[k])
            else:
                self.assertEqual(rows[0][k], data[k])

    # currently Acra fully doesn`t support multi-statement queries for PostgreSQL
    # https://www.postgresql.org/docs/15/protocol-flow.html#PROTOCOL-FLOW-MULTI-STATEMENT
    # but still it should be able to proxy such queries w/o failures
    def testMultiStatementQuery(self):
        # expected query to be run successfully
        self.engine1.execute('prepare t1 as (select 1); execute t1;')
        self.assertIn(
            "nil pendingPacket in handleQueryDataPacket: potential Multi-Statement query not supported by Acra",
            self.read_log(self.acra))

    def testSearchableEncryption(self):
        base.metadata.create_all(self.engine_raw, [self.test_prepared_sql_statements_table])
        self.engine1.execute(self.test_prepared_sql_statements_table.delete())

        context = self.get_test_prepared_sql_statements_table_context()

        search_term = context['searchable']

        # Insert searchable data and some additional different rows
        self.prepare(prepared_name='insert_data', engine=self.engine2,
                     query=self.test_prepared_sql_statements_table.insert(),
                     data_types=self.prepared_sql_statements_table_data_types)
        self.execute_prepared(prepared_name='insert_data', engine=self.engine2, data=context)

        extra_rows_count = 5
        temp_context = context.copy()
        while extra_rows_count != 0:
            new_data = base.get_pregenerated_random_data().encode('utf-8')
            if new_data != search_term:
                temp_context['searchable'] = new_data
                temp_context['id'] = context['id'] + extra_rows_count
                self.execute_prepared(prepared_name='insert_data', engine=self.engine2, data=temp_context)
                extra_rows_count -= 1

        query = sa.select(self.test_prepared_sql_statements_table).where(
            self.test_prepared_sql_statements_table.c.searchable == search_term)

        self.prepare(prepared_name='select_data_by_field', engine=self.engine2, query=query, data_types={
            'searchable': 'bytea'
        }, literal_binds=False)
        rows = self.execute_prepared_fetch(prepared_name='select_data_by_field', engine=self.engine2, data={
            'searchable': search_term
        })
        self.assertEqual(len(rows), 1)

        # should be decrypted
        self.assertEqual(bytes(rows[0]['default_client_id']), context['default_client_id'])
        # should be as is
        self.assertEqual(rows[0]['number'], context['number'])
        self.assertEqual(bytes(rows[0]['raw_data']), context['raw_data'])
        # expected data to be detokenized
        self.assertEqual(rows[0]['token_i32'], context['token_i32'])
        self.assertEqual(rows[0]['token_i64'], context['token_i64'])
        # other data should be encrypted
        self.assertNotEqual(bytes(rows[0]['specified_client_id']), context['specified_client_id'])

        # read raw data via engine1 to check data is encrypted
        query = sa.select(self.test_prepared_sql_statements_table).where(
            self.test_prepared_sql_statements_table.c.id == context['id'])

        self.prepare(prepared_name='select_data_by_id', engine=self.engine1, query=query, data_types={
            'id': 'int'
        }, literal_binds=False)
        row = self.execute_prepared_fetch(prepared_name='select_data_by_id', engine=self.engine1, data={
            'id': context['id']
        })[0]

        # expected data to tokenized
        self.assertNotEqual(row['token_i32'], context['token_i32'])
        self.assertNotEqual(row['token_i64'], context['token_i64'])
        self.assertNotEqual(row['default_client_id'], context['default_client_id'])
        # expect data is decrypted
        self.assertEqual(bytes(row['specified_client_id']), context['specified_client_id'])

        query = sa.delete(self.test_prepared_sql_statements_table).where(
            self.test_prepared_sql_statements_table.c.searchable == search_term)

        # delete search record with prepared
        self.prepare(prepared_name='delete_data_by_field', engine=self.engine2, query=query, data_types={
            'searchable': 'bytea'
        }, literal_binds=False)
        self.execute_prepared(prepared_name='delete_data_by_field', engine=self.engine2, data={
            'searchable': search_term
        })

        rows = self.execute_prepared_fetch(prepared_name='select_data_by_field', engine=self.engine2, data={
            'searchable': search_term
        })
        self.assertEqual(len(rows), 0)

    def testSearchableEncryptionWithDeallocate(self):
        base.metadata.create_all(self.engine_raw, [self.test_prepared_sql_statements_table])
        self.engine1.execute(self.test_prepared_sql_statements_table.delete())

        context = self.get_test_prepared_sql_statements_table_context()

        search_term = context['searchable']

        # Insert searchable data and some additional different rows
        self.prepare(prepared_name='insert_data', engine=self.engine2,
                     query=self.test_prepared_sql_statements_table.insert(),
                     data_types=self.prepared_sql_statements_table_data_types)
        self.execute_prepared(prepared_name='insert_data', engine=self.engine2, data=context)

        extra_rows_count = 5
        temp_context = context.copy()
        while extra_rows_count != 0:
            new_data = base.get_pregenerated_random_data().encode('utf-8')
            if new_data != search_term:
                temp_context['searchable'] = new_data
                temp_context['id'] = context['id'] + extra_rows_count
                self.execute_prepared(prepared_name='insert_data', engine=self.engine2, data=temp_context)
                extra_rows_count -= 1

        query = sa.select(self.test_prepared_sql_statements_table).where(
            self.test_prepared_sql_statements_table.c.searchable == search_term)

        self.prepare(prepared_name='select_data_by_field', engine=self.engine2, query=query, data_types={
            'searchable': 'bytea'
        }, literal_binds=False)
        rows = self.execute_prepared_fetch(prepared_name='select_data_by_field', engine=self.engine2, data={
            'searchable': search_term
        })
        self.assertEqual(len(rows), 1)

        # deallocate prepared statement from DB and delete statement from session registry
        self.deallocate(prepared_name='select_data_by_field', engine=self.engine2)

        # expect fail on the deallocated prepared statement
        try:
            self.execute_prepared_fetch(prepared_name='select_data_by_field', engine=self.engine2,
                                        data={'searchable': search_term})
        except Exception:
            self.assertIn("no prepared statement with given name", self.read_log(self.acra))
            pass

        new_token_int = base.random.randint(0, 2 ** 16)

        update_query = sa.update(self.test_prepared_sql_statements_table). \
            where(self.test_prepared_sql_statements_table.c.searchable == search_term).values(
            token_i32=new_token_int)

        # update search record with prepared
        self.prepare(prepared_name='update_data_by_field', engine=self.engine2, query=update_query, data_types={
            'searchable': 'bytea',
            'token_i32': 'int'
        }, literal_binds=False)
        self.execute_prepared(prepared_name='update_data_by_field', engine=self.engine2, data={
            'searchable': search_term,
            'token_i32': new_token_int
        })

        self.prepare(prepared_name='select_data_by_field', engine=self.engine2, query=query, data_types={
            'searchable': 'bytea'
        }, literal_binds=False)
        rows = self.execute_prepared_fetch(prepared_name='select_data_by_field', engine=self.engine2, data={
            'searchable': search_term
        })
        self.assertEqual(len(rows), 1)

        # should be decrypted
        self.assertEqual(bytes(rows[0]['default_client_id']), context['default_client_id'])
        # should be as is
        self.assertEqual(rows[0]['number'], context['number'])
        self.assertEqual(bytes(rows[0]['raw_data']), context['raw_data'])
        self.assertEqual(rows[0]['token_i32'], new_token_int)
        # other data should be encrypted
        self.assertNotEqual(bytes(rows[0]['specified_client_id']), context['specified_client_id'])


class TestPostgresSQLPreparedStatements(TestSQLPreparedStatements, BaseTokenizationWithBinaryPostgreSQL):
    pass


class BaseTestMySQLPreparedStatementsFromSQL(AcraCatchLogsMixin):
    ENCRYPTOR_CONFIG = base.get_encryptor_config('tests/encryptor_configs/ee_prepared_statements_sql.yaml')

    prepared_sql_statements_table_data_types = {
        'id': 'int',
        'default_client_id': 'bytea',
        'number': 'int',
        'specified_client_id': 'bytea',
        'raw_data': 'bytea',
        'searchable': 'bytea',
        'empty': 'bytea',
        'nullable': 'text',
        'masking': 'bytea',
        'token_bytes': 'bytea',
        'token_email': 'text',
        'token_str': 'text',
        'token_i32': 'int4',
        'token_i64': 'int8',
    }

    test_prepared_sql_statements_table = sa.Table(
        'test_prepared_sql_statements', base.metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('specified_client_id',
                  sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),
        sa.Column('default_client_id',
                  sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),

        sa.Column('number', sa.Integer),
        sa.Column('raw_data', sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),
        sa.Column('nullable', sa.Text, nullable=True),
        sa.Column('searchable', sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),
        sa.Column('empty', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False, default=b''),
        sa.Column('token_i32', sa.Integer(), nullable=False, default=1),
        sa.Column('token_i64', sa.BigInteger(), nullable=False, default=1),
        sa.Column('token_str', sa.Text, nullable=False, default=''),
        sa.Column('token_bytes', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False, default=b''),
        sa.Column('token_email', sa.Text, nullable=False, default=''),
        sa.Column('masking', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False, default=b''),
        extend_existing=True,
    )

    default_client_id_table = sa.Table(
        'test_tokenization_default_client_id', base.metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('nullable_column', sa.Text, nullable=True),
        sa.Column('empty', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False, default=b''),
        sa.Column('token_i32', sa.Integer()),
        sa.Column('token_i64', sa.BigInteger()),
        sa.Column('token_str', sa.Text),
        sa.Column('token_bytes', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False, default=b''),
        sa.Column('token_email', sa.Text),
        extend_existing=True,
    )

    def tearDown(self):
        self.engine_raw.execute(self.test_prepared_sql_statements_table.delete())
        base.metadata.remove(self.test_prepared_sql_statements_table)

        self.engine_raw.execute(self.default_client_id_table.delete())
        base.metadata.remove(self.default_client_id_table)

        super(BaseTestMySQLPreparedStatementsFromSQL, self).tearDown()

    def get_test_prepared_sql_statements_table_context(self):
        return {
            'id': base.get_random_id(),
            'default_client_id': base.get_pregenerated_random_data().encode('ascii'),
            'number': base.get_random_id(),
            'specified_client_id': base.get_pregenerated_random_data().encode('ascii'),
            'raw_data': base.get_pregenerated_random_data().encode('ascii'),
            'searchable': base.get_pregenerated_random_data().encode('ascii'),
            'empty': b'',
            'nullable': None,
            'masking': base.get_pregenerated_random_data().encode('ascii'),
            'token_bytes': base.get_pregenerated_random_data().encode('ascii'),
            'token_email': base.get_pregenerated_random_data(),
            'token_str': base.get_pregenerated_random_data(),
            'token_i32': base.random.randint(0, 2 ** 16),
            'token_i64': base.random.randint(0, 2 ** 32),
        }

    def get_specified_client_id(self):
        return base.TLS_CERT_CLIENT_ID_1

    def testSearchableEncryptionWithQueriesFromArg(self):
        base.metadata.create_all(self.engine_raw, [self.test_prepared_sql_statements_table])
        self.engine1.execute(self.test_prepared_sql_statements_table.delete())

        context = self.get_test_prepared_sql_statements_table_context()
        search_term = context['searchable']

        # Insert searchable data and some additional different rows
        _, columns_order = self.prepare_from_arg(prepared_name='insert_data', engine=self.engine2,
                                                 query=self.test_prepared_sql_statements_table.insert(),
                                                 data_types=self.prepared_sql_statements_table_data_types)

        args = []
        for key in columns_order:
            arg = 'test_prepared_sql_statements__{}'.format(key)
            args.append(arg)
            self.set_arg(arg_name=arg, engine=self.engine2, value=context[key])

        self.execute_prepared(prepared_name='insert_data', engine=self.engine2, args=args)

        extra_rows_count = 5
        while extra_rows_count != 0:
            new_data = base.get_pregenerated_random_data().encode('utf-8')
            if new_data != search_term:
                new_id = context['id'] + extra_rows_count
                self.set_arg(arg_name='test_prepared_sql_statements__searchable', engine=self.engine2, value=new_data)
                self.set_arg(arg_name='test_prepared_sql_statements__id', engine=self.engine2, value=new_id)
                self.execute_prepared(prepared_name='insert_data', engine=self.engine2, args=args)
                extra_rows_count -= 1

        query = sa.select(self.test_prepared_sql_statements_table).where(
            self.test_prepared_sql_statements_table.c.searchable == search_term)

        self.prepare_from_arg(prepared_name='select_data_by_field', engine=self.engine2, query=query, data_types={
            'searchable': 'bytea'
        }, literal_binds=False)

        args = []
        arg = 'test_prepared_sql_statements__searchable'
        args.append(arg)
        self.set_arg(arg_name=arg, engine=self.engine2, value=search_term)

        rows = self.execute_prepared_fetch(prepared_name='select_data_by_field', engine=self.engine2, args=args)
        self.assertEqual(len(rows), 1)
        #
        # should be decrypted
        self.assertEqual(bytes(rows[0]['default_client_id']), context['default_client_id'])
        # should be as is
        self.assertEqual(rows[0]['number'], context['number'])
        self.assertEqual(bytes(rows[0]['raw_data']), context['raw_data'])
        # expected data to be detokenized
        self.assertEqual(rows[0]['token_i32'], context['token_i32'])
        self.assertEqual(rows[0]['token_i64'], context['token_i64'])
        # other data should be encrypted
        self.assertNotEqual(bytes(rows[0]['specified_client_id']), context['specified_client_id'])

        # read raw data via engine1 to check data is encrypted
        query = sa.select(self.test_prepared_sql_statements_table).where(
            self.test_prepared_sql_statements_table.c.id == context['id'])

        self.prepare_from_arg(prepared_name='select_data_by_id', engine=self.engine1, query=query, data_types={
            'id': 'int'
        }, literal_binds=False)

        args = []
        arg = 'test_prepared_sql_statements__id'
        args.append(arg)
        self.set_arg(arg_name=arg, engine=self.engine1, value=context['id'])

        row = self.execute_prepared_fetch(prepared_name='select_data_by_id', engine=self.engine1, args=args)[0]

        # expected data to tokenized
        self.assertNotEqual(row['token_i32'], context['token_i32'])
        self.assertNotEqual(row['token_i64'], context['token_i64'])
        self.assertNotEqual(row['default_client_id'], context['default_client_id'])
        # expect data is decrypted
        self.assertEqual(bytes(row['specified_client_id']), context['specified_client_id'])

        query = sa.delete(self.test_prepared_sql_statements_table).where(
            self.test_prepared_sql_statements_table.c.searchable == search_term)

        # delete search record with prepared
        self.prepare_from_arg(prepared_name='delete_data_by_field', engine=self.engine2, query=query, data_types={
            'searchable': 'bytea'
        }, literal_binds=False)

        args = []
        arg = 'test_prepared_sql_statements__searchable'
        args.append(arg)
        self.set_arg(arg_name=arg, engine=self.engine2, value=search_term)

        self.execute_prepared(prepared_name='delete_data_by_field', engine=self.engine2, args=args)

        rows = self.execute_prepared_fetch(prepared_name='select_data_by_field', engine=self.engine2, args=args)
        self.assertEqual(len(rows), 0)

    def testSearchableEncryption(self):
        base.metadata.create_all(self.engine_raw, [self.test_prepared_sql_statements_table])
        self.engine1.execute(self.test_prepared_sql_statements_table.delete())

        context = self.get_test_prepared_sql_statements_table_context()
        search_term = context['searchable']

        # Insert searchable data and some additional different rows
        _, columns_order = self.prepare(prepared_name='insert_data', engine=self.engine2,
                                        query=self.test_prepared_sql_statements_table.insert(),
                                        data_types=self.prepared_sql_statements_table_data_types)

        args = []
        for key in columns_order:
            arg = 'test_prepared_sql_statements__{}'.format(key)
            args.append(arg)
            self.set_arg(arg_name=arg, engine=self.engine2, value=context[key])

        self.execute_prepared(prepared_name='insert_data', engine=self.engine2, args=args)

        extra_rows_count = 5
        while extra_rows_count != 0:
            new_data = base.get_pregenerated_random_data().encode('utf-8')
            if new_data != search_term:
                new_id = context['id'] + extra_rows_count
                self.set_arg(arg_name='test_prepared_sql_statements__searchable', engine=self.engine2, value=new_data)
                self.set_arg(arg_name='test_prepared_sql_statements__id', engine=self.engine2, value=new_id)
                self.execute_prepared(prepared_name='insert_data', engine=self.engine2, args=args)
                extra_rows_count -= 1

        query = sa.select(self.test_prepared_sql_statements_table).where(
            self.test_prepared_sql_statements_table.c.searchable == search_term)

        self.prepare(prepared_name='select_data_by_field', engine=self.engine2, query=query, data_types={
            'searchable': 'bytea'
        }, literal_binds=False)

        args = []
        arg = 'test_prepared_sql_statements__searchable'
        args.append(arg)
        self.set_arg(arg_name=arg, engine=self.engine2, value=search_term)

        rows = self.execute_prepared_fetch(prepared_name='select_data_by_field', engine=self.engine2, args=args)
        self.assertEqual(len(rows), 1)

        # should be decrypted
        self.assertEqual(bytes(rows[0]['default_client_id']), context['default_client_id'])
        # should be as is
        self.assertEqual(rows[0]['number'], context['number'])
        self.assertEqual(bytes(rows[0]['raw_data']), context['raw_data'])
        # expected data to be detokenized
        self.assertEqual(rows[0]['token_i32'], context['token_i32'])
        self.assertEqual(rows[0]['token_i64'], context['token_i64'])
        # other data should be encrypted
        self.assertNotEqual(bytes(rows[0]['specified_client_id']), context['specified_client_id'])

        # check prepare with replace on search hash, e.g:
        # prepare name from 'select * from table where search = \'value\''
        self.prepare_with_literal_binds(prepared_name='select_data_by_field_value', engine=self.engine2, query=query)

        rows = self.execute_prepared_fetch(prepared_name='select_data_by_field_value', engine=self.engine2, args=[])
        self.assertEqual(len(rows), 1)

        # read raw data via engine1 to check data is encrypted
        query = sa.select(self.test_prepared_sql_statements_table).where(
            self.test_prepared_sql_statements_table.c.id == context['id'])

        self.prepare(prepared_name='select_data_by_id', engine=self.engine1, query=query, data_types={
            'id': 'int'
        }, literal_binds=False)

        args = []
        arg = 'test_prepared_sql_statements__id'
        args.append(arg)
        self.set_arg(arg_name=arg, engine=self.engine1, value=context['id'])

        row = self.execute_prepared_fetch(prepared_name='select_data_by_id', engine=self.engine1, args=args)[0]

        # expected data to tokenized
        self.assertNotEqual(row['token_i32'], context['token_i32'])
        self.assertNotEqual(row['token_i64'], context['token_i64'])
        self.assertNotEqual(row['default_client_id'], context['default_client_id'])
        # expect data is decrypted
        self.assertEqual(bytes(row['specified_client_id']), context['specified_client_id'])

        query = sa.delete(self.test_prepared_sql_statements_table).where(
            self.test_prepared_sql_statements_table.c.searchable == search_term)

        # delete search record with prepared
        self.prepare(prepared_name='delete_data_by_field', engine=self.engine2, query=query, data_types={
            'searchable': 'bytea'
        }, literal_binds=False)

        args = []
        arg = 'test_prepared_sql_statements__searchable'
        args.append(arg)
        self.set_arg(arg_name=arg, engine=self.engine2, value=search_term)

        self.execute_prepared(prepared_name='delete_data_by_field', engine=self.engine2, args=args)

        rows = self.execute_prepared_fetch(prepared_name='select_data_by_field', engine=self.engine2, args=args)
        self.assertEqual(len(rows), 0)

    def testSearchableEncryptionWithDeallocate(self):
        base.metadata.create_all(self.engine_raw, [self.test_prepared_sql_statements_table])
        self.engine1.execute(self.test_prepared_sql_statements_table.delete())

        context = self.get_test_prepared_sql_statements_table_context()
        search_term = context['searchable']

        # Insert searchable data and some additional different rows
        _, columns_order = self.prepare(prepared_name='insert_data', engine=self.engine2,
                                        query=self.test_prepared_sql_statements_table.insert(),
                                        data_types=self.prepared_sql_statements_table_data_types)

        args = []
        for key in columns_order:
            arg = 'test_prepared_sql_statements__{}'.format(key)
            args.append(arg)
            self.set_arg(arg_name=arg, engine=self.engine2, value=context[key])

        self.execute_prepared(prepared_name='insert_data', engine=self.engine2, args=args)

        extra_rows_count = 5
        while extra_rows_count != 0:
            new_data = base.get_pregenerated_random_data().encode('utf-8')
            if new_data != search_term:
                new_id = context['id'] + extra_rows_count
                self.set_arg(arg_name='test_prepared_sql_statements__searchable', engine=self.engine2, value=new_data)
                self.set_arg(arg_name='test_prepared_sql_statements__id', engine=self.engine2, value=new_id)
                self.execute_prepared(prepared_name='insert_data', engine=self.engine2, args=args)
                extra_rows_count -= 1

        query = sa.select(self.test_prepared_sql_statements_table).where(
            self.test_prepared_sql_statements_table.c.searchable == search_term)

        self.prepare(prepared_name='select_data_by_field', engine=self.engine2, query=query, data_types={
            'searchable': 'bytea'
        }, literal_binds=False)

        args = []
        arg = 'test_prepared_sql_statements__searchable'
        args.append(arg)
        self.set_arg(arg_name=arg, engine=self.engine2, value=search_term)

        rows = self.execute_prepared_fetch(prepared_name='select_data_by_field', engine=self.engine2, args=args)
        self.assertEqual(len(rows), 1)

        # deallocate prepared statement from DB and delete statement from session registry
        self.deallocate(prepared_name='select_data_by_field', engine=self.engine2)

        # expect fail on the deallocated prepared statement
        try:
            self.execute_prepared_fetch(prepared_name='select_data_by_field', engine=self.engine2, args=args)
        except Exception:
            self.assertIn("prepared statement not present in registry", self.read_log(self.acra))
            pass

        new_token_int = base.random.randint(0, 2 ** 16)

        update_query = sa.update(self.test_prepared_sql_statements_table). \
            where(self.test_prepared_sql_statements_table.c.searchable == search_term).values(
            token_i32=new_token_int)

        # update search record with prepared
        self.prepare(prepared_name='update_data_by_field', engine=self.engine2, query=update_query, data_types={
            'searchable': 'bytea',
            'token_i32': 'int'
        }, literal_binds=False)

        args = []
        arg = 'test_prepared_sql_statements__token_i32'
        args.append(arg)
        self.set_arg(arg_name=arg, engine=self.engine2, value=new_token_int)

        arg = 'test_prepared_sql_statements__searchable'
        args.append(arg)
        self.set_arg(arg_name=arg, engine=self.engine2, value=search_term)

        self.execute_prepared(prepared_name='update_data_by_field', engine=self.engine2, args=args)

        self.prepare(prepared_name='select_data_by_field', engine=self.engine2, query=query, data_types={
            'searchable': 'bytea'
        }, literal_binds=False)

        args = ['test_prepared_sql_statements__searchable']
        rows = self.execute_prepared_fetch(prepared_name='select_data_by_field', engine=self.engine2, args=args)
        self.assertEqual(len(rows), 1)

        # should be decrypted
        self.assertEqual(bytes(rows[0]['default_client_id']), context['default_client_id'])
        # should be as is
        self.assertEqual(rows[0]['number'], context['number'])
        self.assertEqual(bytes(rows[0]['raw_data']), context['raw_data'])
        self.assertEqual(rows[0]['token_i32'], new_token_int)
        # other data should be encrypted
        self.assertNotEqual(bytes(rows[0]['specified_client_id']), context['specified_client_id'])


class TestMySQLPreparedStatementsFromSQL(BaseTestMySQLPreparedStatementsFromSQL, BaseTokenizationWithBinaryBindMySQL):
    pass


if __name__ == '__main__':
    import xmlrunner

    output_path = os.environ.get('TEST_XMLOUTPUT', '')
    if output_path:
        with open(output_path, 'wb') as output:
            unittest.main(testRunner=xmlrunner.XMLTestRunner(output=output))
    else:
        unittest.main()
