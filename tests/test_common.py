import http
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from base64 import b64encode
from distutils.dir_util import copy_tree
from urllib.parse import urlparse

import grpc
import psycopg2
import psycopg2.errors
import psycopg2.extras
import pymysql
import redis
import requests
import sqlalchemy as sa

import api_pb2
import api_pb2_grpc
import base


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
            base.TEST_TLS_CLIENT_KEY, base.TEST_TLS_CLIENT_CERT, acra_port, 'localhost')
        self.executor2 = self.executor_with_ssl(
            base.TEST_TLS_CLIENT_2_KEY, base.TEST_TLS_CLIENT_2_CERT, acra_port, 'localhost')
        self.raw_executor = self.executor_with_ssl(
            base.TEST_TLS_CLIENT_KEY, base.TEST_TLS_CLIENT_CERT, base.DB_PORT, base.DB_HOST)

    def executor_with_ssl(self, ssl_key, ssl_cert, port, host):
        if port is None:
            port = self.ACRASERVER_PORT
        args = base.ConnectionArgs(
            host=host, port=port, dbname=base.DB_NAME,
            user=base.DB_USER, password=base.DB_USER_PASSWORD,
            ssl_ca=base.TEST_TLS_CA,
            ssl_key=ssl_key,
            ssl_cert=ssl_cert,
            format=self.FORMAT,
            raw=self.RAW_EXECUTOR,
        )
        return self.executor_cls(args)


class Psycopg3ExecutorMixin(ExecutorMixin):
    executor_cls = base.Psycopg3Executor


class AsyncpgExecutorMixin(ExecutorMixin):
    executor_cls = base.AsyncpgExecutor


class MysqlExecutorMixin(ExecutorMixin):
    executor_cls = base.MysqlExecutor


class KeyMakerTest(unittest.TestCase):
    def test_key_length(self):
        key_size = 32

        def random_keys(size):
            if base.KEYSTORE_VERSION == 'v1':
                # Keystore v1 uses simple binary data for keys
                value = os.urandom(size)
            elif base.KEYSTORE_VERSION == 'v2':
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

            return {base.ACRA_MASTER_KEY_VAR_NAME: b64encode(value)}

        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(subprocess.CalledProcessError) as exc:
                subprocess.check_output(
                    [os.path.join(base.BINARY_OUTPUT_FOLDER, 'acra-keymaker'),
                     '--keystore={}'.format(base.KEYSTORE_VERSION),
                     '--keys_output_dir={}'.format(folder),
                     '--keys_public_output_dir={}'.format(folder)],
                    env=random_keys(key_size - 1))

        with tempfile.TemporaryDirectory() as folder:
            subprocess.check_output(
                [os.path.join(base.BINARY_OUTPUT_FOLDER, 'acra-keymaker'),
                 '--keystore={}'.format(base.KEYSTORE_VERSION),
                 '--keys_output_dir={}'.format(folder),
                 '--keys_public_output_dir={}'.format(folder)],
                env=random_keys(key_size))

        with tempfile.TemporaryDirectory() as folder:
            subprocess.check_output(
                [os.path.join(base.BINARY_OUTPUT_FOLDER, 'acra-keymaker'),
                 '--keystore={}'.format(base.KEYSTORE_VERSION),
                 '--keys_output_dir={}'.format(folder),
                 '--keys_public_output_dir={}'.format(folder)],
                env=random_keys(key_size * 2))

    def test_gen_keys_with_empty_client_id(self):
        # keys not needed client_id for generation
        with tempfile.TemporaryDirectory() as folder:
            subprocess.check_output(
                [os.path.join(base.BINARY_OUTPUT_FOLDER, 'acra-keymaker'),
                 '--keystore={}'.format(base.KEYSTORE_VERSION),
                 '--keys_output_dir={}'.format(folder),
                 "--client_id=''",
                 '--generate_poisonrecord_keys',
                 '--generate_log_key',
                 '--keys_public_output_dir={}'.format(folder)])

            # check that keymaker will no fail on case of not created directory
            subprocess.check_output(
                [os.path.join(base.BINARY_OUTPUT_FOLDER, 'acra-keymaker'),
                 '--client_id=',
                 '--tls_cert={}'.format(base.TEST_TLS_CLIENT_CERT),
                 '--keystore={}'.format(base.KEYSTORE_VERSION),
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
        return base.get_tcp_connection_string(port)

    def get_identifier_extractor_type(self):
        return base.TLS_CLIENT_ID_SOURCE_DN


class TLSAuthenticationBySerialNumberMixin(TLSAuthenticationByDistinguishedNameMixin):
    def get_identifier_extractor_type(self):
        return base.TLS_CLIENT_ID_SOURCE_SERIAL


class BaseTestCase(PrometheusMixin, unittest.TestCase):
    DEBUG_LOG = base.get_bool_env('DEBUG_LOG', True)
    # for debugging with manually runned acra-server
    EXTERNAL_ACRA = False
    ACRASERVER_PORT = int(os.environ.get('TEST_ACRASERVER_PORT', 10003))
    ACRASERVER_PROMETHEUS_PORT = int(os.environ.get('TEST_ACRASERVER_PROMETHEUS_PORT', 11004))
    ACRA_BYTEA = 'pgsql_hex_bytea'
    DB_BYTEA = 'hex'
    WHOLECELL_MODE = False
    TEST_DATA_LOG = False

    acra = base.ProcessStub()

    def checkSkip(self):
        if not base.TEST_WITH_TLS:
            self.skipTest("running tests with TLS")

    def wait_acraserver_connection(self, connection_string: str, *args, **kwargs):
        if connection_string.startswith('unix'):
            return base.wait_unix_socket(
                base.socket_path_from_connection_string(connection_string),
                *args, **kwargs)
        else:
            return base.wait_connection(connection_string.split(':')[-1])

    def get_acraserver_connection_string(self, port=None):
        if not port:
            port = self.ACRASERVER_PORT
        return base.get_tcp_connection_string(port)

    def get_acraserver_api_connection_string(self, port=None):
        if not port:
            port = self.ACRASERVER_PORT + 1
        elif port == self.ACRASERVER_PORT:
            port = port + 1
        return base.acra_api_connection_string(port)

    def get_acraserver_bin_path(self):
        return os.path.join(base.BINARY_OUTPUT_FOLDER, 'acra-server')

    def with_tls(self):
        return base.TEST_WITH_TLS

    def get_acra_cli_args(self, acra_kwargs):
        connection_string = self.get_acraserver_connection_string(
            acra_kwargs.get('incoming_connection_port', self.ACRASERVER_PORT))
        api_connection_string = self.get_acraserver_api_connection_string(
            acra_kwargs.get('incoming_connection_api_port')
        )
        args = {
            'db_host': base.DB_HOST,
            'db_port': base.DB_PORT,
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
            'http_api_tls_transport_enable': 'true',
            'keystore_cache_on_start_enable': 'false',
            'keys_dir': base.KEYS_FOLDER.name,
        }
        # keystore v2 doest not support caching, disable it for now
        if base.KEYSTORE_VERSION == 'v2':
            args['keystore_cache_size'] = -1
        if base.TEST_WITH_TRACING:
            args['tracing_log_enable'] = 'true'
            if base.TEST_TRACE_TO_JAEGER:
                args['tracing_jaeger_enable'] = 'true'
        if self.LOG_METRICS:
            args['incoming_connection_prometheus_metrics_string'] = self.get_prometheus_address(
                self.ACRASERVER_PROMETHEUS_PORT)
        if self.with_tls():
            args['tls_key'] = base.TEST_TLS_SERVER_KEY
            args['tls_cert'] = base.TEST_TLS_SERVER_CERT
            args['tls_ca'] = base.TEST_TLS_CA
            args['tls_auth'] = base.ACRA_TLS_AUTH
            args['tls_ocsp_url'] = 'http://localhost:{}'.format(base.OCSP_SERVER_PORT)
            args['tls_ocsp_from_cert'] = 'use'
            args['tls_crl_url'] = 'http://localhost:{}/crl.pem'.format(base.CRL_HTTP_SERVER_PORT)
            args['tls_crl_from_cert'] = 'use'
        else:
            # Explicitly disable certificate validation by default since otherwise we may end up
            # in a situation when some certificate contains OCSP or CRL URI while corresponding
            # services were not started by this script (because TLS testing was disabled)
            args['tls_ocsp_from_cert'] = 'ignore'
            args['tls_crl_from_cert'] = 'ignore'
        if base.TEST_MYSQL:
            args['mysql_enable'] = 'true'
            args['postgresql_enable'] = 'false'
        args.update(acra_kwargs)
        return args

    def _fork_acra(self, acra_kwargs, popen_kwargs):
        logging.info("fork acra")
        args = self.get_acra_cli_args(acra_kwargs)
        for path in [base.socket_path_from_connection_string(args['incoming_connection_string']),
                     base.socket_path_from_connection_string(args['incoming_connection_api_string'])]:
            try:
                os.remove(path)
            except:
                pass

        if not popen_kwargs:
            popen_kwargs = {}
        cli_args = sorted(['--{}={}'.format(k, v) for k, v in args.items() if v is not None])
        print("acra-server args: {}".format(' '.join(cli_args)))
        if self.EXTERNAL_ACRA:
            # set version from default config
            config = base.load_default_config('acra-server', skip_keys=[])
            args['version'] = config['version']
            # if want to use own instance of acra, put a breakpoint on return base.ProcessStub()
            # and run acra-server with --config_file=/tmp/config.yml parameter,
            # restart on every breakpoint stop to pull updated parameters and reset keys from memory cache
            base.dump_yaml_config(args, '/tmp/config.yml')
            return base.ProcessStub()
        process = base.fork(lambda: subprocess.Popen([self.get_acraserver_bin_path()] + cli_args,
                                                     **popen_kwargs))
        try:
            self.wait_acraserver_connection(args['incoming_connection_string'])
        except:
            base.stop_process(process)
            raise
        logging.info("fork acra finished [pid={}]".format(process.pid))
        return process

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        return self._fork_acra(acra_kwargs, popen_kwargs)

    def fork_translator(self, translator_kwargs, popen_kwargs=None):
        logging.info("fork acra-translator")
        default_config = base.load_default_config("acra-translator")
        default_args = {
            'incoming_connection_close_timeout': 0,
            'keys_dir': base.KEYS_FOLDER.name,
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
        if base.KEYSTORE_VERSION == 'v2':
            default_config['keystore_cache_size'] = -1
        if base.TEST_WITH_TRACING:
            default_config['tracing_log_enable'] = 1
            if base.TEST_TRACE_TO_JAEGER:
                default_config['tracing_jaeger_enable'] = 1

        cli_args = ['--{}={}'.format(k, v) for k, v in default_config.items()]

        translator = base.fork(
            lambda: subprocess.Popen([os.path.join(base.BINARY_OUTPUT_FOLDER, 'acra-translator')] + cli_args,
                                     **popen_kwargs))
        try:
            if default_config['incoming_connection_grpc_string']:
                base.wait_connection(urlparse(default_config['incoming_connection_grpc_string']).port)
            if default_config['incoming_connection_http_string']:
                base.wait_connection(urlparse(default_config['incoming_connection_http_string']).port)
        except:
            base.stop_process(translator)
            raise
        return translator

    def setUp(self):
        self.checkSkip()
        try:
            self.acra = self.fork_acra()

            base_args = base.get_connect_args(port=self.ACRASERVER_PORT, sslmode=base.SSLMODE)

            tls_args_1 = base_args.copy()
            tls_args_1.update(base.get_tls_connection_args(base.TEST_TLS_CLIENT_KEY, base.TEST_TLS_CLIENT_CERT))
            connect_str = base.get_engine_connection_string(
                self.get_acraserver_connection_string(self.ACRASERVER_PORT), base.DB_NAME)
            self.engine1 = sa.create_engine(connect_str, connect_args=tls_args_1)

            tls_args_2 = base_args.copy()
            tls_args_2.update(base.get_tls_connection_args(base.TEST_TLS_CLIENT_2_KEY, base.TEST_TLS_CLIENT_2_CERT))
            self.engine2 = sa.create_engine(
                base.get_engine_connection_string(
                    self.get_acraserver_connection_string(self.ACRASERVER_PORT), base.DB_NAME), connect_args=tls_args_2)

            self.engine_raw = sa.create_engine(
                '{}://{}:{}/{}'.format(base.DB_DRIVER, base.DB_HOST, base.DB_PORT, base.DB_NAME),
                connect_args=base.connect_args)

            self.engines = [self.engine1, self.engine2, self.engine_raw]

            base.metadata.create_all(self.engine_raw)
            self.engine_raw.execute('delete from test;')
            for engine in self.engines:
                count = 0
                # try with sleep if acra not up yet
                while True:
                    try:
                        if base.TEST_MYSQL:
                            engine.execute("select 1;")
                        else:
                            engine.execute(
                                "UPDATE pg_settings SET setting = '{}' "
                                "WHERE name = 'bytea_output'".format(self.DB_BYTEA))
                        break
                    except Exception as e:
                        time.sleep(base.SETUP_SQL_COMMAND_TIMEOUT)
                        count += 1
                        if count == base.SQL_EXECUTE_TRY_COUNT:
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
            base.metadata.drop_all(self.engine_raw)
        except:
            pass
        for engine in getattr(self, 'engines', []):
            engine.dispose()
        base.stop_process([getattr(self, 'acra', base.ProcessStub())])
        base.send_signal_by_process_name('acra-server', signal.SIGKILL)

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
            'master_key': base.get_master_key(),
            'key_name': key_name(),
            'data': b64encode(data).decode('ascii'),
            'expected': b64encode(expected).decode('ascii'),
        }

        if storage_client_id:
            public_key = base.read_storage_public_key(storage_client_id, base.KEYS_FOLDER.name)
            private_key = base.read_storage_private_key(base.KEYS_FOLDER.name, storage_client_id)
            log_entry['public_key'] = b64encode(public_key).decode('ascii')
            log_entry['private_key'] = b64encode(private_key).decode('ascii')

        if poison_key:
            public_key = base.read_poison_public_key(base.KEYS_FOLDER.name)
            private_key = base.read_poison_private_key(base.KEYS_FOLDER.name)
            log_entry['public_key'] = b64encode(public_key).decode('ascii')
            log_entry['private_key'] = b64encode(private_key).decode('ascii')
            log_entry['poison_record'] = b64encode(base.get_poison_record()).decode('ascii')

        logging.debug("test log: {}".format(json.dumps(log_entry)))


class AcraCatchLogsMixin(object):
    def __init__(self, *args, **kwargs):
        self.log_files = {}
        super(AcraCatchLogsMixin, self).__init__(*args, **kwargs)

    def read_log(self, process):
        with open(self.log_files[process].name, 'r', errors='replace',
                  encoding='utf-8') as f:
            log = f.read()
            print(log)
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
            base.stop_process(process)


class AcraTranslatorMixin(object):
    def get_identifier_extractor_type(self):
        return base.TLS_CLIENT_ID_SOURCE_DN

    def get_http_schema(self):
        return 'https'

    def get_http_default_kwargs(self):
        return {
            'timeout': base.REQUEST_TIMEOUT,
            'verify': base.TEST_TLS_CA,
            # https://requests.readthedocs.io/en/master/user/advanced/#client-side-certificates
            # first crt, second key
            'cert': (base.TEST_TLS_CLIENT_CERT, base.TEST_TLS_CLIENT_KEY),
        }

    def get_base_translator_args(self):
        return {
            'tls_ocsp_from_cert': 'ignore',
            'tls_crl_from_cert': 'ignore',
            'tls_key': base.abs_path(base.TEST_TLS_SERVER_KEY),
            'tls_cert': base.abs_path(base.TEST_TLS_SERVER_CERT),
            'tls_ca': base.TEST_TLS_CA,
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
        with open(base.TEST_TLS_CA, 'rb') as ca_file, open(base.TEST_TLS_CLIENT_KEY, 'rb') as key_file, open(
                base.TEST_TLS_CLIENT_CERT,
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
                    timeout=base.SOCKET_CONNECT_TIMEOUT)
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
                    timeout=base.SOCKET_CONNECT_TIMEOUT)
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
        if not base.TEST_WITH_REDIS:
            self.skipTest("test only with Redis")
        elif not base.TEST_WITH_TLS:
            self.skipTest("running tests only with TLS")

    def setUp(self):
        redis_hostport = os.environ.get('TEST_REDIS_HOSTPORT', 'localhost:6379')
        redis_host, redis_port = redis_hostport.split(':')
        self.redis_keys_client = redis.Redis(
            host=redis_host, port=int(redis_port), db=self.TEST_REDIS_KEYS_DB,
            ssl=base.TEST_WITH_TLS, ssl_keyfile=base.TEST_TLS_CLIENT_KEY, ssl_certfile=base.TEST_TLS_CLIENT_CERT,
            ssl_ca_certs=base.TEST_TLS_CA, socket_timeout=base.SOCKET_CONNECT_TIMEOUT)
        self.redis_tokens_client = redis.Redis(
            host=redis_host, port=int(redis_port), db=self.TEST_REDIS_TOKEN_DB,
            ssl=base.TEST_WITH_TLS, ssl_keyfile=base.TEST_TLS_CLIENT_KEY, ssl_certfile=base.TEST_TLS_CLIENT_CERT,
            ssl_ca_certs=base.TEST_TLS_CA, socket_timeout=base.SOCKET_CONNECT_TIMEOUT)
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
        if not base.TEST_POSTGRESQL:
            self.skipTest("test only PostgreSQL")

    FORMAT = base.AsyncpgExecutor.BinaryFormat

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
        if not base.TEST_MYSQL:
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
        return base.get_poison_record()

    def setUp(self):
        super(BasePoisonRecordTest, self).setUp()
        try:
            self.log(poison_key=True, data=base.get_poison_record())
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
        base.logger.info("run command '{}'".format(' '.join(args)))
        process = subprocess.Popen(args, stderr=subprocess.PIPE)
        try:
            _, stderr = process.communicate(timeout=5)  # 5 second enough to start binary and stop execution with error
        except:
            raise
        finally:
            process.kill()
        base.logger.debug(stderr)
        return stderr.decode('utf-8')

    def assertProcessHasNotMessage(self, args, status_code, expectedMessage):
        base.logger.info("run command '{}'".format(' '.join(args)))
        process = subprocess.Popen(args, stderr=subprocess.PIPE, cwd=os.getcwd())
        try:
            _, stderr = process.communicate(timeout=1)
            base.logger.debug(stderr)
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
        if not base.TEST_WITH_TLS:
            self.skipTest("Test works only with TLS support on db side")
        self.acra_writer_id = base.extract_client_id_from_cert(tls_cert=base.TEST_TLS_CLIENT_CERT,
                                                               extractor=self.get_identifier_extractor_type())
        self.assertEqual(base.create_client_keypair_from_certificate(tls_cert=base.TEST_TLS_CLIENT_CERT,
                                                                     extractor=self.get_identifier_extractor_type(),
                                                                     keys_dir=base.KEYS_FOLDER.name), 0)
        # generate encryption keys for second certificate too
        self.assertEqual(base.create_client_keypair_from_certificate(tls_cert=base.TEST_TLS_CLIENT_2_CERT,
                                                                     extractor=self.get_identifier_extractor_type(),
                                                                     keys_dir=base.KEYS_FOLDER.name), 0)
        try:
            if not self.EXTERNAL_ACRA:
                # start acra with configured TLS
                self.acra = self.fork_acra(
                    tls_key=base.abs_path(base.TEST_TLS_SERVER_KEY),
                    tls_cert=base.abs_path(base.TEST_TLS_SERVER_CERT),
                    tls_ca=base.TEST_TLS_CA,
                    keys_dir=base.KEYS_FOLDER.name,
                    tls_identifier_extractor_type=self.get_identifier_extractor_type())

            # create two engines which should use different client's certificates for authentication
            base_args = base.get_connect_args(port=self.ACRASERVER_PORT, sslmode='require')
            tls_args_1 = base_args.copy()
            tls_args_1.update(base.get_tls_connection_args(base.TEST_TLS_CLIENT_KEY, base.TEST_TLS_CLIENT_CERT))
            self.engine1 = sa.create_engine(
                base.get_engine_connection_string(self.get_acraserver_connection_string(self.ACRASERVER_PORT),
                                                  base.DB_NAME),
                connect_args=tls_args_1)

            tls_args_2 = base_args.copy()
            tls_args_2.update(base.get_tls_connection_args(base.TEST_TLS_CLIENT_2_KEY, base.TEST_TLS_CLIENT_2_CERT))
            self.engine2 = sa.create_engine(
                base.get_engine_connection_string(self.get_acraserver_connection_string(self.ACRASERVER_PORT),
                                                  base.DB_NAME),
                connect_args=tls_args_2)

            self.engine_raw = sa.create_engine(
                '{}://{}:{}/{}'.format(base.DB_DRIVER, base.DB_HOST, base.DB_PORT, base.DB_NAME),
                connect_args=base.connect_args)

            self.engines = [self.engine1, self.engine2, self.engine_raw]

            base.metadata.create_all(self.engine_raw)
            self.engine_raw.execute('delete from test;')
            for engine in self.engines:
                count = 0
                # try with sleep if acra not up yet
                while True:
                    try:
                        if base.TEST_MYSQL:
                            engine.execute("select 1;")
                        else:
                            engine.execute(
                                "UPDATE pg_settings SET setting = '{}' "
                                "WHERE name = 'bytea_output'".format(self.DB_BYTEA))
                        break
                    except Exception as e:
                        time.sleep(base.SETUP_SQL_COMMAND_TIMEOUT)
                        count += 1
                        if count == base.SQL_EXECUTE_TRY_COUNT:
                            raise
        except:
            self.tearDown()
            raise


class SeparateMetadataMixin:

    def get_metadata(self) -> sa.MetaData:
        if not getattr(self, 'metadata', None):
            self.metadata = sa.MetaData()
        return self.metadata

    def setUp(self):
        super().setUp()
        self.get_metadata().create_all(self.engine_raw)

    def tearDown(self):
        self.get_metadata().drop_all(self.engine_raw)
        self.metadata = None
        super().tearDown()


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
    processes = [getattr(self, 'acra', base.ProcessStub())]
    base.stop_process(processes)
    base.send_signal_by_process_name('acra-server', signal.SIGKILL)


class TestDirectTLSAuthenticationFailures(TLSAuthenticationBySerialNumberMixin, BaseTestCase):
    # override setUp/tearDown from BaseTestCase to avoid extra initialization
    def setUp(self):
        if not base.TEST_WITH_TLS:
            self.skipTest("Test works only with TLS support on db side")

    def tearDown(self):
        pass

    def testInvalidClientAuthConfiguration(self):
        # try to start server with --tls_auth=0 and extracting client_id from TLS which is invalid together
        # because tls_auth=0 doesn't require client's certificate on handshake
        self.assertEqual(
            base.create_client_keypair_from_certificate(tls_cert=base.TEST_TLS_CLIENT_CERT,
                                                        keys_dir=base.KEYS_FOLDER.name), 0)
        # generate encryption keys for second certificate too
        self.assertEqual(
            base.create_client_keypair_from_certificate(tls_cert=base.TEST_TLS_CLIENT_2_CERT,
                                                        keys_dir=base.KEYS_FOLDER.name), 0)
        with self.assertRaises(Exception) as exc:
            self.fork_acra(
                tls_key=base.abs_path(base.TEST_TLS_SERVER_KEY),
                tls_cert=base.abs_path(base.TEST_TLS_SERVER_CERT),
                # specify explicitly that it is not specified to override default value
                tls_client_auth=-1,
                tls_ca=base.TEST_TLS_CA,
                tls_auth=0,
                keys_dir=base.KEYS_FOLDER.name,
                tls_identifier_extractor_type=self.get_identifier_extractor_type())
        # sometimes process start so fast that fork returns PID and between CLI checks and returning os.Exit(1)
        # python code starts connection loop even after process interruption
        self.assertIn(exc.exception.args[0], ('Can\'t fork', base.WAIT_CONNECTION_ERROR_MESSAGE))

    def testDirectConnectionWithoutCertificate(self):
        # try to start server with --tls_auth >= 1 and extracting client_id from TLS and connect directly without
        # providing any certificate
        self.assertEqual(
            base.create_client_keypair_from_certificate(tls_cert=base.TEST_TLS_CLIENT_CERT,
                                                        keys_dir=base.KEYS_FOLDER.name), 0)
        # generate encryption keys for second certificate too
        self.assertEqual(
            base.create_client_keypair_from_certificate(tls_cert=base.TEST_TLS_CLIENT_2_CERT,
                                                        keys_dir=base.KEYS_FOLDER.name), 0)
        acra = base.ProcessStub()
        for tls_auth in range(1, 5):
            try:
                acra = self.fork_acra(
                    tls_key=base.abs_path(base.TEST_TLS_SERVER_KEY),
                    tls_cert=base.abs_path(base.TEST_TLS_SERVER_CERT),
                    tls_ca=base.TEST_TLS_CA,
                    tls_auth=tls_auth,
                    keys_dir=base.KEYS_FOLDER.name,
                    tls_identifier_extractor_type=self.get_identifier_extractor_type())

                base_args = base.get_connect_args(port=self.ACRASERVER_PORT, sslmode='require')
                tls_args_1 = base_args.copy()
                tls_args_1.update(base.get_tls_connection_args_without_certificate())
                if base.TEST_POSTGRESQL:
                    expected_exception = psycopg2.OperationalError
                else:
                    expected_exception = pymysql.err.OperationalError
                print(expected_exception)
                engine1 = sa.create_engine(
                    base.get_engine_connection_string(
                        self.get_acraserver_connection_string(self.ACRASERVER_PORT), base.DB_NAME),
                    connect_args=tls_args_1)
                with self.assertRaises(expected_exception) as exc:
                    # test query
                    engine1.execute('select 1')
            except Exception as exc2:
                pass
            finally:
                base.stop_process(acra)


class ProcessContextManager(object):
    """wrap subprocess.Popen result to use as context manager that call
    stop_process on __exit__
    """

    def __init__(self, process):
        self.process = process

    def __enter__(self):
        return self.process

    def __exit__(self, exc_type, exc_val, exc_tb):
        base.stop_process(self.process)


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
            client_id = base.extract_client_id_from_cert(tls_cert=base.TEST_TLS_CLIENT_CERT,
                                                         extractor=self.get_identifier_extractor_type())
            self.assertEqual(base.create_client_keypair_from_certificate(tls_cert=base.TEST_TLS_CLIENT_CERT,
                                                                         extractor=self.get_identifier_extractor_type(),
                                                                         keys_dir=key_folder.name), 0)
            data = base.get_pregenerated_random_data().encode('ascii')
            client_id_private_key = base.read_storage_private_key(key_folder.name, client_id)
            connection_string = 'tcp://127.0.0.1:{}'.format(translator_port)
            translator_kwargs = {
                'incoming_connection_http_string': connection_string if use_http else '',
                # turn off grpc to avoid check connection to it
                'incoming_connection_grpc_string': connection_string if use_grpc else '',
                'tls_key': base.abs_path(base.TEST_TLS_SERVER_KEY),
                'tls_cert': base.abs_path(base.TEST_TLS_SERVER_CERT),
                'tls_ca': base.TEST_TLS_CA,
                'keys_dir': key_folder.name,
                'tls_identifier_extractor_type': self.get_identifier_extractor_type(),
                'acratranslator_client_id_from_connection_enable': 'true',
                'tls_ocsp_from_cert': 'ignore',
                'tls_crl_from_cert': 'ignore',
            }

            incorrect_client_id = base.TLS_CERT_CLIENT_ID_2
            with ProcessContextManager(self.fork_translator(translator_kwargs)):
                response = request_func(translator_port, incorrect_client_id, data)
                decrypted = base.deserialize_and_decrypt_acrastruct(response, client_id_private_key, client_id)
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
            client_id = base.extract_client_id_from_cert(tls_cert=base.TEST_TLS_CLIENT_CERT,
                                                         extractor=self.get_identifier_extractor_type())
            self.assertEqual(base.create_client_keypair_from_certificate(tls_cert=base.TEST_TLS_CLIENT_CERT,
                                                                         extractor=self.get_identifier_extractor_type(),
                                                                         keys_dir=key_folder.name), 0)
            data = base.get_pregenerated_random_data().encode('ascii')
            encryption_key = base.read_storage_public_key(client_id, keys_dir=key_folder.name)
            acrastruct = base.create_acrastruct(data, encryption_key)
            connection_string = 'tcp://127.0.0.1:{}'.format(translator_port)
            translator_kwargs = {
                'incoming_connection_http_string': connection_string if use_http else '',
                # turn off grpc to avoid check connection to it
                'incoming_connection_grpc_string': connection_string if use_grpc else '',
                'tls_key': base.abs_path(base.TEST_TLS_SERVER_KEY),
                'tls_cert': base.abs_path(base.TEST_TLS_SERVER_CERT),
                'tls_ca': base.TEST_TLS_CA,
                'keys_dir': key_folder.name,
                'tls_identifier_extractor_type': self.get_identifier_extractor_type(),
                'acratranslator_client_id_from_connection_enable': 'true',
                'tls_ocsp_from_cert': 'ignore',
                'tls_crl_from_cert': 'ignore',
            }

            incorrect_client_id = base.TLS_CERT_CLIENT_ID_2
            with ProcessContextManager(self.fork_translator(translator_kwargs)):
                response = request_func(translator_port, incorrect_client_id, acrastruct)
                self.assertEqual(data, response)
        finally:
            shutil.rmtree(key_folder.name)

    def testHTTPSApiResponses(self):
        translator_port = 3456
        data = base.get_pregenerated_random_data().encode('ascii')
        encryption_key = base.read_storage_public_key(
            base.TLS_CERT_CLIENT_ID_1, keys_dir=base.KEYS_FOLDER.name)
        acrastruct = base.create_acrastruct(data, encryption_key)
        connection_string = 'tcp://127.0.0.1:{}'.format(translator_port)
        translator_kwargs = {
            'incoming_connection_http_string': connection_string,
            'tls_key': base.abs_path(base.TEST_TLS_SERVER_KEY),
            'tls_cert': base.abs_path(base.TEST_TLS_SERVER_CERT),
            'tls_ca': base.TEST_TLS_CA,
            'tls_identifier_extractor_type': base.TLS_CLIENT_ID_SOURCE_DN,
            'acratranslator_client_id_from_connection_enable': 'true',
            'tls_ocsp_from_cert': 'ignore',
            'tls_crl_from_cert': 'ignore',
        }

        api_url = 'https://localhost:{}/v1/decrypt'.format(translator_port)
        with ProcessContextManager(self.fork_translator(translator_kwargs)):
            cert = (base.TEST_TLS_CLIENT_CERT, base.TEST_TLS_CLIENT_KEY)

            # test incorrect HTTP method
            response = requests.get(api_url, data=acrastruct, cert=cert, verify=base.TEST_TLS_CA,
                                    timeout=base.REQUEST_TIMEOUT)
            self.assertEqual(
                response.status_code, http.HTTPStatus.METHOD_NOT_ALLOWED)
            self.assertIn('405 method not allowed'.lower(),
                          response.text.lower())
            self.assertEqual(response.headers['Content-Type'], 'text/plain')

            # test without api version
            without_version_api_url = api_url.replace('v1/', '')
            response = requests.post(
                without_version_api_url, data=acrastruct, cert=cert, verify=base.TEST_TLS_CA,
                timeout=base.REQUEST_TIMEOUT)
            self.assertEqual(response.status_code, http.HTTPStatus.NOT_FOUND)
            self.assertIn('404 Page Not Found'.lower(), response.text.lower())
            self.assertEqual(response.headers['Content-Type'], 'text/plain')

            # incorrect version
            without_version_api_url = api_url.replace('v1/', 'v3/')
            response = requests.post(
                without_version_api_url, data=acrastruct, cert=cert, verify=base.TEST_TLS_CA,
                timeout=base.REQUEST_TIMEOUT)
            self.assertEqual(response.status_code,
                             http.HTTPStatus.NOT_FOUND)
            self.assertIn('404 Page Not Found'.lower(), response.text.lower())
            self.assertEqual(response.headers['Content-Type'], 'text/plain')

            # incorrect url
            incorrect_url = 'https://localhost:{}/v1/someurl'.format(translator_port)
            response = requests.post(
                incorrect_url, data=acrastruct, cert=cert, verify=base.TEST_TLS_CA, timeout=base.REQUEST_TIMEOUT)
            self.assertEqual(
                response.status_code, http.HTTPStatus.NOT_FOUND)
            self.assertEqual('404 Page Not Found'.lower(), response.text.lower())
            self.assertEqual(response.headers['Content-Type'], 'text/plain')

            # without acrastruct (http body), pass empty byte array as data
            response = requests.post(api_url, data=b'', cert=cert, verify=base.TEST_TLS_CA,
                                     timeout=base.REQUEST_TIMEOUT)
            self.assertEqual(response.status_code,
                             http.HTTPStatus.UNPROCESSABLE_ENTITY)
            self.assertIn("Can't decrypt AcraStruct".lower(),
                          response.text.lower())
            self.assertEqual(response.headers['Content-Type'], 'text/plain; charset=utf-8')

            # test with correct acrastruct
            response = requests.post(api_url, data=acrastruct, cert=cert, verify=base.TEST_TLS_CA,
                                     timeout=base.REQUEST_TIMEOUT)
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
        client_id = base.TLS_CERT_CLIENT_ID_1
        server_public1 = base.read_storage_public_key(client_id, base.KEYS_FOLDER.name)
        data = base.get_pregenerated_random_data()
        acra_struct = base.create_acrastruct(
            data.encode('ascii'), server_public1)
        row_id = base.get_random_id()

        self.log(storage_client_id=client_id,
                 data=acra_struct, expected=data.encode('ascii'))

        self.engine1.execute(
            base.test_table.insert(),
            {'id': row_id, 'data': acra_struct, 'raw_data': data})
        result = self.engine1.execute(
            sa.select([base.test_table])
            .where(base.test_table.c.id == row_id))
        row = result.fetchone()
        self.assertEqual(row['data'], row['raw_data'].encode('utf-8'))
        self.assertEqual(row['empty'], b'')

        result = self.engine2.execute(
            sa.select([base.test_table])
            .where(base.test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'].decode('ascii', errors='ignore'),
                            row['raw_data'])
        self.assertEqual(row['empty'], b'')

        result = self.engine_raw.execute(
            sa.select([base.test_table])
            .where(base.test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'].decode('ascii', errors='ignore'),
                            row['raw_data'])
        self.assertEqual(row['empty'], b'')

    def testReadAcrastructInAcrastruct(self):
        """test correct decrypting acrastruct when acrastruct concatenated to
        partial another acrastruct"""
        client_id = base.TLS_CERT_CLIENT_ID_1
        server_public1 = base.read_storage_public_key(client_id, base.KEYS_FOLDER.name)
        incorrect_data = base.get_pregenerated_random_data()
        correct_data = base.get_pregenerated_random_data()
        suffix_data = base.get_pregenerated_random_data()[:10]
        fake_offset = (3 + 45 + 84) - 4
        fake_acra_struct = base.create_acrastruct(
            incorrect_data.encode('ascii'), server_public1)[:fake_offset]
        inner_acra_struct = base.create_acrastruct(
            correct_data.encode('ascii'), server_public1)
        data = fake_acra_struct + inner_acra_struct + suffix_data.encode('ascii')
        correct_data = correct_data + suffix_data
        row_id = base.get_random_id()

        self.log(storage_client_id=client_id,
                 data=data,
                 expected=fake_acra_struct + correct_data.encode('ascii'))

        self.engine1.execute(
            base.test_table.insert(),
            {'id': row_id, 'data': data, 'raw_data': correct_data})
        result = self.engine1.execute(
            sa.select([base.test_table])
            .where(base.test_table.c.id == row_id))
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
            sa.select([base.test_table])
            .where(base.test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'][fake_offset:].decode('ascii', errors='ignore'),
                            row['raw_data'])
        self.assertEqual(row['empty'], b'')

        result = self.engine_raw.execute(
            sa.select([base.test_table])
            .where(base.test_table.c.id == row_id))
        row = result.fetchone()
        self.assertNotEqual(row['data'][fake_offset:].decode('ascii', errors='ignore'),
                            row['raw_data'])
        self.assertEqual(row['empty'], b'')


class TestEnableCachedOnStartupTest(HexFormatTest):

    def checkSkip(self):
        super().checkSkip()
        if base.KEYSTORE_VERSION == 'v2':
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
        return base.read_storage_public_key(base.TLS_CERT_CLIENT_ID_1, base.KEYS_FOLDER.name, extra_kwargs=extra_kwargs)

    def create_keypair(self, extra_kwargs: dict = None):
        base.create_client_keypair(base.TLS_CERT_CLIENT_ID_1, only_storage=True, extra_kwargs=extra_kwargs)

    def test_read_after_rotation(self):
        """Verify that AcraServer can decrypt data with old keys."""

        def insert_random_data():
            row_id = base.get_random_id()
            data = base.get_pregenerated_random_data()
            public_key = self.read_rotation_public_key()
            acra_struct = base.create_acrastruct(data.encode('ascii'), public_key)
            self.engine1.execute(
                base.test_table.insert(),
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
            sa.select([base.test_table])
            .where(base.test_table.c.id == row_id_1))
        row = result.fetchone()
        self.assertEqual(row['data'], raw_data_1.encode('utf-8'))
        self.assertEqual(row['empty'], b'')

        result = self.engine1.execute(
            sa.select([base.test_table])
            .where(base.test_table.c.id == row_id_2))
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
        if base.KEYSTORE_VERSION == 'v2':
            self.skipTest("test only for keystore Version v1")

    def setUp(self):
        self.cached_dir = tempfile.TemporaryDirectory()
        # fill temp dir with all keys
        copy_tree(base.KEYS_FOLDER.name, self.cached_dir.name)
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

        client_id = base.extract_client_id_from_cert(tls_cert=base.TEST_TLS_CLIENT_CERT,
                                                     extractor=self.get_identifier_extractor_type())
        self.assertEqual(base.create_client_keypair_from_certificate(tls_cert=base.TEST_TLS_CLIENT_CERT,
                                                                     extractor=self.get_identifier_extractor_type(),
                                                                     keys_dir=self.cached_dir.name), 0)
        data = base.get_pregenerated_random_data().encode('ascii')
        client_id_private_key = base.read_storage_private_key(self.cached_dir.name, client_id)
        connection_string = 'tcp://127.0.0.1:{}'.format(translator_port)
        translator_kwargs = {
            'incoming_connection_http_string': connection_string,
            'tls_key': base.abs_path(base.TEST_TLS_SERVER_KEY),
            'tls_cert': base.abs_path(base.TEST_TLS_SERVER_CERT),
            'tls_ca': base.TEST_TLS_CA,
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
            # we cant encrypt data because AcraServer doest have access to encryption key with disabled keystore caching
            self.assertEqual(response, b"Can't encrypt data")
            with self.assertRaises(ValueError):
                base.deserialize_and_decrypt_acrastruct(response, client_id_private_key, client_id)
