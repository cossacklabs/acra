import base
from test_integrations import *
from random_utils import random_bytes, random_email, random_int32, random_int64, random_str
from utils import (prepare_encryptor_config,
                   get_encryptor_config, get_test_encryptor_config)


class BaseTokenization(BaseTestCase):
    WHOLECELL_MODE = True
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/encryptor_configs/ee_tokenization_config.yaml')

    def get_specified_client_id(self):
        return base.TLS_CERT_CLIENT_ID_2

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        prepare_encryptor_config(
            client_id=self.get_specified_client_id(), config_path=self.ENCRYPTOR_CONFIG)
        acra_kwargs.update(encryptor_config_file=get_test_encryptor_config(self.ENCRYPTOR_CONFIG))
        return super(BaseTokenization, self).fork_acra(popen_kwargs, **acra_kwargs)

    def insert_via_1(self, query, values):
        """Execute SQLAlchemy INSERT query via AcraServer with "TEST_TLS_CLIENT_CERT"."""
        return self.engine1.execute(query, values)

    def execute_via_1(self, query, values):
        """Execute SQLAlchemy execute query via AcraServer with "TEST_TLS_CLIENT_CERT"."""
        return self.engine1.execute(query, values)

    def execute_via_2(self, query):
        """Execute SQLAlchemy execute query via AcraServer with "TEST_TLS_CLIENT_CERT"."""
        return self.engine2.execute(query).fetchall()

    def insert_via_1_bulk(self, query, values):
        """Execute SQLAlchemy Bulk INSERT query via AcraServer with "TEST_TLS_CLIENT_CERT"."""
        self.engine1.execute(query.values(values))

    def fetch_from_1(self, query, parameters={}, literal_binds=True):
        """Execute SQLAlchemy SELECT query via AcraServer with "TEST_TLS_CLIENT_CERT"."""
        return self.engine1.execute(query, parameters).fetchall()

    def fetch_from_2(self, query, parameters={}, literal_binds=True):
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
            redis_host_port=os.environ.get('TEST_REDIS_HOSTPORT', 'localhost:6379'),
            redis_db_tokens=self.TEST_REDIS_TOKEN_DB,
            encryptor_config_file=get_test_encryptor_config(self.ENCRYPTOR_CONFIG))
        if TEST_WITH_TLS:
            acra_kwargs.update(
                redis_tls_client_auth=4,
                redis_tls_client_ca=TEST_TLS_CA,
                redis_tls_client_cert=TEST_TLS_CLIENT_CERT,
                redis_tls_client_key=TEST_TLS_CLIENT_KEY,
                redis_tls_enable=True,
            )
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

    def execute_via_1(self, query, values):
        query, parameters = self.compileQuery(query, values)
        self.executor1.execute_prepared_statement_no_result(query, parameters)

    def fetch_from_1(self, query, parameters={}, literal_binds=True):
        query, parameters = self.compileQuery(query, parameters=parameters, literal_binds=literal_binds)
        return self.executor1.execute_prepared_statement(query, parameters)

    def fetch_from_2(self, query, parameters={}, literal_binds=True):
        query, parameters = self.compileQuery(query, parameters=parameters, literal_binds=literal_binds)
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

    def execute_via_1(self, query, values):
        query, parameters = self.compileQuery(query, values)
        self.executor1.execute_prepared_statement(query, parameters)

    def fetch_from_1(self, query, parameters={}, literal_binds=True):
        query, parameters = self.compileQuery(query, parameters=parameters, literal_binds=literal_binds)
        return self.executor1.execute_prepared_statement(query, parameters)

    def fetch_from_2(self, query, parameters={}, literal_binds=True):
        query, parameters = self.compileQuery(query, parameters=parameters, literal_binds=literal_binds)
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
            host='localhost', port=self.ACRASERVER_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_USER_PASSWORD,
            ssl_ca=TEST_TLS_CA,
            ssl_key=ssl_key,
            ssl_cert=ssl_cert,
            raw=True,
        )
        result = MysqlExecutor(args).execute_prepared_statement(query)
        # For some weird reason MySQL connector in prepared statement mode
        # does not decode TEXT columns into Python strings. In text mode
        # it tries to decode the bytes and returns strings if they decode.
        # Do the same here.
        for row in result:
            for column, value in row.items():
                if isinstance(value, (bytes, bytearray)):
                    try:
                        row[column] = bytes(value)
                    except (LookupError, UnicodeDecodeError):
                        pass
        return result


class BaseMasking(BaseTokenization):
    WHOLECELL_MODE = False
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/encryptor_configs/ee_masking_config.yaml')

    def check_crypto_envelope(self, table, row_id):
        temp_acrastruct = create_acrastruct_with_client_id(b'somedata', base.TLS_CERT_CLIENT_ID_1)
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
        return base.TLS_CERT_CLIENT_ID_2

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        prepare_encryptor_config(
            client_id=self.get_specified_client_id(), config_path=self.ENCRYPTOR_CONFIG)
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


class TestTokenization(BaseTokenization):

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
            if isinstance(source_data[0][k], (bytearray, bytes)) and isinstance(data[k], str):
                self.assertEqual(source_data[0][k], data[k].encode('utf-8'))
                self.assertNotEqual(hidden_data[0][k], data[k].encode('utf-8'))
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
        source_data = self.fetch_from_1(sa.select([default_client_id_table]).order_by(default_client_id_table.c.id))

        hidden_data = self.fetch_from_2(sa.select([default_client_id_table]).order_by(default_client_id_table.c.id))

        if len(source_data) != len(hidden_data):
            self.fail('incorrect len of result data')

        for idx in range(len(source_data)):
            # data owner take source data
            for k in ('token_i32', 'token_i64', 'token_str', 'token_bytes', 'token_email'):
                if isinstance(source_data[idx][k], (bytearray, bytes)) and isinstance(values[idx][k], str):
                    self.assertEqual(source_data[idx][k], bytes(values[idx][k], encoding='utf-8'))
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
            if isinstance(source_data[0][k], (bytearray, bytes)) and isinstance(data[k], str):
                self.assertEqual(source_data[0][k], bytes(data[k], encoding='utf-8'))
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
            # successfully decrypted data returned as string otherwise as bytes
            # always encode to bytes to compare values with same type coercions
            if isinstance(source_data[0][k], (bytearray, bytes, memoryview)) and isinstance(data[k], str):
                self.assertEqual(utils.memoryview_to_bytes(source_data[0][k]), data[k].encode('utf-8'))
                self.assertNotEqual(utils.memoryview_to_bytes(hidden_data[0][k]), data[k].encode('utf-8'))
            else:
                self.assertEqual(utils.memoryview_to_bytes(source_data[0][k]), data[k])
                self.assertNotEqual(utils.memoryview_to_bytes(hidden_data[0][k]), data[k])


class TestSearchableTokenization(AcraCatchLogsMixin, BaseTokenization):
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/encryptor_configs/ee_searchable_tokenization_config.yaml')

    def testSearchableTokenizationDefaultClientID(self):
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

        # insert data data
        self.insert_via_1(default_client_id_table.insert(), data)

        columns = {
            'token_i32': default_client_id_table.c.token_i32,
            'token_i64': default_client_id_table.c.token_i64,
            'token_str': default_client_id_table.c.token_str,
            'token_bytes': default_client_id_table.c.token_bytes,
            'token_email': default_client_id_table.c.token_email,
        }
        # data owner take source data
        for key in columns:
            parameters = {key: data[key]}
            query = sa.select(default_client_id_table).where(columns[key] == data[key])

            source_data = self.fetch_from_1(query, parameters, literal_binds=False)
            for k in ('token_i32', 'token_i64', 'token_str', 'token_bytes', 'token_email'):
                if isinstance(source_data[0][k], (bytearray, bytes)) and isinstance(data[k], str):
                    self.assertEqual(source_data[0][k], data[k].encode('utf-8'))
                else:
                    self.assertEqual(source_data[0][k], data[k])

        new_token_str = random_str()
        update_data = {
            'token_str': new_token_str,
            'token_i32': data['token_i32']
        }

        # test searchable tokenization in update where statements
        query = sa.update(default_client_id_table).where(columns['token_i32'] == data['token_i32']).values(
            token_str=new_token_str)
        self.execute_via_1(query, update_data)

        key = 'token_i32'
        parameters = {key: data[key]}
        query = sa.select(default_client_id_table).where(columns[key] == data[key])
        source_data = self.fetch_from_1(query, parameters, literal_binds=False)

        if isinstance(source_data[0][k], (bytearray, bytes)) and isinstance(data[k], str):
            self.assertEqual(source_data[0]['token_str'], new_token_str.encode('utf-8'))
        else:
            self.assertEqual(source_data[0]['token_str'], new_token_str)

        row_id += 1
        insert_data = {
            'param_1': row_id,
            'token_i32': data['token_i32']
        }
        select_columns = ['id', 'nullable_column', 'empty', 'token_i32', 'token_i64', 'token_str', 'token_bytes',
                          'token_email']
        select_query = sa.select(sa.literal(row_id).label('id'), sa.column('nullable_column'), sa.column('empty'),
                                 columns['token_i32'], columns['token_i64'], columns['token_str'],
                                 columns['token_bytes'], columns['token_email']). \
            where(columns['token_i32'] == data['token_i32'])

        query = sa.insert(default_client_id_table).from_select(select_columns, select_query)
        self.execute_via_1(query, insert_data)

        # expect that data was encrypted with client_id which used to insert (client_id==keypair1)
        source_data = self.fetch_from_1(
            sa.select([default_client_id_table])
            .where(default_client_id_table.c.id == row_id))

        for k in ('token_i32', 'token_i64', 'token_bytes', 'token_email'):
            if isinstance(source_data[0][k], (bytearray, bytes)) and isinstance(data[k], str):
                self.assertEqual(source_data[0][k], data[k].encode('utf-8'))
            else:
                self.assertEqual(source_data[0][k], data[k])

        # test searchable tokenization in update where statements
        query = sa.delete(default_client_id_table).where(columns['token_str'] == update_data['token_str'])
        self.execute_via_1(query, update_data)

        source_data = self.fetch_from_1(sa.select([default_client_id_table]))
        self.assertEqual(0, len(source_data))

    def testSearchableTokenizationNotEqualQuery(self):
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
        # sqlalchemy's sa.insert().values() generates INSERT statement with 'id' column that should be assigned with
        # value or None and it will place configure default value. But this testcase used by different Executors that
        # don't and can't do same and tries to compile statement to the string query and meet problems with it. To avoid
        # it just assign value
        id_generator = iter(range(1, 100500))
        data = {
            'id': next(id_generator),
            'nullable_column': None,
            'empty': b'',
            'token_i32': random_int32(),
            'token_i64': random_int64(),
            'token_str': random_str(),
            'token_bytes': random_bytes(),
            'token_email': random_email(),

        }
        # insert two rows with same values
        expected_rows = [data]
        self.insert_via_1(default_client_id_table.insert(), data)
        data['id'] = next(id_generator)
        self.insert_via_1(default_client_id_table.insert(), data)
        expected_rows.append(data)

        # insert values with different values
        not_expected_rows = []
        for idx in range(5):
            insert_data = {
                'id': next(id_generator),
                'nullable_column': None,
                'empty': b'',
                'token_i32': random_int32(),
                'token_i64': random_int64(),
                'token_str': random_str(),
                'token_bytes': random_bytes(50),
                'token_email': random_email(),
            }
            not_expected_rows.append(insert_data)

        # bulk insert data
        self.insert_via_1_bulk(default_client_id_table.insert(), not_expected_rows)

        columns = {
            'token_i32': default_client_id_table.c.token_i32,
            'token_i64': default_client_id_table.c.token_i64,
            'token_str': default_client_id_table.c.token_str,
            'token_bytes': default_client_id_table.c.token_bytes,
            'token_email': default_client_id_table.c.token_email,
        }

        # query with not equal operator
        for i32_key in columns:
            parameters = {i32_key: data[i32_key]}
            query = sa.select(default_client_id_table).where(columns[i32_key] != data[i32_key]).order_by(
                default_client_id_table.c.id)

            source_data = self.fetch_from_1(query, parameters, literal_binds=False)
            self.assertEqual(len(source_data), len(not_expected_rows))
            for i, row in enumerate(source_data):
                for k in ('token_i32', 'token_i64', 'token_str', 'token_bytes', 'token_email'):
                    if isinstance(row[k], (bytearray, bytes)) and isinstance(not_expected_rows[i][k], str):
                        self.assertEqual(row[k], not_expected_rows[i][k].encode('utf-8'))
                    else:
                        self.assertEqual(row[k], not_expected_rows[i][k])

        new_not_expected_token_str = random_str()
        i32_key = 'b_token_i32'  # use different name for bind value to skip placing it in SET statement by sqlalchemy
        update_not_expected_data = {
            'token_str': new_not_expected_token_str,
            i32_key: data['token_i32'],
        }
        query = sa.update(default_client_id_table).where(columns['token_i32'] != sa.bindparam(i32_key)).values(
            token_str=new_not_expected_token_str)
        self.execute_via_1(query, update_not_expected_data)
        parameters = {'token_i32': data['token_i32']}
        query = sa.select(default_client_id_table).where(columns['token_i32'] != data['token_i32']).order_by(
            default_client_id_table.c.id)
        source_data = self.fetch_from_1(query, parameters, literal_binds=False)
        for i, row in enumerate(source_data):
            if isinstance(row[k], (bytearray, bytes)) and isinstance(not_expected_rows[i][k], str):
                self.assertEqual(row['token_str'], new_not_expected_token_str.encode('utf-8'))
            else:
                self.assertEqual(row['token_str'], new_not_expected_token_str)

        # update sequence counter because INSERT FROM SELECT will use default value but previously we explicitly
        # set values
        if TEST_POSTGRESQL:
            self.engine_raw.execute("select setval('{}_id_seq', {})".format(
                default_client_id_table.name, next(id_generator)))
            id_sequence = sa.text("nextval('{}_id_seq')".format(default_client_id_table.name))
        else:
            # use null as value for auto incremented column
            # https://dev.mysql.com/doc/refman/8.0/en/example-auto-increment.html
            id_sequence = None

        select_columns = ['id', 'nullable_column', 'empty', 'token_i32', 'token_i64', 'token_str', 'token_bytes',
                          'token_email']
        select_query = sa.select(id_sequence, sa.column('nullable_column'), sa.column('empty'),
                                 columns['token_i32'], columns['token_i64'], columns['token_str'],
                                 columns['token_bytes'], columns['token_email']). \
            where(columns['token_i32'] != data['token_i32'])

        query = sa.insert(default_client_id_table).from_select(select_columns, select_query)
        self.execute_via_1(query, {'token_i32': data['token_i32']})

        # expect that data was encrypted with client_id which used to insert (client_id==keypair1)
        source_data = self.fetch_from_1(
            sa.select([default_client_id_table])
            .where(default_client_id_table.c.token_i32 != data['token_i32'])
            .order_by(default_client_id_table.c.id))
        self.assertEqual(len(source_data), len(not_expected_rows) * 2)
        for i, row in enumerate(source_data):
            # due to we have 2 values copy, we should compare them in the cycle with not_expected_rows
            expected_row_index = i % len(not_expected_rows)
            for k in ('token_i32', 'token_i64', 'token_bytes', 'token_email'):
                if isinstance(source_data[i][k], (bytearray, bytes)) and isinstance(
                        not_expected_rows[expected_row_index][k], str):
                    self.assertEqual(source_data[i][k], not_expected_rows[expected_row_index][k].encode('utf-8'))
                else:
                    self.assertEqual(source_data[i][k], not_expected_rows[expected_row_index][k])

        # delete all except first 2 rows
        query = sa.delete(default_client_id_table).where(columns['token_str'] != data['token_str'])
        self.execute_via_1(query, {'token_str': data['token_str']})

        source_data = self.fetch_from_1(sa.select([default_client_id_table]))
        # we expect that deleted all rows except first 2 added
        self.assertEqual(2, len(source_data))

    def testSearchableTokenizationWithJOINs(self):
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
        default_client_id_table_join = sa.Table(
            'test_tokenization_default_client_id_join', metadata,
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
        metadata.create_all(self.engine_raw, [default_client_id_table, default_client_id_table_join])
        self.engine1.execute(default_client_id_table.delete())
        self.engine1.execute(default_client_id_table_join.delete())

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

        # insert data data
        self.insert_via_1(default_client_id_table.insert(), data)
        self.insert_via_1(default_client_id_table_join.insert(), data)

        columns = {
            'id': default_client_id_table_join.c.id,
            'token_i32': default_client_id_table_join.c.token_i32,
            'token_i64': default_client_id_table_join.c.token_i64,
            'token_str': default_client_id_table_join.c.token_str,
            'token_bytes': default_client_id_table_join.c.token_bytes,
            'token_email': default_client_id_table_join.c.token_email,
        }
        # data owner take source data
        for key in columns:
            query = sa.select(
                default_client_id_table.c.token_i32,
                default_client_id_table.c.token_str,
                default_client_id_table_join.c.token_i64,
                default_client_id_table_join.c.token_email,
            ).join(default_client_id_table_join, columns[key] == data[key])

            parameters = {key: data[key]}
            source_data = self.fetch_from_1(query, parameters, literal_binds=False)
            for k in ('token_i32', 'token_i64', 'token_str', 'token_email'):
                if isinstance(source_data[0][k], (bytearray, bytes)) and isinstance(data[k], str):
                    self.assertEqual(source_data[0][k], data[k].encode('utf-8'))
                else:
                    self.assertEqual(source_data[0][k], data[k])

    def testSearchWithDefaultTableWithAlias(self):
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

        default_client_id_table_join = sa.Table(
            'test_tokenization_default_client_id_join', metadata,
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

        metadata.create_all(self.engine_raw, [default_client_id_table, default_client_id_table_join])
        self.engine1.execute(default_client_id_table.delete())
        self.engine1.execute(default_client_id_table_join.delete())

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

        # insert data data
        self.insert_via_1(default_client_id_table.insert(), data)
        self.insert_via_1(default_client_id_table_join.insert(), data)

        # with aliased column in where statement
        query = 'SELECT id, token_i32, token_i64, token_str, token_email FROM test_tokenization_default_client_id as test_table WHERE test_table.token_i64 = :token_i64'
        parameters = {'token_i64': data['token_i64']}

        source_data = self.fetch_from_1(sa.text(query), parameters, literal_binds=False)
        for k in ('token_i32', 'token_i64', 'token_str', 'token_email'):
            if isinstance(source_data[0][k], (bytearray, bytes)) and isinstance(data[k], str):
                self.assertEqual(source_data[0][k], data[k].encode('utf-8'))
            else:
                self.assertEqual(source_data[0][k], data[k])

        # with non-aliased column in where statement
        query = 'SELECT id, token_i32, token_i64, token_str, token_email FROM test_tokenization_default_client_id as test_table WHERE token_i64 = :token_i64'
        parameters = {'token_i64': data['token_i64']}

        source_data = self.fetch_from_1(sa.text(query), parameters, literal_binds=False)
        for k in ('token_i32', 'token_i64', 'token_str', 'token_email'):
            if isinstance(source_data[0][k], (bytearray, bytes)) and isinstance(data[k], str):
                self.assertEqual(source_data[0][k], data[k].encode('utf-8'))
            else:
                self.assertEqual(source_data[0][k], data[k])

        # expect fail this query in DB, we need to check corresponding log message from Acra
        query = 'SELECT id, token_i32, token_i64 FROM test_tokenization_default_client_id as test_table, test_tokenization_default_client_id_join as test_table_join'
        try:
            self.engine1.execute(query)
        except (sa.exc.OperationalError, sa.exc.ProgrammingError) as e:
            self.assertIn("ambiguous", str(e))
            self.assertIn("Ambiguous column found, several tables contain the same column", self.read_log(self.acra))
            pass

    def testSearchableTokenizationSpecificClientID(self):
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

        columns = {
            'id': specific_client_id_table.c.id,
            'token_i32': specific_client_id_table.c.token_i32,
            'token_i64': specific_client_id_table.c.token_i64,
            'token_str': specific_client_id_table.c.token_str,
            'token_bytes': specific_client_id_table.c.token_bytes,
            'token_email': specific_client_id_table.c.token_email,
        }
        # data owner take source data
        for key in columns:
            parameters = {key: data[key]}
            query = sa.select(specific_client_id_table).where(columns[key] == data[key])

            source_data = self.fetch_from_2(query, parameters, literal_binds=False)
            for k in ('token_i32', 'token_i64', 'token_str', 'token_bytes', 'token_email'):
                if isinstance(source_data[0][k], (bytearray, bytes)) and isinstance(data[k], str):
                    self.assertEqual(source_data[0][k], data[k].encode('utf-8'))
                else:
                    self.assertEqual(source_data[0][k], data[k])


class TestTokenizationWithBoltDB(BaseTokenizationWithBoltDB, TestTokenization):
    pass


class TestTokenizationWithRedis(BaseTokenizationWithRedis, TestTokenization):
    pass


class TestTokenizationBinaryMySQL(BaseTokenizationWithBinaryMySQL, TestTokenization):
    pass


class TestTokenizationTextPostgreSQL(BaseTokenizationWithTextPostgreSQL, TestTokenization):
    pass


class TestTokenizationBinaryPostgreSQL(BaseTokenizationWithBinaryPostgreSQL, TestTokenization):
    pass


class TestSearchableTokenizationBinaryPostgreSQL(BaseTokenizationWithBinaryPostgreSQL, TestSearchableTokenization):
    pass


class TestTokenizationBinaryPostgreSQLWithAWSKMSMaterKeyLoading(AWSKMSMasterKeyLoaderMixin,
                                                                BaseTokenizationWithBinaryPostgreSQL, TestTokenization):
    pass


class TestTokenizationBinaryBindMySQL(BaseTokenizationWithBinaryBindMySQL, TestTokenization):
    pass


class TestSearchableTokenizationBinaryBindMySQL(BaseTokenizationWithBinaryBindMySQL, TestSearchableTokenization):
    pass


class TestTokenizationConnectorlessWithTLSBySerialNumber(TLSAuthenticationBySerialNumberMixin,
                                                         TLSAuthenticationDirectlyToAcraMixin, TestTokenization):
    def get_specified_client_id(self):
        return extract_client_id_from_cert(tls_cert=base.TEST_TLS_CLIENT_2_CERT,
                                           extractor=self.get_identifier_extractor_type())


class TestTokenizationConnectorlessWithTLSByDN(TLSAuthenticationByDistinguishedNameMixin,
                                               TLSAuthenticationDirectlyToAcraMixin, TestTokenization):
    def get_specified_client_id(self):
        return extract_client_id_from_cert(tls_cert=base.TEST_TLS_CLIENT_2_CERT,
                                           extractor=self.get_identifier_extractor_type())


class TestMasking(BaseMasking):
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

        for i in (
                'masked_prefix', 'masked_suffix', 'masked_without_plaintext', 'exact_plaintext_length',
                'shorter_plaintext'):
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
        self.assertNotEqual(hidden_data['masked_suffix'][:-len(mask_pattern)],
                            data['masked_suffix'][:-len(mask_pattern)])

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

        for i in (
                'masked_prefix', 'masked_suffix', 'masked_without_plaintext', 'exact_plaintext_length',
                'shorter_plaintext'):
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
        self.assertNotEqual(hidden_data['masked_suffix'][:-len(mask_pattern)],
                            data['masked_suffix'][:-len(mask_pattern)])

        self.assertEqual(mask_pattern, hidden_data['masked_without_plaintext'])

        # if plaintext length > data, then whole data will be encrypted
        self.assertEqual(mask_pattern, hidden_data['exact_plaintext_length'])

        self.assertEqual(mask_pattern, hidden_data['shorter_plaintext'])


class BaseAcraBlockMasking:
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/encryptor_configs/ee_masking_acrablock_config.yaml')

    def check_crypto_envelope(self, table, row_id):
        temp_acrastruct = create_acrastruct_with_client_id(b'somedata', base.TLS_CERT_CLIENT_ID_1)
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


class TestMaskingAcraBlock(BaseAcraBlockMasking, TestMasking):
    pass


class TestMaskingAcraBlockBinaryMySQL(BaseAcraBlockMasking, BaseMaskingBinaryMySQLMixin, TestMasking):
    pass


class TestMaskingAcraBlockBinaryPostgreSQL(BaseAcraBlockMasking, BaseMaskingBinaryPostgreSQLMixin, TestMasking):
    pass


class TestMaskingAcraBlockWithDefaults(BaseAcraBlockMasking, TestMasking):
    ENCRYPTOR_CONFIG = get_encryptor_config('tests/encryptor_configs/ee_masking_acrablock_with_defaults_config.yaml')


class TestMaskingConnectorlessWithTLSByDN(TLSAuthenticationByDistinguishedNameMixin,
                                          TLSAuthenticationDirectlyToAcraMixin, TestMasking):
    def get_specified_client_id(self):
        return extract_client_id_from_cert(tls_cert=base.TEST_TLS_CLIENT_2_CERT,
                                           extractor=self.get_identifier_extractor_type())


class TestMaskingConnectorlessWithTLSBySerialNumber(TLSAuthenticationBySerialNumberMixin,
                                                    TLSAuthenticationDirectlyToAcraMixin, TestMasking):
    def get_specified_client_id(self):
        return extract_client_id_from_cert(tls_cert=base.TEST_TLS_CLIENT_2_CERT,
                                           extractor=self.get_identifier_extractor_type())
