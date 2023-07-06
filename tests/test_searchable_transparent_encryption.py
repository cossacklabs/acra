import os
import signal
import tempfile

import sqlalchemy as sa

import base
import test_common
import test_integrations


class BaseTransparentEncryption(test_common.SeparateMetadataMixin, test_common.BaseTestCase):
    ENCRYPTOR_CONFIG = base.get_encryptor_config('tests/encryptor_configs/encryptor_config.yaml')

    def get_encryptor_table(self):
        encryptor_table = sa.Table(
            'test_transparent_encryption', self.get_metadata(),
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('specified_client_id',
                      sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),
            sa.Column('default_client_id',
                      sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),
            sa.Column('number', sa.Integer),
            sa.Column('raw_data', sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),
            sa.Column('nullable', sa.Text, nullable=True),
            sa.Column('empty', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False, default=b''),
        )
        return encryptor_table

    def setUp(self):
        self.prepare_encryptor_config(client_id=base.TLS_CERT_CLIENT_ID_1)
        self.encryptor_table = self.get_encryptor_table()
        super(BaseTransparentEncryption, self).setUp()

    def get_encryptor_config_path(self):
        self.prepare_encryptor_config(client_id=base.TLS_CERT_CLIENT_ID_1)
        return base.get_test_encryptor_config(self.ENCRYPTOR_CONFIG)

    def prepare_encryptor_config(self, client_id=None):
        base.prepare_encryptor_config(config_path=self.ENCRYPTOR_CONFIG, client_id=client_id)

    def tearDown(self):
        self.engine_raw.execute(self.encryptor_table.delete())
        super(BaseTransparentEncryption, self).tearDown()
        try:
            os.remove(base.get_test_encryptor_config(self.ENCRYPTOR_CONFIG))
        except FileNotFoundError:
            pass

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        acra_kwargs['encryptor_config_file'] = base.get_test_encryptor_config(
            self.ENCRYPTOR_CONFIG)
        return super(BaseTransparentEncryption, self).fork_acra(
            popen_kwargs, **acra_kwargs)


class TestTransparentEncryption(BaseTransparentEncryption):

    def get_context_data(self):
        context = {
            'id': base.get_random_id(),
            'default_client_id': base.get_pregenerated_random_data().encode('ascii'),
            'number': base.get_random_id(),
            'specified_client_id': base.get_pregenerated_random_data().encode('ascii'),
            'raw_data': base.get_pregenerated_random_data().encode('ascii'),
            'empty': b'',
        }
        return context

    def checkDefaultIdEncryption(self, id, default_client_id, specified_client_id, number, raw_data,
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
        self.assertEqual(row['empty'], b'')

    def checkSpecifiedIdEncryption(
            self, id, default_client_id, specified_client_id, raw_data, *args, **kwargs):
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
        self.assertEqual(row['empty'], b'')

    def insertRow(self, data, query=None, ):
        insert_query = self.encryptor_table.insert()
        if query is not None:
            insert_query = query
        # send through acra-server that authenticates as client_id=keypair2
        self.engine2.execute(insert_query, data)

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
        data_fields = ['default_client_id', 'specified_client_id', 'raw_data', 'empty']
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

        for field in ['default_client_id', 'specified_client_id']:
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
                    raw_data=context['raw_data'])
        )

    def fetch_raw_data(self, context):
        result = self.engine_raw.execute(
            sa.select([self.encryptor_table.c.default_client_id,
                       self.encryptor_table.c.specified_client_id,
                       self.encryptor_table.c.number,
                       self.encryptor_table.c.raw_data,
                       self.encryptor_table.c.nullable,
                       self.encryptor_table.c.empty])
            .where(self.encryptor_table.c.id == context['id']))
        data = result.fetchone()
        return data


class TestTransparentAcraBlockEncryption(TestTransparentEncryption):
    ENCRYPTOR_CONFIG = base.get_encryptor_config('tests/encryptor_configs/ee_acrablock_config.yaml')
    def get_encryptor_table(self):
        encryptor_table = sa.Table(
            'test_transparent_acrablock_encryption', self.get_metadata(),
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('specified_client_id',
                      sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),
            sa.Column('default_client_id',
                      sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),
            sa.Column('number', sa.Integer),
            sa.Column('raw_data', sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),
            sa.Column('nullable', sa.Text, nullable=True),
            sa.Column('empty', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False,
                      default=b''),
            sa.Column('token_i64', sa.BigInteger(), nullable=False, default=1),
            sa.Column('token_str', sa.Text, nullable=False, default=''),
            sa.Column('token_bytes', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False,
                      default=b''),
            sa.Column('masked_prefix', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False,
                      default=b''),
        )
        return encryptor_table

    def testAcraStructReEncryption(self):
        specified_id = base.TLS_CERT_CLIENT_ID_1
        default_id = base.TLS_CERT_CLIENT_ID_2
        test_data = base.get_pregenerated_random_data().encode('utf-8')
        specified_acrastruct = base.create_acrastruct_with_client_id(test_data, specified_id)
        default_acrastruct = base.create_acrastruct_with_client_id(test_data, default_id)
        row_id = base.get_random_id()
        data = {'specified_client_id': specified_acrastruct,
                'default_client_id': default_acrastruct,
                'id': row_id,
                'masked_prefix': base.get_pregenerated_random_data().encode('ascii'),
                'token_bytes': base.get_pregenerated_random_data().encode('ascii'),
                'token_str': base.get_pregenerated_random_data(),
                'token_i64': base.random.randint(0, 2 ** 32),
                }
        self.insertRow(data)
        raw_data = self.engine_raw.execute(
            sa.select([self.encryptor_table.c.specified_client_id,
                       self.encryptor_table.c.default_client_id,
                       self.encryptor_table.c.masked_prefix,
                       self.encryptor_table.c.token_bytes,
                       self.encryptor_table.c.token_str,
                       self.encryptor_table.c.token_i64])
            .where(self.encryptor_table.c.id == row_id))

        raw_data = raw_data.fetchone()
        self.assertNotEqual(raw_data['specified_client_id'], test_data)
        self.assertNotEqual(raw_data['default_client_id'], test_data)
        self.assertEqual(raw_data['specified_client_id'][:3], base.CRYPTO_ENVELOPE_HEADER)
        self.assertEqual(raw_data['default_client_id'][:3], base.CRYPTO_ENVELOPE_HEADER)
        for i in ('masked_prefix', 'token_bytes', 'token_str', 'token_i64'):
            self.assertNotEqual(raw_data[i], data[i])

        decrypted_data = self.engine2.execute(
            sa.select([self.encryptor_table.c.specified_client_id,
                       self.encryptor_table.c.default_client_id,
                       self.encryptor_table.c.masked_prefix,
                       self.encryptor_table.c.token_bytes,
                       self.encryptor_table.c.token_str,
                       self.encryptor_table.c.token_i64])
            .where(self.encryptor_table.c.id == row_id))
        decrypted_data = decrypted_data.fetchone()
        self.assertNotEqual(decrypted_data['specified_client_id'], specified_acrastruct)
        self.assertEqual(decrypted_data['default_client_id'], test_data)
        for i in ('masked_prefix', 'token_bytes', 'token_str', 'token_i64'):
            self.assertEqual(decrypted_data[i], data[i])


class TestTransparentEncryptionWithConsulEncryptorConfigLoading(
    test_integrations.HashicorpConsulEncryptorConfigLoaderMixin,
    TestTransparentEncryption):
    pass


class TransparentEncryptionNoKeyMixin(test_common.AcraCatchLogsMixin):
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
            base.stop_process(self.acra)
        base.send_signal_by_process_name('acra-server', signal.SIGKILL)
        self.server_keystore.cleanup()
        super().tearDown()

    def init_key_stores(self):
        self.client_id = 'test_client_ID'
        self.server_keystore = tempfile.TemporaryDirectory()
        self.server_keys_dir = os.path.join(self.server_keystore.name, '.acrakeys')

        base.create_client_keypair(name=self.client_id, keys_dir=self.server_keys_dir, only_storage=True)

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        args = {'keys_dir': self.server_keys_dir, 'client_id': self.client_id}
        acra_kwargs.update(args)
        return super().fork_acra(popen_kwargs, **acra_kwargs)

    def testEncryptedInsert(self):
        base.destroy_server_storage_key(client_id=self.client_id, keys_dir=self.server_keys_dir,
                                        keystore_version=base.KEYSTORE_VERSION)
        try:
            super().testEncryptedInsert()

        except:
            log = self.read_log(self.acra)
            if base.KEYSTORE_VERSION == 'v1':
                no_key_error_msg = 'open {}/.acrakeys/{}_storage_sym: no such file or directory'.format(
                    self.server_keystore.name, self.client_id)
            else:
                no_key_error_msg = 'key path does not exist'
            self.assertIn(no_key_error_msg, log)
            pass


class TestTransparentEncryptionWithNoEncryptionKey(TransparentEncryptionNoKeyMixin, TestTransparentEncryption):
    pass


class TestPostgresqlBinaryPreparedTransparentEncryption(test_common.BaseBinaryPostgreSQLTestCase,
                                                        TestTransparentEncryption):
    """Testing transparent encryption of prepared statements in PostgreSQL (binary format)."""
    FORMAT = base.AsyncpgExecutor.BinaryFormat

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


class TestPostgresqlBinaryPreparedTransparentEncryptionWithAWSKMSKeystore(test_integrations.KMSAWSType,
                                                                          test_integrations.KMSPerClientEncryptorMixin,
                                                                          TestPostgresqlBinaryPreparedTransparentEncryption):
    pass


class TestPostgresqlBinaryPreparedTransparentEncryptionWithAWSKMSMasterKeyLoader(
    test_integrations.AWSKMSMasterKeyLoaderMixin,
    TestPostgresqlBinaryPreparedTransparentEncryption):
    pass


class TestPostgresqlTextPreparedTransparentEncryption(TestPostgresqlBinaryPreparedTransparentEncryption):
    """Testing transparent encryption of prepared statements in PostgreSQL (text format)."""
    FORMAT = base.AsyncpgExecutor.TextFormat


class TestPostgresqlTextPreparedTransparentEncryptionWithAWSKMSMasterKeyLoader(
    test_integrations.AWSKMSMasterKeyLoaderMixin,
    TestPostgresqlTextPreparedTransparentEncryption):
    pass


class BaseSearchableTransparentEncryption(TestTransparentEncryption):
    ENCRYPTOR_CONFIG = base.get_encryptor_config('tests/encryptor_configs/ee_encryptor_config.yaml')

    def get_encryptor_table(self):
        encryptor_table = sa.Table(
            'test_searchable_transparent_encryption', self.get_metadata(),
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('specified_client_id',
                      sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),
            sa.Column('default_client_id',
                      sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),

            sa.Column('number', sa.Integer),
            sa.Column('raw_data', sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),
            sa.Column('nullable', sa.Text, nullable=True),
            sa.Column('searchable', sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),
            sa.Column('searchable_acrablock', sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),
            sa.Column('empty', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('token_i32', sa.Integer(), nullable=False, default=1),
            sa.Column('token_i64', sa.BigInteger(), nullable=False, default=1),
            sa.Column('token_str', sa.Text, nullable=False, default=''),
            sa.Column('token_bytes', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('token_email', sa.Text, nullable=False, default=''),
            sa.Column('masking', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False, default=b''),
        )
        return encryptor_table

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        # Disable keystore cache since it can interfere with rotation tests
        acra_kwargs['keystore_cache_size'] = -1
        return super(BaseSearchableTransparentEncryption, self).fork_acra(popen_kwargs, **acra_kwargs)

    def fetch_raw_data(self, context):
        result = self.engine_raw.execute(
            sa.select([self.encryptor_table.c.default_client_id,
                       self.encryptor_table.c.specified_client_id,
                       self.encryptor_table.c.number,
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
                    raw_data=context['raw_data'],
                    searchable=context.get('searchable'),
                    empty=context.get('empty', b''),
                    nullable=context.get('nullable', None))
        )

    def get_context_data(self):
        context = {
            'id': base.get_random_id(),
            'default_client_id': base.get_pregenerated_random_data().encode('ascii'),
            'number': base.get_random_id(),
            'specified_client_id': base.get_pregenerated_random_data().encode('ascii'),
            'raw_data': base.get_pregenerated_random_data().encode('ascii'),
            'searchable': base.get_pregenerated_random_data().encode('ascii'),
            'searchable_acrablock': base.get_pregenerated_random_data().encode('ascii'),
            'empty': b'',
            'nullable': None,
            'masking': base.get_pregenerated_random_data().encode('ascii'),
            'token_bytes': base.get_pregenerated_random_data().encode('ascii'),
            'token_email': base.get_pregenerated_random_data(),
            'token_str': base.get_pregenerated_random_data(),
            'token_i32': base.random.randint(0, 2 ** 16),
            'token_i64': base.random.randint(0, 2 ** 32),
        }
        return context

    def insertDifferentRows(self, context, count, query=None, search_term=None, search_field='searchable'):
        if not search_term:
            search_term = context[search_field]
        temp_context = context.copy()
        while count != 0:
            new_data = base.get_pregenerated_random_data().encode('utf-8')
            if new_data != search_term:
                temp_context[search_field] = new_data
                temp_context['id'] = context['id'] + count
                self.insertRow(temp_context, query=query)
                count -= 1

    def execute_via_2(self, query, parameters):
        return self.engine2.execute(query, parameters)

    def executeSelect2(self, query, parameters):
        """Execute a SELECT query with parameters via AcraServer for "keypair2"."""
        return self.engine2.execute(query, parameters).fetchall()

    def executeBulkInsert(self, query, values):
        """Execute a Bulk Insert query with list of values via AcraServer for "TEST_TLS_CLIENT_2_CERT"."""
        return self.engine2.execute(query.values(values))


class BaseSearchableTransparentEncryptionBinaryPostgreSQLMixin(test_common.BaseBinaryPostgreSQLTestCase,
                                                               test_common.BaseTestCase):
    def executeSelect2(self, query, parameters):
        query, parameters = self.compileQuery(query, parameters)
        return self.executor2.execute_prepared_statement(query, parameters)

    def execute_via_2(self, query, values):
        query, parameters = self.compileQuery(query, values)
        return self.executor2.execute_prepared_statement(query, parameters)

    def executeBulkInsert(self, query, values):
        """Execute a Bulk Insert query with list of values via AcraServer for "TEST_TLS_CLIENT_2_CERT"."""
        query, parameters = self.compileBulkInsertQuery(query.values(values), values)
        return self.executor2.execute_prepared_statement(query, parameters)


class BaseSearchableTransparentEncryptionBinaryMySQLMixin(test_common.BaseBinaryMySQLTestCase,
                                                          test_common.BaseTestCase):
    def executeSelect2(self, query, parameters):
        query, parameters = self.compileQuery(query, parameters)
        return self.executor2.execute_prepared_statement(query, parameters)

    def execute_via_2(self, query, parameters):
        query, parameters = self.compileQuery(query, parameters)
        return self.executor2.execute_prepared_statement_no_result(query, parameters)

    def executeBulkInsert(self, query, values):
        """Execute a Bulk Insert query with list of values via AcraServer for "TEST_TLS_CLIENT_2_CERT"."""
        query, parameters = self.compileBulkInsertQuery(query.values(values), values)
        return self.executor2.execute_prepared_statement_no_result(query, parameters)


class TestSearchableTransparentEncryption(BaseSearchableTransparentEncryption):
    def get_result_len(self, result):
        '''returns len of object as rowcount field or len() call

        result is sqlalchemy ResultProxy with rowcount field or asyncpg's response as list object without rowcount
        '''
        if hasattr(result, 'rowcount'):
            return result.rowcount
        return len(result)

    def testSearch(self):
        context = self.get_context_data()
        search_term = context['searchable']

        # Insert searchable data and some additional different rows
        self.insertRow(context)
        extra_rows_count = 5
        self.insertDifferentRows(context, count=extra_rows_count)

        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
            .where(self.encryptor_table.c.searchable == sa.bindparam('searchable')),
            {'searchable': search_term},
        )
        self.assertEqual(self.get_result_len(rows), 1)

        # check with null value
        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
            .where(sa.or_(
                self.encryptor_table.c.searchable == sa.bindparam('searchable'),
                self.encryptor_table.c.token_i64 == sa.bindparam('token_i64'))),
            {
                'searchable': search_term,
                'token_i64': None
            },
        )
        self.assertEqual(self.get_result_len(rows), 1)

        self.checkDefaultIdEncryption(**context)
        self.assertEqual(rows[0]['searchable'], search_term)

        # check not equal
        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
            .where(self.encryptor_table.c.searchable != sa.bindparam('searchable')),
            {'searchable': search_term},
        )
        self.assertEqual(self.get_result_len(rows), extra_rows_count)

        for row in rows:
            self.assertNotEqual(row['searchable'], search_term)

    def testExtendedSyntaxNotMatchedSearch(self):
        context = self.get_context_data()
        search_term = context['searchable']

        # Insert searchable data and some additional different rows
        extra_rows_count = 5
        self.insertRow(context)
        self.insertDifferentRows(context, count=extra_rows_count)

        new_token_i32 = random.randint(0, 2 ** 16)
        searchable_update_data = {
            'token_i32': new_token_i32,
            'b_searchable': search_term
        }

        # test searchable tokenization in update where statements
        query = sa.update(self.encryptor_table).where(
            self.encryptor_table.c.searchable != sa.bindparam('b_searchable')).values(token_i32=new_token_i32)
        result = self.execute_via_2(query, searchable_update_data)

        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
            .where(self.encryptor_table.c.searchable != sa.bindparam('searchable')),
            {'searchable': search_term},
        )
        self.assertEqual(len(rows), extra_rows_count)
        for row in rows:
            self.assertNotEqual(row['id'], context['id'])
            self.assertNotEqual(row['searchable'], search_term)
            self.assertEqual(row['token_i32'], new_token_i32)

        row_id = base.get_random_id()
        insert_data = {
            'param_1': row_id,
            'b_searchable': search_term
        }

        select_columns = ['id', 'default_client_id', 'number', 'specified_client_id', 'raw_data', 'searchable',
                          'searchable_acrablock', 'empty', 'nullable', 'masking', 'token_bytes', 'token_email',
                          'token_str', 'token_i32', 'token_i64']

        if base.TEST_POSTGRESQL:
            id_sequence = sa.text("nextval('test_searchable_transparent_encryption_id_seq')")
        else:
            # use null as value for auto incremented column
            # https://dev.mysql.com/doc/refman/8.0/en/example-auto-increment.html
            id_sequence = None
        select_query = sa.select(
            id_sequence, sa.column('default_client_id'), sa.column('number'),
            sa.column('specified_client_id'), sa.column('raw_data'), sa.column('searchable'),
            sa.column('searchable_acrablock'), sa.column('empty'), sa.column('nullable'), sa.column('masking'),
            sa.column('token_bytes'), sa.column('token_email'), sa.column('token_str'), sa.column('token_i32'),
            sa.column('token_i64')). \
            where(self.encryptor_table.c.searchable != sa.bindparam('b_searchable'))

        query = sa.insert(self.encryptor_table).from_select(select_columns, select_query)
        self.execute_via_2(query, insert_data)

        # after insert there extra_rows_count * 2 rows should be present in DB
        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
            .where(self.encryptor_table.c.searchable != sa.bindparam('searchable')),
            {'searchable': search_term},
        )
        self.assertEqual(self.get_result_len(rows), extra_rows_count * 2)

        # test searchable encryption in delete statements
        query = sa.delete(self.encryptor_table).where(self.encryptor_table.c.searchable != sa.bindparam('b_searchable'))
        result = self.execute_via_2(query, searchable_update_data)

        # verify that deleted not searchable
        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
            .where(self.encryptor_table.c.searchable != sa.bindparam('searchable')),
            {'searchable': search_term},
        )
        self.assertEqual(len(rows), 0)
        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
            .where(self.encryptor_table.c.searchable == sa.bindparam('searchable')),
            {'searchable': search_term},
        )
        self.assertEqual(self.get_result_len(rows), 1)

    def testExtendedSyntaxSearch(self):
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

        new_token_i32 = random.randint(0, 2 ** 16)
        update_data = {
            'token_i32': new_token_i32,
            'b_searchable': search_term
        }

        # test searchable tokenization in update where statements
        query = sa.update(self.encryptor_table).where(
            self.encryptor_table.c.searchable == sa.bindparam('b_searchable')).values(token_i32=new_token_i32)
        self.execute_via_2(query, update_data)

        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
            .where(self.encryptor_table.c.searchable == sa.bindparam('searchable')),
            {'searchable': search_term},
        )
        self.assertEqual(len(rows), 1)

        self.checkDefaultIdEncryption(**context)
        self.assertEqual(rows[0]['searchable'], search_term)
        self.assertEqual(rows[0]['token_i32'], new_token_i32)

        row_id = base.get_random_id()
        insert_data = {
            'param_1': row_id,
            'b_searchable': search_term
        }

        select_columns = ['id', 'default_client_id', 'number', 'specified_client_id', 'raw_data', 'searchable',
                          'searchable_acrablock', 'empty',
                          'nullable', 'masking', 'token_bytes', 'token_email', 'token_str', 'token_i32', 'token_i64']

        select_query = sa.select(
            sa.literal(row_id).label('id'), sa.column('default_client_id'), sa.column('number'),
            sa.column('specified_client_id'),
            sa.column('raw_data'), sa.column('searchable'), sa.column('searchable_acrablock'), sa.column('empty'),
            sa.column('nullable'),
            sa.column('masking'), sa.column('token_bytes'), sa.column('token_email'), sa.column('token_str'),
            sa.column('token_i32'), sa.column('token_i64')). \
            where(self.encryptor_table.c.searchable == sa.bindparam('b_searchable'))

        query = sa.insert(self.encryptor_table).from_select(select_columns, select_query)
        self.execute_via_2(query, insert_data)

        # after insert there 2 rows should be present in DB
        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
            .where(self.encryptor_table.c.searchable == sa.bindparam('searchable')),
            {'searchable': search_term},
        )
        self.assertEqual(len(rows), 2)

        # test searchable encryption in delete statements
        query = sa.delete(self.encryptor_table).where(self.encryptor_table.c.searchable == sa.bindparam('b_searchable'))
        self.execute_via_2(query, update_data)

        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
            .where(self.encryptor_table.c.searchable == sa.bindparam('searchable')),
            {'searchable': search_term},
        )
        self.assertEqual(len(rows), 0)

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
        values = [search_context]
        for idx in range(5):
            insert_context = self.get_context_data()
            new_data = base.get_pregenerated_random_data().encode('utf-8')
            if new_data != search_term:
                insert_context['searchable'] = new_data
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

        temp_acrastruct = base.create_acrastruct_with_client_id(b'somedata', base.TLS_CERT_CLIENT_ID_1)
        # AcraBlock should have half of AcraStruct begin tag. Check that searchable_acrablock is not AcraStruct
        self.assertNotEqual(rows[0]['searchable_acrablock'][:8], temp_acrastruct[:8])
        # skip 33 bytes of hash
        self.assertEqual(rows[0]['searchable_acrablock'][33:33 + 3], base.CRYPTO_ENVELOPE_HEADER)

        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
            .where(self.encryptor_table.c.searchable_acrablock == sa.bindparam('searchable_acrablock')),
            {'searchable_acrablock': search_term})
        self.assertEqual(len(rows), 1)

        self.checkDefaultIdEncryption(**context)
        self.assertEqual(rows[0]['searchable_acrablock'], search_term)

    def testSearchAcraBlockNotMatched(self):
        context = self.get_context_data()
        row_id = context['id']
        search_term = context['searchable_acrablock']
        extra_rows_count = 5

        # Insert searchable data and some additional different rows
        self.insertRow(context)
        self.insertDifferentRows(context, count=extra_rows_count, search_field='searchable_acrablock')

        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
            .where(self.encryptor_table.c.searchable_acrablock != sa.bindparam('searchable_acrablock')),
            {'searchable_acrablock': search_term})
        self.assertEqual(len(rows), extra_rows_count)

        for row in rows:
            self.assertNotEqual(row['searchable_acrablock'], search_term)
            self.assertNotEqual(row['id'], context['id'])

    def testDeserializeOldContainerOnDecryptionFail(self):
        acrastruct = base.create_acrastruct_with_client_id(b'somedata', base.TLS_CERT_CLIENT_ID_1)

        context = self.get_context_data()
        context['raw_data'] = acrastruct
        search_term = context['searchable_acrablock']

        # Insert searchable data and raw AcraStruct
        self.insertRow(context)

        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
            .where(self.encryptor_table.c.searchable_acrablock == sa.bindparam('searchable_acrablock')),
            {'searchable_acrablock': search_term})
        self.assertEqual(len(rows), 1)
        self.checkDefaultIdEncryption(**context)

        # AcraStruct should be as is - not serialized inside general container
        self.assertEqual(rows[0]['raw_data'], acrastruct)

    def testSearchWithEncryptedData(self):
        context = self.get_context_data()
        not_encrypted_term = context['raw_data']
        search_term = context['searchable']
        encrypted_term = base.create_acrastruct_with_client_id(
            search_term, base.TLS_CERT_CLIENT_ID_2)
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

    def testSearchWithEncryptedDataNotMatchedQuery(self):
        context = self.get_context_data()
        not_encrypted_term = context['raw_data']
        search_term = context['searchable']
        encrypted_term = base.create_acrastruct_with_client_id(
            search_term, base.TLS_CERT_CLIENT_ID_2)
        context['searchable'] = encrypted_term

        # Insert searchable data and some additional different rows
        self.insertRow(context)
        # Use plaintext search term here to avoid mismatches
        extra_rows_count = 5
        self.insertDifferentRows(context, count=extra_rows_count, search_term=search_term)

        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
            .where(sa.and_(
                self.encryptor_table.c.searchable != sa.bindparam('searchable'),
                self.encryptor_table.c.raw_data == sa.bindparam('raw_data'))),
            {'searchable': search_term,
             'raw_data': not_encrypted_term},
        )
        self.assertEqual(len(rows), extra_rows_count)

        result = self.engine2.execute(
            sa.select([self.encryptor_table])
            .where(self.encryptor_table.c.searchable != encrypted_term))
        rows = result.fetchall()
        self.assertEqual(len(rows), extra_rows_count)

    def testSearchAcraBlockWithEncryptedData(self):
        context = self.get_context_data()
        row_id = context['id']
        not_encrypted_term = context['raw_data']
        search_term = context['searchable_acrablock']
        encrypted_term = base.create_acrastruct_with_client_id(
            search_term, base.TLS_CERT_CLIENT_ID_2)
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
        self.assertEqual(rows[0]['searchable_acrablock'][33:33 + 4], encrypted_term[:4])

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

    def testSearchAcraBlockWithEncryptedDataNotMatchedQuery(self):
        context = self.get_context_data()
        row_id = context['id']
        not_encrypted_term = context['raw_data']
        search_term = context['searchable_acrablock']
        encrypted_term = base.create_acrastruct_with_client_id(
            search_term, base.TLS_CERT_CLIENT_ID_2)
        context['searchable_acrablock'] = encrypted_term

        # Insert searchable data and some additional different rows
        self.insertRow(context)
        # Use plaintext search term here to avoid mismatches
        extra_rows_count = 5
        self.insertDifferentRows(context, count=extra_rows_count, search_term=search_term,
                                 search_field='searchable_acrablock')

        rows = self.executeSelect2(
            sa.select([self.encryptor_table])
            .where(sa.and_(
                self.encryptor_table.c.searchable_acrablock != sa.bindparam('searchable_acrablock'),
                self.encryptor_table.c.raw_data == sa.bindparam('raw_data'))),
            {'searchable_acrablock': search_term,
             'raw_data': not_encrypted_term},
        )
        self.assertEqual(len(rows), extra_rows_count)

        result = self.engine2.execute(
            sa.select([self.encryptor_table])
            .where(self.encryptor_table.c.searchable_acrablock != encrypted_term))
        rows = result.fetchall()
        self.assertEqual(len(rows), extra_rows_count)

    def testRotatedKeys(self):
        """Verify decryption of searchable data with old keys."""
        context = self.get_context_data()
        # Encrypt searchable data with epoch 1 key
        search_term = context['searchable']
        encrypted_term = base.create_acrastruct_with_client_id(
            search_term, base.TLS_CERT_CLIENT_ID_2)
        context['searchable'] = encrypted_term

        # Insert searchable data and some additional different rows
        self.insertRow(context)
        # Use plaintext search term here to avoid mismatches
        self.insertDifferentRows(context, count=5, search_term=search_term)

        # Encrypt the search term again with the same epoch 1 key,
        # this will result in different encrypted data on outside
        encrypted_term_1 = base.create_acrastruct_with_client_id(
            search_term, base.TLS_CERT_CLIENT_ID_2)
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
        base.create_client_keypair(base.TLS_CERT_CLIENT_ID_2, only_storage=True)

        # Encrypt the search term again, now with the epoch 2 key
        encrypted_term_2 = base.create_acrastruct_with_client_id(
            search_term, base.TLS_CERT_CLIENT_ID_2)
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
        encrypted_term = base.create_acrastruct_with_client_id(
            search_term, base.TLS_CERT_CLIENT_ID_2)
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
        self.assertEqual(rows[0]['searchable_acrablock'][33:33 + 4], encrypted_term[:4])

        # Encrypt the search term again with the same epoch 1 key,
        # this will result in different encrypted data on outside
        encrypted_term_1 = base.create_acrastruct_with_client_id(
            search_term, base.TLS_CERT_CLIENT_ID_2)
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
        base.create_client_keypair(base.TLS_CERT_CLIENT_ID_2, only_storage=True)

        # Encrypt the search term again, now with the epoch 2 key
        encrypted_term_2 = base.create_acrastruct_with_client_id(
            search_term, base.TLS_CERT_CLIENT_ID_2)
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
        self.assertEqual(rows[0]['searchable_acrablock'][33:33 + 4], encrypted_term[:4])


class TestSearchableTransparentEncryptionWithJOINs(BaseSearchableTransparentEncryption):
    def setUp(self):
        metadata = self.get_metadata()
        self.encryptor_table_join = sa.Table(
            'test_searchable_transparent_encryption_join', metadata,
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('specified_client_id',
                      sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),
            sa.Column('default_client_id',
                      sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),

            sa.Column('number', sa.Integer),
            sa.Column('raw_data', sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),
            sa.Column('nullable', sa.Text, nullable=True),
            sa.Column('searchable', sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),
            sa.Column('searchable_acrablock', sa.LargeBinary(length=base.COLUMN_DATA_SIZE)),
            sa.Column('empty', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('token_i32', sa.Integer(), nullable=False, default=1),
            sa.Column('token_i64', sa.BigInteger(), nullable=False, default=1),
            sa.Column('token_str', sa.Text, nullable=False, default=''),
            sa.Column('token_bytes', sa.LargeBinary(length=base.COLUMN_DATA_SIZE), nullable=False, default=b''),
            sa.Column('token_email', sa.Text, nullable=False, default=''),
        )
        super().setUp()
        self.engine1.execute(self.encryptor_table_join.delete())

    def testSearchWithJoinedTable(self):
        context = self.get_context_data()
        search_term = context['searchable']

        # Insert searchable data and some additional different rows
        self.insertRow(context)
        self.insertDifferentRows(context, count=5)

        # Insert the same data into encryptor_table_join table
        self.insertRow(context, query=self.encryptor_table_join.insert())
        self.insertDifferentRows(context, count=5, query=self.encryptor_table_join.insert())

        rows = self.executeSelect2(
            sa.select(
                self.encryptor_table.c.number,
                self.encryptor_table_join.c.searchable,
                self.encryptor_table_join.c.default_client_id,
                self.encryptor_table_join.c.raw_data,
                self.encryptor_table_join.c.specified_client_id,
                self.encryptor_table_join.c.empty,
            ).
            join(self.encryptor_table_join, self.encryptor_table_join.c.searchable == sa.bindparam('searchable')).
            where(self.encryptor_table.c.searchable == sa.bindparam('searchable')),
            {'searchable': search_term})
        self.assertEqual(len(rows), 1)
        row = rows[0]

        self.assertEqual(row[0], context['number'])
        self.assertEqual(row[1], search_term)

        # should be decrypted
        self.assertEqual(row['default_client_id'], context['default_client_id'])
        # should be as is
        self.assertEqual(row['raw_data'], context['raw_data'])
        # other data should be encrypted
        self.assertNotEqual(row['specified_client_id'], context['specified_client_id'])
        self.assertEqual(row['empty'], b'')

        # test with invalid search_term
        rows = self.executeSelect2(
            sa.select(
                self.encryptor_table.c.number,
                self.encryptor_table_join.c.searchable,
            ).
            join(self.encryptor_table_join, self.encryptor_table_join.c.searchable == sa.bindparam('searchable')).
            where(self.encryptor_table.c.searchable == sa.bindparam('searchable')),
            {'searchable': 'invalid-search-term'.encode('utf-8')})
        self.assertEqual(len(rows), 0)

        rows = self.executeSelect2(
            sa.select(
                self.encryptor_table.c.number,
                self.encryptor_table_join.c.searchable,
            ).join(self.encryptor_table_join, self.encryptor_table_join.c.searchable == sa.bindparam('searchable')),
            {'searchable': search_term})

        self.assertEqual(len(rows), 6)
        self.assertEqual(rows[0][1], search_term)

        # test join with on table1.searchable = table2.searchable
        rows = self.executeSelect2(
            sa.select(self.encryptor_table.c.number, self.encryptor_table_join.c.searchable).
            where(self.encryptor_table.c.searchable == sa.bindparam('searchable')).
            join(self.encryptor_table_join,
                 self.encryptor_table.c.searchable == self.encryptor_table_join.c.searchable),
            {'searchable': search_term})

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], context['number'])
        self.assertEqual(rows[0][1], search_term)

    def testSearchWithDefaultTable(self):
        context = self.get_context_data()
        search_term = context['searchable']

        # Insert searchable data and some additional different rows
        self.insertRow(context)
        self.insertDifferentRows(context, count=5)

        search_term_join = base.get_pregenerated_random_data().encode('ascii')
        context['searchable'] = search_term_join

        # Insert the same data into encryptor_table_join table with different search term
        self.insertRow(context, query=self.encryptor_table_join.insert())
        self.insertDifferentRows(context, count=5, query=self.encryptor_table_join.insert())

        query = 'SELECT masking, tj.searchable FROM test_searchable_transparent_encryption ' \
                'JOIN test_searchable_transparent_encryption_join tj ON tj.searchable = :search_term_join ' \
                'WHERE test_searchable_transparent_encryption.searchable = :searchable'
        rows = self.executeSelect2(sa.text(query), {'searchable': search_term, 'search_term_join': search_term_join})
        self.assertEqual(len(rows), 1)


class TestSearchableTransparentEncryptionDoubleQuotedTables(BaseSearchableTransparentEncryption):
    def setUp(self):
        super().setUp()

        if base.TEST_MYSQL:
            self.skipTest("useful only for postgresql")
            # TODO: double quoted tables can be used in MySQL only with ANSI mode but currently ACRA doest have proper configuration
            # to use MySQL dialect with ANSI mode
            # self.sql_mode_wo_ansi = self.engine2.execute('SELECT @@SESSION.sql_mode;').fetchone()[0]
            # self.set_ansi_mode(True)

    def testEncryptedInsert(self):
        pass

    def testSearchDoubleQuotedTable(self):
        context = self.get_context_data()
        search_term = context['searchable']

        # Insert searchable data and some additional different rows
        self.insertRow(context)
        self.insertDifferentRows(context, count=5)

        query = 'SELECT * FROM "test_searchable_transparent_encryption" WHERE "searchable" = :searchable'
        rows = self.executeSelect2(sa.text(query), {'searchable': search_term})
        self.assertEqual(len(rows), 1)

        self.checkDefaultIdEncryption(**context)


class TestSearchableTransparentEncryptionWithDefaultsAcraBlockBinaryPostgreSQL(
    BaseSearchableTransparentEncryptionBinaryPostgreSQLMixin, TestSearchableTransparentEncryption):
    ENCRYPTOR_CONFIG = base.get_encryptor_config(
        'tests/encryptor_configs/ee_acrablock_defaults_with_searchable_config.yaml')


class TestSearchableTransparentEncryptionWithDefaultsAcraBlockBinaryPostgreSQLWithConsulEncryptorConfigLoader(
    test_integrations.HashicorpConsulEncryptorConfigLoaderMixin,
    BaseSearchableTransparentEncryptionBinaryPostgreSQLMixin,
    TestSearchableTransparentEncryption):
    ENCRYPTOR_CONFIG = base.get_encryptor_config(
        'tests/encryptor_configs/ee_acrablock_defaults_with_searchable_config.yaml')


class TestSearchableTransparentEncryptionWithDefaultsAcraBlockBinaryMySQL(
    BaseSearchableTransparentEncryptionBinaryMySQLMixin, TestSearchableTransparentEncryption):
    ENCRYPTOR_CONFIG = base.get_encryptor_config(
        'tests/encryptor_configs/ee_acrablock_defaults_with_searchable_config.yaml')


class TestSearchableTransparentEncryptionWithDefaultsAcraStructBinaryPostgreSQL(
    BaseSearchableTransparentEncryptionBinaryPostgreSQLMixin, TestSearchableTransparentEncryption):
    ENCRYPTOR_CONFIG = base.get_encryptor_config(
        'tests/encryptor_configs/ee_acrastruct_defaults_with_searchable_config.yaml')


class TestSearchableTransparentEncryptionWithDefaultsAcraStructBinaryMySQL(
    BaseSearchableTransparentEncryptionBinaryMySQLMixin, TestSearchableTransparentEncryption):
    ENCRYPTOR_CONFIG = base.get_encryptor_config(
        'tests/encryptor_configs/ee_acrastruct_defaults_with_searchable_config.yaml')


class TestSearchableTransparentEncryptionBinaryPostgreSQL(BaseSearchableTransparentEncryptionBinaryPostgreSQLMixin,
                                                          TestSearchableTransparentEncryption):
    pass


class TestSearchableTransparentEncryptionBinaryMySQL(BaseSearchableTransparentEncryptionBinaryMySQLMixin,
                                                     TestSearchableTransparentEncryption):
    pass


class TestTransparentAcraBlockEncryptionMissingExtraLog(TestTransparentAcraBlockEncryption):
    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
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
    ENCRYPTOR_CONFIG = base.get_encryptor_config('tests/encryptor_configs/ee_acrablock_config_with_defaults.yaml')


class TestTransparentEncryptionConnectorlessWithTLSBySerialNumber(test_common.TLSAuthenticationBySerialNumberMixin,
                                                                  TestTransparentEncryption,
                                                                  test_common.TLSAuthenticationDirectlyToAcraMixin):
    pass


class TestTransparentEncryptionConnectorlessWithTLSByDN(test_common.TLSAuthenticationByDistinguishedNameMixin,
                                                        TestTransparentEncryption,
                                                        test_common.TLSAuthenticationDirectlyToAcraMixin):
    pass


class TestSearchableTransparentEncryptionConnectorlessWithTLSByDN(test_common.TLSAuthenticationByDistinguishedNameMixin,
                                                                  TestSearchableTransparentEncryption,
                                                                  test_common.TLSAuthenticationDirectlyToAcraMixin):
    pass


class TestSearchableTransparentEncryptionConnectorlessWithTLSBySerialNumber(
    test_common.TLSAuthenticationBySerialNumberMixin,
    TestSearchableTransparentEncryption,
    test_common.TLSAuthenticationDirectlyToAcraMixin):
    pass


def setUpModule():
    base.setUpModule()


def tearDownModule():
    base.tearDownModule()
