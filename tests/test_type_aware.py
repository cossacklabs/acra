from random import randint

import asyncpg
import mysql.connector
import sqlalchemy as sa
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.sql import expression, operators

import base
import test_common
import test_integrations
import test_searchable_transparent_encryption
from random_utils import random_bytes, random_int32, random_int64, random_str, max_negative_int32, max_negative_int64


class TestPostgresqlTextFormatTypeAwareDecryptionWithDefaults(
    test_searchable_transparent_encryption.BaseTransparentEncryption):
    # test table used for queries and data mapping into python types
    test_table = sa.Table(
        # use new object of metadata to avoid name conflict
        'test_type_aware_decryption_with_defaults', sa.MetaData(),
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.Text),
        sa.Column('value_searchable', sa.Text),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.Integer),
        sa.Column('value_int64', sa.BigInteger),
        sa.Column('value_null_str', sa.Text, nullable=True, default=None),
        sa.Column('value_null_int32', sa.Integer, nullable=True, default=None),
        sa.Column('value_empty_str', sa.Text, nullable=False, default=''),
    )
    # schema table used to generate table in the database with binary column types
    schema_table = sa.Table(

        'test_type_aware_decryption_with_defaults', base.metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.LargeBinary),
        sa.Column('value_searchable', sa.LargeBinary),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.LargeBinary),
        sa.Column('value_int64', sa.LargeBinary),
        sa.Column('value_null_str', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_null_int32', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_empty_str', sa.LargeBinary, nullable=False, default=b''),
    )
    ENCRYPTOR_CONFIG = base.get_encryptor_config('tests/encryptor_configs/transparent_type_aware_decryption.yaml')

    def checkSkip(self):
        if not (base.TEST_POSTGRESQL and base.TEST_WITH_TLS):
            self.skipTest("Test only for PostgreSQL with TLS")

    def testClientIDRead(self):
        """test decrypting with correct clientID and not decrypting with
        incorrect clientID or using direct connection to db
        All result data should be valid for application. Not decrypted data should be returned with their default value
        """
        data = {
            'id': base.get_random_id(),
            'value_str': random_str(),
            'value_bytes': random_bytes(),
            'value_int32': random_int32(),
            'value_int64': random_int64(),
            'value_null_str': None,
            'value_null_int32': None,
            'value_empty_str': '',
            'value_searchable': random_str(),
        }
        default_expected_values = {
            'value_int32': 32,
            'value_int64': 64,
            'value_bytes': b'value_bytes',
            'value_str': 'value_str',
            'value_searchable': 'searchable_str',
        }

        self.schema_table.create(bind=self.engine_raw, checkfirst=True)
        columns = ('value_str', 'value_searchable', 'value_bytes', 'value_int32', 'value_int64', 'value_null_str',
                   'value_null_int32',
                   'value_empty_str')
        self.engine1.execute(self.test_table.insert(), data)
        result = self.engine1.execute(
            sa.select([self.test_table])
            .where(self.test_table.c.id == data['id']))
        row = result.fetchone()
        for column in columns:
            self.assertEqual(data[column], row[column])
            self.assertIsInstance(row[column], type(data[column]))

        result = self.engine2.execute(
            sa.select([self.test_table])
            .where(self.test_table.c.id == data['id']))
        row = result.fetchone()
        for column in columns:
            self.assertIsInstance(row[column], type(data[column]))
            if 'null' in column:
                self.assertIsNone(row[column])
                continue
            if 'empty' in column:
                self.assertEqual(row[column], '')
                self.assertEqual(row[column], data[column])
                continue
            self.assertNotEqual(data[column], row[column])
            if column in ('value_int32', 'value_int64'):
                self.assertEqual(row[column], default_expected_values[column])

        result = self.engine_raw.execute(
            sa.select([self.test_table])
            .where(self.test_table.c.id == data['id']))
        row = result.fetchone()
        for column in columns:
            if 'null' in column:
                self.assertIsNone(row[column])
                continue
            self.assertIsInstance(base.memoryview_to_bytes(row[column]), bytes)
            if column in ('value_str', 'value_bytes'):
                # length of data should be greater than source data due to encryption overhead
                self.assertTrue(len(base.memoryview_to_bytes(row[column])) > len(data[column]))


class TestPostgresqlTextFormatTypeAwareDecryptionWithDefaultsAndDataTypeIDs(
    TestPostgresqlTextFormatTypeAwareDecryptionWithDefaults):
    ENCRYPTOR_CONFIG = base.get_encryptor_config(
        'tests/encryptor_configs/transparent_type_aware_decryption_postgres_with_data_type_id.yaml')
    pass


class TestPostgresqlTextFormatTypeAwareDecryptionWithDefaultsWithConsulEncryptorConfigLoader(
    test_integrations.HashicorpConsulEncryptorConfigLoaderMixin,
    TestPostgresqlTextFormatTypeAwareDecryptionWithDefaults):
    pass


class TestMySQLTextFormatTypeAwareDecryptionWithDefaults(test_common.BaseBinaryMySQLTestCase,
                                                         test_searchable_transparent_encryption.BaseTransparentEncryption):
    # test table used for queries and data mapping into python types
    test_table = sa.Table(
        # use new object of metadata to avoid name conflict
        'test_type_aware_decryption_with_defaults', sa.MetaData(),
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.Text),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.Integer),
        sa.Column('value_int64', sa.BigInteger),
        sa.Column('value_null_str', sa.Text, nullable=True, default=None),
        sa.Column('value_null_int32', sa.Integer, nullable=True, default=None),
        sa.Column('value_empty_str', sa.Text, nullable=False, default=''),
        extend_existing=True
    )
    # schema table used to generate table in the database with binary column types
    schema_table = sa.Table(

        'test_type_aware_decryption_with_defaults', base.metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.LargeBinary),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.LargeBinary),
        sa.Column('value_int64', sa.LargeBinary),
        sa.Column('value_null_str', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_null_int32', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_empty_str', sa.LargeBinary, nullable=False, default=b''),
        extend_existing=True
    )
    ENCRYPTOR_CONFIG = base.get_encryptor_config('tests/encryptor_configs/transparent_type_aware_decryption.yaml')

    # switch off raw mode to be able to convert result rows to python types
    RAW_EXECUTOR = False

    def checkSkip(self):
        if not (base.TEST_MYSQL and base.TEST_WITH_TLS):
            self.skipTest("Test only for MySQL with TLS")

    def testClientIDRead(self):
        """test decrypting with correct clientID and not decrypting with
        incorrect clientID or using direct connection to db
        All result data should be valid for application. Not decrypted data should be returned with their default value
        """
        data = {
            'id': base.get_random_id(),
            'value_str': random_str(),
            'value_bytes': random_bytes(),
            'value_int32': random_int32(),
            'value_int64': random_int64(),
            'value_null_str': None,
            'value_null_int32': None,
            'value_empty_str': ''
        }
        default_expected_values = {
            'value_int32': 32,
            'value_int64': 64,
            'value_bytes': b'value_bytes',
            'value_str': 'value_str',
            'value_empty_str': '',
            'value_null_str': None,
            'value_null_int32': None,
        }

        self.schema_table.create(bind=self.engine_raw, checkfirst=True)
        columns = ('value_bytes', 'value_int32', 'value_int64', 'value_empty_str', 'value_str', 'value_null_str',
                   'value_null_int32')

        self.engine1.execute(self.test_table.insert(), data)

        compile_kwargs = {"literal_binds": True}
        query = sa.select([self.test_table]).where(self.test_table.c.id == data['id'])
        query = str(query.compile(compile_kwargs=compile_kwargs))

        row = self.executor1.execute(query)[0]
        for column in columns:
            self.assertEqual(data[column], row[column])
            self.assertIsInstance(row[column], type(data[column]))

        row = self.executor2.execute(query)[0]
        for column in columns:
            self.assertEqual(row[column], default_expected_values[column])
            self.assertIsInstance(row[column], type(default_expected_values[column]))

        row = self.engine_raw.execute(sa.select([self.test_table])
                                      .where(self.test_table.c.id == data['id'])).fetchone()
        for column in columns:
            if 'null' in column:
                self.assertIsNone(row[column])
                continue
            self.assertIsInstance(base.memoryview_to_bytes(row[column]), bytes)
            if column in ('value_str', 'value_bytes'):
                # length of data should be greater than source data due to encryption overhead
                self.assertTrue(len(base.memoryview_to_bytes(row[column])) > len(data[column]))


class TestMySQLTextFormatTypeAwareDecryptionWithDefaultsWithConsulEncryptorConfigLoader(
    test_integrations.HashicorpConsulEncryptorConfigLoaderMixin,
    TestMySQLTextFormatTypeAwareDecryptionWithDefaults):
    pass


class TestPostgresqlBinaryFormatTypeAwareDecryptionWithDefaults(
    test_common.BaseBinaryPostgreSQLTestCase, TestPostgresqlTextFormatTypeAwareDecryptionWithDefaults):
    def testClientIDRead(self):
        """test decrypting with correct clientID and not decrypting with
        incorrect clientID or using direct connection to db
        All result data should be valid for application. Not decrypted data should be returned with their default value
        """
        data = {
            'id': base.get_random_id(),
            'value_str': random_str(),
            'value_bytes': random_bytes(),
            'value_int32': random_int32(),
            'value_int64': random_int64(),
            'value_null_str': None,
            'value_null_int32': None,
            'value_empty_str': '',
            'value_searchable': random_str(),
        }
        default_expected_values = {
            'value_int32': 32,
            'value_int64': 64,
            'value_bytes': b'value_bytes',
            'value_str': 'value_str',
            'value_searchable': 'searchable_str',
        }

        self.schema_table.create(bind=self.engine_raw, checkfirst=True)
        columns = ('value_str', 'value_searchable', 'value_bytes', 'value_int32', 'value_int64', 'value_null_str',
                   'value_null_int32',
                   'value_empty_str')
        query, args = self.compileQuery(self.test_table.insert(), data)
        self.executor1.execute_prepared_statement(query, args)

        query, args = self.compileQuery(
            sa.select([self.test_table])
            .where(self.test_table.c.id == sa.bindparam('id')), {'id': data['id']})
        row = self.executor1.execute_prepared_statement(query, args)[0]
        for column in columns:
            self.assertEqual(data[column], row[column])
            self.assertIsInstance(row[column], type(data[column]))

        row = self.executor2.execute_prepared_statement(query, args)[0]
        for column in columns:
            if 'null' in column:
                self.assertIsNone(row[column])
                self.assertIsNone(data[column])
                continue
            if 'empty' in column:
                self.assertEqual(data[column], row[column])
                self.assertEqual(data[column], '')
            else:
                self.assertNotEqual(data[column], row[column])
                self.assertEqual(row[column], default_expected_values[column])
            self.assertIsInstance(row[column], type(data[column]))

        row = self.executor2.execute_prepared_statement(query, args)[0]
        for column in columns:
            if 'null' in column:
                self.assertIsNone(row[column])
                self.assertEqual(data[column], row[column])
                continue
            if 'empty' in column:
                self.assertEqual(row[column], '')
                self.assertEqual(row[column], data[column])
                continue
            self.assertNotEqual(data[column], row[column])


class TestPostgresqlBinaryFormatTypeAwareDecryptionWithDefaultsAndDataTypeIDs(
    TestPostgresqlBinaryFormatTypeAwareDecryptionWithDefaults):
    ENCRYPTOR_CONFIG = base.get_encryptor_config(
        'tests/encryptor_configs/transparent_type_aware_decryption_postgres_with_data_type_id.yaml')
    pass


class TestMySQLBinaryFormatTypeAwareDecryptionWithDefaults(TestMySQLTextFormatTypeAwareDecryptionWithDefaults):
    def testClientIDRead(self):
        """test decrypting with correct clientID and not decrypting with
        incorrect clientID or using direct connection to db
        All result data should be valid for application. Not decrypted data should be returned with their default value
        """
        data = {
            'id': base.get_random_id(),
            'value_str': random_str(),
            'value_bytes': random_bytes(),
            'value_int32': random_int32(),
            'value_int64': random_int64(),
            'value_null_str': None,
            'value_null_int32': None,
            'value_empty_str': ''
        }
        default_expected_values = {
            'value_int32': 32,
            'value_int64': 64,
            'value_bytes': b'value_bytes',
            'value_str': 'value_str',
        }

        self.schema_table.create(bind=self.engine_raw, checkfirst=True)
        columns = ('value_str', 'value_int32', 'value_int64', 'value_null_str', 'value_null_int32', 'value_empty_str')
        query, args = self.compileQuery(self.test_table.insert(), data)
        self.executor1.execute_prepared_statement_no_result(query, args)

        query, args = self.compileQuery(
            sa.select([self.test_table])
            .where(self.test_table.c.id == sa.bindparam('id')), {'id': data['id']})
        row = self.executor1.execute_prepared_statement(query, args)[0]

        # mysql bytes response present bytearray type not bytes
        self.assertIsInstance(row['value_bytes'], type(bytearray(data['value_bytes'])))

        for column in columns:
            self.assertEqual(data[column], row[column])
            self.assertIsInstance(row[column], type(data[column]))

        row = self.executor2.execute_prepared_statement(query, args)[0]

        # mysql bytes response present bytearray type not bytes
        self.assertNotEqual(row['value_bytes'], bytearray(data['value_bytes']))
        self.assertEqual(row['value_bytes'], bytearray(default_expected_values['value_bytes']))

        for column in columns:
            if 'empty' in column:
                self.assertEqual(row[column], '')
                self.assertEqual(row[column], data[column])
                continue
            elif 'null' in column:
                self.assertEqual(data[column], row[column])
                self.assertIsNone(data[column])
            else:
                self.assertNotEqual(data[column], row[column])
                self.assertEqual(default_expected_values[column], row[column])
            self.assertIsInstance(row[column], type(data[column]))


class TestPostgresqlTextTypeAwareDecryptionWithoutDefaults(
    test_searchable_transparent_encryption.BaseTransparentEncryption):
    # test table used for queries and data mapping into python types
    test_table = sa.Table(
        # use new object of metadata to avoid name conflict
        'test_type_aware_decryption_without_defaults', sa.MetaData(),
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.Text),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.Integer),
        sa.Column('value_int64', sa.BigInteger),
        sa.Column('value_null_str', sa.Text, nullable=True, default=None),
        sa.Column('value_null_int32', sa.Integer, nullable=True, default=None),
        sa.Column('value_empty_str', sa.Text, nullable=False, default=''),
    )
    # schema table used to generate table in the database with binary column types
    schema_table = sa.Table(

        'test_type_aware_decryption_without_defaults', base.metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.LargeBinary),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.LargeBinary),
        sa.Column('value_int64', sa.LargeBinary),
        sa.Column('value_null_str', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_null_int32', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_empty_str', sa.LargeBinary, nullable=False, default=b''),
    )
    ENCRYPTOR_CONFIG = base.get_encryptor_config('tests/encryptor_configs/transparent_type_aware_decryption.yaml')

    def checkSkip(self):
        if not (base.TEST_POSTGRESQL and base.TEST_WITH_TLS):
            self.skipTest("Test only for PostgreSQL with TLS")

    def testClientIDRead(self):
        """test decrypting with correct clientID and not decrypting with
        incorrect clientID or using direct connection to db
        All result data should be valid for application. Not decrypted data should be returned as is and DB driver
        should cause error
        """
        data = {
            'id': base.get_random_id(),
            'value_str': random_str(),
            'value_bytes': random_bytes(),
            'value_int32': random_int32(),
            'value_int64': random_int64(),
            'value_null_str': None,
            'value_null_int32': None,
            'value_empty_str': ''
        }
        self.schema_table.create(bind=self.engine_raw, checkfirst=True)
        self.engine1.execute(self.test_table.insert(), data)
        columns = ('value_str', 'value_bytes', 'value_int32', 'value_int64', 'value_null_str', 'value_null_int32',
                   'value_empty_str')

        result = self.engine2.execute(
            sa.select([self.test_table])
            .where(self.test_table.c.id == data['id']))
        # acra change types for binary data columns and python driver can't decode to correct types
        with self.assertRaises(UnicodeDecodeError):
            row = result.fetchone()

        # direct connection should receive binary data according to real scheme
        result = self.engine_raw.execute(
            sa.select([self.test_table])
            .where(self.test_table.c.id == data['id']))
        row = result.fetchone()
        for column in columns:
            if 'null' in column:
                self.assertIsNone(row[column])
                self.assertEqual(row[column], data[column])
                continue
            value = base.memoryview_to_bytes(row[column])
            if 'empty' in column:
                self.assertEqual(value, b'')
                continue
            self.assertIsInstance(value, bytes, column)
            self.assertNotEqual(data[column], value, column)


class TestMySQLTextTypeAwareDecryptionWithoutDefaults(test_common.BaseBinaryMySQLTestCase,
                                                      test_searchable_transparent_encryption.BaseTransparentEncryption):
    # test table used for queries and data mapping into python types
    test_table = sa.Table(
        # use new object of metadata to avoid name conflict
        'test_type_aware_decryption_without_defaults', sa.MetaData(),
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.Text),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.Integer),
        sa.Column('value_int64', sa.BigInteger),
        sa.Column('value_null_str', sa.Text, nullable=True, default=None),
        sa.Column('value_null_int32', sa.Integer, nullable=True, default=None),
        sa.Column('value_empty_str', sa.Text, nullable=False, default=''),
        extend_existing=True
    )
    # schema table used to generate table in the database with binary column types
    schema_table = sa.Table(

        'test_type_aware_decryption_without_defaults', base.metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.LargeBinary),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.LargeBinary),
        sa.Column('value_int64', sa.LargeBinary),
        sa.Column('value_null_str', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_null_int32', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_empty_str', sa.LargeBinary, nullable=False, default=b''),
        extend_existing=True
    )
    ENCRYPTOR_CONFIG = base.get_encryptor_config('tests/encryptor_configs/transparent_type_aware_decryption.yaml')

    # switch off raw mode to be able to convert result rows to python types
    RAW_EXECUTOR = False

    def checkSkip(self):
        if not (base.TEST_MYSQL and base.TEST_WITH_TLS):
            self.skipTest("Test only for MySQL with TLS")

    def testClientIDRead(self):
        """test decrypting with correct clientID and not decrypting with
        incorrect clientID or using direct connection to db
        All result data should be valid for application. Not decrypted data should be returned as is and DB driver
        should cause error

        MySQL decoder should roll back FieldType as well.
        """
        data = {
            'id': base.get_random_id(),
            'value_str': random_str(),
            'value_bytes': random_bytes(),
            'value_int32': random_int32(),
            'value_int64': random_int64(),
            'value_null_str': None,
            'value_null_int32': None,
            'value_empty_str': ''
        }
        self.schema_table.create(bind=self.engine_raw, checkfirst=True)
        self.engine1.execute(self.test_table.insert(), data)
        columns = ('value_str', 'value_bytes', 'value_int32', 'value_int64', 'value_empty_str', 'value_null_str',
                   'value_null_int32')

        compile_kwargs = {"literal_binds": True}
        query = sa.select([self.test_table]).where(self.test_table.c.id == data['id'])
        query = str(query.compile(compile_kwargs=compile_kwargs))

        row = self.executor1.execute(query)[0]
        for column in columns:
            self.assertEqual(data[column], row[column])
            self.assertIsInstance(row[column], type(data[column]))

        # field types should be rollbacked in case of invalid encoding
        row = self.executor2.execute(query)[0]

        # direct connection should receive binary data according to real scheme
        result = self.engine_raw.execute(
            sa.select([self.test_table])
            .where(self.test_table.c.id == data['id']))
        row = result.fetchone()
        for column in columns:
            if 'null' in column or 'empty' in column:
                # asyncpg decodes None values as empty str/bytes value
                self.assertFalse(row[column])
                continue
            value = base.memoryview_to_bytes(row[column])
            self.assertIsInstance(value, bytes, column)
            self.assertNotEqual(data[column], value, column)


class TestMySQLTextTypeAwareDecryptionWithoutDefaultsAndDataTypeIDs(TestMySQLTextTypeAwareDecryptionWithoutDefaults):
    ENCRYPTOR_CONFIG = base.get_encryptor_config(
        'tests/encryptor_configs/transparent_type_aware_decryption_mysql_with_data_type_id.yaml')
    pass


class TestPostgresqlBinaryTypeAwareDecryptionWithoutDefaults(TestPostgresqlBinaryFormatTypeAwareDecryptionWithDefaults):
    # test table used for queries and data mapping into python types
    test_table = sa.Table(
        # use new object of metadata to avoid name conflict
        'test_type_aware_decryption_without_defaults', sa.MetaData(),
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.Text),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.Integer),
        sa.Column('value_int64', sa.BigInteger),
        sa.Column('value_null_str', sa.Text, nullable=True, default=None),
        sa.Column('value_null_int32', sa.Integer, nullable=True, default=None),
        sa.Column('value_empty_str', sa.Text, nullable=False, default=''),
        extend_existing=True
    )
    # schema table used to generate table in the database with binary column types
    schema_table = sa.Table(
        'test_type_aware_decryption_without_defaults', base.metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.LargeBinary),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.LargeBinary),
        sa.Column('value_int64', sa.LargeBinary),
        sa.Column('value_null_str', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_null_int32', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_empty_str', sa.LargeBinary, nullable=False, default=b''),
        extend_existing=True
    )
    ENCRYPTOR_CONFIG = base.get_encryptor_config('tests/encryptor_configs/transparent_type_aware_decryption.yaml')

    def checkSkip(self):
        if not (base.TEST_POSTGRESQL and base.TEST_WITH_TLS):
            self.skipTest("Test only for PostgreSQL with TLS")

    def testClientIDRead(self):
        """
        override method from parent class with own table and data
        """
        data = {
            'id': base.get_random_id(),
            'value_str': random_str(),
            'value_bytes': random_bytes(),
            'value_int32': random_int32(),
            'value_int64': random_int64(),
            'value_null_str': None,
            'value_null_int32': None,
            'value_empty_str': ''
        }
        self._testClientIDRead(data)

    def testClientIDReadWithNegativeInteger(self):
        """
        test correct encoding/decoding negative integer values
        """
        data = {
            'id': base.get_random_id(),
            'value_str': random_str(),
            'value_bytes': random_bytes(),
            'value_int32': randint(max_negative_int32, 0),
            'value_int64': randint(max_negative_int64, 0),
            'value_null_str': None,
            'value_null_int32': None,
            'value_empty_str': ''
        }
        self._testClientIDRead(data)

    def _testClientIDRead(self, data):
        """test decrypting with correct clientID and not decrypting with
        incorrect clientID or using direct connection to db
        All result data should be valid for application. Not decrypted data should be returned as is and DB driver
        should cause error
        """
        self.schema_table.create(bind=self.engine_raw, checkfirst=True)
        ######
        columns = ('value_str', 'value_bytes', 'value_int32', 'value_int64', 'value_null_str', 'value_null_int32',
                   'value_empty_str')
        query, args = self.compileQuery(self.test_table.insert(), data)
        self.executor1.execute_prepared_statement(query, args)

        query, args = self.compileQuery(
            sa.select([self.test_table])
            .where(self.test_table.c.id == sa.bindparam('id')), {'id': data['id']})

        # Check that raw bytes were returned, which would not be valid utf
        with self.assertRaises(UnicodeDecodeError):
            row = self.executor2.execute_prepared_statement(query, args)[0]

        row = self.raw_executor.execute_prepared_statement(query, args)[0]
        for column in columns:
            if 'null' in column:
                self.assertIsNone(row[column])
                self.assertEqual(row[column], data[column])
                continue
            value = base.memoryview_to_bytes(row[column])
            if 'empty' in column:
                self.assertEqual(value, b'')
                continue
            self.assertIsInstance(value, bytes, column)
            self.assertNotEqual(data[column], value, column)


class TestPostgresqlBinaryTypeAwareDecryptionWithError(TestPostgresqlBinaryFormatTypeAwareDecryptionWithDefaults):
    # test table used for queries and data mapping into python types
    test_table = sa.Table(
        # use new object of metadata to avoid name conflict
        'test_type_aware_decryption_with_error', sa.MetaData(),
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.Text),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.Integer),
        sa.Column('value_int64', sa.BigInteger),
        sa.Column('value_null_str', sa.Text, nullable=True, default=None),
        sa.Column('value_null_int32', sa.Integer, nullable=True, default=None),
        sa.Column('value_empty_str', sa.Text, nullable=False, default=''),
        extend_existing=True
    )
    # schema table used to generate table in the database with binary column types
    schema_table = sa.Table(
        'test_type_aware_decryption_with_error', sa.MetaData(),
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.LargeBinary),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.LargeBinary),
        sa.Column('value_int64', sa.LargeBinary),
        sa.Column('value_null_str', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_null_int32', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_empty_str', sa.LargeBinary, nullable=False, default=b''),
        extend_existing=True
    )
    ENCRYPTOR_CONFIG = base.get_encryptor_config('tests/encryptor_configs/transparent_type_aware_decryption.yaml')

    def checkSkip(self):
        if not (base.TEST_POSTGRESQL and base.TEST_WITH_TLS):
            self.skipTest("Test only for PostgreSQL with TLS")

    def testClientIDRead(self):
        """
        test decrypting with correct clientID and not decrypting with
        incorrect clientID or using direct connection to db
        All result data should be valid for application. Not decrypted data
        should cause driver specific error
        """
        data = {
            'id': base.get_random_id(),
            'value_str': random_str(),
            'value_bytes': random_bytes(),
            'value_int32': random_int32(),
            'value_int64': random_int64(),
            'value_null_str': None,
            'value_null_int32': None,
            'value_empty_str': ''
        }
        self.schema_table.create(bind=self.engine_raw, checkfirst=True)
        ######
        columns = ('value_str', 'value_bytes', 'value_int32', 'value_int64',
                   'value_null_str', 'value_null_int32', 'value_empty_str')
        query, args = self.compileQuery(self.test_table.insert(), data)
        self.executor1.execute_prepared_statement(query, args)

        query, args = self.compileQuery(
            sa.select([self.test_table])
            .where(self.test_table.c.id == sa.bindparam('id')), {'id': data['id']})

        # We expect db-driver error
        with self.assertRaises(asyncpg.exceptions.SyntaxOrAccessError) as ex:
            row = self.executor2.execute_prepared_statement(query, args)[0]

        self.assertEqual('encoding error in column "value_str"', str(ex.exception))

        row = self.raw_executor.execute_prepared_statement(query, args)[0]
        for column in columns:
            if 'null' in column:
                self.assertIsNone(row[column])
                self.assertEqual(row[column], data[column])
                continue
            value = base.memoryview_to_bytes(row[column])
            if 'empty' in column:
                self.assertEqual(value, b'')
                continue
            self.assertIsInstance(value, bytes, column)
            self.assertNotEqual(data[column], value, column)


class TestPostgresqlTextTypeAwareDecryptionWithError(test_searchable_transparent_encryption.BaseTransparentEncryption):
    # test table used for queries and data mapping into python types
    test_table = sa.Table(
        # use new object of metadata to avoid name conflict
        'test_type_aware_decryption_with_error', sa.MetaData(),
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.Text),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.Integer),
        sa.Column('value_int64', sa.BigInteger),
        sa.Column('value_null_str', sa.Text, nullable=True, default=None),
        sa.Column('value_null_int32', sa.Integer, nullable=True, default=None),
        sa.Column('value_empty_str', sa.Text, nullable=False, default=''),
    )
    # schema table used to generate table in the database with binary column types
    schema_table = sa.Table(
        'test_type_aware_decryption_with_error', sa.MetaData(),
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.LargeBinary),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.LargeBinary),
        sa.Column('value_int64', sa.LargeBinary),
        sa.Column('value_null_str', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_null_int32', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_empty_str', sa.LargeBinary, nullable=False, default=b''),
    )
    ENCRYPTOR_CONFIG = base.get_encryptor_config('tests/encryptor_configs/transparent_type_aware_decryption.yaml')

    def checkSkip(self):
        if not (base.TEST_POSTGRESQL and base.TEST_WITH_TLS):
            self.skipTest("Test only for PostgreSQL with TLS")

    def testClientIDRead(self):
        """
        test decrypting with correct clientID and not decrypting with
        incorrect clientID or using direct connection to db
        All result data should be valid for application. Not decrypted data
        should cause a db-driver error.
        """
        data = {
            'id': base.get_random_id(),
            'value_str': random_str(),
            'value_bytes': random_bytes(),
            'value_int32': random_int32(),
            'value_int64': random_int64(),
            'value_null_str': None,
            'value_null_int32': None,
            'value_empty_str': ''
        }
        self.schema_table.create(bind=self.engine_raw, checkfirst=True)
        self.engine1.execute(self.test_table.insert(), data)
        columns = ('value_str', 'value_bytes', 'value_int32', 'value_int64',
                   'value_null_str', 'value_null_int32', 'value_empty_str')

        # our custom error is wrapped around sqlalchemy's ProgrammingError
        with self.assertRaises(ProgrammingError) as ex:
            self.engine2.execute(
                sa.select([self.test_table])
                .where(self.test_table.c.id == data['id']))

        self.assertEqual('encoding error in column "value_str"\n', str(ex.exception.orig))

        # direct connection should receive binary data according to real scheme
        result = self.engine_raw.execute(
            sa.select([self.test_table])
            .where(self.test_table.c.id == data['id']))
        row = result.fetchone()
        for column in columns:
            if 'null' in column:
                self.assertIsNone(row[column])
                self.assertEqual(row[column], data[column])
                continue
            value = base.memoryview_to_bytes(row[column])
            if 'empty' in column:
                self.assertEqual(value, b'')
                continue
            self.assertIsInstance(value, bytes, column)
            self.assertNotEqual(data[column], value, column)


# `response_on_fail` is `ciphertext` if not defined. That's why the code is
# exactly the same as in TestPostgresqlBinaryTypeAwareDecryptionWithoutDefaults
class TestPostgresqlBinaryTypeAwareDecryptionWithCiphertext(TestPostgresqlBinaryFormatTypeAwareDecryptionWithDefaults):
    # test table used for queries and data mapping into python types
    test_table = sa.Table(
        # use new object of metadata to avoid name conflict
        'test_type_aware_decryption_without_defaults', sa.MetaData(),
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.Text),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.Integer),
        sa.Column('value_int64', sa.BigInteger),
        sa.Column('value_null_str', sa.Text, nullable=True, default=None),
        sa.Column('value_null_int32', sa.Integer, nullable=True, default=None),
        sa.Column('value_empty_str', sa.Text, nullable=False, default=''),
        extend_existing=True
    )
    # schema table used to generate table in the database with binary column types
    schema_table = sa.Table(
        'test_type_aware_decryption_without_defaults', base.metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.LargeBinary),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.LargeBinary),
        sa.Column('value_int64', sa.LargeBinary),
        sa.Column('value_null_str', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_null_int32', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_empty_str', sa.LargeBinary, nullable=False, default=b''),
        extend_existing=True
    )
    ENCRYPTOR_CONFIG = base.get_encryptor_config('tests/encryptor_configs/transparent_type_aware_decryption.yaml')

    def checkSkip(self):
        if not (base.TEST_POSTGRESQL and base.TEST_WITH_TLS):
            self.skipTest("Test only for PostgreSQL with TLS")

    def testClientIDRead(self):
        """test decrypting with correct clientID and not decrypting with
        incorrect clientID or using direct connection to db
        All result data should be valid for application. Not decrypted data should be returned as is and DB driver
        should cause error
        """
        data = {
            'id': base.get_random_id(),
            'value_str': random_str(),
            'value_bytes': random_bytes(),
            'value_int32': random_int32(),
            'value_int64': random_int64(),
            'value_null_str': None,
            'value_null_int32': None,
            'value_empty_str': ''
        }
        self.schema_table.create(bind=self.engine_raw, checkfirst=True)
        ######
        columns = ('value_str', 'value_bytes', 'value_int32', 'value_int64', 'value_null_str', 'value_null_int32',
                   'value_empty_str')
        query, args = self.compileQuery(self.test_table.insert(), data)
        self.executor1.execute_prepared_statement(query, args)

        query, args = self.compileQuery(
            sa.select([self.test_table])
            .where(self.test_table.c.id == sa.bindparam('id')), {'id': data['id']})

        # Check that raw bytes were returned, which would not be valid utf
        with self.assertRaises(UnicodeDecodeError):
            row = self.executor2.execute_prepared_statement(query, args)[0]

        row = self.raw_executor.execute_prepared_statement(query, args)[0]
        for column in columns:
            if 'null' in column:
                self.assertIsNone(row[column])
                self.assertEqual(row[column], data[column])
                continue
            value = base.memoryview_to_bytes(row[column])
            if 'empty' in column:
                self.assertEqual(value, b'')
                continue
            self.assertIsInstance(value, bytes, column)
            self.assertNotEqual(data[column], value, column)


# `response_on_fail` is `ciphertext` if not defined. That's why the code is
# exactly the same as inTestPostgresqlTextTypeAwareDecryptionWithoutDefaults
class TestPostgresqlTextTypeAwareDecryptionWithCiphertext(
    test_searchable_transparent_encryption.BaseTransparentEncryption):
    # test table used for queries and data mapping into python types
    test_table = sa.Table(
        # use new object of metadata to avoid name conflict
        'test_type_aware_decryption_with_ciphertext', sa.MetaData(),
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.Text),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.Integer),
        sa.Column('value_int64', sa.BigInteger),
        sa.Column('value_null_str', sa.Text, nullable=True, default=None),
        sa.Column('value_null_int32', sa.Integer, nullable=True, default=None),
        sa.Column('value_empty_str', sa.Text, nullable=False, default=''),
    )
    # schema table used to generate table in the database with binary column types
    schema_table = sa.Table(
        'test_type_aware_decryption_with_ciphertext', sa.MetaData(),
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.LargeBinary),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.LargeBinary),
        sa.Column('value_int64', sa.LargeBinary),
        sa.Column('value_null_str', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_null_int32', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_empty_str', sa.LargeBinary, nullable=False, default=b''),
    )
    ENCRYPTOR_CONFIG = base.get_encryptor_config('tests/encryptor_configs/transparent_type_aware_decryption.yaml')

    def checkSkip(self):
        if not (base.TEST_POSTGRESQL and base.TEST_WITH_TLS):
            self.skipTest("Test only for PostgreSQL with TLS")

    def testClientIDRead(self):
        """test decrypting with correct clientID and not decrypting with
        incorrect clientID or using direct connection to db
        All result data should be valid for application. Not decrypted data should be returned as is and DB driver
        should cause error
        """
        data = {
            'id': base.get_random_id(),
            'value_str': random_str(),
            'value_bytes': random_bytes(),
            'value_int32': random_int32(),
            'value_int64': random_int64(),
            'value_null_str': None,
            'value_null_int32': None,
            'value_empty_str': ''
        }
        self.schema_table.create(bind=self.engine_raw, checkfirst=True)
        self.engine1.execute(self.test_table.insert(), data)
        columns = ('value_str', 'value_bytes', 'value_int32', 'value_int64', 'value_null_str', 'value_null_int32',
                   'value_empty_str')

        result = self.engine2.execute(
            sa.select([self.test_table])
            .where(self.test_table.c.id == data['id']))
        # acra change types for binary data columns and python driver can't decode to correct types
        with self.assertRaises(UnicodeDecodeError):
            row = result.fetchone()

        # direct connection should receive binary data according to real scheme
        result = self.engine_raw.execute(
            sa.select([self.test_table])
            .where(self.test_table.c.id == data['id']))
        row = result.fetchone()
        for column in columns:
            if 'null' in column:
                self.assertIsNone(row[column])
                self.assertEqual(row[column], data[column])
                continue
            value = base.memoryview_to_bytes(row[column])
            if 'empty' in column:
                self.assertEqual(value, b'')
                continue
            self.assertIsInstance(value, bytes, column)
            self.assertNotEqual(data[column], value, column)


class TestMySQLBinaryTypeAwareDecryptionWithoutDefaults(TestMySQLTextTypeAwareDecryptionWithoutDefaults):
    def checkSkip(self):
        if not (base.TEST_MYSQL and base.TEST_WITH_TLS):
            self.skipTest("Test only for MySQL with TLS")

    def testClientIDRead(self):
        """test decrypting with correct clientID and not decrypting with
        incorrect clientID or using direct connection to db
        All result data should be valid for application. Not decrypted data should be returned as is and DB driver
        should cause error

        MySQL decoder should roll back FieldType as well.
        """
        data = {
            'id': base.get_random_id(),
            'value_str': random_str(),
            'value_bytes': random_bytes(),
            'value_int32': random_int32(),
            'value_int64': random_int64(),
            'value_null_str': None,
            'value_null_int32': None,
            'value_empty_str': ''
        }
        self.schema_table.create(bind=self.engine_raw, checkfirst=True)
        ######
        columns = ('value_str', 'value_bytes', 'value_int32', 'value_int64', 'value_null_str', 'value_null_int32',
                   'value_empty_str')
        query, args = self.compileQuery(self.test_table.insert(), data)
        self.executor1.execute_prepared_statement_no_result(query, args)

        query, args = self.compileQuery(
            sa.select([self.test_table])
            .where(self.test_table.c.id == sa.bindparam('id')), {'id': data['id']})

        # just make sure that it is not failing meant that decoder rollback field types
        row = self.executor2.execute_prepared_statement(query, args)[0]

        for column in columns:
            if 'null' in column or 'empty' in column:
                # asyncpg decodes None values as empty str/bytes value
                self.assertFalse(row[column])
                continue
            value = base.memoryview_to_bytes(row[column])
            self.assertIsInstance(value, bytearray, column)
            self.assertNotEqual(data[column], value, column)


class TestMySQLTextTypeAwareDecryptionWithCiphertext(test_common.BaseBinaryMySQLTestCase,
                                                     test_searchable_transparent_encryption.BaseTransparentEncryption):
    # test table used for queries and data mapping into python types
    test_table = sa.Table(
        # use new object of metadata to avoid name conflict
        'test_type_aware_decryption_with_ciphertext', sa.MetaData(),
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.Text),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.Integer),
        sa.Column('value_int64', sa.BigInteger),
        sa.Column('value_null_str', sa.Text, nullable=True, default=None),
        sa.Column('value_null_int32', sa.Integer, nullable=True, default=None),
        sa.Column('value_empty_str', sa.Text, nullable=False, default=''),
        extend_existing=True
    )
    # schema table used to generate table in the database with binary column types
    schema_table = sa.Table(

        'test_type_aware_decryption_with_ciphertext', base.metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.LargeBinary),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.LargeBinary),
        sa.Column('value_int64', sa.LargeBinary),
        sa.Column('value_null_str', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_null_int32', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_empty_str', sa.LargeBinary, nullable=False, default=b''),
        extend_existing=True
    )
    ENCRYPTOR_CONFIG = base.get_encryptor_config('tests/encryptor_configs/transparent_type_aware_decryption.yaml')

    # switch off raw mode to be able to convert result rows to python types
    RAW_EXECUTOR = False

    def checkSkip(self):
        if not (base.TEST_MYSQL and base.TEST_WITH_TLS):
            self.skipTest("Test only for MySQL with TLS")

    def testClientIDRead(self):
        """test decrypting with correct clientID and not decrypting with
        incorrect clientID or using direct connection to db
        All result data should be valid for application. Not decrypted data should be returned as is and DB driver
        should cause error

        MySQL decoder should roll back FieldType as well.
        """
        data = {
            'id': base.get_random_id(),
            'value_str': random_str(),
            'value_bytes': random_bytes(),
            'value_int32': random_int32(),
            'value_int64': random_int64(),
            'value_null_str': None,
            'value_null_int32': None,
            'value_empty_str': ''
        }
        self.schema_table.create(bind=self.engine_raw, checkfirst=True)
        self.engine1.execute(self.test_table.insert(), data)
        columns = ('value_str', 'value_bytes', 'value_int32', 'value_int64', 'value_empty_str', 'value_null_str',
                   'value_null_int32')

        compile_kwargs = {"literal_binds": True}
        query = sa.select([self.test_table]).where(self.test_table.c.id == data['id'])
        query = str(query.compile(compile_kwargs=compile_kwargs))

        row = self.executor1.execute(query)[0]
        for column in columns:
            self.assertEqual(data[column], row[column])
            self.assertIsInstance(row[column], type(data[column]))

        # field types should be rollbacked in case of invalid encoding
        row = self.executor2.execute(query)[0]

        # direct connection should receive binary data according to real scheme
        result = self.engine_raw.execute(
            sa.select([self.test_table])
            .where(self.test_table.c.id == data['id']))
        row = result.fetchone()
        for column in columns:
            if 'null' in column or 'empty' in column:
                # asyncpg decodes None values as empty str/bytes value
                self.assertFalse(row[column])
                continue
            value = base.memoryview_to_bytes(row[column])
            self.assertIsInstance(value, bytes, column)
            self.assertNotEqual(data[column], value, column)


class TestMariaDBTextTypeAwareDecryptionWithCiphertext(test_common.AcraCatchLogsMixin, test_common.BaseBinaryMariaDBTestCase,
                                                       test_searchable_transparent_encryption.BaseTransparentEncryption):
    # test table used for queries and data mapping into python types
    test_table = sa.Table(
        # use new object of metadata to avoid name conflict
        'test_type_aware_decryption_with_ciphertext', sa.MetaData(),
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.Text),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.Integer),
        sa.Column('value_int64', sa.BigInteger),
        sa.Column('value_null_str', sa.Text, nullable=True, default=None),
        sa.Column('value_null_int32', sa.Integer, nullable=True, default=None),
        sa.Column('value_empty_str', sa.Text, nullable=False, default=''),
        extend_existing=True
    )
    # schema table used to generate table in the database with binary column types
    schema_table = sa.Table(

        'test_type_aware_decryption_with_ciphertext', base.metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.LargeBinary),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.LargeBinary),
        sa.Column('value_int64', sa.LargeBinary),
        sa.Column('value_null_str', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_null_int32', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_empty_str', sa.LargeBinary, nullable=False, default=b''),
        extend_existing=True
    )
    ENCRYPTOR_CONFIG = base.get_encryptor_config('./encryptor_configs/transparent_type_aware_decryption.yaml')

    # switch off raw mode to be able to convert result rows to python types
    RAW_EXECUTOR = False

    def checkSkip(self):
        if not (base.TEST_MARIADB and base.TEST_WITH_TLS):
            self.skipTest("Test only for MariaDB with TLS")

    def testClientIDRead(self):
        """test decrypting with correct clientID and not decrypting with
        incorrect clientID or using direct connection to db
        All result data should be valid for application. Not decrypted data should be returned as is and DB driver
        should cause error

        MySQL decoder should roll back FieldType as well.
        """
        data = {
            'id': base.get_random_id(),
            'value_str': random_str(),
            'value_bytes': random_bytes(),
            'value_int32': random_int32(),
            'value_int64': random_int64(),
            'value_null_str': None,
            'value_null_int32': None,
            'value_empty_str': ''
        }
        self.schema_table.create(bind=self.engine_raw, checkfirst=True)
        self.engine1.execute(self.test_table.insert(), data)
        columns = ('value_str', 'value_bytes', 'value_int32', 'value_int64', 'value_empty_str', 'value_null_str',
                   'value_null_int32')

        compile_kwargs = {"literal_binds": True}
        query = sa.select([self.test_table]).where(self.test_table.c.id == data['id'])
        query = str(query.compile(compile_kwargs=compile_kwargs))

        row = self.executor1.execute(query)[0]
        for column in columns:
            self.assertEqual(data[column], row[column])
            self.assertIsInstance(row[column], type(data[column]))

        try:
            # field types should be rollbacked in case of invalid encoding
            self.executor2.execute(query)[0]
        except Exception as ex:
            log = self.read_log(self.acra)
            self.assertIn('Failed to change data type - rollback field type', log)

        # direct connection should receive binary data according to real scheme
        result = self.engine_raw.execute(
            sa.select([self.test_table])
            .where(self.test_table.c.id == data['id']))
        row = result.fetchone()
        for column in columns:
            if 'null' in column or 'empty' in column:
                # asyncpg decodes None values as empty str/bytes value
                self.assertFalse(row[column])
                continue
            value = base.memoryview_to_bytes(row[column])
            self.assertIsInstance(value, bytes, column)
            self.assertNotEqual(data[column], value, column)


class TestMySQLTextTypeAwareDecryptionWithCiphertextWithDataTypeIDs(TestMySQLTextTypeAwareDecryptionWithCiphertext):
    ENCRYPTOR_CONFIG = base.get_encryptor_config(
        'tests/encryptor_configs/transparent_type_aware_decryption_mysql_with_data_type_id.yaml')
    pass


class TestMySQLBinaryTypeAwareDecryptionWithCiphertext(TestMySQLTextTypeAwareDecryptionWithCiphertext):
    def checkSkip(self):
        if not (base.TEST_MYSQL and base.TEST_WITH_TLS):
            self.skipTest("Test only for MySQL with TLS")

    def testClientIDRead(self):
        """test decrypting with correct clientID and not decrypting with
        incorrect clientID or using direct connection to db
        All result data should be valid for application. Not decrypted data should be returned as is and DB driver
        should cause error

        MySQL decoder should roll back FieldType as well.
        """
        data = {
            'id': base.get_random_id(),
            'value_str': random_str(),
            'value_bytes': random_bytes(),
            'value_int32': random_int32(),
            'value_int64': random_int64(),
            'value_null_str': None,
            'value_null_int32': None,
            'value_empty_str': ''
        }
        self.schema_table.create(bind=self.engine_raw, checkfirst=True)
        ######
        columns = ('value_str', 'value_bytes', 'value_int32', 'value_int64', 'value_null_str', 'value_null_int32',
                   'value_empty_str')
        query, args = self.compileQuery(self.test_table.insert(), data)
        self.executor1.execute_prepared_statement_no_result(query, args)

        query, args = self.compileQuery(
            sa.select([self.test_table])
            .where(self.test_table.c.id == sa.bindparam('id')), {'id': data['id']})

        # just make sure that it is not failing meant that decoder rollback field types
        row = self.executor2.execute_prepared_statement(query, args)[0]

        for column in columns:
            if 'null' in column or 'empty' in column:
                # asyncpg decodes None values as empty str/bytes value
                self.assertFalse(row[column])
                continue
            value = base.memoryview_to_bytes(row[column])
            self.assertIsInstance(value, bytearray, column)
            self.assertNotEqual(data[column], value, column)


class TestMySQLBinaryTypeAwareDecryptionWithCiphertextWithDataTypeIDs(TestMySQLBinaryTypeAwareDecryptionWithCiphertext):
    ENCRYPTOR_CONFIG = base.get_encryptor_config(
        'tests/encryptor_configs/transparent_type_aware_decryption_mysql_with_data_type_id.yaml')
    pass


class TestMySQLTextTypeAwareDecryptionWithError(test_common.BaseBinaryMySQLTestCase,
                                                test_searchable_transparent_encryption.BaseTransparentEncryption):
    # test table used for queries and data mapping into python types
    test_table = sa.Table(
        # use new object of metadata to avoid name conflict
        'test_type_aware_decryption_with_error', sa.MetaData(),
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.Text),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.Integer),
        sa.Column('value_int64', sa.BigInteger),
        sa.Column('value_null_str', sa.Text, nullable=True, default=None),
        sa.Column('value_null_int32', sa.Integer, nullable=True, default=None),
        sa.Column('value_empty_str', sa.Text, nullable=False, default=''),
        extend_existing=True
    )
    # schema table used to generate table in the database with binary column types
    schema_table = sa.Table(
        'test_type_aware_decryption_with_error', base.metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('value_str', sa.LargeBinary),
        sa.Column('value_bytes', sa.LargeBinary),
        sa.Column('value_int32', sa.LargeBinary),
        sa.Column('value_int64', sa.LargeBinary),
        sa.Column('value_null_str', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_null_int32', sa.LargeBinary, nullable=True, default=None),
        sa.Column('value_empty_str', sa.LargeBinary, nullable=False, default=b''),
        extend_existing=True
    )
    ENCRYPTOR_CONFIG = base.get_encryptor_config('tests/encryptor_configs/transparent_type_aware_decryption.yaml')

    # switch off raw mode to be able to convert result rows to python types
    RAW_EXECUTOR = False

    def checkSkip(self):
        if not (base.TEST_MYSQL and base.TEST_WITH_TLS):
            self.skipTest("Test only for MySQL with TLS")

    def testClientIDRead(self):
        """test decrypting with correct clientID and not decrypting with
        incorrect clientID or using direct connection to db
        All result data should be valid for application. Not decrypted data should be returned as is and DB driver
        should cause error

        MySQL decoder should roll back FieldType as well.
        """
        data = {
            'id': base.get_random_id(),
            'value_str': random_str(),
            'value_bytes': random_bytes(),
            'value_int32': random_int32(),
            'value_int64': random_int64(),
            'value_null_str': None,
            'value_null_int32': None,
            'value_empty_str': ''
        }
        self.schema_table.create(bind=self.engine_raw, checkfirst=True)
        self.engine1.execute(self.test_table.insert(), data)
        columns = ('value_str', 'value_bytes', 'value_int32', 'value_int64', 'value_empty_str', 'value_null_str',
                   'value_null_int32')

        compile_kwargs = {"literal_binds": True}
        query = sa.select([self.test_table]).where(self.test_table.c.id == data['id'])
        query = str(query.compile(compile_kwargs=compile_kwargs))

        row = self.executor1.execute(query)[0]
        for column in columns:
            self.assertEqual(data[column], row[column])
            self.assertIsInstance(row[column], type(data[column]))

        # we expect an exception because of decryption error
        with self.assertRaises(mysql.connector.errors.DatabaseError) as ex:
            self.executor2.execute(query)[0]

        self.assertEqual('encoding error in column "value_str"', ex.exception.msg)
        self.assertEqual(ex.exception.errno, base.MYSQL_ERR_QUERY_INTERRUPTED_CODE)


class TestMySQLTextTypeAwareDecryptionWithErrorWithDataTypeIDs(TestMySQLTextTypeAwareDecryptionWithError):
    ENCRYPTOR_CONFIG = base.get_encryptor_config(
        'tests/encryptor_configs/transparent_type_aware_decryption_mysql_with_data_type_id.yaml')
    pass


class TestMySQLBinaryTypeAwareDecryptionWithError(TestMySQLTextTypeAwareDecryptionWithError):
    def checkSkip(self):
        if not (base.TEST_MYSQL and base.TEST_WITH_TLS):
            self.skipTest("Test only for MySQL with TLS")

    def testClientIDRead(self):
        """test decrypting with correct clientID and not decrypting with
        incorrect clientID or using direct connection to db
        All result data should be valid for application. Not decrypted data should be returned as is and DB driver
        should cause error

        MySQL decoder should roll back FieldType as well.
        """
        data = {
            'id': base.get_random_id(),
            'value_str': random_str(),
            'value_bytes': random_bytes(),
            'value_int32': random_int32(),
            'value_int64': random_int64(),
            'value_null_str': None,
            'value_null_int32': None,
            'value_empty_str': ''
        }
        self.schema_table.create(bind=self.engine_raw, checkfirst=True)
        ######
        columns = ('value_str', 'value_bytes', 'value_int32', 'value_int64', 'value_null_str', 'value_null_int32',
                   'value_empty_str')
        query, args = self.compileQuery(self.test_table.insert(), data)
        self.executor1.execute_prepared_statement_no_result(query, args)

        query, args = self.compileQuery(
            sa.select([self.test_table])
            .where(self.test_table.c.id == sa.bindparam('id')), {'id': data['id']})

        # we expect an exception because of decryption error
        with self.assertRaises(mysql.connector.errors.DatabaseError) as ex:
            self.executor2.execute_prepared_statement(query, args)[0]

        self.assertEqual('encoding error in column "value_str"', ex.exception.msg)
        self.assertEqual(ex.exception.errno, base.MYSQL_ERR_QUERY_INTERRUPTED_CODE)


class TestMySQLBinaryTypeAwareDecryptionWithErrorWithDataTypeIDs(TestMySQLBinaryTypeAwareDecryptionWithError):
    ENCRYPTOR_CONFIG = base.get_encryptor_config(
        'tests/encryptor_configs/transparent_type_aware_decryption_mysql_with_data_type_id.yaml')
    pass


class TestMySQLTextCharsetLiterals(TestMySQLTextTypeAwareDecryptionWithoutDefaults):
    def testClientIDRead(self):
        """
        We don't directly support charset introducers[1], but at least make
        sure it can handle _binary in paretheses.

        [1]: https://dev.mysql.com/doc/refman/8.0/en/charset-introducer.html
        """

        self.schema_table.create(bind=self.engine_raw, checkfirst=True)
        id = base.get_random_id()
        insert = self.test_table.insert().values(
            id=id,
            # Crafts `_binary 'binary_string'`
            value_bytes=expression.UnaryExpression(
                expression.literal('binary_string'),
                operator=operators.custom_op('_binary'),
                type_=sa.Text,
            ),
            value_empty_str='',
        )
        self.engine1.execute(insert)

        columns = [self.test_table.c.id, self.test_table.c.value_bytes]

        query = sa.select(columns).where(self.test_table.c.id == id)
        query = str(query.compile(compile_kwargs={"literal_binds": True}))

        row = self.executor1.execute(query)[0]
        self.assertEqual(row['id'], id)
        self.assertEqual(row['value_bytes'], b'binary_string')

        # direct connection should receive binary data according to real scheme
        result = self.engine_raw.execute(query)
        row = result.fetchone()
        self.assertNotEqual(row['value_bytes'], b'binary_string')

    def testClientIDReadRawSql(self):
        """
        We don't directly support charset introducers[1], but at least make
        sure it can handle _binary.

        [1]: https://dev.mysql.com/doc/refman/8.0/en/charset-introducer.html
        """

        self.schema_table.create(bind=self.engine_raw, checkfirst=True)
        id = base.get_random_id()
        # DON'T EVER, EVER DO THIS
        # Do not use direct string interpolation for sql values
        # This is just a test example.
        #
        # Also, insert value_empty_str because it can't be null
        insert = f"""
            INSERT INTO {self.test_table.name}(id, value_bytes, value_empty_str)
            VALUES ({id}, _binary 'binary_string', '')
        """
        self.engine1.execute(insert)

        columns = [self.test_table.c.id, self.test_table.c.value_bytes]

        query = sa.select(columns).where(self.test_table.c.id == id)
        query = str(query.compile(compile_kwargs={"literal_binds": True}))

        row = self.executor1.execute(query)[0]
        self.assertEqual(row['id'], id)
        self.assertEqual(row['value_bytes'], b'binary_string')

        # direct connection should receive encrypted data
        result = self.engine_raw.execute(query)
        row = result.fetchone()
        self.assertNotEqual(row['value_bytes'], b'binary_string')


class TestPostgresqlTypeAwareDecryptionWithDefaultsPsycopg3(test_common.Psycopg3ExecutorMixin,
                                                            TestPostgresqlBinaryFormatTypeAwareDecryptionWithDefaults):
    # Psycopg3 includes a type of parameters in a parse string, which is optional
    # and therefore most of the frontends doesn't do that. So, test also with it.
    pass


class TestClientIDDecryptionWithVaultMasterKeyLoader(test_integrations.HashiCorpVaultMasterKeyLoaderMixin,
                                                     test_common.HexFormatTest):
    pass


def setUpModule():
    base.setUpModule()


def tearDownModule():
    base.tearDownModule()
