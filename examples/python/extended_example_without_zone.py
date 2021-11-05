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
import argparse
import json
import os
from base64 import b64decode

from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import BYTEA

try:
    # For Python 3.0 and later
    from urllib.request import urlopen
except ImportError:
    # Fall back to Python 2's urllib2
    from urllib2 import urlopen

from sqlalchemy import (Table, Column, Integer, MetaData, create_engine,
                        select, Binary, Text, BigInteger, cast, text, literal)

metadata = MetaData()
test_table = Table(
    'test', metadata,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('data', Binary, nullable=True),
    Column('masking', Binary, nullable=True),
    Column('token_i32', Integer, nullable=True),
    Column('token_i64', BigInteger, nullable=True),
    Column('token_str', Text, nullable=True),
    Column('token_bytes', Binary, nullable=True),
    Column('token_email', Text, nullable=True),
)

rotation_test_table = Table(
    'users', metadata,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('email', Binary, nullable=True),
)

table_map = {
    test_table.name: test_table,
    rotation_test_table.name: rotation_test_table,
}


def get_default(name, value):
    """return value from environment variables with name EXAMPLE_<name>
    or value"""
    return os.environ.get('EXAMPLE_{}'.format(name.upper()), value)


def print_data(connection, columns, table=test_table):
    """fetch data from database (use zone_id if not empty/None) and print to
    console"""
    default_columns = ['id']
    try:
        if columns:
            table_columns = [table.c.id] + [
                getattr(table.c, i) for i in columns]
            query = select(table_columns)
            extra_columns = columns
        else:
            table_columns = [table.c.id] + [
                i for i in table.columns if i.name not in default_columns]
            query = select(table_columns)
            extra_columns = [i.name for i in table.columns if i.name not in default_columns]
    except AttributeError:
        print("\n\n{0}\nprobably you used incorrect column name\n{0}\n\n".format('*'*30))
        raise
        exit(1)

    print("Fetch data by query {}\n",
          query.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
    result = connection.execute(query)
    result = result.fetchall()

    print(len(result))
    print("{:<3} - {}".format(*default_columns, ' - '.join(extra_columns)))
    for row in result:
        values = ['{:<3}'.format(row['id'])]
        for col in row[1:]:
            if isinstance(col, (bytes, bytearray)):
                values.append(col.decode('utf-8', errors='ignore'))
            else:
                values.append(str(col))

        print(' - '.join(values))


def write_data(data, connection, table=test_table):
    # here we encrypt our data and wrap into AcraStruct
    with open(data, 'r') as f:
        data = json.load(f)
    print("data: {}".format(data))
    rows = data
    if isinstance(data, dict):
        rows = [data]
    for row in rows:
        for k in ('data', 'email', 'token_bytes', 'masking'):
            if k in row:
                row[k] = row[k].encode('ascii')
        connection.execute(
            table.insert(), row)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--db_name', type=str,
                        default=get_default('db_name', 'acra'),
                        help='Database name')
    parser.add_argument('--db_user', type=str,
                        default=get_default('db_user', 'test'),
                        help='Database user')
    parser.add_argument('--db_password', type=str,
                        default=get_default('db_password', 'test'),
                        help='Database user\'s password')
    parser.add_argument('--port', type=int,
                        default=get_default('port', 9494),
                        help='Port of database or AcraConnector')
    parser.add_argument('--host', type=str,
                        default=get_default('host', 'localhost'),
                        help='Host of database or AcraConnector')
    parser.add_argument('--data', type=str,
                        default=get_default('data', ''),
                        help='data to save in ascii. default random data')
    parser.add_argument('--print', action='store_true',
                        default=get_default('print', False),
                        help='Print data ')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                        default=get_default('verbose', False), help='verbose')
    parser.add_argument('-c', '--columns', nargs='+', dest='columns',
                        default=get_default('columns', False), help='List of columns to display')
    parser.add_argument('--db_table', default=test_table.name, help='Table used to read/write data')
    args = parser.parse_args()

    driver = 'postgresql'

    engine = create_engine(
        '{}://{}:{}@{}:{}/{}'.format(
            driver, args.db_user, args.db_password, args.host, args.port,
            args.db_name),
        echo=bool(args.verbose))
    connection = engine.connect()
    metadata.create_all(engine)

    print('DB driver: {}'.format(driver))

    if args.print:
        print_data(connection, args.columns, table_map[args.db_table])
    elif args.data:
        write_data(args.data, connection, table_map[args.db_table])
    else:
        print('Use --print or --data options')
        exit(1)
