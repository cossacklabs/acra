# Copyright 2024, Cossack Labs Limited
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

from sqlalchemy import (Table, Column, Integer, MetaData, select, LargeBinary, Text, BigInteger)
from sqlalchemy.dialects import postgresql

from common import get_engine, get_default, register_common_cli_params

metadata = MetaData()
test_table = Table(
    'test', MetaData(),
    Column('id', Integer, primary_key=True, nullable=False),
    Column('data_str', Text, nullable=True),
    Column('masking', Text, nullable=True),
    Column('token_i32', Integer, nullable=True),
    Column('data_i32', Integer, nullable=True),
    Column('token_i64', BigInteger, nullable=True),
    Column('data_i64', BigInteger, nullable=True),
    Column('token_str', Text, nullable=True),
    Column('token_bytes', LargeBinary, nullable=True),
    Column('token_email', Text, nullable=True),
)
# _schema_test_table used to generate table in the database with binary column types
_schema_test_table = Table(
    'test', metadata,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('data_str', LargeBinary, nullable=True),
    Column('masking', LargeBinary, nullable=True),
    Column('token_i32', Integer, nullable=True),
    Column('data_i32', LargeBinary, nullable=True),
    Column('token_i64', BigInteger, nullable=True),
    Column('data_i64', LargeBinary, nullable=True),
    Column('token_str', Text, nullable=True),
    Column('token_bytes', LargeBinary, nullable=True),
    Column('token_email', Text, nullable=True),
)

table_map = {
    test_table.name: test_table,
}


def print_data(connection, columns, table=test_table):
    """fetch data from database and print to console"""
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
        print("\n\n{0}\nprobably you used incorrect column name\n{0}\n\n".format('*' * 30))
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
        if 'token_bytes' in row:
            # explicitly encode bytes data to bytes so alchemy send it as hexadecimal string in insert query
            row['token_bytes'] = row['token_bytes'].encode('ascii')
        connection.execute(
            table.insert(), row)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    register_common_cli_params(parser)
    parser.add_argument('--data', type=str,
                        default=get_default('data', ''),
                        help='data to save in ascii. default random data')
    parser.add_argument('-c', '--columns', nargs='+', dest='columns',
                        default=get_default('columns', False), help='List of columns to display')
    parser.add_argument('--db_table', default=test_table.name, help='Table used to read/write data')
    args = parser.parse_args()

    engine = get_engine(
        db_host=args.host, db_port=args.port, db_user=args.db_user, db_password=args.db_password,
        db_name=args.db_name, is_mysql=args.mysql, is_postgresql=args.postgresql,
        tls_ca=args.tls_root_cert, tls_key=args.tls_key, tls_crt=args.tls_cert,
        sslmode=args.ssl_mode, verbose=args.verbose)
    connection = engine.connect()
    metadata.create_all(engine)

    if args.print:
        print_data(connection, args.columns, table_map[args.db_table])
    elif args.data:
        write_data(args.data, connection, table_map[args.db_table])
    else:
        print('Use --print or --data options')
        exit(1)
