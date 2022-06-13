# Copyright 2022, Cossack Labs Limited
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
from pprint import pprint

from sqlalchemy import (Table, Column, Integer, MetaData, select, LargeBinary)
from sqlalchemy.dialects import postgresql

from common import get_engine, get_default, register_common_cli_params

# green
COLOR = '\u001b[32m'
RESET = '\u001b[0m'

metadata = MetaData()
test_table = Table(
    'test', metadata,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('searchable_name', LargeBinary, nullable=True),
    Column('searchable_email', LargeBinary, nullable=True),
)


def fetch_data(connection, columns, search_name, search_email,
               table=test_table):
    try:
        if columns:
            table_columns = [table.c.id] + \
                [getattr(table.c, i) for i in columns]
        else:
            table_columns = [i for i in table.columns]

        query = select(table_columns)

    except AttributeError:
        p = '*' * 30
        print(f'\n\n{p}\nprobably you used incorrect column name\n{p}\n\n')
        raise

    if search_email:
        search_email = search_email.encode('ascii')
        query = query.where(table.c.searchable_email == search_email)

    if search_name:
        search_name = search_name.encode('ascii')
        query = query.where(table.c.searchable_name == search_name)

    compiled = query.compile(dialect=postgresql.dialect(),
                             compile_kwargs={'literal_bind': True})
    print(f'Fetch data by query {compiled}')
    rows = connection.execute(query).fetchall()
    column_names = [str(column.name) for column in table_columns]
    return column_names, rows


def print_data(columns, rows):
    for row in rows:
        indent = '- '
        for column in columns:
            value = row[column]
            if isinstance(value, (bytes, bytearray)):
                value = value.decode('utf-8', errors='ignore')
            print(f'{indent}{COLOR}{column}{RESET}: {value}')
            indent = '  '
    print()

    print(f'{COLOR}TOTAL{RESET} {len(rows)}')


def write_data(data, connection, table=test_table):
    with open(data, 'r') as f:
        data = json.load(f)
    print("data:")
    pprint(data)
    rows = data
    if isinstance(data, dict):
        rows = [data]
    to_escape = ('searchable_name', 'searchable_email')

    for row in rows:
        for k in row:
            if k in to_escape:
                row[k] = row[k].encode('ascii')
        connection.execute(table.insert(), row)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    register_common_cli_params(parser)
    parser.add_argument('--data', type=str,
                        default=get_default('data', ''),
                        help='data to save in ascii')

    parser.add_argument('-c', '--columns', nargs='+', dest='columns',
                        default=get_default('columns', False),
                        help='List of columns to display')

    parser.add_argument('--db_table', default=test_table.name,
                        help='Table used to read/write data')

    parser.add_argument('--search_email', type=str,
                        default=get_default('search_email', ''),
                        help='select rows where email equals'
                             ' the provided value')

    parser.add_argument('--search_name', type=str,
                        default=get_default('search_name', ''),
                        help='select rows where name equals'
                             ' the provided value')
    args = parser.parse_args()

    engine = get_engine(
        db_host=args.host, db_port=args.port, db_user=args.db_user,
        db_password=args.db_password, db_name=args.db_name,
        is_mysql=args.mysql, is_postgresql=args.postgresql,
        tls_ca=args.tls_root_cert, tls_key=args.tls_key, tls_crt=args.tls_cert,
        sslmode=args.ssl_mode, verbose=args.verbose)
    connection = engine.connect()
    metadata.create_all(engine)

    if args.print:
        names, rows = fetch_data(connection, args.columns,
                                 args.search_name, args.search_email,
                                 test_table)
        print_data(names, rows)
    elif args.data:
        write_data(args.data, connection, test_table)
    else:
        print('Use --print or --data options')
        exit(1)
