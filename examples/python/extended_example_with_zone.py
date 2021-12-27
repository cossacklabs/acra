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
import ssl

from sqlalchemy.dialects import postgresql

from sqlalchemy import (Table, Column, Integer, MetaData, select, LargeBinary, Text, BigInteger, literal)
from common import get_engine, get_default, get_zone, register_common_cli_params

metadata = MetaData()
test_table = Table(
    'test', metadata,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('data', LargeBinary, nullable=True),
    Column('masking', LargeBinary, nullable=True),
    Column('token_i32', Integer, nullable=True),
    Column('token_i64', BigInteger, nullable=True),
    Column('token_str', Text, nullable=True),
    Column('token_bytes', LargeBinary, nullable=True),
    Column('token_email', Text, nullable=True),
)


def print_data(connection, zone_id, columns):
    """fetch data from database (use zone_id if not empty/None) and print to
    console"""
    default_columns = ['id', 'zone_id']
    try:
        if columns:
            table_columns = [test_table.c.id, literal(zone_id)] + [
                getattr(test_table.c, i) for i in columns]
            query = select(table_columns)
            extra_columns = columns
        else:
            table_columns = [test_table.c.id, literal(zone_id)] + [
                i for i in test_table.columns if i.name not in default_columns]
            query = select(table_columns)
            extra_columns = [i.name for i in test_table.columns if i.name not in default_columns]
    except AttributeError:
        print("\n\n{0}\nprobably you used incorrect column name\n{0}\n\n".format('*'*30))
        raise
        exit(1)

    print("Fetch data by query {}\n",
          query.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
    result = connection.execute(query)
    result = result.fetchall()

    print(len(result))
    print("{:<3} - {} - {}".format(*default_columns, ' - '.join(extra_columns)))
    for row in result:
        values = ['{:<3}'.format(row['id'])]
        for col in row[1:]:
            if isinstance(col, (bytes, bytearray)):
                values.append(col.decode('utf-8', errors='ignore'))
            else:
                values.append(str(col))

        print(' - '.join(values))


def write_data(data, connection):
    # here we encrypt our data and wrap into AcraStruct
    with open(data, 'r') as f:
        data = json.load(f)
    print("data: {}".format(data))
    rows = data
    if isinstance(data, dict):
        rows = [data]
    for row in rows:
        for k in ('data', 'token_bytes', 'masking'):
            row[k] = row[k].encode('ascii')
        connection.execute(
            test_table.insert(), row)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    register_common_cli_params(parser)
    parser.add_argument('--data', type=str,
                        default=get_default('data', ''),
                        help='data to save in ascii. default random data')
    parser.add_argument('-c', '--columns', nargs='+', dest='columns',
                        default=get_default('columns', False), help='List of columns to display')
    parser.add_argument('--zone_id', type=str, dest='zone_id',
                        default=get_default('zone_id', ''),
                        help='Zone id for fetching data. Use only with --print option')
    parser.add_argument('--generate_zone', action='store_true', dest="generate_zone",
                        default=get_default('generate_zone', False),
                        help='Generate new zone via http api')
    args = parser.parse_args()

    engine = get_engine(
        db_host=args.host, db_port=args.port, db_user=args.db_user, db_password=args.db_password,
        db_name=args.db_name, is_mysql=args.mysql, is_postgresql=args.postgresql,
        tls_ca=args.tls_root_cert, tls_key=args.tls_key, tls_crt=args.tls_cert,
        sslmode=args.ssl_mode, verbose=args.verbose)
    connection = engine.connect()
    metadata.create_all(engine)

    if args.print:
        if not args.zone_id:
            print('parameter --zone_id is required')
            exit(1)
        print_data(connection, args.zone_id, args.columns)
    elif args.generate_zone:
        context = None
        if args.tls_root_cert and args.tls_cert and args.tls_key:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=args.tls_root_cert)
            context.load_cert_chain(certfile=args.tls_cert, keyfile=args.tls_key)
        # context is not used for now until we finish task 2418
        zone_id, public = get_zone(sslcontext=None)
        print('zone_id: {}\nzone public key in base64: {}'.format(zone_id, public))
    elif args.data:
        write_data(args.data, connection)
    else:
        print('Use --print or --data options')
        exit(1)
