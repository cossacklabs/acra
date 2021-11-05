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


def get_zone():
    """make http response to AcraServer api to generate new zone and return tuple
    of zone id and public key
    """
    response = urlopen('{}/getNewZone'.format(ACRA_CONNECTOR_API_ADDRESS))
    json_data = response.read().decode('utf-8')
    zone_data = json.loads(json_data)
    return zone_data['id'], zone_data['public_key']


def get_default(name, value):
    """return value from environment variables with name EXAMPLE_<name>
    or value"""
    return os.environ.get('EXAMPLE_{}'.format(name.upper()), value)


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
                        help='Print data (use --zone_id to set specific ZoneId '
                             'which will be used to fetch data)')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                        default=get_default('verbose', False), help='verbose')
    parser.add_argument('-c', '--columns', nargs='+', dest='columns',
                        default=get_default('columns', False), help='List of columns to display')
    parser.add_argument('--zone_id', type=str, dest='zone_id',
                        default=get_default('zone_id', ''),
                        help='Zone id for fetching data. Use only with --print option')
    parser.add_argument('--generate_zone', action='store_true', dest="generate_zone",
                        default=get_default('generate_zone', False),
                        help='Generate new zone via http api')

    args = parser.parse_args()

    ACRA_CONNECTOR_API_ADDRESS = get_default(
        'acra_connector_api_address', 'http://127.0.0.1:9191')
    # default driver
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
        if not args.zone_id:
            print('parameter --zone_id is required')
            exit(1)
        print_data(connection, args.zone_id, args.columns)
    elif args.generate_zone:
        zone_id, public = get_zone()
        print('zone_id: {}\nzone public key in base64: {}'.format(zone_id, public))
    elif args.data:
        write_data(args.data, connection)
    else:
        print('Use --print or --data options')
        exit(1)
