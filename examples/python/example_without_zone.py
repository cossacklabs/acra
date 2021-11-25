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
import os

from acrawriter.sqlalchemy import AcraBinary
from sqlalchemy import (Table, Column, Integer, MetaData, create_engine,
                        select, Text)


def get_default(name, value):
    """return value from environment variables with name EXAMPLE_<name>
    or value"""
    return os.environ.get('EXAMPLE_{}'.format(name.upper()), value)


def print_data(connection):
    result = connection.execute(select([test_table]))
    result = result.fetchall()
    print("{:<3} - {:<20} - {}".format("id", "data", "raw_data"))
    for row in result:
        print("{:<3} - {:<20} - {}".format(row['id'], row['data'].decode(
            "utf-8", errors='ignore'), row['raw_data']))


def write_data(data, connection):
    print('insert data: {}'.format(data))
    connection.execute(
        test_table.insert(), data=data.encode('utf-8'), raw_data=data)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--public_key', type=str, default=get_default('public_key', ''),
        help='path to acra-server public key '
             '(for example .acrakeys/<client_id>_storage.pub)')
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
    parser.add_argument('--ssl_mode', action='store_true',
                        default=get_default('ssl_mode', False),
                        help='SSL connection mode')
    parser.add_argument('--tls_root_cert', action='store_true',
                        default=get_default('tls_root_cert', False),
                        help='Path to root certificate used in TLS connection')
    parser.add_argument('--tls_key', action='store_true',
                        default=get_default('tls_key', False),
                        help='Path to client TLS key used in TLS connection')
    parser.add_argument('--tls_cert', action='store_true',
                        default=get_default('tls_cert', False),
                        help='Path to client TLS certificate used in TLS connection')
    parser.add_argument('--print', action='store_true',
                        default=get_default('print', False),
                        help='Print data (use --zone_id to set specific ZoneId '
                             'which will be used to fetch data)')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                        default=get_default('verbose', False), help='verbose')
    parser.add_argument('--postgresql', action='store_true',
                        default=get_default('postgresql', False),
                        help="Use postgresql driver (default if nothing else "
                             "set)")
    parser.add_argument('--mysql', action='store_true',
                        default=get_default('mysql', False),
                        help="Use mysql driver")
    args = parser.parse_args()

    # default driver
    driver = 'postgresql'
    ssl_args = {
        'sslmode': args.ssl_mode,
        'sslrootcert': args.tls_root_cert,
        'sslkey': args.tls_key,
        'sslcert': args.tls_cert,
    }
    if args.mysql:
        driver = 'mysql+pymysql'
        ssl_args = {
            'ssl_ca': args.tls_root_cert,
            'ssl_cert': args.tls_cert,
            'ssl_key': args.tls_key
        }

    metadata = MetaData()
    # here we load public key for AcraStructs
    with open(args.public_key, 'rb') as f:
        key = f.read()

    test_table = Table(
        'test_example_without_zone', metadata,
        Column('id', Integer, primary_key=True, nullable=False),
        # here we use acrawriter's wrapper for Binary type in sqlalchemy
        Column('data', AcraBinary(key), nullable=False),
        Column('raw_data', Text, nullable=False))

    engine = create_engine(
        '{}://{}:{}@{}:{}/{}'.format(
            driver, args.db_user, args.db_password, args.host, args.port,
            args.db_name),
        connect_args=ssl_args,
        echo=bool(args.verbose))
    metadata.create_all(engine)
    connection = engine.connect()

    print('DB driver: {}'.format(driver))

    if args.print:
        print_data(connection)
    else:
        write_data(args.data, connection)
