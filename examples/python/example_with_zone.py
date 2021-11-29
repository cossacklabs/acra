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
import os
import argparse
import json
from base64 import b64decode
from random import randint, choice
try:
    # For Python 3.0 and later
    from urllib.request import urlopen
except ImportError:
    # Fall back to Python 2's urllib2
    from urllib2 import urlopen

from sqlalchemy import (Table, Column, Integer, MetaData, create_engine,
                        select, LargeBinary, Text, cast)
from sqlalchemy.dialects.postgresql import BYTEA

from acrawriter import create_acrastruct


def get_zone():
    """make http response to AcraServer api to generate new zone and return tuple
    of zone id and public key
    """
    response = urlopen('{}/getNewZone'.format(ACRA_SERVER_API_ADDRESS))
    json_data = response.read().decode('utf-8')
    zone_data = json.loads(json_data)
    return zone_data['id'], b64decode(zone_data['public_key'])


def get_default(name, value):
    """return value from environment variables with name EXAMPLE_<name>
    or value"""
    return os.environ.get('EXAMPLE_{}'.format(name.upper()), value)


def print_data(zone_id, connection):
    """fetch data from database (use zone_id if not empty/None) and print to
    console"""
    result = connection.execute(
        # explicitly pass zone id before related data
        select([cast(zone_id.encode('utf-8'), BYTEA), test_table]))
    result = result.fetchall()
    ZONE_ID_INDEX = 0
    print("use zone_id: ", zone_id)
    print("{:<3} - {} - {} - {}".format("id", 'zone', "data", "raw_data"))
    for row in result:
        print(
            "{:<3} - {} - {} - {}\n".format(
            row['id'], row[ZONE_ID_INDEX].decode('utf-8'),
            row['data'].decode('utf-8', errors='ignore'), row['raw_data']))


def write_data(data, connection):
    zone_id, key = get_zone()
    print("data: {}\nzone: {}".format(data, zone_id))

    # here we encrypt our data and wrap into AcraStruct
    encrypted_data = create_acrastruct(
        data.encode('utf-8'), key, zone_id.encode('utf-8'))

    connection.execute(
        test_table.insert(), data=encrypted_data,
        zone_id=zone_id.encode('utf-8'),
        raw_data=data)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--zone_id', type=str,
                        default=get_default('zone_id', ''),
                        help='Zone id for fetching data. Use only with --print '
                             'option')
    parser.add_argument('--db_name', type=str,
                        default=get_default('db_name', 'acra'),
                        help='Database name')
    parser.add_argument('--db_user', type=str,
                        default=get_default('db_user','test'),
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

    ACRA_SERVER_API_ADDRESS = get_default(
        'acra_server_api_address', 'http://127.0.0.1:9191')
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
    test_table = Table(
        'test_example_with_zone', metadata,
        Column('id', Integer, primary_key=True, nullable=False),
        Column('zone_id', LargeBinary, nullable=True),
        Column('data', LargeBinary, nullable=False),
        Column('raw_data', Text, nullable=False),
    )
    engine = create_engine(
        '{}://{}:{}@{}:{}/{}'.format(
            driver, args.db_user, args.db_password, args.host, args.port,
            args.db_name),
        connect_args=ssl_args,
        echo=bool(args.verbose))
    connection = engine.connect()
    metadata.create_all(engine)

    print('DB driver: {}'.format(driver))

    if args.print:
        print_data(args.zone_id, connection)
    elif args.data:
        if args.zone_id:
            print("To encrypt data script will generate new zone and print "
                  "zone id with public key after execution. Don't use "
                  "--zone_id option with --data option.")
            exit(1)
        write_data(args.data, connection)
    else:
        print('Use --print or --data options')
        exit(1)
