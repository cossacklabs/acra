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
from sqlalchemy import (Table, Column, Integer, MetaData, select, LargeBinary, Text, cast)
from sqlalchemy.dialects.postgresql import BYTEA
from acrawriter import create_acrastruct
from common import get_engine, get_default, get_zone, register_common_cli_params


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
    register_common_cli_params(parser)
    parser.add_argument('--zone_id', type=str,
                        default=get_default('zone_id', ''),
                        help='Zone id for fetching data. Use only with --print '
                             'option')
    parser.add_argument('--data', type=str,
                        default=get_default('data', ''),
                        help='data to save in ascii. default random data')
    args = parser.parse_args()

    metadata = MetaData()
    test_table = Table(
        'test_example_with_zone', metadata,
        Column('id', Integer, primary_key=True, nullable=False),
        Column('zone_id', LargeBinary, nullable=True),
        Column('data', LargeBinary, nullable=False),
        Column('raw_data', Text, nullable=False),
    )

    engine = get_engine(
        db_host=args.host, db_port=args.port, db_user=args.db_user, db_password=args.db_password,
        db_name=args.db_name, is_mysql=args.mysql, is_postgresql=args.postgresql,
        tls_ca=args.tls_root_cert, tls_key=args.tls_key, tls_crt=args.tls_cert,
        sslmode=args.ssl_mode, verbose=args.verbose)
    connection = engine.connect()
    metadata.create_all(engine)

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
