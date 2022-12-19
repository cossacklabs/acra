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

from acrawriter.sqlalchemy import AcraBinary
from sqlalchemy import (Table, Column, Integer, MetaData, select, Text)
from common import get_engine, get_default, register_common_cli_params


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
    register_common_cli_params(parser)
    parser.add_argument(
        '--public_key', type=str, default=get_default('public_key', ''),
        help='path to acra-server public key '
             '(for example .acrakeys/<client_id>_storage.pub)')
    parser.add_argument('--data', type=str,
                        default=get_default('data', ''),
                        help='data to save in ascii. default random data')
    args = parser.parse_args()


    metadata = MetaData()
    # here we load public key for AcraStructs
    with open(args.public_key, 'rb') as f:
        key = f.read()

    test_table = Table(
        'test_example', metadata,
        Column('id', Integer, primary_key=True, nullable=False),
        # here we use acrawriter's wrapper for Binary type in sqlalchemy
        Column('data', AcraBinary(key), nullable=False),
        Column('raw_data', Text, nullable=False))

    engine = get_engine(
        db_host=args.host, db_port=args.port, db_user=args.db_user, db_password=args.db_password,
        db_name=args.db_name, is_mysql=args.mysql, is_postgresql=args.postgresql,
        tls_ca=args.tls_root_cert, tls_key=args.tls_key, tls_crt=args.tls_cert,
        sslmode=args.ssl_mode, verbose=args.verbose)
    metadata.create_all(engine)
    connection = engine.connect()

    if args.print:
        print_data(connection)
    else:
        write_data(args.data, connection)
