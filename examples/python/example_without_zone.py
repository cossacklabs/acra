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
import string
from random import randint, choice

from sqlalchemy import (Table, Column, Integer, MetaData, create_engine,
                        select, Text)

from acrawriter.sqlalchemy import AcraBinary


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--public_key', type=str, help='path to acra-server public key  (for example .acrakeys/<client_id>_server.pub)')
    parser.add_argument('--db_name', type=str, default='acra', help='db name to connect')
    parser.add_argument('--db_user', type=str, default='test', help='db user to connect')
    parser.add_argument('--db_password', type=str, default='test', help='db password to connect')
    parser.add_argument('--port', type=int, default=5433, help='port of acra-connector to connect')
    parser.add_argument('--host', type=str, default='localhost', help='host of acra-connector to connect')
    parser.add_argument('--data', type=str, help='data to save in ascii. default random data')
    parser.add_argument('--print', action='store_true', help='just print data', default=False)
    parser.add_argument('--postgresql', action='store_true', help="use postgresql driver (default if nothing else   set)")
    parser.add_argument('--mysql', action='store_true', help="use mysql driver")
    args = parser.parse_args()

    # default driver
    driver = 'postgresql'
    if args.mysql:
        driver = 'mysql+pymysql'

    metadata = MetaData()
    with open(args.public_key, 'rb') as f:
        key = f.read()
    test = Table('test_example_without_zone', metadata,
        Column('id', Integer, primary_key=True),
        Column('data', AcraBinary(key)),
        Column('raw_data', Text),
    )

    proxy_engine = create_engine('{}://{}:{}@{}:{}/{}'.format(driver, args.db_user, args.db_password, args.host, args.port, args.db_name))
    proxy_connection = proxy_engine.connect()
    metadata.create_all(proxy_engine)
    if getattr(args, 'print', False):
        result = proxy_connection.execute(select([test]))
        result = result.fetchall()
        print("{:<3} - {:<20} - {}".format("id", "data", "raw_data"))
        for row in result:
            print("{:<3} - {:<20} - {}".format(row['id'], row['data'].decode("utf-8", errors='ignore'), row['raw_data']))
    else:
        data = bytes([randint(32, 126) for _ in range(randint(10, 20))])
        string_data = ''.join(choice(string.ascii_letters) for _ in range(randint(10, 20)))
        data = args.data or string_data
        print('insert data: {}'.format(data))
        proxy_connection.execute(test.insert(), data=data.encode('utf-8'), raw_data=data)
