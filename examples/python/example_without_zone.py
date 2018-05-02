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

from sqlalchemy import Table, Column, Integer, String, MetaData, types, create_engine, select

from acrawriter import create_acrastruct


class AcraBinary(types.TypeDecorator):
    impl = types.Binary

    def __init__(self, public_key, *args, **kwargs):
        super(AcraBinary, self).__init__(*args, **kwargs)
        self._public_key = public_key

    def process_bind_param(self, value, dialect):
        return create_acrastruct(value, self._public_key)

    def process_result_value(self, value, dialect):
        return value


class AcraString(AcraBinary):
    def __init__(self, public_key, encoding='utf-8', *args, **kwargs):
        super(AcraString, self).__init__(public_key, *args, **kwargs)
        self._encoding = encoding

    def process_bind_param(self, value, dialect):
        return super(AcraString, self).process_bind_param(value.encode(self._encoding), dialect)

    def process_result_value(self, value, dialect):
        if isinstance(value, str):
            return value
        else:
            return value.decode(self._encoding)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--public_key', type=str, help='path to acraserver public key  (for example .acrakeys/<client_id>_server.pub)')
    parser.add_argument('--db_user', type=str, default='test', help='db user to connect')
    parser.add_argument('--db_password', type=str, default='test', help='db password to connect')
    parser.add_argument('--port', type=int, default=5433, help='port of acra-connector to connect')
    parser.add_argument('--host', type=str, default='localhost', help='host of acra-connector to connect')
    parser.add_argument('--data', type=str, help='data to save in ascii. default random data')
    parser.add_argument('--print', action='store_true', help='just print data', default=False)
    args = parser.parse_args()

    metadata = MetaData()
    with open(args.public_key, 'rb') as f:
        key = f.read()
    test = Table('test_example_without_zone', metadata,
        Column('id', Integer, primary_key=True),
        Column('data', AcraBinary(key)),
        Column('raw_data', String),
    )

    proxy_engine = create_engine('postgresql://{}:{}@{}:{}/acra'.format(args.db_user, args.db_password, args.host, args.port))
    proxy_connection = proxy_engine.connect()
    metadata.create_all(proxy_engine)
    if getattr(args, 'print', False):
        result = proxy_connection.execute(select([test]))
        result = result.fetchall()
        print("{:<3} - {:<20} - {}".format("id", "data", "raw_data"))
        for row in result:
            print("{:<3} - {} - {:>10}".format(row['id'], row['data'], row['raw_data']))
    else:
        data = bytes([randint(32, 126) for _ in range(randint(10, 20))])
        string_data = ''.join(choice(string.ascii_letters) for _ in range(randint(10, 20)))
        data = args.data or string_data
        print('insert data: {}'.format(data))
        proxy_connection.execute(test.insert(), data=data.encode('utf-8'), raw_data=data)
