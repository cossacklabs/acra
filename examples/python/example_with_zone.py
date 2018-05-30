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
import string
import subprocess
from base64 import b64decode
from random import randint, choice
try:
    # For Python 3.0 and later
    from urllib.request import urlopen
except ImportError:
    # Fall back to Python 2's urllib2
    from urllib2 import urlopen

from sqlalchemy import Table, Column, Integer, String, MetaData, create_engine, select, Binary
from sqlalchemy import cast
from sqlalchemy.dialects.postgresql import BYTEA

from acrawriter import create_acrastruct


def get_zone():
    response = urlopen('http://127.0.0.1:9191/getNewZone')
    json_data = response.read().decode('utf-8')
    zone_data = json.loads(json_data)
    return zone_data['id'], b64decode(zone_data['public_key'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--zone_id', type=str, default='', help='zone id for fetching data')
    parser.add_argument('--db_name', type=str, default='acra', help='db name to connect')
    parser.add_argument('--db_user', type=str, default='test', help='db user to connect')
    parser.add_argument('--db_password', type=str, default='test', help='db password to connect')
    parser.add_argument('--port', type=int, default=5433, help='port of acra-connector to connect')
    parser.add_argument('--host', type=str, default='localhost', help='host of acra-connector to connect')
    parser.add_argument('--data', type=str, help='data to save in ascii. default random data')
    parser.add_argument('--print', action='store_true', help='just print data', default=False)
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose', default=False)
    args = parser.parse_args()

    metadata = MetaData()
    test = Table('test_example_with_zone', metadata,
        Column('id', Integer, primary_key=True),
        Column('data', Binary),
        Column('raw_data', String),
    )
    if args.verbose:
        proxy_engine = create_engine('postgresql://{}:{}@{}:{}/{}'.format(args.db_user, args.db_password, args.host, args.port, args.db_name), echo=True)
    else:
        proxy_engine = create_engine('postgresql://{}:{}@{}:{}/{}'.format(args.db_user, args.db_password, args.host, args.port, args.db_name))
    proxy_connection = proxy_engine.connect()
    metadata.create_all(proxy_engine)

    if getattr(args, 'print', False):
        if args.zone_id:
            print("use zone_id: ", args.zone_id)
            result = proxy_connection.execute(
                select([cast(args.zone_id.encode('utf-8'), BYTEA), test]))
        else:
            result = proxy_connection.execute(
                select([cast('without zone'.encode('utf-8'), BYTEA), test]))
        result = result.fetchall()
        print("{:<3} - {} - {} - {:>10}".format("id", 'zone', "data", "raw_data"))
        for row in result:
            try:
                print("{:<3} - {} - {} - {:>10}\n".format(row['id'], row[0], row['data'].decode('utf-8'), row['raw_data']))
            except:
                print("{:<3} - {} - {} - {:>10}\n".format(row['id'], row[0], row['data'], row['raw_data']))

    else:
        if args.zone_id:
            print("For encrypting will be used random generated zone_id")
            exit(1)
        zone_id, key = get_zone()
        data = bytes([randint(32, 126) for _ in range(randint(10, 20))])
        string_data = ''.join(choice(string.ascii_letters) for _ in range(randint(10, 20)))

        data = args.data or string_data
        print("data: {}\nzone: {}".format(data, zone_id))

        encrypted_data = create_acrastruct(data.encode('utf-8'), key, zone_id.encode('utf-8'))
        rid = randint(1, 100500)
        proxy_connection.execute(test.insert(), data=encrypted_data, id=rid,
                                 raw_data='(zone: {}) - {}'.format(zone_id, data))
        print("saved with zone: {}".format(zone_id))
