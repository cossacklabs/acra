# coding: utf-8
import argparse
import json
import string
import subprocess
from base64 import b64decode
from random import randint, choice

from sqlalchemy import Table, Column, Integer, String, MetaData, create_engine, select, Binary
from sqlalchemy import cast
from sqlalchemy.dialects.postgresql import BYTEA

from acra import Acra, create_acra_struct

__author__ = 'Lagovas <lagovas.lagovas@gmail.com>'


def add_zone():
    output = subprocess.check_output(["../../addzone"])
    parsed = json.loads(output.decode('utf-8'))
    return parsed['id'], b64decode(parsed['public_key'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--zone_id', type=str, default='', help='zone id')
    parser.add_argument('--db_user', type=str, default='test', help='db user to connect')
    parser.add_argument('--db_password', type=str, default='test', help='db password to connect')
    parser.add_argument('--port', type=int, default=5433, help='port of acraproxy to connect')
    parser.add_argument('--host', type=str, default='localhost', help='host of acraproxy to connect')
    parser.add_argument('--data', type=str, help='data to save in ascii. default random data')
    parser.add_argument('--print', action='store_true', help='just print data', default=False)
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose', default=False)
    args = parser.parse_args()

    metadata = MetaData()
    test = Table('test', metadata,
        Column('id', Integer, primary_key=True),
        Column('data', Binary),
        Column('raw_data', String),
    )
    if args.verbose:
        proxy_engine = create_engine('postgresql://{}:{}@{}:{}/acra'.format(args.db_user, args.db_password, args.host, args.port), echo=True)
    else:
        proxy_engine = create_engine('postgresql://{}:{}@{}:{}/acra'.format(args.db_user, args.db_password, args.host, args.port))
    proxy_connection = proxy_engine.connect()
    metadata.create_all(proxy_engine)

    if getattr(args, 'print', False) and args.zone_id:
        print("use zone_id: ", args.zone_id)
        assert len(args.zone_id) == (16+3)
        result = proxy_connection.execute(
            select([cast(args.zone_id.encode('utf-8'), BYTEA), test]))
        result = result.fetchall()
        print("{:<3} - {:<20} - {}".format("id", "data", "raw_data"))
        for row in result:
            try:
                print("{:<3} - {} - {} - {:>10}\n".format(row['id'], row[0], Acra.unpack(row['data']).decode('utf-8'), row['raw_data']))
            except:
                print("{:<3} - {} - {} - {:>10}\n".format(row['id'], row[0], row['data'], row['raw_data']))

    else:
        if args.zone_id:
            print("For encrypting will be used random generated zone_id")
            exit(1)
        zone_id, key = add_zone()
        data = bytes([randint(32, 126) for _ in range(randint(10, 20))])
        string_data = ''.join(choice(string.ascii_letters) for _ in range(randint(10, 20)))

        data = args.data or string_data
        print("data: {}\nzone: {}".format(data, zone_id))

        encrypted_data = create_acra_struct(data.encode('utf-8'), key, zone_id.encode('utf-8'))
        rid = randint(1, 100500)
        proxy_connection.execute(test.insert(), data=encrypted_data, id=rid,
                                 raw_data='(zone: {}) - {}'.format(zone_id, data))
        print("saved with zone: {}".format(zone_id))
