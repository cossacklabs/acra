# coding: utf-8
import argparse
import binascii
import string
from os.path import expanduser
from random import randint, choice

from sqlalchemy import Table, Column, Integer, String, MetaData, types, create_engine, select

from wrappers.python import Acra

__author__ = 'Lagovas <lagovas.lagovas@gmail.com>'


class AcraBinary(types.TypeDecorator):
    impl = types.Binary

    def __init__(self, public_key, *args, **kwargs):
        super(AcraBinary, self).__init__(*args, **kwargs)
        self._acra = Acra(public_key)

    def process_bind_param(self, value, dialect):
        return self._acra.create(value)

    def process_result_value(self, value, dialect):
        if dialect.name == 'postgresql':
            return self._acra.unpack(value)
        else:
            return value


class AcraString(AcraBinary):
    def __init__(self, public_key, encoding='utf-8', *args, **kwargs):
        super(AcraString, self).__init__(public_key, *args, **kwargs)
        self._acra = Acra(public_key)
        self._encoding = encoding

    def process_bind_param(self, value, dialect):
        return super(AcraString, self).process_bind_param(value.encode(self._encoding), dialect)

    def process_result_value(self, value, dialect):
        data = super(AcraString, self).process_result_value(value, dialect)
        if isinstance(data, str):
            return data
        else:
            # DEMO ONLY
            try:
                return data.decode('utf-8')
            except UnicodeDecodeError:
                return binascii.hexlify(data)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--client_id', type=str, default='test', help='will be used server\'s public key like ~/.ssession/<client_id>_server.pub')
    parser.add_argument('--db_user', type=str, default='test', help='db user to connect')
    parser.add_argument('--db_password', type=str, default='test', help='db password to connect')
    parser.add_argument('--port', type=int, default=5433, help='port of acraproxy to connect')
    parser.add_argument('--host', type=str, default='localhost', help='host of acraproxy to connect')
    parser.add_argument('--data', type=str, help='data to save in ascii. default random data')
    parser.add_argument('--print', action='store_true', help='just print data', default=False)
    args = parser.parse_args()

    metadata = MetaData()
    with open('{}/.ssession/{}_server.pub'.format(expanduser('~'), args.client_id), 'rb') as f:
        key = f.read()
    test = Table('test', metadata,
        Column('id', Integer, primary_key=True),
        Column('data', types.Binary),
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
            #print("{:<3} - {} - {:>10}".format(*row))
            print("{:<3} - {} - {:>10}".format(row['id'], row['data'].decode('utf-8', errors='ignore'), row['raw_data']))

    else:
        data = bytes([randint(32, 126) for _ in range(randint(10, 20))])
        string_data = ''.join(choice(string.ascii_letters) for _ in range(randint(10, 20)))
        data = args.data or string_data
        print(data)
        proxy_connection.execute(test.insert(), data=Acra(key).create(data), raw_data=data)
