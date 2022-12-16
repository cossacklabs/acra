import json
import os
from base64 import b64decode
from urllib.request import urlopen

from sqlalchemy import create_engine


def register_common_cli_params(parser):
    parser.add_argument('--db_name', type=str,
                        default=get_default('db_name', 'test'),
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
    parser.add_argument('--print', action='store_true',
                        default=get_default('print', False),
                        help='Print data')
    parser.add_argument('--ssl_mode',
                        default=get_default('ssl_mode', False),
                        help='SSL connection mode')
    parser.add_argument('--tls_root_cert', 
                        default=get_default('tls_root_cert', False),
                        help='Path to root certificate used in TLS connection')
    parser.add_argument('--tls_key', 
                        default=get_default('tls_key', False),
                        help='Path to client TLS key used in TLS connection')
    parser.add_argument('--tls_cert', 
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


def get_default(name, value):
    """return value from environment variables with name EXAMPLE_<name>
    or value"""
    return os.environ.get('EXAMPLE_{}'.format(name.upper()), value)


def get_engine(db_host, db_port, db_user, db_password, db_name, is_mysql=False, is_postgresql=False, tls_ca=None,
               tls_key=None, tls_crt=None, sslmode=None, verbose=False):
    ssl_args = {}
    with_tls = tls_crt and tls_key and tls_ca
    if not (is_mysql or is_postgresql):
        is_postgresql = True
    if is_postgresql:
        driver = 'postgresql'
        if with_tls:
            ssl_args = {
                'sslmode': sslmode,
                'sslrootcert': tls_ca,
                'sslkey': tls_key,
                'sslcert': tls_crt,
            }
    else:
        driver = 'mysql+pymysql'
        if with_tls:
            ssl_args = {
                'ssl': {
                    'ca': tls_ca,
                    'cert': tls_crt,
                    'key': tls_key
                }
            }
    return create_engine(
        '{}://{}:{}@{}:{}/{}'.format(
            driver, db_user, db_password, db_host, db_port,
            db_name),
        connect_args=ssl_args, echo=bool(verbose))