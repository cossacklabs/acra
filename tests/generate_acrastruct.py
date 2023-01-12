import argparse
import os
import sys

import base

# add to path our wrapper until not published to PYPI
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                'wrappers/python'))
from acrawriter import create_acrastruct

parser = argparse.ArgumentParser(
    description='This small script generate AcraStruct for testing purposes.')
parser.add_argument(
    '--client_id', nargs='?', default='testclientid',
    help='Client ID (default: testclientid)')
parser.add_argument(
    '--keys_dir', nargs='?', default='docker/.acrakeys/acra-writer',
    help='Directory where keys placed (default: docker/.acrakeys/acra-writer)')
parser.add_argument(
    '--data', nargs='?', default='Plain text.',
    help='Plain text to encode (default: "Plain text.")')
parser.add_argument(
    '--out_file', nargs='?', default='',
    help='Save AcraStruct to filename (default: "<client_id>.acrastruct")')
args = parser.parse_args()

as_out_file = args.out_file
if as_out_file == '':
    as_out_file = '{}.acrastruct'.format(args.client_id)

encryption_key = base.read_storage_public_key(args.client_id, args.keys_dir)
acrastruct = create_acrastruct(args.data.encode('utf-8'), encryption_key)

with open(as_out_file, 'wb') as f:
    f.write(acrastruct)
