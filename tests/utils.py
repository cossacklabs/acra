# coding: utf-8
import yaml


def load_default_config(service_name):
    with open('configs/{}.yaml'.format(service_name), 'r') as f:
        return yaml.safe_load(f)


def read_storage_public_key(client_id, keys_dir='.acrakeys'):
    with open('{}/{}_storage.pub'.format(keys_dir, client_id), 'rb') as f:
            return f.read()

def read_zone_public_key(zone_id, keys_dir='.acrakeys'):
    with open('{}/{}_zone.pub'.format(keys_dir, zone_id), 'rb') as f:
        return f.read()
