# coding: utf-8
import yaml


def load_default_config(service_name):
    with open('configs/{}.yaml'.format(service_name), 'r') as f:
        return yaml.safe_load(f)


def read_storage_public_key(client_id):
    with open('.acrakeys/{}_storage.pub'.format(client_id), 'rb') as f:
            return f.read()
