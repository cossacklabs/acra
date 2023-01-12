import json
import os
import random
import string

TEMP_DATA_FOLDER_VARNAME = 'TEST_RANDOM_DATA_FOLDER'


def get_random_data(config):
    size = random.randint(config['data_min_size'], config['data_max_size'])
    return ''.join(random.SystemRandom().choice(string.ascii_letters) for _ in range(size)).encode('ascii')


if __name__ == '__main__':
    data_folder = os.environ.get(TEMP_DATA_FOLDER_VARNAME)
    if not data_folder:
        print("You must set TEST_RANDOM_DATA_FOLDER env variable")
        exit(1)
    os.makedirs(data_folder, exist_ok=True)
    with open(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'tests/random_data_config.json'), 'r') as f:
        config = json.load(f)

    for i in range(config['file_count']):
        data = get_random_data(config)
        with open(os.path.join(data_folder, 'test_data_{}.bin'.format(i)), 'wb') as f:
            f.write(data)
