import os
import json
import random
import string
from utils import abs_path, TEMP_DATA_FOLDER_VARNAME


def get_random_unicode(length):
    '''returns random utf8 string with not only latin symbols

    snippet from https://stackoverflow.com/a/21666621
    '''
    get_char = chr

    # Update this to include code point ranges to be sampled
    include_ranges = [
        (0x0021, 0x0021),
        (0x0023, 0x0026),
        (0x0028, 0x007E),
        (0x00A1, 0x00AC),
        (0x00AE, 0x00FF),
        (0x0100, 0x017F),
        (0x0180, 0x024F),
        (0x2C60, 0x2C7F),
        (0x16A0, 0x16F0),
        (0x0370, 0x0377),
        (0x037A, 0x037E),
        (0x0384, 0x038A),
        (0x038C, 0x038C),
    ]

    alphabet = [
        get_char(code_point) for current_range in include_ranges
        for code_point in range(current_range[0], current_range[1] + 1)
    ]
    return ''.join(random.choice(alphabet) for i in range(length))


def get_random_data(config):
    size = random.randint(config['data_min_size'], config['data_max_size'])
    return get_random_unicode(size).encode('utf-8')


if __name__ == '__main__':
    data_folder = os.environ.get(TEMP_DATA_FOLDER_VARNAME)
    if not data_folder:
        print("You must set TEST_RANDOM_DATA_FOLDER env variable")
        exit(1)
    os.makedirs(data_folder, exist_ok=True)
    with open(abs_path('tests/random_data_config.json'), 'r') as f:
        config = json.load(f)

    for i in range(config['file_count']):
        data = get_random_data(config)
        with open(os.path.join(data_folder, 'test_data_{}.bin'.format(i)), 'wb') as f:
            f.write(data)
