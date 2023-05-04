import argparse
import json
import binascii

parser = argparse.ArgumentParser()

parser.add_argument('--json', type=str, help='name of input json-file')
parser.add_argument('--stage', type=str, default='prod', help='stage to use')
parser.add_argument('--token', type=str, help='token for id-service access')
parser.add_argument('--out', type=str, help='name of output csv-file')

args = parser.parse_args()

if args.stage == 'prod':
    backend_public_key = '74BIrQbAKFrwF3AJOBgwxGzsAl0B2GCF51pPAEHC5pA='
elif args.stage == 'dev' or args.stage == 'demo':
    backend_public_key = 'okA7krya3TZbPNEv8SDQIGR/hOppg/mLxMh+D0vozWY='
else:
    raise Exception('Unknown stage')

out_filename = args.filename.split('.')[0] + '.csv' \
    if args.out is None else args.out


def csv_head_template(backend_public_key, token):
    head = f'''key,type,encoding,value
key_storage,namespace,,
server_key,data,base64,{backend_public_key}
'''
    if args.token is not None:
        head += f'token,data,binary,{token}'

    return head


def csv_device_template(short_name, uuid, password):
    # compare components/ubirch-esp32-key-storage/id_handling.h:37-41
    ID_STATE_ID_REGISTERED = 0b00000010
    ID_STATE_PASSWORD_SET = 0b00000100
    initial_state = f"{ID_STATE_ID_REGISTERED | ID_STATE_PASSWORD_SET:02x}"
    password_hex = binascii.hexlify(
        bytes(password, 'utf-8')).decode('utf-8') + '00'
    assert(len(password_hex) == 2 * (36 + 1))  # 36 byte + 1 (\0)
    keypair_dummy = 64 * '00'
    next_update_dummy = 4 * '00'
    pre_sign_dummy = 64 * '00'
    return f'''{short_name},namespace,,
blob,data,hex2bin,{initial_state}{uuid}{password_hex}{keypair_dummy}{next_update_dummy}
pre_sign,data,hex2bin,{pre_sign_dummy}
'''


if args.json is not None:
    with open(args.json, 'r') as _f:
        devices = json.loads(_f.read())

    if type(devices) == dict:
        devices = [devices]

    csv = csv_head_template(backend_public_key, args.token)

    for dev in devices:
        dev['uuid'] = dev['uuid'].replace('-', '')
        csv += csv_device_template(dev['short_name'],
                                   dev['uuid'],
                                   dev['password'])

with open(out_filename, 'w') as _f:
    _f.write(csv)
