#
# Copyright 2020 Ravikiran Bukkasagara <contact@ravikiranb.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#    
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import sys
import json
import argparse

from fw_info import FWInfo, DEFAULT_MBR_SIZE

class JSONBytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            # base64 encoding might save few bytes but lets
            # keep things simple on device side.
            return obj.hex()
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)

default_ota_json_file = "ota.json"
default_ota_bin_file = "ota.ebin"
default_bl_settings_init_file = "../../bootloader/src/bl_settings_init.c"
default_app_version = 0


parser = argparse.ArgumentParser(
        description='Generate files for nRF52840 OTA updates and boot loader settings.\
        Only Application Or SD + Application combination is supported.')

parser.add_argument('-u', '--url', help='Primary HTTP URL of encrypted firwmare. Required for OTA files.')
parser.add_argument('-a', '--alternate-url',
        help='Alternate HTTP URL of encrypted firwmare. Default = Primary URL.')
parser.add_argument('-k', '--aes-key', help='Testing only. 16 bytes Hex string. Default = Auto generated.')
parser.add_argument('-i', '--aes-iv', help='Testing only. 16 bytes Hex string. Default = Auto generated.')
parser.add_argument('-b', '--generate-bl-settings',
        const=default_bl_settings_init_file,
        nargs='?',
        help='Generate Bootloader settings. Optionally specify different location to save.\
            Default location = ' + default_bl_settings_init_file)
parser.add_argument('-j', '--generate-ota-json-file',
        const=default_ota_json_file,
        nargs='?',
        help='Generate OTA files (JSON + Encrypted binary).\
            Optionally specify different location for json file. Default = ' + default_ota_json_file)
parser.add_argument('-o', '--generate-ota-binary-file',
        const=default_ota_bin_file,
        nargs='?',
        help='Generate OTA files (JSON + Encrypted binary).\
            Optionally specify different location for the encrypted binary file. Default = ' + default_ota_bin_file)
parser.add_argument('-s', '--softdevice-hexfile',
        help='Add optional softdevice at the given path.')

parser.add_argument('-m', '--mbr-size',
        default=DEFAULT_MBR_SIZE,
        type=int,
        help='Change MBR size. Default = ' + str(DEFAULT_MBR_SIZE))

parser.add_argument('-A', '--app-version',
        default=default_app_version,
        type=int,
        help='Application version. Default = ' + str(default_app_version))

parser.add_argument('app_hexfile', metavar='application_hexfile', help="Provide your application hex file path.")

args = parser.parse_args()

jfile = None
efile = None
n_tasks = 0

# Either or both option can be specified for OTA files.
if args.generate_ota_json_file:
    jfile = args.generate_ota_json_file
    efile = default_ota_bin_file
    n_tasks += 1
if args.generate_ota_binary_file:
    efile = args.generate_ota_binary_file
    if jfile is None:
        jfile = default_ota_json_file
    n_tasks += 1

if args.aes_key:
    if len(args.aes_key) != 32:
        print("AES key size must be 16 bytes, two hex digits per byte.")
        sys.exit(-1)

if args.aes_iv:
    if len(args.aes_iv) != 32:
        print("AES IV size must be 16 bytes, two hex digits per byte.")
        sys.exit(-1)

fw = FWInfo(args.app_hexfile, args.softdevice_hexfile, args.app_version, efile, args.aes_key, args.aes_iv)

if jfile:
    if args.url is None:
        print("URL argument required for OTA.")
        sys.exit(-1)
    
    # TODO: URL validation.
    url = args.url
    alt_url = url
    if args.alternate_url:
        alt_url = args.alternate_url
    

    fw_update_msg = {}
    fw_update_msg.setdefault('type', 'update_fw')
    fw_update_msg.setdefault('url', url)
    fw_update_msg.setdefault('alt_url', alt_url)
    fw_update_msg.setdefault('fw_info', fw.to_nrf52_hex_string())

    with open(jfile, "w") as msg_fobj:
        json.dump(fw_update_msg, msg_fobj, indent="    ", cls=JSONBytesEncoder)

    print("Generated", jfile, efile)

if args.generate_bl_settings:
    fw.gen_bl_settings_init_code(args.generate_bl_settings)
    n_tasks += 1
    print("Generated", args.generate_bl_settings)

if n_tasks == 0:
    print("No files generated.")










