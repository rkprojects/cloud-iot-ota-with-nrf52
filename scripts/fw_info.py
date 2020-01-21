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

import zipfile
from zipfile import ZipFile
import sys
import json
import os
import io
import hashlib
import struct


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

AES_KEY_SIZE = 16

K_MANIFEST = 'manifest'
K_SOFTDEVICE = 'softdevice'
K_APP = 'application'
K_BIN_FILE = 'bin_file'

MANIFEST_FILE = "manifest.json"

BL_SETTINGS_CODE =  0xABCDEF12

BL_SETTINGS_C_GEN = """
/*
Auto generated file. Required during first deployment.
Bootloader needs application's hash before it can transfer control to it.
*/

#include "bl_data.h"

const bl_info_t bl_settings __attribute__((section(".bl_settings_rodata"))) = {{
    .settings_code = 0x{bl_settings_code:x},
    .app_start_reason = 0,
    .update_info = {{
        .update_in_progress = 0,
    }},
    .fw_info = {{
        .version = 0x{version:x},
        .fp_base = 0x{fp_base:x},
        .pbin_size = {pbin_size},
        .pbin_hash = {{ {pbin_hash} }},
        .ebin_size = {ebin_size},
        .aes_key = {{ {aes_key} }},
        .aes_iv = {{ {aes_iv} }},
        .ebin_hash = {{ {ebin_hash} }},
        .fs_path = "E:/nrf52840_fw.ebin",
    }},

}};
"""

class InvalidDFUFile(Exception):
    def __init__(self, message):
        self.messsage = message
    
    def __str__(self):
        return repr("Error: " + str(self.messsage))


class FWInfo:
    def __init__(self, dfufile, app_version, ebin_file=None, aes_key=None, aes_iv=None):
        if not zipfile.is_zipfile(dfufile):
            raise InvalidDFUFile("Unknown DFU package: " + dfufile)

        self.dfufile = dfufile
        self.ebin_file = ebin_file
        
        
        self.fw_info = {}
        self.fw_info.setdefault('fp_base', 0x1000)
        self.fw_info.setdefault('app_version', app_version)
        self.fw_info.setdefault('ebin_hash', '')
        self.fw_info.setdefault('pbin_hash', '')

        if aes_key is None:
            aes_key = os.urandom(AES_KEY_SIZE)
        else:
            aes_key = bytes.fromhex(aes_key)
        
        if aes_iv is None:
            aes_iv = os.urandom(AES_KEY_SIZE)
        else:
            aes_iv = bytes.fromhex(aes_iv)

        self.fw_info.setdefault('aes_key', aes_key)
        self.fw_info.setdefault('aes_iv', aes_iv)
        self.fw_info.setdefault('ebin_size', 0)
        self.fw_info.setdefault('pbin_size', 0)

        self._compute_fw_info()

    def _compute_fw_info(self):
        cipher = Cipher(algorithms.AES(self.fw_info['aes_key']),
                        modes.CBC(self.fw_info['aes_iv']), 
                        backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(AES_KEY_SIZE * 8).padder()
        ebin_hash = hashlib.sha256()
        pbin_hash = hashlib.sha256()

        with ZipFile(self.dfufile) as pkg:
            archive_members = pkg.namelist()
            if MANIFEST_FILE not in archive_members:
                raise InvalidDFUFile("Manifest file '{}' not found in '{}'.".format(MANIFEST_FILE, self.dfufile))

            with pkg.open(MANIFEST_FILE) as manifest_fobj:
                manifest = json.loads(manifest_fobj.read().decode('utf-8'))

                
                if self.ebin_file is None:
                    ebin_fobj = io.BytesIO()
                else:
                    ebin_fobj = open(str(self.ebin_file), 'wb')

                try:
                    if K_SOFTDEVICE in manifest[K_MANIFEST]:
                        if manifest[K_MANIFEST][K_SOFTDEVICE][K_BIN_FILE] not in archive_members:
                            raise InvalidDFUFile("Softdevice binary '{}' not found in '{}'.".format(
                                    manifest[K_MANIFEST][K_SOFTDEVICE][K_BIN_FILE],
                                     self.dfufile))
                        print("Adding softdevice binary")
                        self.fw_info['pbin_size'] = self.fw_info['pbin_size'] + \
                                pkg.getinfo(manifest[K_MANIFEST][K_SOFTDEVICE][K_BIN_FILE]).file_size

                        with pkg.open(manifest[K_MANIFEST][K_SOFTDEVICE][K_BIN_FILE]) as pbin_fobj:
                            #firmware sizes are reasonably small.
                            pdata = pbin_fobj.read()
                            pbin_hash.update(pdata)
                            edata = encryptor.update(padder.update(pdata))
                            ebin_hash.update(edata)
                            ebin_fobj.write(edata)
                    
                    if K_APP in manifest[K_MANIFEST]:
                        if manifest[K_MANIFEST][K_APP][K_BIN_FILE] not in archive_members:
                            raise InvalidDFUFile("Application binary '{}' not found in '{}'.".format(
                                    manifest[K_MANIFEST][K_APP][K_BIN_FILE],
                                     self.dfufile))
                        print("Adding application binary")
                        
                        # TODO: Get from manifest binary data file. complex?
                        # self.fw_info['app_version'] = 

                        self.fw_info['pbin_size'] = self.fw_info['pbin_size'] + \
                                pkg.getinfo(manifest[K_MANIFEST][K_APP][K_BIN_FILE]).file_size
                        with pkg.open(manifest[K_MANIFEST][K_APP][K_BIN_FILE]) as pbin_fobj:
                            #firmware sizes are reasonably small.
                            pdata = pbin_fobj.read()
                            pbin_hash.update(pdata)
                            edata = encryptor.update(padder.update(pdata))
                            ebin_hash.update(edata)
                            ebin_fobj.write(edata)
                    
                    edata = encryptor.update(padder.finalize()) + encryptor.finalize()
                    ebin_hash.update(edata)
                    ebin_fobj.write(edata)
                    self.fw_info['ebin_size'] = ebin_fobj.tell()
                    self.fw_info['ebin_hash'] = ebin_hash.digest()
                    self.fw_info['pbin_hash'] = pbin_hash.digest()
                except Exception as e:
                    raise(e)
                finally:
                    ebin_fobj.close()


        if self.fw_info['ebin_size'] == 0:
            raise InvalidDFUFile("No binaries found in '{}'.".format(self.dfufile))

    def to_nrf52_hex_string(self):
        """
        Keep the struct members type, order same in C code.
        """

        """
        struct {
            unsigned long version;
            unsigned long fp_base;
            unsigned long pbin_size;
            unsigned long ebin_size;
            unsigned char aes_key[16];
            unsigned char aes_iv[16];
            unsigned char pbin_hash[32]; 
            unsigned char ebin_hash[32];
        }
        """
        fw_info_struct = struct.pack("<LLLL16s16s32s32s", 
                        self.fw_info['app_version'],
                        self.fw_info['fp_base'],
                        self.fw_info['pbin_size'],
                        self.fw_info['ebin_size'],
                        self.fw_info['aes_key'],
                        self.fw_info['aes_iv'],
                        self.fw_info['pbin_hash'],
                        self.fw_info['ebin_hash'])
        
        return fw_info_struct.hex()

    def gen_bl_settings_init_code(self, cfile):
        pbin_hash_str = ""
        for b in self.fw_info['pbin_hash']:
            pbin_hash_str += hex(b) + ','
        
        ebin_hash_str = ""
        for b in self.fw_info['ebin_hash']:
            ebin_hash_str += hex(b) + ','

        aes_key_str = ""
        for b in self.fw_info['aes_key']:
            aes_key_str += hex(b) + ','

        aes_iv_str = ""
        for b in self.fw_info['aes_iv']:
            aes_iv_str += hex(b) + ','

        with open(str(cfile), "w") as fobj:
            fobj.write(BL_SETTINGS_C_GEN.format(bl_settings_code=BL_SETTINGS_CODE,
                        version=self.fw_info['app_version'],
                        fp_base=self.fw_info['fp_base'],
                        pbin_size=self.fw_info['pbin_size'],
                        pbin_hash=pbin_hash_str,
                        ebin_hash=ebin_hash_str,
                        aes_key=aes_key_str,
                        aes_iv=aes_iv_str,
                        ebin_size=self.fw_info['ebin_size']))
        

