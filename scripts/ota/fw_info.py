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
import os
import io
import hashlib
import struct
from intelhex import IntelHex

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

AES_KEY_SIZE = 16
DEFAULT_MBR_SIZE = 4096
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

class OTAGeneratorError(Exception):
    def __init__(self, msg):
        self.msg = msg
    
    def __str__(self):
        return repr(self.message)

class FWInfoWriter:
    def __init__(self, aes_key, aes_iv, outfile=None):
        self.pbin_size = 0
        self.ebin_size = 0
        
        cipher = Cipher(algorithms.AES(aes_key),
                        modes.CBC(aes_iv), 
                        backend=default_backend())
        self.encryptor = cipher.encryptor()
        self.padder = padding.PKCS7(AES_KEY_SIZE * 8).padder()
        self.ebin_hash = hashlib.sha256()
        self.pbin_hash = hashlib.sha256()
        
        self.fobj = outfile

        if outfile and isinstance(outfile, str):
            self.fobj = open(outfile, "wb")
        
        self.closed = False
     
    def write(self, wdata):
        self.pbin_size += len(wdata)
        self.pbin_hash.update(wdata)
        edata = self.encryptor.update(self.padder.update(wdata))
        self.ebin_hash.update(edata)
        self.ebin_size += len(edata)

        if self.fobj:
            self.fobj.write(edata)

        return len(wdata)

    def close(self):
        if self.closed:
            return
        
        edata = self.encryptor.update(self.padder.finalize()) + self.encryptor.finalize()
        self.ebin_size += len(edata)
        self.ebin_hash.update(edata)
        
        if self.fobj:
            self.fobj.write(edata)
            self.fobj.close()

        self.closed = True


class FWInfo:
    def __init__(self, app_hex_file, sd_hex_file, app_version, ebin_file=None, aes_key=None, aes_iv=None, mbr_size=DEFAULT_MBR_SIZE):
        
        self.ihex = IntelHex()
        self.ihex.padding = 0x0

        if sd_hex_file:
            self.ihex.merge(IntelHex(sd_hex_file)) # default response to overlap is error.
        
        if app_hex_file:
            self.ihex.merge(IntelHex(app_hex_file))
        else:
            raise OTAGeneratorError("Application hex file is required.")

        # Check for MBR overlap and find fp_base.
        start, end  = self.ihex.segments()[0] # segment 0.
        fp_base = 0
        if sd_hex_file is None:
            if start < mbr_size:
                raise OTAGeneratorError("Application overlaps with MBR {:x}.".format(mbr_size))
            else:
                fp_base = start
        else:
            if end > mbr_size:
                raise OTAGeneratorError("Integrated MBR with softdevice is "
                    " larger than given MBR size. {:x} > {:x}".format(end, mbr_size))
            else:
                fp_base = self.ihex.segments()[1][0] # start address of next segment.

        self.ihex.write_hex_file("ota.hex")
        self.ihex.tobinfile("ota.pbin", start = fp_base)
        

        self.ebin_file = ebin_file
        
        self.fw_info = {}
        self.fw_info.setdefault('fp_base', fp_base)
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
        try:
            writer = FWInfoWriter(self.fw_info['aes_key'], self.fw_info['aes_iv'], self.ebin_file)
            self.ihex.tobinfile(writer, start = self.fw_info['fp_base'])
            writer.close()
            self.fw_info['pbin_size'] = writer.pbin_size
            self.fw_info['ebin_size'] = writer.ebin_size
            self.fw_info['ebin_hash'] = writer.ebin_hash.digest()
            self.fw_info['pbin_hash'] = writer.pbin_hash.digest()
        except Exception as e:
            raise(e)
        
        if self.fw_info['ebin_size'] == 0:
            raise OTAGeneratorError("No output generated.")

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
        

