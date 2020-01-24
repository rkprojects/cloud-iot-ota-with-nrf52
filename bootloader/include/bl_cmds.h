/*
 * Copyright 2020 Ravikiran Bukkasagara <contact@ravikiranb.com>
 *        
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *    
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef _BL_COMMANDS_H_
#define _BL_COMMANDS_H_

#include <stdint.h>

#define MAX_FW_STORAGE_PATH 31
#define MIN_FP_BASE_ADDRESS 0x1000
#define MAX_FP_BASE_ADDRESS 0x000F0000
#define MAX_EBIN_SIZE 0x100000 //1MB

#define MAX_PROGRAMMING_ATTEMPTS 10

#define AES_KEY_SIZE 16
#define HASH_SIZE 32

// pfn_bl_commands_t return error codes.
enum {
    BL_CMD_OK = 0,
    BL_CMD_ERROR_INVALID_PARAMS = -100,
    BL_CMD_ERROR_FAILED_TO_SAVE_SETTINGS,
    BL_CMD_ERROR_CMD_NOT_SUPPORTED,
    BL_CMD_ERROR_ALREADY_PROGRAMMED,
};

// app_start_reason codes
enum {
    APP_START_REASON_NORMAL = 0,
    APP_START_REASON_PROG_FAILED, //if old app still available

};

typedef struct {
    uint32_t version; //Application version, unused in bootloader.
    uint32_t fp_base; //Flash programming base address. Aligned to page boundary.
    uint32_t pbin_size; //Plain binary size.
    uint32_t ebin_size; //Encrypted binary size.
    uint8_t aes_key[AES_KEY_SIZE];
    uint8_t aes_iv[AES_KEY_SIZE];
    uint8_t pbin_hash[HASH_SIZE]; //Plain binary SHA256 hash.
    uint8_t ebin_hash[HASH_SIZE]; //Encrypted binary SHA256 hash.
    // members from this point not included in fw_info OTA message.
    char fs_path[MAX_FW_STORAGE_PATH + 1]; //Image path in SIMCOM module filesystem.
    // TODO: Add checksum for this struct.
} fw_info_t;

typedef struct {
    int app_start_reason;
    int last_error_code;
} app_start_info_t;

typedef union {
    fw_info_t fw_info;
    app_start_info_t app_start_info;
} bl_cmd_params_t;

//provide fw_info_t in params
#define BL_CMD_UPDATE_FW 0
#define BL_CMD_GET_APP_START_REASON 1

typedef int (*pfn_bl_commands_t)(int, bl_cmd_params_t*);

/*
//To call bootloader commands from application code:
pfn_bl_commands_t fn = BL_COMMANDS_FN_ADDR;
fn(cmd, params);
*/
#define BL_COMMANDS_FN_ADDR ((pfn_bl_commands_t)(0xf0200 + 1)) //Thumb2 instruction.

#endif //_BL_COMMANDS_H_