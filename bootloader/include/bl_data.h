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

#ifndef _BL_DATA_H_
#define _BL_DATA_H_

#include "bl_cmds.h"
#include <stdint.h>

//NRF error codes are postive and 16 bit.
// error codes in bootloader are negative and
#define NRF_ERROR_POS_TO_NEG_BASE -131072 // -0x20000

#define NRF_ERROR_TO_BL_ERROR(x) (NRF_ERROR_POS_TO_NEG_BASE + (x))

#define BOOTLOADER_SETTINGS_PAGE_ADDR 0x000FF000UL
#define BL_SETTINGS_CODE 0xABCDEF12

//structs are aligned to 32 bit on this platform.
#define SIZE_BYTES_WORDS(x) ((x) / 4)
#define PAGE_SIZE 4096

#define IS_ADDRESS_PAGE_ALIGNED(x) (!((x) & (PAGE_SIZE - 1)))

// TODO: Internal Error Codes. NRF error codes are positive.

enum {
    PROG_STEP_EBIN_VERIFY = 0,
    PROG_STEP_PROGRAM,
    PROG_STEP_PBIN_VERIFY,
    PROG_STEP_DONE
};

typedef struct {
    int update_in_progress;
    int attempts;
    int last_error_code;
    int prog_step;
} fw_update_progress_t;

typedef struct {
    fw_info_t fw_info; //current one in flash.
    fw_info_t new_fw_info; //to be programmed.
    fw_update_progress_t update_info;
    int app_start_reason;
    uint32_t settings_code;
    // TODO: Add checksum for this struct.
} bl_info_t;

extern const bl_info_t bl_settings;

#endif //_BL_DATA_H_
