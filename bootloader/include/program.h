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

#ifndef _PROGRAM_H_
#define _PROGRAM_H_

#include <stdint.h>
#include <stdio.h>
#include "bl_data.h"

enum {
    PROG_ERROR_BASE = -30000,
    PROG_ERROR_MAX_ATTEMPT_REACHED,
    PROG_ERROR_HASH_NOT_MATCHED,
    PROG_ERROR_UNALIGNED_BASE_ADDRESS,
    PROG_ERROR_INVALID_PROG_STEP,
    PROG_ERROR_FILEREAD_FAILED,
};

// Buffer length should a common factor of 
// PAGE_SIZE and multiple of 4 and 16 bytes.
#define PROG_MEM_BUF_LENGTH 512L

extern unsigned char prog_mem_buf_in[];

int hash_verify(const uint8_t* data, size_t data_len, int data_in_rom, const uint8_t* expected_hash);
int hash_file_verify(const char* path, int file_len, const uint8_t* expected_hash);
int app_verify(void);
int start_program(void);
int programming_required(void);
int update_bl_settings(const bl_info_t* bl_info);

#endif //_PROGRAM_H_