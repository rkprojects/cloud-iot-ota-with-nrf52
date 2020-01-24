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

#include <stdio.h>
#include <string.h>

#include "nrf.h"

#include "bl_cmds.h"
#include "bl_data.h"
#include "program.h"

#include "uart_print.h"

static int check_array(const uint8_t* a, int len);
static int check_string(const char* s, int len);
static int check_update_fw_params(const fw_info_t* fw_info);

__attribute__((section(".bl_cmd_fn_addr"))) int bl_commands(int cmd, bl_cmd_params_t* params)
{
    int ret;
    bl_info_t bl_info;

    dbg_printf(DEBUG_LEVEL_DEBUG, "bl_commands %d, %p\r\n", cmd, params);

    if (params == NULL)
        return -1;

    switch (cmd) {
    case BL_CMD_GET_APP_START_REASON:
        params->app_start_info.app_start_reason = bl_settings.app_start_reason;
        params->app_start_info.last_error_code = bl_settings.update_info.last_error_code;
        break;
    case BL_CMD_UPDATE_FW:
        // validate fw_info struct.
        ret = check_update_fw_params(&params->fw_info);
        if (ret < 0)
            return ret;

        // Check for repeated programming.
        ret = memcmp(bl_settings.fw_info.pbin_hash, params->fw_info.pbin_hash, HASH_SIZE);
        if (ret == 0) {
            if (bl_settings.fw_info.fp_base == params->fw_info.fp_base) {
                //new image is exact copy of current one.
                return BL_CMD_ERROR_ALREADY_PROGRAMMED;
            }
        }

        // Accept parameters.
        bl_info = bl_settings;
        bl_info.new_fw_info = params->fw_info;
        memset(&bl_info.update_info, 0, sizeof(fw_update_progress_t));
        bl_info.update_info.update_in_progress = 1;
        ret = update_bl_settings(&bl_info);
        if (ret < 0)
            return BL_CMD_ERROR_FAILED_TO_SAVE_SETTINGS;

        // Update on chip reset to undo all application side effects.
        NVIC_SystemReset();
        break;
    default:
        return BL_CMD_ERROR_CMD_NOT_SUPPORTED;
    }

    return BL_CMD_OK;
}

//basic check: contents should not be same bytes.
static int check_array(const uint8_t* a, int len)
{
    int i;

    if (a == NULL)
        return -1;

    for (i = 1; i < len; i++) {
        if (a[i] != a[i - 1])
            return 0;
    }

    return -1;
}

static int check_string(const char* s, int len)
{
    int i;

    if (s == NULL)
        return -1;

    for (i = 0; i < len; i++) {
        if (s[i] == 0)
            break;
    }

    if (i >= len) //null termination not found.
        return -1;

    if (i == 0) //string len is zero.
        return -1;

    return 0;
}

static int check_update_fw_params(const fw_info_t* fw_info)
{
    int ret;

    if (fw_info->pbin_size <= 0)
        return BL_CMD_ERROR_INVALID_PARAMS;

    if (fw_info->pbin_size > (MAX_FP_BASE_ADDRESS - MIN_FP_BASE_ADDRESS))
        return BL_CMD_ERROR_INVALID_PARAMS;

    if (fw_info->fp_base < MIN_FP_BASE_ADDRESS)
        return BL_CMD_ERROR_INVALID_PARAMS;

    if ((fw_info->fp_base + fw_info->pbin_size) > MAX_FP_BASE_ADDRESS)
        return BL_CMD_ERROR_INVALID_PARAMS;

    if (fw_info->ebin_size <= 0)
        return BL_CMD_ERROR_INVALID_PARAMS;

    if (fw_info->ebin_size > MAX_EBIN_SIZE)
        return BL_CMD_ERROR_INVALID_PARAMS;

    ret = check_array(fw_info->aes_key, AES_KEY_SIZE);
    if (ret < 0)
        return BL_CMD_ERROR_INVALID_PARAMS;

    ret = check_array(fw_info->aes_iv, AES_KEY_SIZE);
    if (ret < 0)
        return BL_CMD_ERROR_INVALID_PARAMS;

    ret = check_array(fw_info->pbin_hash, HASH_SIZE);
    if (ret < 0)
        return BL_CMD_ERROR_INVALID_PARAMS;

    ret = check_array(fw_info->ebin_hash, HASH_SIZE);
    if (ret < 0)
        return BL_CMD_ERROR_INVALID_PARAMS;

    ret = check_string(fw_info->fs_path, MAX_FW_STORAGE_PATH + 1);
    if (ret < 0)
        return BL_CMD_ERROR_INVALID_PARAMS;

    return 0;
}