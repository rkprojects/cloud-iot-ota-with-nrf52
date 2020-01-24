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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bsp.h"
#include "nrf.h"
#include "nrf_delay.h"
#include "nrf_uarte.h"
#include "nrfx_uarte.h"
#include "nrfx_wdt.h"

#include "nrf_crypto.h"
#include "nrf_crypto_hash.h"

#include "nrf_nvmc.h"

#include "bl_data.h"
#include "program.h"

#include "sim7600_gprs.h"
#include "uart_print.h"

static int aes_file_decrypt_and_flash(const fw_info_t* fw_info);
static void flash(uint32_t address, const uint32_t* buf, uint32_t words);
static int programming_success(void);
static int programming_failed(int abort, int err_code, int prog_step);

// Memories for file read, verify and decryption
unsigned char prog_mem_buf_in[PROG_MEM_BUF_LENGTH];
unsigned char prog_mem_buf_out[PROG_MEM_BUF_LENGTH];

int programming_pending(void)
{
    int ret = 0;

    if (bl_settings.update_info.update_in_progress) {
        if (bl_settings.update_info.attempts < MAX_PROGRAMMING_ATTEMPTS) {
            ret = 1;
        } else {
            ret = PROG_ERROR_MAX_ATTEMPT_REACHED;
        }
    }

    return ret;
}

int start_program(void)
{
    int ret;
    const fw_info_t* new_fw_info = &bl_settings.new_fw_info;

    dbg_printf(DEBUG_LEVEL_DEBUG, "Modem Init\r\n");

    nrfx_wdt_feed();

    ret = gprs_init(0, 0, 1);
    if (ret < 0) {
        //programming_failed(0, ret);
        return ret;
    }

    switch (bl_settings.update_info.prog_step) {
    case PROG_STEP_EBIN_VERIFY:
        nrfx_wdt_feed();
        dbg_printf(DEBUG_LEVEL_DEBUG, "Program: Step %d - Verify whether encrypted binary is still intact.\r\n", PROG_STEP_EBIN_VERIFY);

        ret = hash_file_verify(new_fw_info->fs_path, (int)new_fw_info->ebin_size, new_fw_info->ebin_hash);
        if (ret < 0) {
            // Do not attempt again for hash mismatch.
            if (ret == PROG_ERROR_HASH_NOT_MATCHED)
                programming_failed(1, ret, PROG_STEP_EBIN_VERIFY);
            else
                programming_failed(0, ret, PROG_STEP_EBIN_VERIFY);

            return ret;
        }
    // fall through.
    case PROG_STEP_PROGRAM:
        nrfx_wdt_feed();
        dbg_printf(DEBUG_LEVEL_DEBUG, "Program: Step %d - Decrypt and program.\r\n", PROG_STEP_PROGRAM);

        ret = aes_file_decrypt_and_flash(new_fw_info);
        if (ret < 0) {
            programming_failed(0, ret, PROG_STEP_PROGRAM);
            return ret;
        }
    // fall through
    case PROG_STEP_PBIN_VERIFY:

        nrfx_wdt_feed();

        dbg_printf(DEBUG_LEVEL_DEBUG, "Program: Step %d - Verify programmed image.\r\n", PROG_STEP_PBIN_VERIFY);

        ret = hash_verify((const uint8_t*)new_fw_info->fp_base, new_fw_info->pbin_size, 1, new_fw_info->pbin_hash);
        if (ret < 0) {
            if (ret == PROG_ERROR_HASH_NOT_MATCHED) {
                // reprogram
                programming_failed(0, ret, PROG_STEP_PROGRAM);
            } else {
                programming_failed(0, ret, PROG_STEP_PBIN_VERIFY);
            }

            return ret;
        }
    // fall through
    case PROG_STEP_DONE:
        nrfx_wdt_feed();

        dbg_printf(DEBUG_LEVEL_DEBUG, "Program: Step %d - Save settings.\r\n", PROG_STEP_DONE);

        programming_success();
        break;
    default:
        programming_failed(0, PROG_ERROR_INVALID_PROG_STEP, PROG_STEP_EBIN_VERIFY);
        break;
    }

    return 0;
}

static int aes_file_decrypt_and_flash(const fw_info_t* fw_info)
{
    nrf_crypto_aes_context_t cbc_decr_128_ctx;
    ret_code_t nrf_ret;
    int ret;
    int bytes_read;

    //CC310 backend needs all input data in ram.
    uint8_t aes_key[AES_KEY_SIZE];
    uint8_t aes_iv[AES_KEY_SIZE];

    if (!IS_ADDRESS_PAGE_ALIGNED(fw_info->fp_base)) {
        dbg_printf(DEBUG_LEVEL_ERROR, "base_address = %x must be page aligned\r\n", fw_info->fp_base);
        return PROG_ERROR_UNALIGNED_BASE_ADDRESS;
    }

    memcpy(aes_key, fw_info->aes_key, AES_KEY_SIZE);
    memcpy(aes_iv, fw_info->aes_iv, AES_KEY_SIZE);

    nrf_ret = nrf_crypto_aes_init(&cbc_decr_128_ctx,
        &g_nrf_crypto_aes_cbc_128_pad_pkcs7_info,
        NRF_CRYPTO_DECRYPT);

    if (nrf_ret != NRF_SUCCESS) {
        dbg_printf(DEBUG_LEVEL_ERROR, "nrf_crypto_aes_init failed: %d\r\n", nrf_ret);
        return NRF_ERROR_TO_BL_ERROR(nrf_ret);
    }

    nrf_ret = nrf_crypto_aes_key_set(&cbc_decr_128_ctx, aes_key);
    if (nrf_ret != NRF_SUCCESS) {
        dbg_printf(DEBUG_LEVEL_ERROR, "nrf_crypto_aes_key_set failed: %d\r\n", nrf_ret);
        return NRF_ERROR_TO_BL_ERROR(nrf_ret);
    }

    nrf_ret = nrf_crypto_aes_iv_set(&cbc_decr_128_ctx, aes_iv);
    if (nrf_ret != NRF_SUCCESS) {
        dbg_printf(DEBUG_LEVEL_ERROR, "nrf_crypto_aes_iv_set failed: %d\r\n", nrf_ret);
        return NRF_ERROR_TO_BL_ERROR(nrf_ret);
    }

    dbg_printf(DEBUG_LEVEL_DEBUG, "Flashing from=%x, len=%d\r\n", fw_info->fp_base, fw_info->ebin_size);

    for (bytes_read = 0; bytes_read < fw_info->ebin_size; bytes_read += ret) {
        //dbg_printf(DEBUG_LEVEL_DEBUG, "%d/%d\r", bytes_read, fw_info->ebin_size);

        // Caution: this loop must exit.
        nrfx_wdt_feed();

        ret = simcom_fs_readfile(fw_info->fs_path, bytes_read, prog_mem_buf_in, PROG_MEM_BUF_LENGTH);
        if (ret <= 0) {
            dbg_printf(DEBUG_LEVEL_ERROR, "simcom_fs_readfile failed at: %d, ret: %d\r\n",
                bytes_read,
                ret);
            if (ret == 0)
                return PROG_ERROR_FILEREAD_FAILED;
            return ret;
        }

        if (ret < PROG_MEM_BUF_LENGTH) // last block.
        {
            size_t out_buf_size = PROG_MEM_BUF_LENGTH;

            memset(prog_mem_buf_out, 0xff, PROG_MEM_BUF_LENGTH);
            nrf_ret = nrf_crypto_aes_finalize(&cbc_decr_128_ctx, prog_mem_buf_in,
                ret, prog_mem_buf_out, &out_buf_size);
            if (nrf_ret != NRF_SUCCESS) {
                dbg_printf(DEBUG_LEVEL_ERROR, "nrf_crypto_aes_finalize failed: %d\r\n", nrf_ret);

                return NRF_ERROR_TO_BL_ERROR(nrf_ret);
            }
        } else {
            nrf_ret = nrf_crypto_aes_update(&cbc_decr_128_ctx, prog_mem_buf_in,
                PROG_MEM_BUF_LENGTH, prog_mem_buf_out);
            if (nrf_ret != NRF_SUCCESS) {
                dbg_printf(DEBUG_LEVEL_ERROR, "nrf_crypto_aes_update failed: %d\r\n", nrf_ret);
                return NRF_ERROR_TO_BL_ERROR(nrf_ret);
            }
        }

        // for last block out_buf is padded to make it buf_len.
        flash(fw_info->fp_base + bytes_read, (const uint32_t*)prog_mem_buf_out,
            (uint32_t)(PROG_MEM_BUF_LENGTH / 4));
    }

    dbg_printf(DEBUG_LEVEL_DEBUG, "Done\r\n");

    return 0;
}

static void flash(uint32_t address, const uint32_t* buf, uint32_t words)
{
    if (IS_ADDRESS_PAGE_ALIGNED(address)) {
        nrf_nvmc_page_erase(address);
    }

    nrf_nvmc_write_words(address, buf, words);
}

int update_bl_settings(const bl_info_t* bl_info)
{
    int ret;

    ret = memcmp(bl_info, &bl_settings, sizeof(bl_info_t));
    if (ret == 0) // skip if same.
    {
        return 0;
    }

    nrf_nvmc_page_erase(BOOTLOADER_SETTINGS_PAGE_ADDR);
    nrf_nvmc_write_words(BOOTLOADER_SETTINGS_PAGE_ADDR, (const uint32_t*)bl_info, SIZE_BYTES_WORDS(sizeof(bl_info_t)));

    return 0;
}

static int programming_failed(int abort, int err_code, int prog_step)
{
    bl_info_t bl_info;

    bl_info = bl_settings;

    bl_info.update_info.prog_step = prog_step;

    if (abort) {
        bl_info.update_info.attempts = 0;
        bl_info.update_info.update_in_progress = 0;
    } else {
        bl_info.update_info.attempts++;
    }

    bl_info.update_info.last_error_code = err_code;
    bl_info.app_start_reason = APP_START_REASON_PROG_FAILED;

    return update_bl_settings(&bl_info);
}

static int programming_success(void)
{
    bl_info_t bl_info;

    bl_info = bl_settings;
    bl_info.fw_info = bl_settings.new_fw_info;
    memset(&bl_info.update_info, 0, sizeof(fw_update_progress_t));
    bl_info.update_info.prog_step = PROG_STEP_DONE;
    bl_info.app_start_reason = APP_START_REASON_NORMAL;

    return update_bl_settings(&bl_info);
}
