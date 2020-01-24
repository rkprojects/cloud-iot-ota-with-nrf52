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

#include "nrf_crypto.h"
#include "nrf_crypto_hash.h"

#include "program.h"

#include "uart_print.h"

#include "at_modem.h"
#include "sim7600_gprs.h"

int app_verify(void)
{
    return hash_verify((const uint8_t*)bl_settings.fw_info.fp_base, bl_settings.fw_info.pbin_size, 1, bl_settings.fw_info.pbin_hash);
}

int hash_file_verify(const char* path, int file_len, const uint8_t* expected_hash)
{
    ret_code_t nrf_err;
    int ret;
    nrf_crypto_hash_context_t hash_context;
    nrf_crypto_hash_sha256_digest_t digest;
    size_t digest_len = NRF_CRYPTO_HASH_SIZE_SHA256;
    int bytes_read;

    nrf_err = nrf_crypto_hash_init(&hash_context, &g_nrf_crypto_hash_sha256_info);
    if (nrf_err != NRF_SUCCESS)
        return NRF_ERROR_TO_BL_ERROR(nrf_err);

    dbg_printf(DEBUG_LEVEL_DEBUG, "file_len=%d\r\n", file_len);
    for (bytes_read = 0; bytes_read < file_len; bytes_read += ret) {
        ret = simcom_fs_readfile(path, bytes_read, prog_mem_buf_in, PROG_MEM_BUF_LENGTH);
        if (ret < 0) {
            dbg_printf(DEBUG_LEVEL_ERROR, "simcom_fs_readfile failed at: %d, ret: %d\r\n",
                bytes_read, ret);
            return ret;
        }

        nrf_err = nrf_crypto_hash_update(&hash_context, prog_mem_buf_in, ret);
        if (nrf_err != NRF_SUCCESS)
            return NRF_ERROR_TO_BL_ERROR(nrf_err);

        //dbg_printf(DEBUG_LEVEL_DEBUG, "read=%d, ret=%d\r\n", bytes_read, ret);
    }

    nrf_err = nrf_crypto_hash_finalize(&hash_context, digest, &digest_len);
    if (nrf_err != NRF_SUCCESS)
        return NRF_ERROR_TO_BL_ERROR(nrf_err);

    if (memcmp(digest, expected_hash, NRF_CRYPTO_HASH_SIZE_SHA256) != 0) {
        int i;
        for (i = 0; i < NRF_CRYPTO_HASH_SIZE_SHA256; i++) {
            if (digest[i] != expected_hash[i]) {
                dbg_printf(DEBUG_LEVEL_ERROR, "Hash mismatch at %d, Expected: %x != Actual: %x\r\n", i, expected_hash[i], digest[i]);
                return PROG_ERROR_HASH_NOT_MATCHED;
            }
        }
    }

    return 0;
}

int hash_verify(const uint8_t* data, size_t data_len, int data_in_rom, const uint8_t* expected_hash)
{
    ret_code_t nrf_err;
    nrf_crypto_hash_context_t hash_context;
    nrf_crypto_hash_sha256_digest_t digest;
    size_t digest_len = NRF_CRYPTO_HASH_SIZE_SHA256;
    int i;

    nrf_err = nrf_crypto_hash_init(&hash_context, &g_nrf_crypto_hash_sha256_info);
    if (nrf_err != NRF_SUCCESS)
        return NRF_ERROR_TO_BL_ERROR(nrf_err);

    if (data_in_rom) //CC310 backend uses DMA and nRF doesn't allow flash mem for DMA even for reads.
    {
        size_t block_size;
        while (data_len > 0) {
            block_size = data_len;
            if (block_size > PROG_MEM_BUF_LENGTH)
                block_size = PROG_MEM_BUF_LENGTH;

            memcpy(prog_mem_buf_in, data, block_size);
            nrf_err = nrf_crypto_hash_update(&hash_context, prog_mem_buf_in, block_size);
            if (nrf_err != NRF_SUCCESS)
                return NRF_ERROR_TO_BL_ERROR(nrf_err);

            data += block_size;
            data_len -= block_size;
        }
    } else {
        nrf_err = nrf_crypto_hash_update(&hash_context, data, data_len);
        if (nrf_err != NRF_SUCCESS)
            return NRF_ERROR_TO_BL_ERROR(nrf_err);
    }

    nrf_err = nrf_crypto_hash_finalize(&hash_context, digest, &digest_len);
    if (nrf_err != NRF_SUCCESS)
        return NRF_ERROR_TO_BL_ERROR(nrf_err);

    if (memcmp(digest, expected_hash, NRF_CRYPTO_HASH_SIZE_SHA256) != 0) {
        for (i = 0; i < NRF_CRYPTO_HASH_SIZE_SHA256; i++) {
            if (digest[i] != expected_hash[i]) {
                dbg_printf(DEBUG_LEVEL_ERROR, "Hash mismatch at %d, Expected: %x != Actual: %x\r\n", i, expected_hash[i], digest[i]);
                return PROG_ERROR_HASH_NOT_MATCHED;
            }
        }
    }

    dbg_printf(DEBUG_LEVEL_DEBUG, "computed digest=");
    for (i = 0; i < NRF_CRYPTO_HASH_SIZE_SHA256; i++) {
        dbg_printf(DEBUG_LEVEL_DEBUG, "%x", digest[i]);
    }
    dbg_printf(DEBUG_LEVEL_DEBUG, "\r\n");

    return 0;
}