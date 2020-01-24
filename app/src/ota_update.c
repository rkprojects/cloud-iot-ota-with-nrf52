/*

Copyright 2019-2020 Ravikiran Bukkasagara <contact@ravikiranb.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include <stdio.h>
#include <string.h>

// JSON lib from AWS SDK external libs.
#include "jsmn.h"

#include "bl_cmds.h"
#include "ota_update.h"
#include "sim7600_gprs.h"
#include "uart_print.h"
#include "version.h"

#define MAX_JSON_TOKENS 16

#define LOCAL_FW_FILENAME "nrf52840_fw.ebin"
#define LOCAL_FW_FILEPATH ("E:/" LOCAL_FW_FILENAME)

static jsmn_parser parser;
static jsmntok_t json_tokens[MAX_JSON_TOKENS];
static fw_info_t fw_info;

#define URL_BUF_SIZE 80
#define MAX_URLS 2
static char url_buf[MAX_URLS][URL_BUF_SIZE];
static const char* url_keys[MAX_URLS] = { "url", "alt_url" };
static int update_enable_run = 0;

static int find_keyval(const char* jbuf, int n_tokens, const char* key, jsmntype_t value_type, const char** value);
static int hexstr_to_binarray(const char* str, unsigned char* buf, size_t n);
static int build_fw_info(const char* jbuf, int n_tokens);
static int download_image(void);

// Returns negative on error. TODO: error codes.
// Zero if update not required.
// Positive if update required and prepared.
int ota_update_prepare(const char* msg, int msg_len)
{
    int n_tokens;
    int ret;
    int i;
    const char* value;

    update_enable_run = 0;

    dbg_printf(DEBUG_LEVEL_INFO, "ota_update_prepare, msg_len = %d\r\n", msg_len);

    jsmn_init(&parser);

    n_tokens = jsmn_parse(&parser, msg, (size_t)msg_len, json_tokens, MAX_JSON_TOKENS);
    if (n_tokens <= 0) {
        dbg_printf(DEBUG_LEVEL_ERROR, "jsmn_parse failed: %d\r\n", n_tokens);
        return -1;
    }

    // process only update_fw message.
    ret = find_keyval(msg, n_tokens, "type", JSMN_STRING, &value);
    if (ret < 0) {
        dbg_printf(DEBUG_LEVEL_ERROR, "find_keyval failed: %d\r\n", ret);
        return ret;
    }

    if (strncmp(value, "update_fw", ret) != 0) {
        dbg_printf(DEBUG_LEVEL_ERROR, "update_fw not found\r\n");
        return -1;
    }

    ret = build_fw_info(msg, n_tokens);
    if (ret < 0) {
        dbg_printf(DEBUG_LEVEL_ERROR, "build_fw_info failed: %d\r\n", ret);
        return ret;
    }

    if (fw_info.version <= APP_VERSION) {
        dbg_printf(DEBUG_LEVEL_INFO, "Application is already at latest version: %d. "
                                     "New image version: %d\r\n",
            APP_VERSION, fw_info.version);
        return 0;
    }

    // save URLs.
    for (i = 0; i < MAX_URLS; i++) {
        memset(url_buf[i], 0, URL_BUF_SIZE);

        ret = find_keyval(msg, n_tokens, url_keys[i], JSMN_STRING, &value);
        if (ret < 0) {
            dbg_printf(DEBUG_LEVEL_ERROR, "URL key: %s not found: %d\r\n", url_keys[i], ret);
            return ret;
        }

        if (ret >= URL_BUF_SIZE) {
            dbg_printf(DEBUG_LEVEL_ERROR, "URL length too big: %d\r\n", ret);
            return -1;
        }

        strncpy(url_buf[i], value, ret);
    }

    update_enable_run = 1;

    return 1;
}

int ota_update_run(void)
{
    int ret;
    pfn_bl_commands_t bl_cmd_fn;
    bl_cmd_params_t bl_params;

    if (!update_enable_run) {
        dbg_printf(DEBUG_LEVEL_ERROR, "OTA update not ready to run.\r\n");
        return -1;
    }

#if 0 //Not required. Added to check SSL HTTPS download issue when single SSL TCP/IP socket is open.
    ret = gprs_ssl_stop();
    if (ret < 0)
        return ret;
#endif

    ret = gprs_http_init();
    if (ret < 0) {
        dbg_printf(DEBUG_LEVEL_ERROR, "gprs_http_init: %d\r\n", ret);
        return ret;
    }

    // Download Image
    ret = download_image();
    if (ret < 0)
        return ret;

    // verify ebin hash.
    // Bootloader verifies ebin hash, skip here for now.
    update_enable_run = 0;

    bl_cmd_fn = BL_COMMANDS_FN_ADDR;
    bl_params.fw_info = fw_info;

    dbg_printf(DEBUG_LEVEL_INFO, "Calling bl_command=%p\r\n", bl_cmd_fn);

    ret = bl_cmd_fn(BL_CMD_UPDATE_FW, &bl_params);
    if (ret < 0) {
        dbg_printf(DEBUG_LEVEL_ERROR, "BL_CMD_UPDATE_FW failed: %d\r\n", ret);
        return ret;
    }

    return 0;
}

// Returns found value as string.
static int find_keyval(const char* jbuf, int n_tokens, const char* key, jsmntype_t value_type, const char** value)
{
    int i;

    for (i = 0; i < (n_tokens - 1); i++) {
        if (json_tokens[i].type == JSMN_STRING) {
            const char* name = &jbuf[json_tokens[i].start];
            size_t size = json_tokens[i].end - json_tokens[i].start;

            if ((size == strlen(key)) && (strncmp(name, key, size) == 0)) {
                if (json_tokens[i + 1].type == value_type) {
                    i++;
                    size = json_tokens[i].end - json_tokens[i].start;
                    *value = &jbuf[json_tokens[i].start];
                    return size;
                }
            }
        }
    }

    return -1;
}

static int build_fw_info(const char* jbuf, int n_tokens)
{
    int ret;
    const char* value;

    ret = find_keyval(jbuf, n_tokens, "fw_info", JSMN_STRING, &value);
    if (ret < 0)
        return ret;

    //TODO: Check hex string size against fw_info_t

    memset(&fw_info, 0, sizeof(fw_info_t));

    hexstr_to_binarray(value, (uint8_t*)&fw_info, sizeof(fw_info_t));

    strncpy(fw_info.fs_path, LOCAL_FW_FILEPATH, MAX_FW_STORAGE_PATH);

    //#ifdef DEBUG
    {
        int i;
        dbg_printf(DEBUG_LEVEL_DEBUG, "fw_info.version= %d\r\n", fw_info.version);
        dbg_printf(DEBUG_LEVEL_DEBUG, "fw_info.fp_base= %p\r\n", fw_info.fp_base);
        dbg_printf(DEBUG_LEVEL_DEBUG, "fw_info.pbin_size= %lu\r\n", fw_info.pbin_size);
        dbg_printf(DEBUG_LEVEL_DEBUG, "fw_info.ebin_size= %lu\r\n", fw_info.ebin_size);
        dbg_printf(DEBUG_LEVEL_DEBUG, "fw_info.aes_key= ");
        for (i = 0; i < AES_KEY_SIZE; i++) {
            dbg_printf(DEBUG_LEVEL_DEBUG, "%.2x", fw_info.aes_key[i]);
        }
        dbg_printf(DEBUG_LEVEL_DEBUG, "\r\n");

        dbg_printf(DEBUG_LEVEL_DEBUG, "fw_info.aes_iv= ");
        for (i = 0; i < AES_KEY_SIZE; i++) {
            dbg_printf(DEBUG_LEVEL_DEBUG, "%.2x", fw_info.aes_iv[i]);
        }
        dbg_printf(DEBUG_LEVEL_DEBUG, "\r\n");

        dbg_printf(DEBUG_LEVEL_DEBUG, "fw_info.pbin_hash= ");
        for (i = 0; i < AES_KEY_SIZE; i++) {
            dbg_printf(DEBUG_LEVEL_DEBUG, "%.2x", fw_info.pbin_hash[i]);
        }
        dbg_printf(DEBUG_LEVEL_DEBUG, "\r\n");

        dbg_printf(DEBUG_LEVEL_DEBUG, "fw_info.ebin_hash= ");
        for (i = 0; i < AES_KEY_SIZE; i++) {
            dbg_printf(DEBUG_LEVEL_DEBUG, "%.2x", fw_info.ebin_hash[i]);
        }
        dbg_printf(DEBUG_LEVEL_DEBUG, "\r\n");

        dbg_printf(DEBUG_LEVEL_DEBUG, "fw_info.fs_path=%s\r\n", fw_info.fs_path);
    }
    //#endif //DEBUG

    return 0;
}

static int hexstr_to_binarray(const char* str, uint8_t* buf, size_t n)
{
    size_t i, j;
    unsigned char b;

    for (i = 0, j = 0; (i < 2 * n) && (str[i] != 0); i++) {
        if (str[i] <= '9')
            b = str[i] - '0';
        else if (str[i] <= 'F')
            b = str[i] - 'A' + 10;
        else // (str[i] <= 'f')
            b = str[i] - 'a' + 10;

        if (i & 1) {
            buf[j] += b;
            j++;
        } else
            buf[j] = b * 16;
    }

    return j; //bytes written in buffer.
}

static int download_image(void)
{
    int ret = -1;
    int i;

    for (i = 0; i < MAX_URLS; i++) {
        if (strlen(url_buf[i]) == 0)
            continue;

        dbg_printf(DEBUG_LEVEL_INFO, "Downloading image from: %s\r\n", url_buf[i]);
        dbg_printf(DEBUG_LEVEL_INFO, "Expected length: %lu\r\n", fw_info.ebin_size);

        ret = gprs_http_download(url_buf[i], LOCAL_FW_FILENAME, fw_info.ebin_size, GPRS_GENERAL_API_TIMEOUT_MS);
        if (ret < 0) {
            dbg_printf(DEBUG_LEVEL_ERROR, "gprs_http_download failed: %d\r\n", ret);
            continue;
        }

        return 0;
    }

    return ret;
}
