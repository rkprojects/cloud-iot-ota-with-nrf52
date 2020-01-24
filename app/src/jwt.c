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

#include "jwt.h"

#include "mbedtls/base64.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"

#include "nrf_drv_rng.h"

#include "uart_print.h"

static mbedtls_pk_context pk;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static const string_t rs256_header = "{ \"alg\": \"RS256\", \"typ\": \"JWT\" }";

static int entropy_simple_src(void* data, unsigned char* output, size_t len, size_t* olen);
static int base64_to_url(string_t base64);

static int base64_to_url(string_t base64)
{
    int i;
    for (i = 0; base64[i] != 0; i++) {
        if (base64[i] == '+')
            base64[i] = '-';
        if (base64[i] == '/')
            base64[i] = '_';
        if (base64[i] == '=') {
            base64[i] = 0;
            break;
        }
    }

    return i;
}

static int entropy_rng_src(void* data, unsigned char* output, size_t len, size_t* olen)
{
    (void)data;

    nrf_drv_rng_block_rand(output, len);

    *olen = len;

    return 0;
}

int jwt_init(void)
{
    int ret;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_entropy_add_source(&entropy,
        entropy_rng_src,
        NULL,
        0,
        MBEDTLS_ENTROPY_SOURCE_STRONG);

    if (ret)
        return ret;

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
        mbedtls_entropy_func, &entropy,
        NULL,
        0);
    return ret;
}

int jwt_pk_init(const unsigned char* key, size_t keylen)
{
    int ret;

    mbedtls_pk_init(&pk);

    ret = mbedtls_pk_parse_key(&pk,
        key,
        keylen,
        NULL,
        0);

    return ret;
}

int jwt_create_RS256_token(cstring_t payload, string_t* otoken, size_t* token_len)
{
    int ret;

    size_t tlen = 512; //token max length
    string_t token = (string_t)malloc(tlen);
    size_t rlen = 0; // running length
    size_t len; // current length
    const mbedtls_md_info_t* md_info;
    unsigned char hash[32];
    unsigned char* sign_buf;

    if (payload == NULL) {
        ret = -1;
        goto err0;
    }

    ret = mbedtls_base64_encode((unsigned char*)token,
        tlen,
        &len,
        (const unsigned char*)rs256_header,
        strlen((string_t)rs256_header));

    if (ret) {
        dbg_printf(DEBUG_LEVEL_ERROR, "mbedtls_base64_encode: %d\r\n", ret);
        goto err0;
    }

    token[rlen + len] = 0;
    // This may change length.
    len = base64_to_url(token);
    rlen += len;

    token[rlen] = '.';
    rlen++;

    ret = mbedtls_base64_encode((unsigned char*)&token[rlen],
        tlen - rlen,
        &len,
        (const unsigned char*)payload,
        strlen((string_t)payload));

    if (ret) {
        dbg_printf(DEBUG_LEVEL_ERROR, "mbedtls_base64_encode: %d\r\n", ret);
        goto err0;
    }

    token[rlen + len] = 0;
    len = base64_to_url(&token[rlen]);
    rlen += len;

    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    ret = mbedtls_md(md_info,
        (const unsigned char*)token,
        rlen,
        hash);

    if (ret) {
        dbg_printf(DEBUG_LEVEL_ERROR, "mbedtls_md: %d\r\n", ret);
        goto err0;
    }

    sign_buf = malloc(MBEDTLS_MPI_MAX_SIZE);

    ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256,
        hash, 0, sign_buf, &len,
        mbedtls_ctr_drbg_random, &ctr_drbg);

    if (ret) {
        dbg_printf(DEBUG_LEVEL_ERROR, "mbedtls_pk_sign: %d\r\n", ret);
        goto err1;
    }

    token[rlen] = '.';
    rlen++;

    ret = mbedtls_base64_encode((unsigned char*)&token[rlen],
        tlen - rlen,
        &len,
        (const unsigned char*)sign_buf,
        len);

    if (ret) {
        dbg_printf(DEBUG_LEVEL_ERROR, "mbedtls_base64_encode: %d\r\n", ret);
        goto err1;
    }

    token[rlen + len] = 0;
    len = base64_to_url(&token[rlen]);
    rlen += len;

    free(sign_buf);
    // callers frees token
    *otoken = token;
    *token_len = rlen;
    return ret;

err1:
    free(sign_buf);

err0:
    free(token);
    return ret;
}
