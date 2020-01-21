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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#endif


#include "mbedtls/net_sockets.h"

#include <string.h>
#include <stdlib.h>

#include "sim7600_gprs.h"
#include "uart_print.h"

/*
 * Initialize a context
 */
void mbedtls_net_init( mbedtls_net_context *ctx )
{
    ctx->fd = -1;
}

/*
 * Initiate a TCP connection with host:port and the given protocol
 */
int mbedtls_net_connect( mbedtls_net_context *ctx, const char *host,
                         const char *port, int proto )
{
	int ret;

	ret = gprs_connect(host, atoi(port), GPRS_GENERAL_API_TIMEOUT_MS);
	if (ret < 0) {
		dbg_printf(DEBUG_LEVEL_ERROR, "gprs_connect failed: %d\r\n", ret);
		return MBEDTLS_ERR_NET_CONNECT_FAILED;
	}

	ctx->fd = ret;

	return 0;
}

/*
 * Create a listening socket on bind_ip:port
 */
int mbedtls_net_bind( mbedtls_net_context *ctx, const char *bind_ip, const char *port, int proto)
{
    (void) ctx;
    (void) bind_ip;
    (void) port;
    (void) proto;
    
    return MBEDTLS_ERR_NET_NOT_SUPPORTED;
}

/*
 * Accept a connection from a remote client
 */
int mbedtls_net_accept( mbedtls_net_context *bind_ctx,
                        mbedtls_net_context *client_ctx,
                        void *client_ip, size_t buf_size, size_t *ip_len )
{
    (void)bind_ctx;
    (void)client_ctx; 
    (void)client_ip; 
    (void)buf_size; 
    (void)ip_len;
    
    return MBEDTLS_ERR_NET_NOT_SUPPORTED;
}

/*
 * Set the socket blocking
 */
int mbedtls_net_set_block( mbedtls_net_context *ctx )
{
    (void) ctx;
	return 0;
}

/*
 * Set the socket non-blocking
 */
int mbedtls_net_set_nonblock( mbedtls_net_context *ctx )
{
    (void) ctx;
    return 0;
}

/*
 * Check if data is available on the socket
 */
#if 0
int mbedtls_net_poll( mbedtls_net_context *ctx, uint32_t rw, uint32_t timeout_ms )
{
	uint32_t rw_stat = 0;
	int ret;
	

	if( rw & MBEDTLS_NET_POLL_WRITE )
	{
		rw_stat |= MBEDTLS_NET_POLL_WRITE;
	}

	if( rw & MBEDTLS_NET_POLL_READ )
	{
		ret = gprs_recv_poll(ctx->fd, (int) timeout_ms);
		if (ret < 0)
		{
			dbg_printf(DEBUG_LEVEL_ERROR, "gprs_poll failed: %d\r\n", ret);
			return MBEDTLS_ERR_NET_POLL_FAILED;
		}
		else if (ret > 0)
			rw_stat |= MBEDTLS_NET_POLL_READ;
	}

	return rw_stat;
}
#endif
/*
 * Read at most 'len' characters
 */
#if 0
int mbedtls_net_recv( mbedtls_net_context *ctx, unsigned char *buf, size_t len )
{
    return mbedtls_net_recv_timeout(ctx, buf, len, GPRS_GENERAL_API_TIMEOUT_MS);
}
#endif
/*
 * Read at most 'len' characters, blocking for at most 'timeout' ms
 */
int mbedtls_net_recv_timeout( void *ctx, unsigned char *buf,
                              size_t len, uint32_t timeout_ms )
{
	int ret;
	(void) timeout_ms;
	int fd = ((mbedtls_net_context*)ctx)->fd;
	
	if (timeout_ms < GPRS_MINIMUM_API_TIMEOUT_MS)
		timeout_ms = GPRS_MINIMUM_API_TIMEOUT_MS;

	ret = gprs_recv(fd, buf, len, (int) timeout_ms);

	if (ret < 0)
	{
		if (ret == GPRS_ERROR_TIMEOUT)
			return MBEDTLS_ERR_SSL_WANT_READ;

		dbg_printf(DEBUG_LEVEL_ERROR, "gprs_recv failed: %d\r\n", ret);
		return MBEDTLS_ERR_NET_RECV_FAILED;
	}

	return ret;
}

/*
 * Write at most 'len' characters
 */
int mbedtls_net_send( void *ctx, const unsigned char *buf, size_t len )
{
	int ret;
	int fd = ((mbedtls_net_context*)ctx)->fd;
	
	ret = gprs_send(fd, buf, len, GPRS_GENERAL_API_TIMEOUT_MS);
	if (ret < 0)
	{
		//if (ret == GPRS_ERROR_SEND_TRY_AGAIN)
		//	return MBEDTLS_ERR_SSL_WANT_WRITE;

		dbg_printf(DEBUG_LEVEL_ERROR, "gprs_send failed: %d\r\n", ret);
		return MBEDTLS_ERR_NET_SEND_FAILED;
	}

	return ret;
}

/*
 * Gracefully close the connection
 */
void mbedtls_net_free( mbedtls_net_context *ctx )
{
    gprs_close(ctx->fd);
    
    ctx->fd = -1;
}


