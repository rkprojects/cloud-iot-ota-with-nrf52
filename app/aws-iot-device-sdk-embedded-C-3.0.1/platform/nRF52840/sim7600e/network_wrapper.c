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

#include <stdbool.h>
#include <string.h>
#include "timer_platform.h"
#include "network_interface.h"

#include "aws_iot_error.h"
#include "aws_iot_log.h"
#include "network_interface.h"
#include "network_platform.h"

#include "uart_print.h"
#include "sim7600_gprs.h"


/* This is the value used for ssl read timeout */
#define IOT_SSL_READ_TIMEOUT 10
#define AWS_IOT_SSL_CONTEXT_ID 0

void _iot_tls_set_connect_params(Network *pNetwork, const char *pRootCALocation, const char *pDeviceCertLocation,
								 const char *pDevicePrivateKeyLocation, const char *pDestinationURL,
								 uint16_t destinationPort, uint32_t timeout_ms, bool ServerVerificationFlag) {
	pNetwork->tlsConnectParams.DestinationPort = destinationPort;
	pNetwork->tlsConnectParams.pDestinationURL = pDestinationURL;
	pNetwork->tlsConnectParams.pDeviceCertLocation = pDeviceCertLocation;
	pNetwork->tlsConnectParams.pDevicePrivateKeyLocation = pDevicePrivateKeyLocation;
	pNetwork->tlsConnectParams.pRootCALocation = pRootCALocation;
	
	if (timeout_ms < GPRS_MINIMUM_API_TIMEOUT_MS)
		pNetwork->tlsConnectParams.timeout_ms = GPRS_MINIMUM_API_TIMEOUT_MS;
	else
		pNetwork->tlsConnectParams.timeout_ms = timeout_ms;
		
	pNetwork->tlsConnectParams.ServerVerificationFlag = ServerVerificationFlag;
}

IoT_Error_t iot_tls_init(Network *pNetwork, const char *pRootCALocation, const char *pDeviceCertLocation,
						 const char *pDevicePrivateKeyLocation, const char *pDestinationURL,
						 uint16_t destinationPort, uint32_t timeout_ms, bool ServerVerificationFlag) {
							 
	_iot_tls_set_connect_params(pNetwork, pRootCALocation, pDeviceCertLocation, pDevicePrivateKeyLocation,
								pDestinationURL, destinationPort, timeout_ms, ServerVerificationFlag);
	
	pNetwork->connect = iot_tls_connect;
	pNetwork->read = iot_tls_read;
	pNetwork->write = iot_tls_write;
	pNetwork->disconnect = iot_tls_disconnect;
	pNetwork->isConnected = iot_tls_is_connected;
	pNetwork->destroy = iot_tls_destroy;
	
	pNetwork->tlsDataParams.session_id = -1;
	
	

	return SUCCESS;
}

IoT_Error_t iot_tls_is_connected(Network *pNetwork) {
	/* Use this to add implementation which can check for physical layer disconnect */
	return NETWORK_PHYSICAL_LAYER_CONNECTED;
}

IoT_Error_t iot_tls_connect(Network *pNetwork, TLSConnectParams *params) {
	int ret = 0;
	gprs_ssl_context_t ssl_context = DEFAULT_SSL_CONTEXT_PARAMS;
	
	if(NULL == pNetwork) {
		return NULL_VALUE_ERROR;
	}

	if(NULL != params) {
		_iot_tls_set_connect_params(pNetwork, params->pRootCALocation, params->pDeviceCertLocation,
									params->pDevicePrivateKeyLocation, params->pDestinationURL,
									params->DestinationPort, params->timeout_ms, params->ServerVerificationFlag);
	}
	
	pNetwork->tlsDataParams.session_id = -1;

	
	ssl_context.cacert = pNetwork->tlsConnectParams.pRootCALocation;
	ssl_context.clientcert = pNetwork->tlsConnectParams.pDeviceCertLocation;
	ssl_context.clientkey = pNetwork->tlsConnectParams.pDevicePrivateKeyLocation;
	
	if ((ssl_context.cacert) && (ssl_context.clientcert))
	{
		ssl_context.auth_mode = SSL_AUTH_MODE_SERVER_CLIENT;
	}
	else if (ssl_context.cacert)
	{
		ssl_context.auth_mode = SSL_AUTH_MODE_ONLY_SERVER;
	}
	else
	{
		ssl_context.auth_mode = SSL_AUTH_MODE_NONE;
	}
	
	dbg_printf(DEBUG_LEVEL_DEBUG, "Setting ssl_context.auth_mode = %d\r\n", ssl_context.auth_mode);
	
	ret = gprs_ssl_config_context(AWS_IOT_SSL_CONTEXT_ID, &ssl_context);
    if (ret < 0)
    {
        dbg_printf(DEBUG_LEVEL_ERROR, "gprs_ssl_config_context: %d\r\n", ret);
        return NETWORK_SSL_UNKNOWN_ERROR;
    }
    
    ret = gprs_ssl_connect(AWS_IOT_SSL_CONTEXT_ID,
						pNetwork->tlsConnectParams.pDestinationURL,
						pNetwork->tlsConnectParams.DestinationPort,
						pNetwork->tlsConnectParams.timeout_ms);
	if (ret < 0)
    {
        dbg_printf(DEBUG_LEVEL_ERROR, "gprs_ssl_connect: %d\r\n", ret);
        
        switch(ret)
        {
			case GPRS_ERROR_SSL_CREATE_SOCKET:
			case GPRS_ERROR_SSL_NETWORK:
				ret = gprs_init(0, 0, 0);
				if (ret < 0) 
					return NETWORK_SSL_UNKNOWN_ERROR;
				ret = gprs_ssl_init();
				if (ret < 0)
					return NETWORK_SSL_UNKNOWN_ERROR;
				break;
		}
        return NETWORK_ERR_NET_CONNECT_FAILED;
	}
	
	pNetwork->tlsDataParams.session_id = ret;

	return (IoT_Error_t) SUCCESS;
}

IoT_Error_t iot_tls_write(Network *pNetwork, unsigned char *pMsg, size_t len, Timer *timer, size_t *written_len) {
	size_t written_so_far;
	int ret = 0;
	int session_id = pNetwork->tlsDataParams.session_id;
	
	for(written_so_far = 0; written_so_far < len && !has_timer_expired(timer); written_so_far += ret) {
		ret = gprs_ssl_send(session_id, &pMsg[written_so_far], (int) (len - written_so_far), GPRS_GENERAL_API_TIMEOUT_MS);
		if (ret < 0)
		{
			dbg_printf(DEBUG_LEVEL_ERROR, "gprs_ssl_send: %d\r\n", ret);
			return NETWORK_SSL_WRITE_ERROR;
		}
	}

	*written_len = written_so_far;

	if(has_timer_expired(timer) && written_so_far != len) {
		return NETWORK_SSL_WRITE_TIMEOUT_ERROR;
	}

	return SUCCESS;
}

IoT_Error_t iot_tls_read(Network *pNetwork, unsigned char *pMsg, size_t len, Timer *timer, size_t *read_len) {
	size_t rxLen = 0;
	int ret;
	int session_id = pNetwork->tlsDataParams.session_id;
	
	while (len > 0) {
		// This read will timeout after IOT_SSL_READ_TIMEOUT if there's no data to be read
		ret = gprs_ssl_recv(session_id, &pMsg[rxLen], (int) len , GPRS_GENERAL_API_TIMEOUT_MS);
		if (ret > 0) {
			rxLen += ret;
			len -= ret;
		} else if ((ret == 0) || (ret != GPRS_ERROR_TIMEOUT)) {
			dbg_printf(DEBUG_LEVEL_ERROR, "gprs_ssl_recv: %d\r\n", ret);
			return NETWORK_SSL_READ_ERROR;
		}

		// Evaluate timeout after the read to make sure read is done at least once
		if (has_timer_expired(timer)) {
			break;
		}
	}

	if (len == 0) {
		*read_len = rxLen;
		return SUCCESS;
	}

	if (rxLen == 0) {
		return NETWORK_SSL_NOTHING_TO_READ;
	} else {
		return NETWORK_SSL_READ_TIMEOUT_ERROR;
	}
}

IoT_Error_t iot_tls_disconnect(Network *pNetwork) {
	int session_id = pNetwork->tlsDataParams.session_id;
	int ret;
	
	ret = gprs_ssl_close(session_id);
	if (ret < 0)
	{
		dbg_printf(DEBUG_LEVEL_ERROR, "gprs_ssl_close: %d\r\n", ret);
	}
	
	/* All other negative return values indicate connection needs to be reset.
	 * No further action required since this is disconnect call */

	return SUCCESS;
}

IoT_Error_t iot_tls_destroy(Network *pNetwork) {
	
	return SUCCESS;
}

