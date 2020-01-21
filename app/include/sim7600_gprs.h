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

#ifndef SIM7600_GPRS_H_
#define SIM7600_GPRS_H_

#include <sim7600_config.h>


#define GPRS_TCP_SEND_CHUNK_SIZE	1500

//Should be smaller than AT modem rx buffer size.
#define GPRS_TCP_RECV_CHUNK_SIZE	1500

#define GPRS_GENERAL_API_TIMEOUT_MS				90000
#define GPRS_MINIMUM_API_TIMEOUT_MS				5000
#define GPRS_NETWORK_REG_TIMEOUT_SECONDS 		(2*60)
#define GPRS_WAIT_AFTER_MODULE_RESET_SECONDS	10

enum GPRS_ERROR_CODES{
	GPRS_OK = 0,
	GPRS_ERROR_MODEM_COMM_FAILED = -100,
	GPRS_ERROR_NET_ERROR,
	GPRS_ERROR_TIMEOUT,
	GPRS_ERROR_PIN_NOT_READY,
	GPRS_ERROR_CMD_ERROR,
	GPRS_ERROR_NET_REG_FAILED,
	GPRS_ERROR_CONNECT_FAILED,
	GPRS_ERROR_CLOSE_FAILED,
	GPRS_ERROR_SEND_FAILED,
	GPRS_ERROR_SEND_TRY_AGAIN,
	GPRS_ERROR_RECV_FAILED,
	GPRS_ERROR_POLL_FAILED,
	GPRS_ERROR_ALL_IP_LINKS_BUSY,
	GPRS_ERROR_INVALID_PARAMETERS,
	GPRS_ERROR_CONNECTION_NOT_OPENED,
	GPRS_ERROR_COMMAND_TOO_LONG,
	GPRS_ERROR_NO_SUCH_CERTIFICATE,
	GPRS_ERROR_CERT_READ_FAILED,
	GPRS_ERROR_CERT_DOWNLOAD_FAILED,
	GPRS_ERROR_GET_TIME_FAILED,
	GPRS_ERROR_CONNECTION_CLOSED,
    GPRS_ERROR_CFTRAN_FAILED,
    GPRS_ERROR_HTTP_DOWNLOAD_LEN_MISMATCH,
    GPRS_ERROR_HTTP_DOWNLOAD_FAILED,
    GPRS_ERROR_HTTP_READFILE_FAILED,
    GPRS_ERROR_SSL_SERVICE_STOP_FAILED,
	
	//Error codes from SIMCOM SSL APIs
	GPRS_ERROR_SSL_BASE = -500,
	GPRS_ERROR_SSL_ALERTING,
	GPRS_ERROR_SSL_UNKNOWN,
	GPRS_ERROR_SSL_BUSY,
	GPRS_ERROR_SSL_PEER_CLOSED,
	GPRS_ERROR_SSL_OP_TIMEOUT,
	GPRS_ERROR_SSL_TRANSFER_FAILED,
	GPRS_ERROR_SSL_MEMORY,
	GPRS_ERROR_SSL_INVALID_PARAMS,
	GPRS_ERROR_SSL_NETWORK,
	GPRS_ERROR_SSL_OPEN_SESSION,
	GPRS_ERROR_SSL_STATE,
	GPRS_ERROR_SSL_CREATE_SOCKET,
	GPRS_ERROR_SSL_GET_DNS,
	GPRS_ERROR_SSL_CONNECT_SOCKET,
	GPRS_ERROR_SSL_HANDSHAKE,
	GPRS_ERROR_SSL_CLOSE_SOCKET,
	GPRS_ERROR_SSL_NONET,
	GPRS_ERROR_SSL_SEND_DATA_TIMEOUT,
	GPRS_ERROR_SSL_NO_SET_CERTIFICATES,
	
	//Error codes from SIMCOM Non SSL TCP/IP APIs - CHAPTER 4
	GPRS_ERROR_TCPIP_BASE = -1000,
	GPRS_ERROR_TCPIP_NETWORK,
	GPRS_ERROR_TCPIP_NETWORK_NOT_OPENED,
	GPRS_ERROR_TCPIP_WRONG_PARAMS,
	GPRS_ERROR_TCPIP_OP_NOT_SUPPORTED,
	GPRS_ERROR_TCPIP_CREATE_SOCKET_FAILED,
	GPRS_ERROR_TCPIP_BIND_SOCKET_FAILED,
	GPRS_ERROR_TCPIP_TCP_SERVER_ALREADY_LISTENING,
	GPRS_ERROR_TCPIP_BUSY,
	GPRS_ERROR_TCPIP_SOCKETS_OPENDED,
	GPRS_ERROR_TCPIP_TIMEOUT,
	GPRS_ERROR_TCPIP_DNS_FAILED_FOR_CIPOPEN,
	GPRS_ERROR_TCPIP_UNKNOWN,
	
	
	//Error codes from SIMCOM NTP APIs,
	GPRS_ERROR_NTP_BASE = -1500,
	GPRS_ERROR_NTP_UNKNOWN,
	GPRS_ERROR_NTP_INVALID_PARAMS,
	GPRS_ERROR_NTP_INVALID_DATE_TIME_CALCULATED,
	GPRS_ERROR_NTP_NETWORK_FAILED,
	GPRS_ERROR_NTP_TIME_ZONE_ERROR,
	GPRS_ERROR_NTP_TIMEOUT,

    //Error codes from SIMCOM HTTP APIs, range 0 to 719
    GPRS_ERROR_HTTP_BASE = -2500,

    
	
};

typedef enum {
	NETWORK_MODE_NO_SERVICE = 0,
	NETWORK_MODE_GSM,
	NETWORK_MODE_GPRS,
	NETWORK_MODE_EDGE,
	NETWORK_MODE_WCDMA,
	NETWORK_MODE_HSDPA,
	NETWORK_MODE_HSUPA,
	NETWORK_MODE_HSPA,
	NETWORK_MODE_LTE,
	NETWORK_MODE_TDS_CDMA,
	NETWORK_MODE_TDS_HSDPA,
	NETWORK_MODE_TDS_HSUPA,
	NETWORK_MODE_TDS_HSPA,
	NETWORK_MODE_CDMA,
	NETWORK_MODE_EVDO,
	NETWORK_MODE_HYBRID_CDMA_EVDO,
	NETWORK_MODE_1XLTE,
	NETWORK_MODE_eHRPD = 23,
	NETWORK_MODE_HYBRID_CDMA_eHRPD,
} gprs_network_mode_t;

//SIMCOM(SC) NON-SSL TCP GPRS APIs
int gprs_init(int do_power_cycle, int disable_quicksend, int no_internet);
int gprs_connect(const char* domain_name_or_ip, int port, int timeout_ms);
int gprs_send(int conn_id, const unsigned char* buf, int buf_len, int timeout_ms);
int gprs_recv(int conn_id, unsigned char* buf, int buf_len, int timeout_ms);
int gprs_recv_poll(int conn_id, int timeout_ms);
int gprs_close(int conn_id);
int gprs_get_my_ip(char *ipv4, int ipv4_buf_len, char* ipv6, int ipv6_buf_len);
int gprs_get_network_mode(gprs_network_mode_t* mode);
//int gprs_get_send_status(int conn_id, int *tx_len, int *ack_len, int *nack_len);
int gsm_get_signal_quality(int* rssi, int *ber);

int gprs_ntp_sync(const char* server, int tz_code);

// HTTP(S) APIs
int gprs_http_init(void);

/* 
File will be downloaded in = E:/filename
If expected_len > 0 then recevied file will be saved only if length matches.
*/
int gprs_http_download(const char* url, const char* filename, int expected_len, int timeout_ms);

// Usually there is no need to call this function. It is used internally by other APIs.
int gprs_http_readfile(const char* filename, int timeout_ms);
int gprs_http_stop(void);

//automatically adjusts timezone and returns utc time.
int gsm_get_time(unsigned long* utc_time);

typedef enum {
	SSL_AUTH_MODE_NONE = 0,
	SSL_AUTH_MODE_ONLY_SERVER,
	SSL_AUTH_MODE_SERVER_CLIENT,
	SSL_AUTH_MODE_ONLY_CLIENT
} ssl_auth_mode_t;

#define MAX_SSL_CERT_NAME_LENGTH 	128
#define MAX_SSL_SESSIONS 			2
#define MAX_SSL_CONTEXTS 			10

#define DEFAULT_SSL_CONTEXT_PARAMS { \
		.version = 4, \
		.auth_mode = SSL_AUTH_MODE_ONLY_SERVER, \
		.ignore_localtime = 1, \
		.negotiate_time = 120, \
		.cacert = "server-cert.pem", \
		.clientcert = NULL, \
		.clientkey = NULL, \
	}

//Only ASCII filenames are supported for certificates.
typedef struct {
	unsigned char version;
	ssl_auth_mode_t auth_mode;
	unsigned char ignore_localtime;
	unsigned short negotiate_time;
	const char* cacert;
	const char* clientcert;
	const char* clientkey;
} gprs_ssl_context_t;

//SIMCOM(SC) SSL TCP GPRS APIs

//Call gprs_init before ssl init.
int gprs_ssl_init(void);

//Choose ssl_ctx_id from [0-MAX_SSL_CONTEXTS]
int gprs_ssl_config_context(int ssl_ctx_id, const gprs_ssl_context_t* ssl_ctx);

//ssl_ctx_id is different than ssl_session_id.
int gprs_ssl_connect(int ssl_ctx_id, const char* domain_name_or_ip, int port, int timeout_ms);
int gprs_ssl_send(int ssl_session_id, const unsigned char* buf, int buf_len, int timeout_ms);
int gprs_ssl_recv_poll(int ssl_sessions[], int n_sessions, int timeout_ms);
int gprs_ssl_recv(int ssl_session_id, unsigned char* buf, int buf_len, int timeout_ms);
int gprs_ssl_close(int ssl_session_id);
int gprs_ssl_stop(void);
int gprs_ssl_cert_download(const char* ro_fs_path);
int gprs_ssl_cert_is_present(const char* ro_fs_path);
int gprs_ssl_cert_delete(const char* ro_fs_path);


//SIMCOM AT Commands that do not need SIM or Internet.
int simcom_fs_readfile(const char* path, int offset, unsigned char* buf, int buf_len);

#endif /* SIM7600_GPRS_H_ */
