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

#include "sim7600_gprs.h"
#include "sim7600_config.h"
#include "sim7600_parser.h"
#include "timer_interface.h"

#include "at_modem.h"
#include "rofs.h"
#include "uart_print.h"

#include <stdarg.h>
#include <stdlib.h>

//nRF52 UART DMA requires memory to be in RAM even for memory -> TXD transaction.
//All AT commands to be sent are copied to ram before sending.

#define MAX_IP_LINKS 10

static int bringup_internet(int disable_quicksend, int no_internet);
static int bringup_modem_comm(int do_soft_reset);
static int check_cpin(void);
static int check_creg(int do_gprs_reg);
static int cmd_simple(const char* cmd, int timeout_ms);
static int cmd_variadic(int timeout_ms, const char* cmd, ...);
static int get_links_state(unsigned int* state);
static int get_filename(const char* path, const char** name);

extern int caltime_to_unix_ts(char* cal_time, unsigned long* time);

#define MAX_ATTEMPTS 10

#define FLAGS_GOT_OK (1 << 0)
#define FLAGS_GOT_DATA (1 << 1)
#define FLAGS_RETRY_CMD (1 << 2)
#define FLAGS_DATA_ERR (1 << 3)
#define FLAGS_GOT_ERR (1 << 4)
#define FLAGS_GOT_IPCLOSE (1 << 5)

#define FLAGS_OK_DATA (FLAGS_GOT_OK | FLAGS_GOT_DATA)
#define FLAGS_OK_DATA_ERR (FLAGS_GOT_OK | FLAGS_DATA_ERR)
#define FLAGS_ERR_DATA_ERR (FLAGS_GOT_ERR | FLAGS_DATA_ERR)
#define FLAGS_OK_RETRY (FLAGS_GOT_OK | FLAGS_RETRY_CMD)

#define IS_CMD_COMPLETE(n) ((((n)&FLAGS_OK_DATA) == FLAGS_OK_DATA) ? 1 : 0)
#define CMD_RETRY_NEEDED(n) ((((n)&FLAGS_OK_RETRY) == FLAGS_OK_RETRY) ? 1 : 0)
#define CMD_COMPLETE_BUT_ERR(n) ((((n)&FLAGS_OK_DATA_ERR) == FLAGS_OK_DATA_ERR) ? 1 : 0)
#define CMD_DATA_RECVD(n) ((((n)&FLAGS_GOT_DATA) == FLAGS_GOT_DATA) ? 1 : 0)
#define CMD_ERRED_WITH_DATA(n) ((((n)&FLAGS_ERR_DATA_ERR) == FLAGS_ERR_DATA_ERR) ? 1 : 0)

#define SCRATCH_PAD_BUF 128
static char scratch_pad_buf[SCRATCH_PAD_BUF];
static int ssl_session_ids[MAX_SSL_SESSIONS];

int gprs_init(int do_power_cycle, int disable_quicksend, int no_internet)
{
    int ret;
    int do_soft_reset = 1;

    if (do_power_cycle) {
        // Power cycle module with Power key pin.
        //TODO

        //No need to do soft reset if power cycling the modem.
        do_soft_reset = 0;
    }

    ret = at_init();
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;

    dbg_printf(DEBUG_LEVEL_INFO, "Initializing modem.\r\n");

    ret = bringup_modem_comm(do_soft_reset);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;

    dbg_printf(DEBUG_LEVEL_INFO, "Modem uart comm working ok\r\n");

    // Connect to internet.
    ret = bringup_internet(disable_quicksend, no_internet);
    if (ret < 0)
        return GPRS_ERROR_NET_ERROR;

    dbg_printf(DEBUG_LEVEL_INFO, "Modem connected to internet.\r\n");

    return 0;
}

int gprs_recv_poll(int conn_id, int timeout_ms)
{
    int ret;
    Timer timer_cmd; // inner timer
    Timer timer_poll; // outer timer
    int flags = 0;
    int available_bytes = 0;

    if ((conn_id < 0) || (conn_id >= MAX_IP_LINKS))
        return GPRS_ERROR_INVALID_PARAMETERS;

    init_timer(&timer_poll);
    init_timer(&timer_cmd);

    countdown_ms(&timer_poll, timeout_ms);

    do {
        if (has_timer_expired(&timer_poll))
            return GPRS_ERROR_TIMEOUT;

        //Query pending rx bytes.
        snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CIPRXGET=4,%d\r",
            conn_id);
        ret = at_send_cmd(scratch_pad_buf);
        if (ret < 0)
            return GPRS_ERROR_MODEM_COMM_FAILED;

        countdown_ms(&timer_cmd, AT_RESP_SHORT_TIMEOUT_MS);
        flags = 0;

        do {
            ret = sim7600_parse_line(NULL);
            if (ret >= 0) {
                switch (at_response_fields[0].ival) {
                case AT_RESP_CIPRXGET:
                    if ((ret == 3) && (at_response_fields[1].ival == 4) && (at_response_fields[2].ival == conn_id)) // three fields and mode==4 and mine
                    {
                        available_bytes = at_response_fields[3].ival;
                        flags |= FLAGS_GOT_DATA;
                    } else if ((ret == 2) && (at_response_fields[1].ival == 1) && (at_response_fields[2].ival == conn_id)) // two fields and mode==1 and mine , event got reported.
                    {
                        flags |= FLAGS_RETRY_CMD;
                    }
                    break;
                case AT_RESP_OK:
                    flags |= FLAGS_GOT_OK;
                    break;
                case AT_RESP_IP_ERR:
                    flags |= FLAGS_DATA_ERR;
                    break;
                case AT_RESP_ERR:
                    flags |= FLAGS_GOT_ERR;
                    break;
                case AT_RESP_IPCLOSE:
                    if (at_response_fields[1].ival == conn_id) {
                        flags |= FLAGS_GOT_IPCLOSE;
                    }
                    break;
                }
            }

            if (IS_CMD_COMPLETE(flags)) {
                if (flags & FLAGS_GOT_IPCLOSE)
                    return GPRS_ERROR_CONNECTION_CLOSED;

                if (available_bytes > 0)
                    return available_bytes;

                if (CMD_RETRY_NEEDED(flags))
                    break; //data rx event received, retry poll to get its info.
            } else if (CMD_ERRED_WITH_DATA(flags)) {
                if (flags & FLAGS_GOT_IPCLOSE)
                    return GPRS_ERROR_CONNECTION_CLOSED;

                return GPRS_ERROR_CMD_ERROR;
            }

            if (has_timer_expired(&timer_cmd)) {
                if (flags & FLAGS_GOT_IPCLOSE)
                    return GPRS_ERROR_CONNECTION_CLOSED;

                if (CMD_RETRY_NEEDED(flags))
                    break;

                if (!IS_CMD_COMPLETE(flags))
                    return GPRS_ERROR_POLL_FAILED;
                else
                    break; //no data rx event received. retry poll.
            }

        } while (1);

    } while (1);

    return GPRS_ERROR_TIMEOUT;
}

int gprs_recv(int conn_id, unsigned char* buf, int buf_len, int timeout_ms)
{
    int ret;
    Timer timer;
    int flags = 0;
    int bytes_to_read = 0;
    int bytes_returned = 0;

    if ((conn_id < 0) || (conn_id >= MAX_IP_LINKS))
        return GPRS_ERROR_INVALID_PARAMETERS;

    dbg_printf(DEBUG_LEVEL_DEBUG, "Requested bytes to receive: %d\r\n", buf_len);

    ret = gprs_recv_poll(conn_id, timeout_ms);
    if (ret < 0)
        return ret;

    dbg_printf(DEBUG_LEVEL_DEBUG, "Available bytes to read: %d\r\n", ret);

    bytes_to_read = buf_len;
    if (ret < buf_len)
        bytes_to_read = ret;

    if (bytes_to_read > GPRS_TCP_RECV_CHUNK_SIZE)
        bytes_to_read = GPRS_TCP_RECV_CHUNK_SIZE;

    init_timer(&timer);
    countdown_ms(&timer, timeout_ms);

    //Read binary bytes.
    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CIPRXGET=2,%d,%d\r",
        conn_id,
        bytes_to_read);
    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;

    countdown_ms(&timer, AT_RESP_SHORT_TIMEOUT_MS);

    do {
        if (has_timer_expired(&timer)) {
            at_dump_buffer();
            return GPRS_ERROR_TIMEOUT;
        }

        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_CIPRXGET:
                if ((ret == 4) && (at_response_fields[1].ival == 2) && (at_response_fields[2].ival == conn_id)) // four fields and mode==2 and mine
                {
                    bytes_returned = at_response_fields[3].ival;
                    dbg_printf(DEBUG_LEVEL_DEBUG, "Actual bytes returned: %d\r\n", bytes_returned);

                    {
                        int bytes_read;
                        int pending_bytes;
                        // extract raw data directly from modem buffer.
                        // keep reading until bytes_returned is read,
                        // since mcu is faster than uart.
                        for (bytes_read = 0; bytes_read < bytes_returned; bytes_read += ret) {
                            pending_bytes = bytes_returned - bytes_read;
                            ret = at_get_raw_data(&buf[bytes_read], pending_bytes);

                            if (has_timer_expired(&timer)) // Should not timeout here but if it does, it means error.
                                return GPRS_ERROR_RECV_FAILED;
                        }
                        flags |= FLAGS_GOT_DATA;
                    }
                } else {
                    //else //more CIPRXGET can be received here.
                    //	flags |= FLAGS_DATA_ERR;
                    //these will get processed in next call.
                    //dbg_printf(DEBUG_LEVEL_DEBUG, "ret=%d, mode=%d, conn id=%d\r\n", ret, at_response_fields[1].ival, at_response_fields[2].ival);
                }
                break;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            case AT_RESP_IP_ERR:
                flags |= FLAGS_DATA_ERR;
                break;
            case AT_RESP_ERR:
                flags |= FLAGS_GOT_ERR;
                break;
            case AT_RESP_IPCLOSE:
                if (at_response_fields[1].ival == conn_id) {
                    flags |= FLAGS_GOT_IPCLOSE;
                }
                break;
            }
        }

        if (CMD_ERRED_WITH_DATA(flags)) {
            if (flags & FLAGS_GOT_IPCLOSE)
                return GPRS_ERROR_CONNECTION_CLOSED;

            return GPRS_ERROR_SEND_FAILED;
        }
        if (IS_CMD_COMPLETE(flags)) {
            if (flags & FLAGS_GOT_IPCLOSE)
                return GPRS_ERROR_CONNECTION_CLOSED;

            return bytes_returned;
        }

    } while (1);
}

int gprs_send(int conn_id, const unsigned char* buf, int buf_len, int timeout_ms)
{

    int ret;
    Timer timer;
    int flags = 0;
    int sent_bytes;
    int chunk_size = 0;
    int pending_bytes = 0;
    const char* prompt = ">";
    int actual_bytes_accepted = 0;

    if ((conn_id < 0) || (conn_id >= MAX_IP_LINKS))
        return GPRS_ERROR_INVALID_PARAMETERS;

    dbg_printf(DEBUG_LEVEL_DEBUG, "Requested bytes to send: %d\r\n", buf_len);

    init_timer(&timer);
    countdown_ms(&timer, timeout_ms);

    //Send fixed length raw data.
    //Send in chunks
    for (sent_bytes = 0; sent_bytes < buf_len; sent_bytes += chunk_size) {
        pending_bytes = buf_len - sent_bytes;

        if (pending_bytes >= GPRS_TCP_SEND_CHUNK_SIZE)
            chunk_size = GPRS_TCP_SEND_CHUNK_SIZE;
        else
            chunk_size = pending_bytes;

        snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CIPSEND=%d,%d\r",
            conn_id,
            chunk_size);
        ret = at_send_cmd(scratch_pad_buf);
        if (ret < 0)
            return GPRS_ERROR_MODEM_COMM_FAILED;

        flags = 0;

        do {
            if (has_timer_expired(&timer))
                return GPRS_ERROR_TIMEOUT;

            ret = sim7600_parse_line(prompt);
            if (ret >= 0) {
                switch (at_response_fields[0].ival) {
                case AT_RESP_LINE_VALUE:
                    if (at_response_fields[1].sval[0] == '>') {
                        ret = at_send_data(&buf[sent_bytes], chunk_size);
                        if (ret < 0)
                            return GPRS_ERROR_MODEM_COMM_FAILED;
                    }
                    break;
                case AT_RESP_CIPSEND:
                    if (at_response_fields[1].ival == conn_id) {
                        actual_bytes_accepted = at_response_fields[3].ival; //cnfSendLength
                        flags |= FLAGS_GOT_DATA;
                    }
                    break;
                case AT_RESP_OK:
                    flags |= FLAGS_GOT_OK;
                    break;
                case AT_RESP_CIP_ERR:
                    flags |= FLAGS_DATA_ERR;
                    break;
                case AT_RESP_ERR:
                    flags |= FLAGS_GOT_ERR;
                    break;
                }
            }

            if (CMD_ERRED_WITH_DATA(flags))
                return GPRS_ERROR_SEND_FAILED;
            else if (IS_CMD_COMPLETE(flags)) {
                break;
            }

        } while (1);

        if (actual_bytes_accepted < chunk_size) {
            //modem tx buffer full. abort.
            sent_bytes += actual_bytes_accepted;
            break;
        }
    }

    return sent_bytes;
}

static int get_links_state(unsigned int* state)
{
    int ret;
    Timer timer;
    int flags = 0;

    init_timer(&timer);

    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CIPCLOSE?\r");
    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;

    countdown_ms(&timer, AT_RESP_SHORT_TIMEOUT_MS);

    do {
        if (has_timer_expired(&timer))
            return GPRS_ERROR_TIMEOUT;

        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_CIPCLOSE:
                if (ret != MAX_IP_LINKS)
                    flags |= FLAGS_DATA_ERR;
                else {
                    int i;
                    *state = 0;
                    for (i = 0; i < MAX_IP_LINKS; i++) {
                        *state |= (at_response_fields[1 + i].ival & 1) ? 1 << i : 0;
                    }
                    flags |= FLAGS_GOT_DATA;
                }
                break;
            case AT_RESP_ERR:
                return GPRS_ERROR_CMD_ERROR;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            }
        }

        if (IS_CMD_COMPLETE(flags)) {
            return GPRS_OK;
        }

    } while (1);
}

int gprs_close(int conn_id)
{
    int ret;
    Timer timer;
    int flags = 0;
    int err_code = GPRS_ERROR_TCPIP_BASE;

    if ((conn_id < 0) || (conn_id >= MAX_IP_LINKS))
        return GPRS_ERROR_INVALID_PARAMETERS;

    init_timer(&timer);

    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CIPCLOSE=%d\r",
        conn_id);
    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;

    countdown_ms(&timer, AT_RESP_SHORT_TIMEOUT_MS);

    do {
        if (has_timer_expired(&timer))
            return GPRS_ERROR_TIMEOUT;

        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_CIPCLOSE:
                if (at_response_fields[1].ival == conn_id) //link number
                {
                    if (at_response_fields[2].ival == 0) //err number
                        flags |= FLAGS_GOT_DATA;
                    else {
                        flags |= FLAGS_DATA_ERR;
                        err_code += at_response_fields[2].ival;
                        dbg_printf(DEBUG_LEVEL_DEBUG, "Err-code: %d\r\n", err_code);
                    }
                } else {
                    //handle this case differently - TODO.
                    flags |= FLAGS_DATA_ERR;
                }
                break;
            case AT_RESP_ERR:
                flags |= FLAGS_GOT_ERR;
                break;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            }
        }

        if (CMD_ERRED_WITH_DATA(flags))
            return err_code;
        else if (IS_CMD_COMPLETE(flags)) {
            return GPRS_OK;
        }

    } while (1);
}

int gprs_http_init(void)
{
    return cmd_simple("AT+HTTPINIT\r", AT_RESP_LONG_TIMEOUT_MS);
}

int gprs_http_download(const char* url, const char* filename, int expected_len, int timeout_ms)
{
    int ret;
    Timer timer;
    int flags = 0;
    int err_code = 0;

    if (url == NULL)
        return GPRS_ERROR_INVALID_PARAMETERS;

    if (filename == NULL)
        return GPRS_ERROR_INVALID_PARAMETERS;

    ret = cmd_variadic(AT_RESP_SHORT_TIMEOUT_MS, "AT+HTTPPARA=\"URL\",\"%s\"\r", url);
    if (ret < 0)
        return ret;

    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+HTTPACTION=0\r");
    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;

    init_timer(&timer);
    countdown_ms(&timer, timeout_ms);

    do {
        if (has_timer_expired(&timer)) {
            return GPRS_ERROR_TIMEOUT;
        }

        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_HTTPACTION:
                if (at_response_fields[1].ival == 0) //GET Method
                {
                    if (at_response_fields[2].ival == 200) // HTTP 200 OK
                    {
                        if ((expected_len > 0) && (expected_len != at_response_fields[3].ival)) {
                            err_code = GPRS_ERROR_HTTP_DOWNLOAD_LEN_MISMATCH;
                            flags |= FLAGS_DATA_ERR;
                        } else {
                            flags |= FLAGS_GOT_DATA;
                        }
                    } else {
                        flags |= FLAGS_DATA_ERR;
                        dbg_printf(DEBUG_LEVEL_DEBUG, "Err-code: %d\r\n", at_response_fields[2].ival);
                        dbg_printf(DEBUG_LEVEL_DEBUG, "Data Length: %d\r\n", at_response_fields[3].ival);
                    }
                } else {
                    //handle this case differently - TODO.
                    flags |= FLAGS_DATA_ERR;
                }
                break;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            case AT_RESP_ERR:
                return GPRS_ERROR_HTTP_DOWNLOAD_FAILED;
            }
        }

        if (CMD_COMPLETE_BUT_ERR(flags)) {
            if (err_code)
                return err_code;
            return GPRS_ERROR_HTTP_DOWNLOAD_FAILED;
        } else if (IS_CMD_COMPLETE(flags)) {
            break;
        }
    } while (1);

    return gprs_http_readfile(filename, timeout_ms);
}

int gprs_http_stop(void)
{
    return cmd_simple("AT+HTTPTERM\r", AT_RESP_SHORT_TIMEOUT_MS);
}

int gprs_http_readfile(const char* filename, int timeout_ms)
{
    int ret;
    Timer timer;
    int flags = 0;
    int err_code = 0;

    // store in E:/ drive.
    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+HTTPREADFILE=\"%s\",3\r", filename);
    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;

    init_timer(&timer);
    countdown_ms(&timer, timeout_ms);

    do {
        if (has_timer_expired(&timer)) {
            return GPRS_ERROR_TIMEOUT;
        }

        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_HTTPREADFILE:
                err_code = at_response_fields[1].ival;
                if (err_code == 0) //result code
                {
                    flags |= FLAGS_GOT_DATA;
                } else {
                    flags |= FLAGS_DATA_ERR;
                }
                break;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            case AT_RESP_ERR:
                return GPRS_ERROR_HTTP_READFILE_FAILED;
            }
        }

        if (CMD_COMPLETE_BUT_ERR(flags)) {
            if (err_code)
                return GPRS_ERROR_HTTP_BASE + err_code;
            return GPRS_ERROR_HTTP_READFILE_FAILED;
        } else if (IS_CMD_COMPLETE(flags)) {
            return GPRS_OK;
        }
    } while (1);
}

int gprs_connect(const char* domain_name_or_ip, int port, int timeout_ms)
{
    int ret;
    Timer timer;
    int flags = 0;
    int conn_id;
    unsigned int links_state = 0;
    int err_code = GPRS_ERROR_TCPIP_BASE;

    ret = get_links_state(&links_state);
    if (ret < 0)
        return ret;

    for (conn_id = 0; links_state & (1 << conn_id); conn_id++) {
    }

    if (conn_id >= MAX_IP_LINKS)
        return GPRS_ERROR_ALL_IP_LINKS_BUSY;

    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CIPOPEN=%d,\"TCP\",\"%s\",%d\r",
        conn_id,
        domain_name_or_ip,
        port);

    init_timer(&timer);

    dbg_printf(DEBUG_LEVEL_DEBUG, "Connecting to: %d) %s\r\n", conn_id, scratch_pad_buf);

    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;

    countdown_ms(&timer, timeout_ms);

    do {
        if (has_timer_expired(&timer)) {
            dbg_printf(DEBUG_LEVEL_DEBUG, "gprs_connect flags: %d\r\n", flags);
            return GPRS_ERROR_TIMEOUT;
        }
        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_CIPOPEN:
                if (at_response_fields[1].ival == conn_id) //link number
                {
                    if (at_response_fields[2].ival == 0) // no error
                    {
                        flags |= FLAGS_GOT_DATA;
                    } else {
                        flags |= FLAGS_DATA_ERR;
                        err_code += at_response_fields[2].ival;
                        dbg_printf(DEBUG_LEVEL_DEBUG, "Err-code: %d\r\n", err_code);
                    }
                } else {
                    //handle this case differently - TODO.
                    flags |= FLAGS_DATA_ERR;
                }
                break;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            case AT_RESP_ERR:
                flags |= FLAGS_GOT_ERR;
                break;
            }
        }

        if (CMD_ERRED_WITH_DATA(flags))
            return err_code;
        else if (IS_CMD_COMPLETE(flags)) {
            break;
        }

    } while (1);

    return conn_id;
}

int gprs_get_network_mode(gprs_network_mode_t* mode)
{
    Timer timer;
    int ret;
    int flags = 0;

    init_timer(&timer);

    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF, "AT+CNSMOD?\r");
    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;

    countdown_ms(&timer, AT_RESP_SHORT_TIMEOUT_MS);

    do {
        if (has_timer_expired(&timer))
            return GPRS_ERROR_TIMEOUT;

        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_CNSMOD:
                *mode = at_response_fields[2].ival;
                flags |= FLAGS_GOT_DATA;
                break;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            case AT_RESP_ERR:
                return GPRS_ERROR_CMD_ERROR;
            }
        }

        if (IS_CMD_COMPLETE(flags))
            return GPRS_OK;

    } while (1);
}

//CGPADDR returns multiple context addresses but only the first one is stored
//and total count is returned.
int gprs_get_my_ip(char* ipv4, int ipv4_buf_len, char* ipv6, int ipv6_buf_len)
{
    Timer timer;
    int ret;
    int flags = 0;
    int n_pdp_contexts;
    init_timer(&timer);

    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CGPADDR\r");
    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;

    countdown_ms(&timer, AT_RESP_SHORT_TIMEOUT_MS);
    n_pdp_contexts = 0;
    do {
        if (has_timer_expired(&timer))
            return GPRS_ERROR_TIMEOUT;

        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_CGPADDR:
                if (n_pdp_contexts == 0) {
                    if ((ret > 1) && (ipv4 != NULL))
                        strncpy(ipv4, at_response_fields[2].sval, ipv4_buf_len);
                    if ((ret > 2) && (ipv6 != NULL))
                        strncpy(ipv6, at_response_fields[3].sval, ipv6_buf_len);

                    flags |= FLAGS_GOT_DATA;
                }
                n_pdp_contexts++;
                break;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            case AT_RESP_ERR:
                return GPRS_ERROR_CMD_ERROR;
            }
        }

        if (IS_CMD_COMPLETE(flags)) {
            break;
        }

    } while (1);

    return n_pdp_contexts;
}

static int bringup_modem_comm(int do_soft_reset)
{
    int ret;
    int attempts;
    int reset_done = 0;
    Timer timer;

    init_timer(&timer);

    for (attempts = 0; attempts < MAX_ATTEMPTS; attempts++) {
        dbg_printf(DEBUG_LEVEL_INFO, "Modem comm attempt: %d\r\n", attempts);
        // Check whether UART is working ok.
        ret = cmd_simple("AT\r", AT_RESP_SHORT_TIMEOUT_MS);
        if (ret < 0)
            continue;

        if (do_soft_reset && (!reset_done)) {
            //dbg_printf(DEBUG_LEVEL_DEBUG, "Soft powering off module\r\n");
            //
            //Module BK-SIM7600E-H auto powers-up after successful
            //shutdown command.
            //ret = cmd_simple("AT+CPOF\r", AT_RESP_SHORT_TIMEOUT_MS);

            dbg_printf(DEBUG_LEVEL_DEBUG, "Soft resetting module\r\n");
            //Module Reset - how effective is this, no documentation.
            ret = cmd_simple("AT+CRESET\r", AT_RESP_SHORT_TIMEOUT_MS);
            if (ret < 0)
                continue;

            reset_done = 1;
            attempts = 0;

            countdown_sec(&timer, GPRS_WAIT_AFTER_MODULE_RESET_SECONDS);
            while (!has_timer_expired(&timer))
                ;

            continue;
        }

        //Disable uart echo.
        ret = cmd_simple("ATE0\r", AT_RESP_SHORT_TIMEOUT_MS);
        if (ret < 0)
            continue;

        return GPRS_OK;
    }

    return GPRS_ERROR_MODEM_COMM_FAILED;
}

static int check_cpin(void)
{
    Timer timer;
    int ret;
    int flags = 0;

    init_timer(&timer);

    //Check PIN ready
    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CPIN?\r");
    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;
    countdown_ms(&timer, AT_RESP_SHORT_TIMEOUT_MS);

    do {
        if (has_timer_expired(&timer))
            return GPRS_ERROR_TIMEOUT;

        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_CPIN:
                if (strcmp(at_response_fields[1].sval, "READY") == 0)
                    flags |= FLAGS_GOT_DATA;
                else
                    flags |= FLAGS_DATA_ERR;
                break;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            case AT_RESP_ERR:
                return GPRS_ERROR_CMD_ERROR;
            }
        }

        if (CMD_COMPLETE_BUT_ERR(flags))
            return GPRS_ERROR_PIN_NOT_READY;
        else if (IS_CMD_COMPLETE(flags))
            return GPRS_OK;

    } while (1);
}

static int netopen(void)
{
    Timer timer;
    int ret;
    int flags;

    init_timer(&timer);

    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+NETOPEN\r");
    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;
    countdown_ms(&timer, AT_RESP_LONG_TIMEOUT_MS);
    flags = 0;

    do {
        if (has_timer_expired(&timer))
            return GPRS_ERROR_TIMEOUT;

        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_NETOPEN:
                if (at_response_fields[1].ival == 0) // err field
                {
                    flags |= FLAGS_GOT_DATA;
                } else {
                    flags |= FLAGS_DATA_ERR;
                    dbg_printf(DEBUG_LEVEL_DEBUG, "Err-code: %d\r\n", at_response_fields[1].ival);
                }
                break;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            case AT_RESP_IP_ERR:
                if (strstr(at_response_fields[1].sval, "already opened") != NULL) {
                    flags |= FLAGS_GOT_DATA;
                }
                break;
            case AT_RESP_ERR:
                if (CMD_DATA_RECVD(flags)) {
                    flags |= FLAGS_GOT_OK;
                } else
                    return GPRS_ERROR_CMD_ERROR;
                break;
            }
        }

        if (CMD_COMPLETE_BUT_ERR(flags))
            return GPRS_ERROR_NET_ERROR;
        else if (IS_CMD_COMPLETE(flags))
            return GPRS_OK;
    } while (1);
}

static int check_creg(int do_gprs_reg)
{
    Timer timer;
    int ret;
    int flags;

    init_timer(&timer);

    countdown_ms(&timer, AT_RESP_SHORT_TIMEOUT_MS);

    do {
        flags = 0;
        if (do_gprs_reg)
            snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CGREG?\r");
        else
            snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CREG?\r");
        ret = at_send_cmd(scratch_pad_buf);
        if (ret < 0)
            return GPRS_ERROR_MODEM_COMM_FAILED;

        do {
            if (has_timer_expired(&timer))
                return GPRS_ERROR_TIMEOUT;

            ret = sim7600_parse_line(NULL);
            if (ret >= 0) {
                switch (at_response_fields[0].ival) {
                case AT_RESP_CREG:
                case AT_RESP_CGREG:
                    switch (at_response_fields[2].ival) // stat field
                    {
                    case 1: //registered
                    case 5: // registered but roaming
                        flags |= FLAGS_GOT_DATA;
                        break;
                    case 2: //searching , try again
                        flags |= FLAGS_RETRY_CMD;
                        break;
                    default:
                        flags |= FLAGS_DATA_ERR;
                        break;
                    }
                    break;
                case AT_RESP_OK:
                    flags |= FLAGS_GOT_OK;
                    break;
                case AT_RESP_ERR:
                    return GPRS_ERROR_CMD_ERROR;
                }
            }

            if (CMD_RETRY_NEEDED(flags))
                break;
            if (CMD_COMPLETE_BUT_ERR(flags))
                return GPRS_ERROR_NET_REG_FAILED;
            else if (IS_CMD_COMPLETE(flags))
                return GPRS_OK;
        } while (1);
    } while (1);
}

static int cmd_simple(const char* cmd, int timeout_ms)
{
    Timer timer;
    int ret;

    init_timer(&timer);

    //cmd string will be in flash read only section, it needs to be in RAM for DMA tx.
    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, cmd);
    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;
    countdown_ms(&timer, timeout_ms);

    do {
        if (has_timer_expired(&timer))
            return GPRS_ERROR_TIMEOUT;

        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_OK:
                return GPRS_OK;
            case AT_RESP_ERR:
                return GPRS_ERROR_CMD_ERROR;
            }
        }
    } while (1);
}

static int cmd_variadic(int timeout_ms, const char* cmd, ...)
{
    Timer timer;
    int ret;
    va_list ap;

    va_start(ap, cmd);
    ret = vsnprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, cmd, ap);
    va_end(ap);

    if (ret >= SCRATCH_PAD_BUF - 1)
        return GPRS_ERROR_COMMAND_TOO_LONG;

    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;

    init_timer(&timer);
    countdown_ms(&timer, timeout_ms);

    do {
        if (has_timer_expired(&timer))
            return GPRS_ERROR_TIMEOUT;

        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_OK:
                return GPRS_OK;
            case AT_RESP_ERR:
                return GPRS_ERROR_CMD_ERROR;
            }
        }
    } while (1);
}

static int bringup_internet(int disable_quicksend, int no_internet)
{
    int ret = -1;
    int rssi = 0;
    int ber = 0;
    int attempts;
    Timer timer;
    int state = 0;

    init_timer(&timer);
    countdown_sec(&timer, GPRS_NETWORK_REG_TIMEOUT_SECONDS);

    for (attempts = 0; !has_timer_expired(&timer); attempts++) {
        dbg_printf(DEBUG_LEVEL_DEBUG, "bringup_internet, attempt=%d, state=%d, ret=%d\r\n", attempts, state, ret);

        switch (state) {
        case 0:
            ret = check_cpin();
            if (ret < 0)
                break;

            state++;
            dbg_printf(DEBUG_LEVEL_INFO, "SIM PIN Ready\r\n");
            if (no_internet) {
                return GPRS_OK;
            }
        case 1:
            ret = check_creg(0);
            if (ret < 0)
                break;
            state++;
            dbg_printf(DEBUG_LEVEL_INFO, "Network Registered.\r\n");
        case 2:
            ret = check_creg(1);
            if (ret < 0)
                break;
            dbg_printf(DEBUG_LEVEL_INFO, "GPRS Network Registered.\r\n");
            break;
        }

        if (ret >= 0)
            break;
    }

    if (ret < 0)
        return ret;

    //Report Signal quality
    ret = gsm_get_signal_quality(&rssi, &ber);
    if (ret < 0)
        return ret;

    dbg_printf(DEBUG_LEVEL_INFO, "GSM Signal quality: RSSI=%d, BER=%d\r\n", rssi, ber);

    //Set IP RX in manual buffered mode.
    ret = cmd_simple("AT+CIPRXGET=1\r", AT_RESP_SHORT_TIMEOUT_MS);
    if (ret < 0)
        return ret;

    if (disable_quicksend) {
        dbg_printf(DEBUG_LEVEL_INFO, "Disabling Quick Send feature\r\n");
        ret = cmd_simple("AT+CIPSENDMODE=1\r", AT_RESP_SHORT_TIMEOUT_MS);
    } else {
        ret = cmd_simple("AT+CIPSENDMODE=0\r", AT_RESP_SHORT_TIMEOUT_MS);
    }
    if (ret < 0)
        return ret;

    //Set TCP/IP in non-transparent mode.
    ret = cmd_simple("AT+CIPMODE=0\r", AT_RESP_SHORT_TIMEOUT_MS);
    if (ret < 0)
        return ret;

    //Enable automatic time and time zone update with NITZ if supported by network.
    ret = cmd_simple("AT+CTZU=1\r", AT_RESP_SHORT_TIMEOUT_MS);
    if (ret < 0)
        return ret;

    //By default module will automatically define PDP context based on SIM/Network.
    //Define Custom PDP context - TODO
    ret = netopen();
    if (ret < 0)
        return ret;

    //do NTP time sync - TODO

    return GPRS_OK;
}

int gsm_get_signal_quality(int* rssi, int* ber)
{
    Timer timer;
    int ret;
    int flags;

    init_timer(&timer);

    //Get Network signal strength.
    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CSQ\r");
    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;
    countdown_ms(&timer, AT_RESP_SHORT_TIMEOUT_MS);
    flags = 0;

    do {
        if (has_timer_expired(&timer))
            return GPRS_ERROR_TIMEOUT;

        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_CSQ:
                if (ret == 2) {
                    *rssi = at_response_fields[1].ival;
                    *ber = at_response_fields[2].ival;
                    flags |= FLAGS_GOT_DATA;
                }
                break;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            case AT_RESP_ERR:
                return GPRS_ERROR_CMD_ERROR;
            }
        }

        if (IS_CMD_COMPLETE(flags))
            return GPRS_OK;
    } while (1);
}

static int sslstart(void)
{
    Timer timer;
    int ret;
    int flags;

    init_timer(&timer);

    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CCHSTART\r");
    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;

    countdown_ms(&timer, AT_RESP_LONG_TIMEOUT_MS);
    flags = 0;

    do {
        if (has_timer_expired(&timer))
            return GPRS_ERROR_TIMEOUT;

        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_CCHSTART:
                if (at_response_fields[1].ival == 0) // err field
                {
                    flags |= FLAGS_GOT_DATA;
                } else {
                    flags |= FLAGS_DATA_ERR;
                    dbg_printf(DEBUG_LEVEL_DEBUG, "Err-code: %d\r\n", at_response_fields[1].ival);
                }
                break;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            case AT_RESP_ERR:
                flags |= FLAGS_GOT_ERR;
                break;
            }
        }

        if (CMD_ERRED_WITH_DATA(flags))
            return GPRS_ERROR_NET_ERROR;
        else if (IS_CMD_COMPLETE(flags))
            return GPRS_OK;
    } while (1);
}

int gprs_ssl_init(void)
{
    int ret;

    //Quick send, manual receive.
    ret = cmd_simple("AT+CCHSET=0,1\r", AT_RESP_SHORT_TIMEOUT_MS);
    if (ret < 0)
        return ret;

    //Non-transparent mode.
    ret = cmd_simple("AT+CCHMODE=0\r", AT_RESP_SHORT_TIMEOUT_MS);
    if (ret < 0)
        return ret;

    ret = sslstart();
    if (ret < 0)
        return ret;

    return GPRS_OK;
}

int gprs_ssl_config_context(int ssl_ctx_id, const gprs_ssl_context_t* ssl_ctx)
{
    int ret;

    if ((ssl_ctx_id < 0) || (ssl_ctx_id >= MAX_SSL_CONTEXTS))
        return GPRS_ERROR_INVALID_PARAMETERS;

    ret = cmd_variadic(AT_RESP_SHORT_TIMEOUT_MS,
        "AT+CSSLCFG=\"sslversion\",%d,%d\r",
        ssl_ctx_id, ssl_ctx->version);
    if (ret < 0)
        return ret;

    ret = cmd_variadic(AT_RESP_SHORT_TIMEOUT_MS,
        "AT+CSSLCFG=\"authmode\",%d,%d\r",
        ssl_ctx_id, ssl_ctx->auth_mode);
    if (ret < 0)
        return ret;

    ret = cmd_variadic(AT_RESP_SHORT_TIMEOUT_MS,
        "AT+CSSLCFG=\"ignorelocaltime\",%d,%d\r",
        ssl_ctx_id, ssl_ctx->ignore_localtime);
    if (ret < 0)
        return ret;

    ret = cmd_variadic(AT_RESP_SHORT_TIMEOUT_MS,
        "AT+CSSLCFG=\"negotiatetime\",%d,%d\r",
        ssl_ctx_id, ssl_ctx->negotiate_time);
    if (ret < 0)
        return ret;

    if (ssl_ctx->cacert) {
        const char* name;

        ret = gprs_ssl_cert_is_present(ssl_ctx->cacert);
        if (ret < 0)
            return ret;

        if (!ret) {
            ret = gprs_ssl_cert_download(ssl_ctx->cacert);
            if (ret < 0)
                return ret;
        }

        ret = get_filename(ssl_ctx->cacert, &name);
        if (ret < 0)
            return ret;

        ret = cmd_variadic(AT_RESP_SHORT_TIMEOUT_MS,
            "AT+CSSLCFG=\"cacert\",%d,\"%s\"\r",
            ssl_ctx_id, name);
        if (ret < 0)
            return ret;
    }

    if (ssl_ctx->clientcert) {
        const char* name;

        ret = gprs_ssl_cert_is_present(ssl_ctx->clientcert);
        if (ret < 0)
            return ret;

        if (!ret) {
            ret = gprs_ssl_cert_download(ssl_ctx->clientcert);
            if (ret < 0)
                return ret;
        }

        ret = get_filename(ssl_ctx->clientcert, &name);
        if (ret < 0)
            return ret;

        ret = cmd_variadic(AT_RESP_SHORT_TIMEOUT_MS,
            "AT+CSSLCFG=\"clientcert\",%d,\"%s\"\r",
            ssl_ctx_id, name);
        if (ret < 0)
            return ret;
    }

    if (ssl_ctx->clientkey) {
        const char* name;

        ret = gprs_ssl_cert_is_present(ssl_ctx->clientkey);
        if (ret < 0)
            return ret;

        if (!ret) {
            ret = gprs_ssl_cert_download(ssl_ctx->clientkey);
            if (ret < 0)
                return ret;
        }

        ret = get_filename(ssl_ctx->clientkey, &name);
        if (ret < 0)
            return ret;

        ret = cmd_variadic(AT_RESP_SHORT_TIMEOUT_MS,
            "AT+CSSLCFG=\"clientkey\",%d,\"%s\"\r",
            ssl_ctx_id, name);
        if (ret < 0)
            return ret;
    }

    return GPRS_OK;
}

int gprs_ssl_connect(int ssl_ctx_id, const char* domain_name_or_ip, int port, int timeout_ms)
{
    int session_id;
    Timer timer;
    int ret;
    int flags;
    int err_code = GPRS_ERROR_SSL_BASE;

    if ((ssl_ctx_id < 0) || (ssl_ctx_id >= MAX_SSL_CONTEXTS))
        return GPRS_ERROR_INVALID_PARAMETERS;

    //for (session_id = 0; session_id < MAX_SSL_SESSIONS; session_id++)
    for (session_id = MAX_SSL_SESSIONS - 1; session_id >= 0; session_id--) {
        if (ssl_session_ids[session_id] == 0)
            break;
    }

    if (session_id >= MAX_SSL_SESSIONS)
        return GPRS_ERROR_ALL_IP_LINKS_BUSY;

    ret = cmd_variadic(AT_RESP_SHORT_TIMEOUT_MS, "AT+CCHSSLCFG=%d,%d\r",
        session_id, ssl_ctx_id);
    if (ret < 0)
        return ret;

    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CCHOPEN=%d,\"%s\",%d,2\r",
        session_id, domain_name_or_ip, port);
    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;

    init_timer(&timer);

    countdown_ms(&timer, timeout_ms);
    flags = 0;

    do {
        if (has_timer_expired(&timer)) {
            dbg_printf(DEBUG_LEVEL_DEBUG, "gprs_ssl_connect flags: %d\r\n", flags);
            return GPRS_ERROR_TIMEOUT;
        }
        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_CCHOPEN:
                if (at_response_fields[1].ival == session_id) //session number
                {
                    if (at_response_fields[2].ival == 0) // no error
                    {
                        flags |= FLAGS_GOT_DATA;
                    } else {
                        flags |= FLAGS_DATA_ERR;
                        err_code += at_response_fields[2].ival;
                        dbg_printf(DEBUG_LEVEL_DEBUG, "Err-code: %d\r\n", err_code);
                    }
                } else {
                    //handle this case differently - TODO.
                    flags |= FLAGS_DATA_ERR;
                }
                break;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            case AT_RESP_ERR:
                flags |= FLAGS_GOT_ERR;
                break;
            }
        }

        if (CMD_ERRED_WITH_DATA(flags))
            return err_code;
        else if (CMD_COMPLETE_BUT_ERR(flags))
            return err_code;
        else if (IS_CMD_COMPLETE(flags)) {
            break;
        }

    } while (1);

    ssl_session_ids[session_id] = 1;
    return session_id;
}

int gprs_ssl_stop(void)
{
    Timer timer;
    int ret;
    int flags;
    int err_code = GPRS_ERROR_SSL_BASE;

    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CCHSTOP\r");
    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;

    init_timer(&timer);

    countdown_ms(&timer, AT_RESP_LONG_TIMEOUT_MS);
    flags = 0;

    do {
        if (has_timer_expired(&timer)) {
            return GPRS_ERROR_TIMEOUT;
        }
        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_CCHSTOP:
                if (at_response_fields[1].ival == 0) //error code
                {
                    flags |= FLAGS_GOT_DATA;
                } else {
                    flags |= FLAGS_DATA_ERR;
                    err_code += at_response_fields[1].ival;
                    dbg_printf(DEBUG_LEVEL_DEBUG, "Err-code: %d\r\n", err_code);
                }
                break;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            case AT_RESP_ERR:
                return GPRS_ERROR_SSL_SERVICE_STOP_FAILED;
            }
        }

        if (CMD_COMPLETE_BUT_ERR(flags)) {
            return err_code;
        } else if (IS_CMD_COMPLETE(flags)) {
            break;
        }

    } while (1);

    memset(ssl_session_ids, 0, sizeof(ssl_session_ids));

    return GPRS_OK;
}

int gprs_ssl_close(int session_id)
{
    Timer timer;
    int ret;
    int flags;
    int err_code = GPRS_ERROR_SSL_BASE;

    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CCHCLOSE=%d\r",
        session_id);
    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;

    init_timer(&timer);

    countdown_ms(&timer, AT_RESP_LONG_TIMEOUT_MS);
    flags = 0;

    ssl_session_ids[session_id] = 0;

    do {
        if (has_timer_expired(&timer)) {
            dbg_printf(DEBUG_LEVEL_DEBUG, "gprs_ssl_close flags: %d\r\n", flags);
            return GPRS_ERROR_TIMEOUT;
        }
        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_CCHCLOSE:
                if (at_response_fields[1].ival == session_id) //session number
                {
                    if (at_response_fields[2].ival == 0) // no error
                    {
                        flags |= FLAGS_GOT_DATA;
                    } else {
                        flags |= FLAGS_DATA_ERR;
                        err_code += at_response_fields[2].ival;
                        dbg_printf(DEBUG_LEVEL_DEBUG, "Err-code: %d\r\n", err_code);
                    }
                } else {
                    //handle this case differently - TODO.
                    flags |= FLAGS_DATA_ERR;
                }
                break;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            case AT_RESP_ERR:
                flags |= FLAGS_GOT_ERR;
                break;
            }
        }

        if (CMD_ERRED_WITH_DATA(flags))
            return err_code;
        else if (CMD_COMPLETE_BUT_ERR(flags))
            return GPRS_ERROR_CLOSE_FAILED;
        else if (IS_CMD_COMPLETE(flags)) {
            break;
        }

    } while (1);

    return GPRS_OK;
}

int gprs_ssl_send(int session_id, const unsigned char* buf, int buf_len, int timeout_ms)
{
    int ret;
    Timer timer;
    int flags = 0;
    int sent_bytes;
    int chunk_size = 0;
    int pending_bytes = 0;
    const char* prompt = ">";

    if ((session_id < 0) || (session_id >= MAX_SSL_SESSIONS))
        return GPRS_ERROR_INVALID_PARAMETERS;

    dbg_printf(DEBUG_LEVEL_DEBUG, "Requested bytes to send: %d\r\n", buf_len);

    init_timer(&timer);
    countdown_ms(&timer, timeout_ms);

    //Send fixed length raw data.
    //Send in chunks
    for (sent_bytes = 0; sent_bytes < buf_len; sent_bytes += chunk_size) {
        pending_bytes = buf_len - sent_bytes;

        if (pending_bytes >= GPRS_TCP_SEND_CHUNK_SIZE)
            chunk_size = GPRS_TCP_SEND_CHUNK_SIZE;
        else
            chunk_size = pending_bytes;

        snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CCHSEND=%d,%d\r",
            session_id,
            chunk_size);

        ret = at_send_cmd(scratch_pad_buf);
        if (ret < 0)
            return GPRS_ERROR_MODEM_COMM_FAILED;

        flags = 0;

        do {
            if (has_timer_expired(&timer))
                return GPRS_ERROR_TIMEOUT;

            ret = sim7600_parse_line(prompt);
            if (ret >= 0) {
                switch (at_response_fields[0].ival) {
                case AT_RESP_LINE_VALUE:
                    if (at_response_fields[1].sval[0] == '>') {
                        ret = at_send_data(&buf[sent_bytes], chunk_size);
                        if (ret < 0)
                            return GPRS_ERROR_MODEM_COMM_FAILED;
                        flags |= FLAGS_GOT_DATA;
                    }
                    break;
                case AT_RESP_OK:
                    flags |= FLAGS_GOT_OK;
                    break;
                case AT_RESP_ERR:
                    return GPRS_ERROR_SEND_FAILED;
                }
            }

            if (IS_CMD_COMPLETE(flags)) {
                break;
            }

        } while (1);
    }

    return sent_bytes;
}

int gprs_ssl_recv_poll(int ssl_sessions[], int n_sessions, int timeout_ms)
{
    int ret;
    Timer timer_cmd; // inner timer
    Timer timer_poll; // outer timer
    int flags = 0;
    int available_bytes = 0;

    if (n_sessions < MAX_SSL_SESSIONS)
        return GPRS_ERROR_INVALID_PARAMETERS;

    init_timer(&timer_poll);
    init_timer(&timer_cmd);

    countdown_ms(&timer_poll, timeout_ms);

    do {
        if (has_timer_expired(&timer_poll))
            return GPRS_ERROR_TIMEOUT;

        //Query pending rx bytes.
        snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CCHRECV?\r");
        ret = at_send_cmd(scratch_pad_buf);
        if (ret < 0)
            return GPRS_ERROR_MODEM_COMM_FAILED;

        countdown_ms(&timer_cmd, AT_RESP_SHORT_TIMEOUT_MS);
        flags = 0;

        do {
            ret = sim7600_parse_line(NULL);
            if (ret >= 0) {
                switch (at_response_fields[0].ival) {
                case AT_RESP_CCHRECV:
                    if (ret == 3) {
                        if (strcmp(at_response_fields[1].sval, "LEN") == 0) {
                            int i;
                            for (i = 0; i < (ret - 1); i++) {
                                ssl_sessions[i] = at_response_fields[2 + i].ival;
                                if (ssl_sessions[i] > 0)
                                    available_bytes = ssl_sessions[i];
                            }
                            flags |= FLAGS_GOT_DATA;
                            break;
                        }
                    }
                    flags |= FLAGS_DATA_ERR;
                    break;
                case AT_RESP_CCHEVENT:
                    flags |= FLAGS_RETRY_CMD;
                    break;
                case AT_RESP_OK:
                    flags |= FLAGS_GOT_OK;
                    break;
                case AT_RESP_ERR:
                    return GPRS_ERROR_POLL_FAILED;
                }
            }

            if (IS_CMD_COMPLETE(flags)) {
                if (available_bytes > 0)
                    return GPRS_OK;

                if (CMD_RETRY_NEEDED(flags))
                    break; //data rx event received, retry poll to get its info.
            }

            if (has_timer_expired(&timer_cmd)) {
                if (CMD_RETRY_NEEDED(flags))
                    break;

                if (!IS_CMD_COMPLETE(flags))
                    return GPRS_ERROR_POLL_FAILED;
                else
                    break; //no data rx event received. retry poll.
            }

        } while (1);

    } while (1);
}

int gprs_ssl_recv(int session_id, unsigned char* buf, int buf_len, int timeout_ms)
{
    int ret;
    Timer timer;
    int flags = 0;
    int bytes_to_read = 0;
    int bytes_returned = 0;
    int ssl_sessions[MAX_SSL_SESSIONS];
    int err_code = GPRS_ERROR_SSL_BASE;

    if ((session_id < 0) || (session_id >= MAX_SSL_SESSIONS))
        return GPRS_ERROR_INVALID_PARAMETERS;

    dbg_printf(DEBUG_LEVEL_DEBUG, "Requested bytes to receive: %d\r\n", buf_len);

    memset(ssl_sessions, 0, sizeof(ssl_sessions));

    ret = gprs_ssl_recv_poll(ssl_sessions, MAX_SSL_SESSIONS, timeout_ms);
    if (ret < 0) {
        if (ret == GPRS_ERROR_TIMEOUT)
            return GPRS_ERROR_TIMEOUT;
        else
            return GPRS_ERROR_RECV_FAILED;
    }

    if (ssl_sessions[session_id] > 0)
        ret = ssl_sessions[session_id];
    else
        return GPRS_ERROR_TIMEOUT;

    dbg_printf(DEBUG_LEVEL_DEBUG, "Available bytes to read: %d\r\n", ret);

    bytes_to_read = buf_len;
    if (ret < buf_len)
        bytes_to_read = ret;

    if (bytes_to_read > GPRS_TCP_RECV_CHUNK_SIZE)
        bytes_to_read = GPRS_TCP_RECV_CHUNK_SIZE;

    init_timer(&timer);

    //Read binary bytes.
    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CCHRECV=%d,%d\r",
        session_id,
        bytes_to_read);
    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;

    countdown_ms(&timer, AT_RESP_SHORT_TIMEOUT_MS);

    do {
        if (has_timer_expired(&timer)) {
            return GPRS_ERROR_TIMEOUT;
        }

        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_CCHRECV:
                if ((ret == 3) && (at_response_fields[2].ival == session_id)) //+CCHRECV: DATA, <session_id>,<len>
                {
                    if (strcmp(at_response_fields[1].sval, "DATA") == 0) {
                        bytes_returned = at_response_fields[3].ival;
                        dbg_printf(DEBUG_LEVEL_DEBUG, "Actual bytes returned: %d\r\n", bytes_returned);

                        int bytes_read;
                        int pending_bytes;
                        // extract raw data directly from modem buffer.
                        // keep reading until bytes_returned is read,
                        // since mcu is faster than uart.
                        for (bytes_read = 0; bytes_read < bytes_returned; bytes_read += ret) {
                            pending_bytes = bytes_returned - bytes_read;
                            ret = at_get_raw_data(&buf[bytes_read], pending_bytes);

                            if (has_timer_expired(&timer)) // Should not timeout here but if it does, it means error.
                                return GPRS_ERROR_RECV_FAILED;
                        }
                    }
                } else if ((ret == 2) && (atoi(at_response_fields[1].sval) == session_id)) //+CCHRECV: <session_id>,<err>
                {
                    if (at_response_fields[2].ival == 0) //err
                    {
                        flags |= FLAGS_GOT_DATA;
                    } else {
                        flags |= FLAGS_DATA_ERR;
                        err_code += at_response_fields[2].ival;
                    }
                }
                break;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            case AT_RESP_ERR:
                flags |= FLAGS_GOT_ERR;
                break;
            }
        }

        if (CMD_ERRED_WITH_DATA(flags))
            return err_code;
        if (IS_CMD_COMPLETE(flags)) {
            return bytes_returned;
        }

    } while (1);
}

static int get_filename(const char* path, const char** name)
{
    const char* s;

    if (path[0] != '/') {
        *name = path;
        return GPRS_OK;
    }

    for (s = path; *path != 0; path++) {
        if (*path == '/')
            s = path;
    }

    *name = ++s;

    return GPRS_OK;
}

//the only function which uses malloc because of the limitation of uarte easy dma cannot
//use flash memory even for TX transmission and certificate length is not known to use static memory.
int gprs_ssl_cert_download(const char* ro_fs_path)
{
    int ret;
    const char* certname;
    Timer timer;
    int flags = 0;
    const char* prompt = ">";
    const unsigned char* filedata;
    const rofs_file_info_t* fileinfo;
    unsigned char* ram;

#if 0 //Let user specifically delete certificates.
	//delete if already exists.
	ret = gprs_ssl_cert_delete(ro_fs_path);
	if (ret < 0)
	{
		if (ret != GPRS_ERROR_NO_SUCH_CERTIFICATE)
			return ret;
	}
#endif

    ret = get_filename(ro_fs_path, &certname);
    if (ret < 0)
        return ret;

    ret = rofs_readfile(ro_fs_path, &filedata, &fileinfo);
    if (ret < 0)
        return GPRS_ERROR_CERT_READ_FAILED;

    //DO not use return statement from this point.
    ram = malloc(fileinfo->length);

    memcpy(ram, filedata, fileinfo->length);

    init_timer(&timer);
    countdown_ms(&timer, AT_RESP_SHORT_TIMEOUT_MS);

    dbg_printf(DEBUG_LEVEL_DEBUG, "Downloading certificate \"%s\", %u\r\n", certname, fileinfo->length);

    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CCERTDOWN=\"%s\",%u\r",
        certname,
        fileinfo->length);
    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        goto err0;

    flags = 0;

    do {
        if (has_timer_expired(&timer)) {
            ret = GPRS_ERROR_TIMEOUT;
            goto err0;
        }

        ret = sim7600_parse_line(prompt);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_LINE_VALUE:
                if (at_response_fields[1].sval[0] == '>') {
                    ret = at_send_data(ram, fileinfo->length);
                    if (ret < 0) {
                        ret = GPRS_ERROR_MODEM_COMM_FAILED;
                        goto err0;
                    }
                    flags |= FLAGS_GOT_DATA;
                }
                break;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            case AT_RESP_ERR:
                ret = GPRS_ERROR_CERT_DOWNLOAD_FAILED;
                goto err0;
                break;
            }
        }

        if (IS_CMD_COMPLETE(flags)) {
            ret = GPRS_OK;
            break;
        }

    } while (1);

err0:
    free(ram);
    return ret;
}

int gprs_ssl_cert_is_present(const char* ro_fs_path)
{
    int ret;
    const char* certname;
    Timer timer;
    int flags = 0;
    int found = 0;

    ret = get_filename(ro_fs_path, &certname);
    if (ret < 0)
        return ret;

    dbg_printf(DEBUG_LEVEL_DEBUG, "Check if \"%s\" certificate is present.\r\n", certname);

    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CCERTLIST\r");
    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;

    init_timer(&timer);

    countdown_ms(&timer, AT_RESP_SHORT_TIMEOUT_MS);
    flags = 0;

    do {
        if (has_timer_expired(&timer))
            return GPRS_ERROR_TIMEOUT;

        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_CCERTLIST:
                if (strstr(at_response_fields[1].sval, certname))
                    found++;
                break;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            case AT_RESP_ERR:
                return GPRS_ERROR_CMD_ERROR;
            }
        }

        if (flags & FLAGS_GOT_OK) {
            return found;
        }

    } while (1);
}

//delete only if present.
int gprs_ssl_cert_delete(const char* ro_fs_path)
{
    int ret;
    const char* certname;

    ret = gprs_ssl_cert_is_present(ro_fs_path);
    if (ret < 0)
        return ret;
    if (ret == 0)
        return GPRS_ERROR_NO_SUCH_CERTIFICATE;

    ret = get_filename(ro_fs_path, &certname);
    if (ret < 0)
        return ret;

    dbg_printf(DEBUG_LEVEL_DEBUG, "Deleting certificate \"%s\"\r\n", certname);

    ret = cmd_variadic(AT_RESP_SHORT_TIMEOUT_MS,
        "AT+CCERTDELE=\"%s\"\r", certname);
    if (ret < 0)
        return ret;

    return ret;
}

int gprs_ntp_sync(const char* server, int tz_code)
{
    int ret;
    Timer timer;
    int flags = 0;
    int err_code = GPRS_ERROR_NTP_BASE;

    ret = cmd_variadic(AT_RESP_SHORT_TIMEOUT_MS, "AT+CNTP=\"%s\",%d\r",
        server,
        tz_code);

    if (ret < 0)
        return ret;

    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CNTP\r");
    init_timer(&timer);

    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;

    countdown_ms(&timer, AT_RESP_LONG_TIMEOUT_MS);

    do {
        if (has_timer_expired(&timer)) {
            dbg_printf(DEBUG_LEVEL_DEBUG, "gprs_ntp_sync flags: %d\r\n", flags);
            return GPRS_ERROR_TIMEOUT;
        }

        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_CNTP:
                if (at_response_fields[1].ival == 0) {
                    flags |= FLAGS_GOT_DATA;
                } else {
                    flags |= FLAGS_DATA_ERR;
                    err_code += at_response_fields[1].ival;
                    dbg_printf(DEBUG_LEVEL_DEBUG, "Err-code: %d\r\n", err_code);
                }
                break;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            case AT_RESP_ERR:
                return GPRS_ERROR_NTP_UNKNOWN;
            }
        }

        if (CMD_COMPLETE_BUT_ERR(flags))
            return err_code;
        else if (IS_CMD_COMPLETE(flags)) {
            return GPRS_OK;
        }

    } while (1);
}

int gsm_get_time(unsigned long* utc_time)
{
    int ret;
    Timer timer;
    int flags = 0;

    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CCLK?\r");
    init_timer(&timer);

    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return GPRS_ERROR_MODEM_COMM_FAILED;

    countdown_ms(&timer, AT_RESP_SHORT_TIMEOUT_MS);

    do {
        if (has_timer_expired(&timer)) {
            dbg_printf(DEBUG_LEVEL_DEBUG, "gsm_get_time flags: %d\r\n", flags);
            return GPRS_ERROR_TIMEOUT;
        }

        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_CCLK: {
                char cal_time[24];
                strncpy(cal_time, at_response_fields[1].sval, 24);
                caltime_to_unix_ts(cal_time, utc_time);
                flags |= FLAGS_GOT_DATA;
            } break;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            case AT_RESP_ERR:
                return GPRS_ERROR_GET_TIME_FAILED;
            }
        }

        if (IS_CMD_COMPLETE(flags)) {
            return GPRS_OK;
        }

    } while (1);
}

int simcom_fs_readfile(const char* path, int offset, unsigned char* buf, int buf_len)
{

    int ret;
    Timer timer;
    int flags = 0;
    int bytes_written = 0;

    init_timer(&timer);
    countdown_ms(&timer, AT_RESP_SHORT_TIMEOUT_MS);

    snprintf(scratch_pad_buf, SCRATCH_PAD_BUF - 1, "AT+CFTRANTX=\"%s\",%d,%d\r",
        path,
        offset,
        buf_len);

    ret = at_send_cmd(scratch_pad_buf);
    if (ret < 0)
        return ret;

    flags = 0;

    do {
        if (has_timer_expired(&timer)) {
            return GPRS_ERROR_TIMEOUT;
        }

        ret = sim7600_parse_line(NULL);
        if (ret >= 0) {
            switch (at_response_fields[0].ival) {
            case AT_RESP_CFTRANTX:
                if (at_response_fields[1].sval[0] == '0') {
                    flags |= FLAGS_GOT_DATA;
                } else {
                    int pending_bytes = at_response_fields[2].ival;
                    // extract raw data directly from modem buffer.
                    // keep reading until bytes_returned is read,
                    // since mcu is faster than uart.
                    while (pending_bytes > 0) {
                        ret = at_get_raw_data(&buf[bytes_written], pending_bytes);
                        pending_bytes -= ret;
                        bytes_written += ret;

                        if (has_timer_expired(&timer)) // Should not timeout here but if it does, it means error/bug.
                            return GPRS_ERROR_TIMEOUT;
                    }
                }
                break;
            case AT_RESP_OK:
                flags |= FLAGS_GOT_OK;
                break;
            case AT_RESP_ERR:
                return GPRS_ERROR_CFTRAN_FAILED;
                break;
            }
        }

        if (IS_CMD_COMPLETE(flags)) {
            return bytes_written;
        }

    } while (1);
}
