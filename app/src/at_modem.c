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

#include "uarte.h"

#include "at_modem.h"
#include "uart_print.h"

// should be larger than packet chunk size used.
#define UART_RX_BUFFER_SIZE     1800
#define UART_RX_DMA_BLOCK_SIZE  1 // 1 = this will generate two interrupts per byte.
#define LINE_DELIMIT "\r\n"

static unsigned char rx_buffer[UART_RX_BUFFER_SIZE];
static int unread_length = 0;
static int wr_index = 0;
static int rd_index = 0;
static int err_count = 0;

static nrfx_uarte_t uarte_modem = NRFX_UARTE_INSTANCE(0);
static inline void atomic_rmw(int* addr, int m);
static int extract_line_from_buffer(char* buf, int buf_len, int end_index);

static void uarte_modem_irq(void)
{
    if (nrf_uarte_event_check(uarte_modem.p_reg, NRF_UARTE_EVENT_RXSTARTED)) {
        // Update next dma address. Noridic EasyDMA doesn't have real time view
        // of DMA progress!
        nrf_uarte_event_clear(uarte_modem.p_reg, NRF_UARTE_EVENT_RXSTARTED);

        // This will also take care of 4 cycle delay required to avoid recurring
        // interrupts.
        wr_index = (wr_index + UART_RX_DMA_BLOCK_SIZE) % UART_RX_BUFFER_SIZE;
        nrf_uarte_rx_buffer_set(uarte_modem.p_reg, &rx_buffer[wr_index],
            UART_RX_DMA_BLOCK_SIZE);
    }

    if (nrf_uarte_event_check(uarte_modem.p_reg, NRF_UARTE_EVENT_ENDRX)) {
        nrf_uarte_event_clear(uarte_modem.p_reg, NRF_UARTE_EVENT_ENDRX);
        unread_length += UART_RX_DMA_BLOCK_SIZE;
    }

    if (nrf_uarte_event_check(uarte_modem.p_reg, NRF_UARTE_EVENT_ERROR)) {
        nrf_uarte_event_clear(uarte_modem.p_reg, NRF_UARTE_EVENT_ERROR);
        err_count++;
    }
}

// Atomic Read-Modify-Write: *addr += m
// m can be negative.
static inline void atomic_rmw(int* addr, int m)
{
    int v;
    do {
        v = __LDREXW((uint32_t*)addr);
        v += m; // could be negative
    } while (__STREXW(v, (uint32_t*)addr));
}

int at_init(void)
{
    static int init_done = 0;

    if (!init_done) {
        uarte_init(uarte_modem.p_reg, UART_MODEM_TX_PIN_PSEL, UART_MODEM_RX_PIN_PSEL);
        if (uarte_rx_dma_start(uarte_modem.p_reg, uarte_modem_irq, rx_buffer,
                    UART_RX_DMA_BLOCK_SIZE)
                != NRFX_SUCCESS) {
                return AT_ERROR;
        }
        init_done = 1;
    }

    return AT_OK;
}

int at_get_raw_data(unsigned char* buf, int buf_len)
{
    int i;

    if (unread_length <= 0)
        return 0;

    for (i = 0; (i < buf_len) && (i < unread_length); i++) {
        buf[i] = rx_buffer[rd_index];
        rd_index = (rd_index + 1) % UART_RX_BUFFER_SIZE;
    }

    atomic_rmw(&unread_length, -i);

    return i;
}

int at_send_data(const unsigned char* buf, int buf_len)
{
    uarte_tx(uarte_modem.p_reg, buf, buf_len);
    return buf_len;
}

// DO not call from app side.
static int extract_line_from_buffer(char* buf, int buf_len, int end_index)
{
    int i;

    if (unread_length <= 0)
        return 0;

    end_index = (end_index + 1) % UART_RX_BUFFER_SIZE;

    for (i = 0; (i < buf_len) && (rd_index != end_index); i++) {
        buf[i] = rx_buffer[rd_index];
        rd_index = (rd_index + 1) % UART_RX_BUFFER_SIZE;
    }

    atomic_rmw(&unread_length, -i);

    return i;
}

int at_get_next_line(char* buf, int buf_len)
{
    int i;
    int k;
    const char* sep = LINE_DELIMIT;
    int m;

    if (unread_length <= 0)
        return 0;

    m = -1;
    k = 0;
    for (i = 0; i < unread_length; i++) {
        int index = (rd_index + i) % UART_RX_BUFFER_SIZE;

        switch (m) {
        case -1: // No match yet.
            if (rx_buffer[index] == sep[k]) {
                m = i; // match begins
                k++;
                if (sep[k] == 0) // match complete
                {
                    rx_buffer[(rd_index + m) % UART_RX_BUFFER_SIZE] = 0;
                    return extract_line_from_buffer(buf, buf_len, index);
                }
            }
            break;
        default:
            if (rx_buffer[index] == sep[k]) {
                k++;
                if (sep[k] == 0) // match complete
                {
                    rx_buffer[(rd_index + m) % UART_RX_BUFFER_SIZE] = 0;
                    return extract_line_from_buffer(buf, buf_len, index);
                }
            } else {
                i = m; // m + 1 increment will happen in loop end.
                m = -1;
                k = 0;
            }
            break;
        }
    }

    return 0;
}

int at_match_token(const char* token)
{
    int i;

    if (unread_length <= 0)
        return 0;

    for (i = 0; i < unread_length; i++) {
        int index = (rd_index + i) % UART_RX_BUFFER_SIZE;

        if (rx_buffer[index] == token[i]) {
            if (token[i + 1] == 0) // match complete
            {
                rd_index = (index + 1) % UART_RX_BUFFER_SIZE;

                atomic_rmw(&unread_length, -(i + 1));

                return 1;
            }
        } else
            break;
    }

    return 0;
}

int at_send_cmd(const char* cmd)
{
    return at_send_data((const unsigned char*)cmd, strlen(cmd));
}

int at_dump_buffer(void)
{
    int i;

    dbg_printf(DEBUG_LEVEL_INFO, "\r\nat modem uart rx_buffer:\r\n");

    for (i = 0; i < UART_RX_BUFFER_SIZE; i++) {
        if (i == rd_index) {
            dbg_printf(DEBUG_LEVEL_INFO, "\r\n\r\n* RD INDEX %d *\r\n\n\r", rd_index);
            dbg_printf(DEBUG_LEVEL_INFO, "\r\n\r\n* UNREAD LEN %d *\r\n\n\r", unread_length);
        }

        dbg_printf(DEBUG_LEVEL_INFO, "%c", rx_buffer[i]);
    }

    dbg_printf(DEBUG_LEVEL_INFO, "\r\n\r\n");

    return AT_OK;
}
