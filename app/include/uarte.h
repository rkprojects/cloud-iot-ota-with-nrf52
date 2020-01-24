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

#ifndef UARTE_H_
#define UARTE_H_

#include "bsp.h"
#include "nrf.h"
#include "nrf_delay.h"
#include "nrf_drv_clock.h"
#include "nrf_uarte.h"
#include "nrfx_prs.h"
#include "nrfx_uarte.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define UART_MODEM_RX_PIN_PSEL NRF_GPIO_PIN_MAP(1, 11)
#define UART_MODEM_TX_PIN_PSEL NRF_GPIO_PIN_MAP(1, 10)

#define UART_DEBUG_RX_PIN_PSEL NRF_GPIO_PIN_MAP(0, 29)
#define UART_DEBUG_TX_PIN_PSEL NRF_GPIO_PIN_MAP(0, 31)

typedef void (*uarte_modem_irq_t)(void);

nrfx_err_t uarte_init(NRF_UARTE_Type* p_reg, uint32_t tx_pin, uint32_t rx_pin);
nrfx_err_t uarte_rx_dma_start(NRF_UARTE_Type* p_reg, uarte_modem_irq_t irq_handler, unsigned char* rx_buf, size_t buf_len);
void uarte_tx(NRF_UARTE_Type* p_reg, const uint8_t* buf, size_t length);

#endif //UARTE_H_
