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

nrfx_err_t uarte_init(NRF_UARTE_Type* p_reg, uint32_t tx_pin, uint32_t rx_pin)
{
    nrf_uarte_configure(p_reg, NRF_UARTE_PARITY_EXCLUDED,
        NRF_UARTE_HWFC_DISABLED);

    nrf_uarte_baudrate_set(p_reg, NRF_UARTE_BAUDRATE_115200);

    nrf_uarte_txrx_pins_set(p_reg, tx_pin,
        rx_pin);
    
    nrf_uarte_enable(p_reg);
    
    return NRFX_SUCCESS;
}

//Enable uart rx in circular DMA mode.
nrfx_err_t uarte_rx_dma_start(NRF_UARTE_Type* p_reg, uarte_modem_irq_t irq_handler, unsigned char* rx_buf, size_t buf_len)
{
    
    nrf_uarte_disable(p_reg);
    
    if (nrfx_prs_acquire(p_reg, irq_handler) != NRFX_SUCCESS) {
        return NRFX_ERROR_INTERNAL;
    }

    //enable interrupts
    nrf_uarte_int_enable(p_reg,
        NRF_UARTE_INT_ENDRX_MASK | NRF_UARTE_INT_RXSTARTED_MASK | NRF_UARTE_INT_ERROR_MASK);

    NRFX_IRQ_PRIORITY_SET(nrfx_get_irq_number(p_reg),
        APP_IRQ_PRIORITY_HIGHEST);
    NRFX_IRQ_ENABLE(nrfx_get_irq_number(p_reg));

    nrf_uarte_rx_buffer_set(p_reg, rx_buf, buf_len);
    
    nrf_uarte_enable(p_reg);
    
    nrf_uarte_shorts_enable(p_reg, NRF_UARTE_SHORT_ENDRX_STARTRX);
    nrf_uarte_task_trigger(p_reg, NRF_UARTE_TASK_STARTRX);

    return NRFX_SUCCESS;
}

//DMA TX transfer. Wait until transfer is complete as higher
//layers may end up re-using tx buffer. If thats not the case then
//move event wait statement before starting Tx.
void uarte_tx(NRF_UARTE_Type* p_reg, const uint8_t* buf, size_t length)
{
    nrf_uarte_event_clear(p_reg, NRF_UARTE_EVENT_TXSTARTED);
    nrf_uarte_event_clear(p_reg, NRF_UARTE_EVENT_ENDTX);
    nrf_uarte_tx_buffer_set(p_reg, (uint8_t*)buf, length);
    nrf_uarte_task_trigger(p_reg, NRF_UARTE_TASK_STARTTX);

    while (nrf_uarte_event_check(p_reg, NRF_UARTE_EVENT_ENDTX) == false)
        ;
}
