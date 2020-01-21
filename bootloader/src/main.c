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


#include "nrf_delay.h"
#include "nrf.h"
#include "bsp.h"
#include "nrf_uarte.h"
#include "nrfx_uarte.h"
#include "nrfx_prs.h"
#include "nrf_drv_clock.h"
#include "nrfx_rtc.h"
#include "nrfx_wdt.h"
#include "nrf_drv_rng.h"

#include "nrf_crypto.h"

#include "nrf_nvmc.h"
#include "nrf_mbr.h"

#include "uart_print.h"

#include "bl_cmds.h"
#include "bl_data.h"
#include "program.h"

#include "sim7600_gprs.h"

#define LED_BLUE    0
#define LED_GREEN   1

static void halt_error(void);
static void rtc_init_for_timers(void);

static void halt_error(void)
{

    bsp_board_led_on(LED_BLUE);

    while (true)
    {
        // Do nothing.
    }
}

static void rtc1_handler (nrfx_rtc_int_type_t type)
{
    (void)type;
}

static void rtc_init_for_timers(void)
{
    nrfx_err_t ret;
    nrfx_rtc_t rtc = NRFX_RTC_INSTANCE(1);
    nrfx_rtc_config_t config = NRFX_RTC_DEFAULT_CONFIG;
    
    ret = nrfx_rtc_init(&rtc, &config, rtc1_handler);
    if (ret != NRFX_SUCCESS) 
        halt_error();   
    
    //disable all interrupts.
    nrfx_rtc_int_disable (&rtc, &ret);
	
    nrfx_rtc_enable (&rtc);
    
    //from this point RTC1 driver is no where used.
    //only HAL counter register reads.
}



int main(void)
{
    int ret;
    sd_mbr_command_t mbr_command;
    nrfx_wdt_config_t wdt_config = NRFX_WDT_DEAFULT_CONFIG;
    
    nrf_drv_clock_init();
    
    nrf_drv_clock_hfclk_request(NULL);
    
    while(!nrf_drv_clock_hfclk_is_running());
    
    //LFCLK synthesized from HFXO HF CLK.
    nrf_drv_clock_lfclk_request(NULL);

    while(!nrf_drv_clock_lfclk_is_running());
    
    console_init();
    console_set_print_debug_level(DEBUG_LEVEL_DEBUG);

    dbg_printf(DEBUG_LEVEL_DEBUG, "\r\n\r\nDebug Console\r\n\r\n");

    ret = nrfx_wdt_init (&wdt_config, NULL);
	if (ret != NRF_SUCCESS)
    {
        dbg_printf(DEBUG_LEVEL_ERROR, "nrfx_wdt_init failed: %d\r\n", ret);
        halt_error();
    }

    if (bl_settings.settings_code != BL_SETTINGS_CODE)
    {
        dbg_printf(DEBUG_LEVEL_ERROR, "Bootloader not correctly programmed %x. Cannot continue.\r\n", bl_settings.settings_code);
        halt_error();
    }
    else
    {
        dbg_printf(DEBUG_LEVEL_DEBUG, "BL Settings Code = %x\r\n", bl_settings.settings_code);
    }

    // Required for Hash too.
    ret = nrf_crypto_init();
    if (ret != NRF_SUCCESS)
    {
        dbg_printf(DEBUG_LEVEL_ERROR, "nrf_crypto_init failed: %d\r\n", ret);
        halt_error();
    }

    ret = programming_required();
    if (ret < 0)
    {
        dbg_printf(DEBUG_LEVEL_ERROR, "programming_required failed: %d\r\n", ret);
        halt_error();
    }
    else if (ret)
    {
        // Enable WDT only when programming flash else application
        // will be forced to use WDT.
        nrfx_wdt_channel_id wdt_bl_channel = 0;

        ret = nrfx_wdt_channel_alloc (&wdt_bl_channel);
        if (ret != NRF_SUCCESS)
        {
            dbg_printf(DEBUG_LEVEL_ERROR, "nrfx_wdt_channel_alloc failed: %d\r\n", ret);
            halt_error();
        }

        nrfx_wdt_enable(); 

        dbg_printf(DEBUG_LEVEL_DEBUG, "WDT enabled, timeout = %d ms\r\n", NRFX_WDT_CONFIG_RELOAD_VALUE);

        rtc_init_for_timers();
    
        ret = nrf_drv_rng_init(NULL);
        if (ret != NRF_SUCCESS)
            halt_error();
        
        ret = start_program();
        if (ret < 0)
        {
            dbg_printf(DEBUG_LEVEL_ERROR, "start_program failed: %d\r\n", ret);
            // TODO: If error is re-attemptable then do it.
            //halt_error();
        }

        // Reset MCU again else application
        // will be forced to use WDT.
        NVIC_SystemReset();
    }
    else
    {
        ret = app_verify();
        if (ret < 0)
        {
            dbg_printf(DEBUG_LEVEL_ERROR, "No valid application found: %d\r\n", ret);
            halt_error();
        }

        #if 0//Test BL command call.
        {
            pfn_bl_commands_t fn = BL_COMMANDS_FN_ADDR;
            bl_cmd_params_t params;
            extern int bl_commands(int cmd, bl_cmd_params_t* params);
            memcpy(&params.fw_info, &bl_settings.fw_info, sizeof(fw_info_t));

            dbg_printf(DEBUG_LEVEL_DEBUG, "Calling bl_command=%p, addr=%p\r\n", 
                            bl_commands,
                            fn);

            ret = fn(BL_CMD_UPDATE_FW, &params);
            if (ret < 0)
            {
                dbg_printf(DEBUG_LEVEL_ERROR, "BL_CMD_UPDATE_FW failed: %d\r\n", ret);
                halt_error();
            }
        }
        #endif
    }
    
    dbg_printf(DEBUG_LEVEL_DEBUG, "Jumping to App = %p\r\n", bl_settings.fw_info.fp_base);

    
    mbr_command.command = SD_MBR_COMMAND_IRQ_FORWARD_ADDRESS_SET;
    mbr_command.params.irq_forward_address_set.address = bl_settings.fw_info.fp_base;
    ret = sd_mbr_command(&mbr_command);
    if (ret != NRF_SUCCESS)
    {
        dbg_printf(DEBUG_LEVEL_ERROR, "sd_mbr_command failed %d\r\n", ret);
        halt_error();
    }
    else 
    {
        uint32_t *vtable = (uint32_t*) bl_settings.fw_info.fp_base;
        typedef void(*rst_fn_t)(void);
        rst_fn_t rst_fn = (rst_fn_t) vtable[1];
        //simulate stack loading after cpu reset.
        __ASM("msr msp, %[stack]":: [stack] "r" (vtable[0]));
        // start reset handler in thread context.
        rst_fn();
        while(1);
    }

    while(1);
}
