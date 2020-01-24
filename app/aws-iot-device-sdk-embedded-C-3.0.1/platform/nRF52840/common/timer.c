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
#include <stdio.h>

#include "timer_interface.h"
#include "timer_platform.h"

#include "nrfx_rtc.h"

#define SECONDS_TO_MS(s) ((s)*1000U)

#define MAX_MS_VALUE (0xffffffU + 1)

static nrfx_rtc_t rtc = NRFX_RTC_INSTANCE(1);

static uint32_t now(void);

static uint32_t now(void)
{
    return nrf_rtc_counter_get(rtc.p_reg);
}

bool has_timer_expired(Timer* timer)
{
    return left_ms(timer) == 0;
}

void countdown_ms(Timer* timer, uint32_t expire_ms)
{
    if (expire_ms >= MAX_MS_VALUE)
        expire_ms = MAX_MS_VALUE - 1;

    timer->diff = expire_ms;
    timer->that_time = now(); //remember
}

void countdown_sec(Timer* timer, uint32_t expire_sec)
{
    countdown_ms(timer, SECONDS_TO_MS(expire_sec));
}

uint32_t left_ms(Timer* timer)
{
    uint32_t time = now();
    uint32_t elapsed;
    elapsed = (time >= timer->that_time) ? time - timer->that_time : MAX_MS_VALUE - timer->that_time + time;

    return (elapsed < timer->diff) ? timer->diff - elapsed : 0;
}

void init_timer(Timer* timer)
{
    timer->diff = 0;
    timer->that_time = now();
}
