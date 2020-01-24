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

#include "temp_sensor.h"
#include "nrf_temp.h"

void temps_init(void)
{
    nrf_temp_init();
}

int temps_read(void)
{
    int t;

    NRF_TEMP->TASKS_START = 1;

    while (NRF_TEMP->EVENTS_DATARDY == 0) {
        // Do nothing. tTemp = 36 usec (typ)
    }
    NRF_TEMP->EVENTS_DATARDY = 0;

    // Workarounds from examples source code in nRF52 SDK

    //PAN_028 rev2.0A anomaly 29 - TEMP: Stop task clears the TEMP register. */
    t = (nrf_temp_read() / 4);

    //PAN_028 rev2.0A anomaly 30 - TEMP: Temp module analog front end does not power down when DATARDY event occurs. */
    NRF_TEMP->TASKS_STOP = 1; /** Stop the temperature measurement. */

    return t;
}
