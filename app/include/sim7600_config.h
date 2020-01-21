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

#ifndef SIM7600_CONFIG_H_
#define SIM7600_CONFIG_H_

#define SIM_PIN     ""

//Add your time zones.
#define TIME_ZONE_CODE_IST      22 //GMT+5:30 = 5.5 hours * 4 quarters

#define TIME_ZONE_CODE_CURRENT  TIME_ZONE_CODE_IST


#define AT_RESP_SHORT_TIMEOUT_MS    3000
#define AT_RESP_LONG_TIMEOUT_MS	    90000


#endif /* SIM7600_CONFIG_H_ */
