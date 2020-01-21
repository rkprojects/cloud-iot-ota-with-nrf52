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

#ifndef TIMER_PLATFORM_H_
#define TIMER_PLATFORM_H_

#include <stdint.h>

//Underlying timer should be configured for 1 ms ticks and up counting.
//All values in milliseconds.
struct Timer {
    uint32_t diff;
    uint32_t that_time;
};


#endif /* TIMER_PLATFORM_H_ */
