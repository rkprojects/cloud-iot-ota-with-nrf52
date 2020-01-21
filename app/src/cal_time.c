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


#include <stdlib.h>
#include <time.h>

#include "uart_print.h"

#define EPOCH_YEAR      2000
#define EPOCH_TIMESTAMP 946684800 //with respect to unix timestamp

#define TIME_ZONE_CODE_TO_SECONDS(tzc) ((tzc) * 15 * 60) // 1 quarter = 15 minutes

static const unsigned char days_in_month_list[] = {31, 28, 31, 30,
                                        31, 30, 31, 31, 
                                        30, 31, 30, 31};
                                        
static int is_leap_year(unsigned int year)
{
    if ((year % 4) == 0)
    {
        if ((year % 100) == 0)
        {
            if ((year % 400) == 0)
                return 1;
        }
        else
            return 1;
    }
    
    return 0;
}

//Calendar time to Unix timestamp
int caltime_to_unix_ts(char* cal_time, unsigned long* time)
{
    //cal_time format from AT+CCLK
    //"yy/MM/dd,hh:mm:ss+zz"
    //0123456789012345678901
	// 
    int tz_offset;
    struct tm cal_tm;
    unsigned long days = 0;
    
    int i;
    
    dbg_printf(DEBUG_LEVEL_DEBUG, "System time: %s\r\n", cal_time);
    
    //year
    cal_time[3] = 0;
    cal_tm.tm_year = atoi(&cal_time[1]);
    //month
    cal_time[6] = 0;
    cal_tm.tm_mon = atoi(&cal_time[4]) - 1;
    //day
    cal_time[9] = 0;
    cal_tm.tm_mday = atoi(&cal_time[7]);
    //hour
    cal_time[12] = 0;
    cal_tm.tm_hour = atoi(&cal_time[10]);
    //minutes
    cal_time[15] = 0;
    cal_tm.tm_min = atoi(&cal_time[13]);
    //time zone
    cal_time[21] = 0;
    tz_offset = TIME_ZONE_CODE_TO_SECONDS(atoi(&cal_time[19]));
    if (cal_time[18] == '+') //revert to adjust to utc.
        tz_offset = -tz_offset;
    //seconds
    cal_time[18] = 0;
    cal_tm.tm_sec = atoi(&cal_time[16]);
    //day light - TODO
    cal_tm.tm_isdst = 0;
    
    //past years
    for (i = 0; i < cal_tm.tm_year; i++)
    {
        days += 365 + is_leap_year(i + EPOCH_YEAR);
    }
    
    //current year
    for (i = 0; i < cal_tm.tm_mon; i++)
    {
        days += days_in_month_list[i];
        if (i == 1) //feb
            days += is_leap_year(cal_tm.tm_year + EPOCH_YEAR);
    }
    
    //current month
    days += cal_tm.tm_mday - 1;
    *time = EPOCH_TIMESTAMP;
    *time += days * 24 * 60 * 60;
    
    //current day
    *time += (cal_tm.tm_hour * 60 + cal_tm.tm_min) * 60;
    *time += cal_tm.tm_sec;
    
    //make it utc.
    *time += tz_offset;
    
    //mktime calculating incorrect time, something is missing - TODO
    //*time = mktime(&cal_tm);
    
    return 0;
}
