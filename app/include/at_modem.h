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

#ifndef AT_MODEM_H
#define AT_MODEM_H

enum AT_ERROR 
{
    AT_OK = 0,
    AT_ERROR = -100,
};

int at_init(void);
int at_get_raw_data(unsigned char *buf, int buf_len);
int at_get_next_line(char *buf, int buf_len);
int at_match_token(const char *token);
int at_send_cmd(const char* cmd);
int at_send_data(const unsigned char* buf, int buf_len);
int at_dump_buffer(void);

#endif //AT_MODEM_H
