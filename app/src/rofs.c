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

#include <string.h>

#include "rofs.h"

extern const unsigned char rofs_data[];
extern const rofs_file_info_t rofs_index_table[];

int rofs_readfile(const char* filepath, const unsigned char** filemem, const rofs_file_info_t** fileinfo)
{
    unsigned int i;

    if ((filepath == NULL) || (filemem == NULL) || (fileinfo == NULL))
        return -1;

    for (i = 0; rofs_index_table[i].filepath != NULL; i++) {
        if (strcmp(filepath, rofs_index_table[i].filepath) == 0) {

            *filemem = &rofs_data[rofs_index_table[i].index];
            *fileinfo = &rofs_index_table[i];
            return 0;
        }
    }

    return -1;
}
