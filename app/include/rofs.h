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

#ifndef ROFS_H_
#define ROFS_H_

typedef struct {
    const char* filepath;
    unsigned int index; //do not use this in application.
    unsigned int length; //without null character if added.
    unsigned int null_added; //1 if added extra by generator.
    const char* mime_type;
} rofs_file_info_t;

//Returns 0 on success, -1 on file not found.
int rofs_readfile(const char* filepath, const unsigned char** filemem, const rofs_file_info_t** fileinfo);

#endif /* ROFS_H_ */
