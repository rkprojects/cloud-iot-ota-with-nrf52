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

#ifndef JWT_H_
#define JWT_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef char* string_t;
typedef const char* cstring_t;

int jwt_init(void);
int jwt_pk_init(const unsigned char* key, size_t keylen);
int jwt_create_RS256_token(cstring_t payload, string_t* otoken, size_t* token_len);

#endif /* JWT_H_ */
