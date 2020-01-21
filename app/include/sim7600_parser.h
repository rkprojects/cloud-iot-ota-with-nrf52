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

#ifndef SIM7600_PARSER_H_
#define SIM7600_PARSER_H_

#define MAX_RESPONSE_FIELDS 20

typedef enum {
	AT_RESP_LINE_VALUE,
	AT_RESP_NOT_FOUND,
	AT_RESP_OK,
	AT_RESP_ERR,
	AT_RESP_IP_ERR,
	AT_RESP_CIP_ERR,
	AT_RESP_CPIN,
	AT_RESP_CREG,
	AT_RESP_CGREG,
	AT_RESP_CGATT,
	AT_RESP_CGPADDR,
	AT_RESP_NETOPEN,
	AT_RESP_NETCLOSE,
	AT_RESP_CIPOPEN,
	AT_RESP_CIPSEND,
	AT_RESP_CIPCLOSE,
	AT_RESP_CIPRXGET,
	AT_RESP_CNSMOD,
	AT_RESP_CSQ,
	AT_RESP_CIPACK,
	AT_RESP_CCERTLIST,
	AT_RESP_CCHSTART,
	AT_RESP_CCHSTOP,
	AT_RESP_CCHCLOSE,
	AT_RESP_CCHRECV,
	AT_RESP_CCHOPEN,
	AT_RESP_CCHEVENT,
	AT_RESP_CNTP,
	AT_RESP_CCLK,
	AT_RESP_IPCLOSE,
	AT_RESP_CCH_PEER_CLOSED,
	AT_RESP_CCHRECV_CLOSED,
    AT_RESP_CFTRANTX,
    AT_RESP_HTTPACTION,
    AT_RESP_HTTPREADFILE,
} at_response_t;

typedef union {
	const char* sval;
	int  ival;
} at_response_field_t;

extern at_response_field_t at_response_fields[MAX_RESPONSE_FIELDS];

//Use it to wait for debugger irrespective of break points.
extern volatile int dbg_break_code;

int sim7600_parse_line(const char* alternate_token);

#endif /* SIM7600_PARSER_H_ */
