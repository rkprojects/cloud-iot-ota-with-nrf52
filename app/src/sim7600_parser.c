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

#include "sim7600_parser.h"
#include "at_modem.h"
#include "sim7600_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FIELD_TYPE_INTEGER 0
#define FIELD_TYPE_STRING 1

#define INTEGER_FIELD_BIT(n) (FIELD_TYPE_INTEGER << (n))
#define STRING_FIELD_BIT(n) (FIELD_TYPE_STRING << (n))

#define LINE_DELIMIT "\r\n"

at_response_field_t at_response_fields[MAX_RESPONSE_FIELDS];

#define RESP_LINE_SIZE 128
static char resp_line[RESP_LINE_SIZE];

static int parse_type(const char* type, char* fields);
static int parse_fields(char* fields, unsigned int pattern, int expected_count);

static int parse_type(const char* type, char* fields)
{
    if (strcmp("+CPIN:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CPIN;
        return parse_fields(fields,
            STRING_FIELD_BIT(0),
            1);
    }

    if (strcmp("+CREG:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CREG;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0) | INTEGER_FIELD_BIT(1),
            2);
    }

    if (strcmp("+CGREG:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CGREG;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0) | INTEGER_FIELD_BIT(1),
            2);
    }

    if (strcmp("+CGATT:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CGATT;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0),
            1);
    }

    if (strcmp("+CIPRXGET:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CIPRXGET;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0) | INTEGER_FIELD_BIT(1) | INTEGER_FIELD_BIT(2) | INTEGER_FIELD_BIT(3),
            4);
    }

    if (strcmp("+CIPSEND:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CIPSEND;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0) | INTEGER_FIELD_BIT(1) | INTEGER_FIELD_BIT(2),
            3);
    }

    if (strcmp("+CSQ:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CSQ;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0) | INTEGER_FIELD_BIT(1),
            2);
    }

    if (strcmp("+CIPACK:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CIPACK;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0) | INTEGER_FIELD_BIT(1) | INTEGER_FIELD_BIT(2),
            3);
    }

    if (strcmp("+IP ERROR:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_IP_ERR;
        return parse_fields(fields,
            STRING_FIELD_BIT(0),
            1);
    }

    if (strcmp("+CIPERROR:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CIP_ERR;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0),
            1);
    }

    if (strcmp("+CGPADDR:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CGPADDR;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0) | STRING_FIELD_BIT(1) | STRING_FIELD_BIT(2),
            3);
    }

    if (strcmp("+NETOPEN:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_NETOPEN;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0),
            1);
    }

    if (strcmp("+NETCLOSE:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_NETCLOSE;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0),
            1);
    }

    if (strcmp("+CIPOPEN:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CIPOPEN;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0) | INTEGER_FIELD_BIT(1),
            2);
    }

    if (strcmp("+CIPCLOSE:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CIPCLOSE;
        unsigned int pat = FIELD_TYPE_INTEGER ? -1 : 0;
        return parse_fields(fields,
            pat,
            10);
    }

    if (strcmp("+CNSMOD:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CNSMOD;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0) | INTEGER_FIELD_BIT(1),
            2);
    }

    if (strcmp("+CCERTLIST:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CCERTLIST;
        return parse_fields(fields,
            STRING_FIELD_BIT(0),
            1);
    }

    if (strcmp("+CCHSTART:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CCHSTART;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0),
            1);
    }

    if (strcmp("+CCHSTOP:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CCHSTOP;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0),
            1);
    }

    if (strcmp("+CCHCLOSE:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CCHCLOSE;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0),
            1);
    }

    //First field have variable type depending on field count,
    //leave it as string, upper layer should take care.
    if (strcmp("+CCHRECV:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CCHRECV;
        return parse_fields(fields,
            STRING_FIELD_BIT(0) | INTEGER_FIELD_BIT(1) | INTEGER_FIELD_BIT(2),
            3);
    }

    if (strcmp("+CCHOPEN:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CCHOPEN;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0) | INTEGER_FIELD_BIT(1),
            2);
    }

    if (strcmp("+CCHEVENT:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CCHEVENT;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0) | STRING_FIELD_BIT(1),
            2);
    }

    if (strcmp("+CNTP:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CNTP;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0),
            1);
    }

    if (strcmp("+CCLK:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CCLK;
        return parse_fields(fields,
            STRING_FIELD_BIT(0),
            1);
    }

    if (strcmp("+IPCLOSE:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_IPCLOSE;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0) | INTEGER_FIELD_BIT(1),
            2);
    }

    if (strcmp("+CCH_RECV_CLOSED:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CCHRECV_CLOSED;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0) | INTEGER_FIELD_BIT(1),
            2);
    }

    if (strcmp("+CCH_PEER_CLOSED:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CCH_PEER_CLOSED;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0),
            1);
    }

    if (strcmp("+CFTRANTX:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_CFTRANTX;
        return parse_fields(fields,
            STRING_FIELD_BIT(0) | INTEGER_FIELD_BIT(1),
            2);
    }

    if (strcmp("+HTTPACTION:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_HTTPACTION;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0) | INTEGER_FIELD_BIT(1) | INTEGER_FIELD_BIT(2),
            3);
    }

    if (strcmp("+HTTPREADFILE:", type) == 0) {
        at_response_fields[0].ival = AT_RESP_HTTPREADFILE;
        return parse_fields(fields,
            INTEGER_FIELD_BIT(0),
            1);
    }

    at_response_fields[0].ival = AT_RESP_NOT_FOUND;

    return -1;
}

int sim7600_parse_line(const char* alternate_token)
{

    char* token;
    int ret;

    //additional_token should not be a line as lines are parsed by default.
    //token if found is emulated as a value line.
    if (alternate_token != NULL) {
        ret = at_match_token(alternate_token);
        if (ret) {
            at_response_fields[0].ival = AT_RESP_LINE_VALUE;
            at_response_fields[1].sval = alternate_token;
            return 1;
        }
    }

    ret = at_get_next_line(resp_line, RESP_LINE_SIZE);
    //ignore blank lines.
    if ((ret == 0) || (resp_line[0] == 0))
        return -1;

    if (strcmp(resp_line, "OK") == 0) {
        at_response_fields[0].ival = AT_RESP_OK;
        return 0;
    }

    if (strcmp(resp_line, "ERROR") == 0) {
        at_response_fields[0].ival = AT_RESP_ERR;
        return 0;
    }

    if (resp_line[0] != '+') {
        at_response_fields[0].ival = AT_RESP_LINE_VALUE;
        at_response_fields[1].sval = resp_line;
        return 1;
    }

    // first get header
    token = strtok(resp_line, " ");
    if (token == NULL)
        return -1;

    at_response_fields[0].sval = token;
    //There is no delimiter left, this will return comma seprated fields part.
    token = strtok(NULL, LINE_DELIMIT);

    if (token == NULL)
        return 0;

    return parse_type(at_response_fields[0].sval, token);
}

static void hide_quoted_commas(char* str, int hide)
{
    int i;
    int quoted = 0;

    for (i = 0; str[i] != 0; i++) {
        if (str[i] == '"') {
            quoted = !quoted;
            continue;
        }

        if (hide) {
            //stripped AT response line won't contain new line.
            if ((str[i] == ',') && (quoted))
                str[i] = '\n';
        } else {
            if ((str[i] == '\n') && (quoted))
                str[i] = ',';
        }
    }
}

//Actual count can be less than or more than expected count.
static int parse_fields(char* fields, unsigned int pattern, int expected_count)
{
    int i = 0;
    char* t;

    if (fields == NULL)
        return 0;

    hide_quoted_commas(fields, 1);

    //response_fields are filled from index 1. Field 0 contains type.
    t = strtok(fields, ",");

    for (i = 0; (i < expected_count) && (t != NULL); i++) {
        //if (t == NULL) //probably incomplete or variable fields present.
        //	break;

        if ((pattern & (1 << i)) == FIELD_TYPE_INTEGER)
            at_response_fields[i + 1].ival = atoi(t);
        else {
            hide_quoted_commas(t, 0);
            at_response_fields[i + 1].sval = t;
        }

        t = strtok(NULL, ",");
    }

    return i;
}
