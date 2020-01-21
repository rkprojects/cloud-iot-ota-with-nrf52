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

#include <stdarg.h>
#include "uarte.h"
#include "uart_print.h"


#ifndef NRFX_UARTE1_ENABLED
#error "NRFX_UARTE1_ENABLED undefined. Requried for Debug Console"
#endif

static nrfx_uarte_t uarte_console = NRFX_UARTE_INSTANCE(1);

char console_print_buf[CONSOLE_PRINT_BUF_SIZE];
char console_print_debug_level = DEBUG_LEVEL_ERROR;

int console_init(void)
{
    return (int) uarte_init(uarte_console.p_reg, UART_DEBUG_TX_PIN_PSEL, UART_DEBUG_RX_PIN_PSEL);
}

void console_set_print_debug_level(debug_level_t level)
{
    console_print_debug_level = level;
}

void console_prints(const char *str)
{
    uarte_tx(uarte_console.p_reg, (const uint8_t*) str, strlen(str));
}

int console_fprintf(FILE* stream, const char* fmt, ...)
{
	va_list ap;
	int ret;

	(void) stream;

	va_start(ap, fmt);
	ret = vsnprintf(console_print_buf, CONSOLE_PRINT_BUF_SIZE-1, fmt, ap);
	va_end(ap);
	console_prints(console_print_buf);

	return ret;
}

