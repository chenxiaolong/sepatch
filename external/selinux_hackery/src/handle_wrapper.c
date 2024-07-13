/*
 * SPDX-FileCopyrightText: 2024 Andrew Gunnerson
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "handle_wrapper.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

__attribute__ ((format(printf, 3, 4)))
static void callback(void *varg, sepol_handle_t *handle, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    char *msg;
    if (vasprintf(&msg, fmt, ap) < 0) {
        // There's nothing we can do.
        msg = NULL;
    }

    va_end(ap);

    struct msg_non_variadic_callback_data *data =
        (struct msg_non_variadic_callback_data *) varg;
    data->func(data->data, handle, msg);

    free(msg);
}

void sepol_msg_set_non_variadic_callback(
    sepol_handle_t *handle,
    struct msg_non_variadic_callback_data *data
) {
    sepol_msg_set_callback(handle, callback, data);
}
