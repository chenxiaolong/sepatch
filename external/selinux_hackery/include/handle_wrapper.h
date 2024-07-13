/*
 * SPDX-FileCopyrightText: 2024 Andrew Gunnerson
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include <sepol/debug.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (msg_non_variadic_callback)(void *varg, sepol_handle_t *handle, const char *msg);

struct msg_non_variadic_callback_data {
    msg_non_variadic_callback *func;
    void *data;
};

void sepol_msg_set_non_variadic_callback(
    sepol_handle_t *handle,
    struct msg_non_variadic_callback_data *data
);

#ifdef __cplusplus
}
#endif
