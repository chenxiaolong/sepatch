/*
 * SPDX-FileCopyrightText: 2024 Andrew Gunnerson
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "policydb_wrapper.h"

#include "policydb.c"

int policydb_index_decls_wrapper(sepol_handle_t *handle, policydb_t *p) {
    return policydb_index_decls(handle, p);
}
