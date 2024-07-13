/*
 * SPDX-FileCopyrightText: 2024 Andrew Gunnerson
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include <stdint.h>

#include <sepol/policydb/ebitmap.h>

#ifdef __cplusplus
extern "C" {
#endif

unsigned int ebitmap_start_wrapper(const ebitmap_t *e, ebitmap_node_t **n);
void ebitmap_init_wrapper(ebitmap_t *e);
unsigned int ebitmap_next_wrapper(ebitmap_node_t **n, unsigned int bit);
int ebitmap_node_get_bit_wrapper(const ebitmap_node_t *n, unsigned int bit);

#ifdef __cplusplus
}
#endif
