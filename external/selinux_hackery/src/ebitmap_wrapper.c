/*
 * SPDX-FileCopyrightText: 2024 Andrew Gunnerson
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "ebitmap_wrapper.h"

#include "ebitmap.c"

unsigned int ebitmap_start_wrapper(const ebitmap_t *e, ebitmap_node_t **n) {
    return ebitmap_start(e, n);
}

void ebitmap_init_wrapper(ebitmap_t *e) {
    ebitmap_init(e);
}

unsigned int ebitmap_next_wrapper(ebitmap_node_t **n, unsigned int bit) {
    return ebitmap_next(n, bit);
}

int ebitmap_node_get_bit_wrapper(const ebitmap_node_t *n, unsigned int bit) {
    return ebitmap_node_get_bit(n, bit);
}
