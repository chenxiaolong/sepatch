/*
 * SPDX-FileCopyrightText: 2024 Andrew Gunnerson
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "avtab_wrapper.h"

#include "avtab.c"

int avtab_hash_wrapper(struct avtab_key *keyp, uint32_t mask) {
    return avtab_hash(keyp, mask);
}
