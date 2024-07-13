/*
 * SPDX-FileCopyrightText: 2024 Andrew Gunnerson
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include <stdint.h>

#include <sepol/policydb/avtab.h>

#ifdef __cplusplus
extern "C" {
#endif

int avtab_hash_wrapper(struct avtab_key *keyp, uint32_t mask);

#ifdef __cplusplus
}
#endif
