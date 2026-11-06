/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_MODULE_LOAD_FILTER
#define __KSU_H_MODULE_LOAD_FILTER

#include <linux/ptrace.h>
#include <linux/types.h>

extern char ksu_baka_block_modules[256];

long ksu_baka_module_load(int orig_nr, const struct pt_regs *regs, bool *handled);

#endif /* __KSU_H_MODULE_LOAD_FILTER */
