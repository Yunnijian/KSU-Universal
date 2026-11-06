/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_FINA_MODULE_FILTER
#define __KSU_H_FINA_MODULE_FILTER

#include <linux/ptrace.h>
#include <linux/types.h>

long ksu_fina_module_load(int orig_nr, const struct pt_regs *regs, bool *handled);

#endif /* __KSU_H_FINA_MODULE_FILTER */
