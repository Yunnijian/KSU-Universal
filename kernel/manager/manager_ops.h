/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_MANAGER_OPS
#define __KSU_H_MANAGER_OPS

#include <linux/ptrace.h>
#include <linux/types.h>

#include "manager/manager_table.h"

/*
 * Per-profile control flow. Only behavior that differs between manager
 * families lives here; shared low-level helpers stay in their feature files.
 *
 * module_load: return *handled = true to use the returned value, or leave
 * *handled = false to let the dispatcher call the original syscall.
 */
struct ksu_manager_ops {
    const char *name;
    int (*setuid)(uid_t old_uid, uid_t new_uid);
    int (*umount)(uid_t old_uid, uid_t new_uid);
    long (*module_load)(int orig_nr, const struct pt_regs *regs, bool *handled);
    void (*dynamic_load)(void);
    void (*dynamic_save)(void);
    void (*activate)(void);
    void (*deactivate)(void);
};

const struct ksu_manager_ops *ksu_manager_ops_current(void);
void ksu_manager_ops_select(enum ksu_manager_profile profile);

#endif /* __KSU_H_MANAGER_OPS */
