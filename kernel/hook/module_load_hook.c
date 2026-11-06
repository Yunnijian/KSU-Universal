// SPDX-License-Identifier: GPL-2.0
/*
 * Shared init_module/finit_module dispatcher. The active manager ops decides
 * whether the profile wants to filter the load; otherwise the original
 * syscall runs untouched.
 */
#include <asm/unistd.h>

#include "hook/module_load_hook.h"
#include "hook/syscall_hook.h"
#include "manager/manager_ops.h"

static long ksu_module_load_hook_fn(int orig_nr, const struct pt_regs *regs)
{
    const struct ksu_manager_ops *ops = ksu_manager_ops_current();
    bool handled = false;

    if (ops && ops->module_load) {
        long ret = ops->module_load(orig_nr, regs, &handled);

        if (handled)
            return ret;
    }

    return ksu_syscall_table[orig_nr](regs);
}

void ksu_module_load_hook_init(void)
{
#ifdef __NR_init_module
    ksu_register_syscall_hook(__NR_init_module, ksu_module_load_hook_fn);
#endif
#ifdef __NR_finit_module
    ksu_register_syscall_hook(__NR_finit_module, ksu_module_load_hook_fn);
#endif
}

void ksu_module_load_hook_exit(void)
{
#ifdef __NR_init_module
    ksu_unregister_syscall_hook(__NR_init_module);
#endif
#ifdef __NR_finit_module
    ksu_unregister_syscall_hook(__NR_finit_module);
#endif
}
