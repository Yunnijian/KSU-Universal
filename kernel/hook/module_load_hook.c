// SPDX-License-Identifier: GPL-2.0
/*
 * Direct syscall-table hooks for init_module/finit_module.
 *
 * The module filters parse ELF data and may read a file, so they must not run
 * from the sys_enter tracepoint dispatcher: that context is not sleep-safe.
 * BakaSU and FinaSU both use direct syscall-table hooks for the same reason.
 */
#include <asm/unistd.h>

#include "hook/module_load_hook.h"
#include "hook/syscall_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_ops.h"

#ifdef __NR_init_module
static syscall_fn_t ksu_orig_init_module;

static long ksu_init_module_hook(const struct pt_regs *regs)
{
    const struct ksu_manager_ops *ops = ksu_manager_ops_current();
    bool handled = false;

    if (ops && ops->module_load) {
        long ret = ops->module_load(__NR_init_module, regs, &handled);

        if (handled)
            return ret;
    }

    return ksu_orig_init_module(regs);
}
#endif

#ifdef __NR_finit_module
static syscall_fn_t ksu_orig_finit_module;

static long ksu_finit_module_hook(const struct pt_regs *regs)
{
    const struct ksu_manager_ops *ops = ksu_manager_ops_current();
    bool handled = false;

    if (ops && ops->module_load) {
        long ret = ops->module_load(__NR_finit_module, regs, &handled);

        if (handled)
            return ret;
    }

    return ksu_orig_finit_module(regs);
}
#endif

void ksu_module_load_hook_init(void)
{
    if (!ksu_syscall_table) {
        pr_warn("module_load_hook: syscall table unavailable\n");
        return;
    }

#ifdef __NR_init_module
    ksu_syscall_table_hook(__NR_init_module, (syscall_fn_t)ksu_init_module_hook,
                           &ksu_orig_init_module);
#endif
#ifdef __NR_finit_module
    ksu_syscall_table_hook(__NR_finit_module, (syscall_fn_t)ksu_finit_module_hook,
                           &ksu_orig_finit_module);
#endif
}

void ksu_module_load_hook_exit(void)
{
#ifdef __NR_init_module
    ksu_syscall_table_unhook(__NR_init_module);
#endif
#ifdef __NR_finit_module
    ksu_syscall_table_unhook(__NR_finit_module);
#endif
}
