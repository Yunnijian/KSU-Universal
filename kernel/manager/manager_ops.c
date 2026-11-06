// SPDX-License-Identifier: GPL-2.0
/*
 * Per-profile operation tables.
 *
 * The active table is swapped only by /proc/kernelsu_manager. Hot paths read
 * the pointer once; the tables themselves are static and never modified.
 */
#include <linux/compiler.h>

#include "feature/baka_compat.h"
#include "feature/fina_module_filter.h"
#include "feature/kernel_umount.h"
#include "feature/module_load_filter.h"
#include "hook/setuid_hook.h"
#include "manager/profile_dynamic.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_ops.h"
#include "manager/manager_table.h"

static const struct ksu_manager_ops ksu_default_ops = {
    .name = "default",
    .setuid = ksu_setuid_default,
    .umount = ksu_handle_umount,
};

static const struct ksu_manager_ops ksu_baka_ops = {
    .name = "baka",
    .setuid = ksu_baka_setuid,
    .umount = ksu_handle_umount_baka,
    .module_load = ksu_baka_module_load,
    .deactivate = ksu_baka_deactivate,
};

static const struct ksu_manager_ops ksu_fina_ops = {
    .name = "fina",
    .setuid = ksu_setuid_default,
    .umount = ksu_handle_umount,
    .module_load = ksu_fina_module_load,
    .dynamic_load = ksu_fina_dynamic_load,
    .dynamic_save = ksu_fina_dynamic_save,
    .activate = ksu_fina_dynamic_load,
    .deactivate = ksu_fina_dynamic_save,
};

/* Next keeps the default table until a difference is verified. */
static const struct ksu_manager_ops *ksu_ops_for_profile(enum ksu_manager_profile profile)
{
    switch (profile) {
    case KSU_MANAGER_PROFILE_BAKA:
        return &ksu_baka_ops;
    case KSU_MANAGER_PROFILE_FINA:
        return &ksu_fina_ops;
    case KSU_MANAGER_PROFILE_NEXT:
    case KSU_MANAGER_PROFILE_OFFICIAL:
    case KSU_MANAGER_PROFILE_SUKISU:
    default:
        return &ksu_default_ops;
    }
}

static const struct ksu_manager_ops *ksu_active_ops = &ksu_default_ops;

const struct ksu_manager_ops *ksu_manager_ops_current(void)
{
    return READ_ONCE(ksu_active_ops);
}

void ksu_manager_ops_select(enum ksu_manager_profile profile)
{
    const struct ksu_manager_ops *ops = ksu_ops_for_profile(profile);

    WRITE_ONCE(ksu_active_ops, ops);
    pr_info("manager ops: %s\n", ops->name);
}
