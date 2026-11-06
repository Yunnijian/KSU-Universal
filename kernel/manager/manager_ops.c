// SPDX-License-Identifier: GPL-2.0
/*
 * Per-profile operation tables.
 *
 * The active table is swapped only by /proc/kernelsu_manager. Hot paths read
 * the pointer once; the tables themselves are static and never modified.
 */
#include <linux/compiler.h>

#include "feature/baka_compat.h"
#include "feature/kernel_umount.h"
#include "hook/setuid_hook.h"
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
    .deactivate = ksu_baka_deactivate,
};

/* Fina/Next tables are filled in once their compat paths are ported. */
static const struct ksu_manager_ops *ksu_ops_for_profile(enum ksu_manager_profile profile)
{
    switch (profile) {
    case KSU_MANAGER_PROFILE_BAKA:
        return &ksu_baka_ops;
    case KSU_MANAGER_PROFILE_FINA:
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
