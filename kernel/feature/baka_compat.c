// SPDX-License-Identifier: GPL-2.0
/*
 * BakaSU profile behavior that is independent of the optional inline SUSFS
 * frontend. The SUSFS implementation stays in the external guard module.
 */
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/seccomp.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "feature/baka_compat.h"
#include "feature/kernel_umount.h"
#include "hook/tp_marker.h"
#include "infra/seccomp_cache.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "policy/allowlist.h"
#include "selinux/selinux.h"
#include "supercall/supercall.h"

#define KSU_BAKA_KSUD_PATH "/data/adb/ksud"

static void ksu_baka_set_file_immutable(const char *path_name, bool immutable)
{
    struct path path;
    struct inode *inode;
    int error;

    error = kern_path(path_name, LOOKUP_FOLLOW, &path);
    if (error)
        return;

    inode = d_inode(path.dentry);

    error = mnt_want_write(path.mnt);
    if (error) {
        path_put(&path);
        return;
    }

    inode_lock(inode);
    if (immutable)
        inode->i_flags |= S_IMMUTABLE;
    else
        inode->i_flags &= ~S_IMMUTABLE;
    inode_unlock(inode);

    mnt_drop_write(path.mnt);
    path_put(&path);
}

static void ksu_baka_set_ksud_status(uid_t uid)
{
    if (is_uid_manager(uid)) {
        ksu_baka_set_file_immutable(KSU_BAKA_KSUD_PATH, false);
        pr_info("baka: mark /data/adb/ksud read write\n");
    } else {
        ksu_baka_set_file_immutable(KSU_BAKA_KSUD_PATH, true);
        pr_info("baka: mark /data/adb/ksud read only\n");
    }
}

int ksu_baka_setuid(uid_t old_uid, uid_t new_uid)
{
    /* BakaSU only acts on processes spawned by zygote. */
    if (!is_zygote(current_cred()))
        return 0;

    if (old_uid != new_uid)
        pr_info("baka: handle_setresuid from %d to %d\n", old_uid, new_uid);

    if (ksu_is_allow_uid_for_current(new_uid)) {
        if (current->seccomp.mode == SECCOMP_MODE_FILTER && current->seccomp.filter) {
            spin_lock_irq(&current->sighand->siglock);
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
            spin_unlock_irq(&current->sighand->siglock);
        }

        /* Baka's ksu_clear_current_proc_unprivillege(). */
        ksu_set_task_tracepoint_flag(current);

        if (is_uid_manager(new_uid)) {
            pr_info("baka: install fd for manager (uid=%d)\n", new_uid);
            ksu_baka_set_ksud_status(new_uid);
            ksu_install_fd();
        }
        return 0;
    }

    /* Baka's ksu_set_current_proc_unprivillege(). */
    ksu_clear_task_tracepoint_flag_if_needed(current);

    return ksu_handle_umount_baka(old_uid, new_uid);
}

void ksu_baka_deactivate(void)
{
    /* Leaving BakaSU must not leave ksud immutable for the next profile. */
    ksu_baka_set_file_immutable(KSU_BAKA_KSUD_PATH, false);
}
