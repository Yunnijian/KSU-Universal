// SPDX-License-Identifier: GPL-2.0
/*
 * Runtime primary-manager switch for the static dual-manager build.
 *
 * The node accepts exactly:
 *
 *     <package> <uid> <base.apk path>
 *
 * Both package and certificate are matched against the built-in static table.
 * Only root may write it. A successful write sets ksu_manager_appid to the
 * supplied uid's appid, making that manager the primary one for this boot.
 */
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kstrtox.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/uidgid.h>
#include <linux/uaccess.h>

#include "klog.h" // IWYU pragma: keep
#include "manager/apk_sign.h"
#include "manager/manager_identity.h"
#include "manager/manager_switch.h"
#include "manager/manager_table.h"
#include "manager/throne_tracker.h"
#include "policy/feature.h"
#include "extension/extension.h"
#include "feature/netisolate.h"

#define KSU_MANAGER_SWITCH_MAX 512

static ssize_t ksu_manager_switch_write(struct file *file, const char __user *ubuf,
                                        size_t count, loff_t *ppos)
{
    char buf[KSU_MANAGER_SWITCH_MAX];
    char *cursor;
    char *package;
    char *uid_text;
    char *apk_path;
    char apk_dir[KSU_MANAGER_SWITCH_MAX];
    char apk_pkg[KSU_MAX_PACKAGE_NAME];
    const char *slash;
    size_t dir_len;
    unsigned int uid;
    const struct ksu_manager_identity *identity;

    if (!uid_eq(current_euid(), GLOBAL_ROOT_UID))
        return -EPERM;
    if (!count || count >= sizeof(buf))
        return -EINVAL;
    if (copy_from_user(buf, ubuf, count))
        return -EFAULT;
    buf[count] = '\0';

    cursor = strstrip(buf);
    package = strsep(&cursor, " \t");
    uid_text = strsep(&cursor, " \t");
    apk_path = strsep(&cursor, " \t");
    if (!package || !*package || !uid_text || !*uid_text || !apk_path || !*apk_path)
        return -EINVAL;
    if (kstrtouint(uid_text, 10, &uid))
        return -EINVAL;

    identity = ksu_manager_identity_for_package(package);
    if (!identity)
        return -EINVAL;

    /* The APK must really belong to the claimed package, not only be signed
     * with its certificate: otherwise a root caller could hand another app's
     * uid the primary-manager appid together with a copied manager APK. */
    slash = strrchr(apk_path, '/');
    if (!slash)
        return -EINVAL;
    dir_len = slash - apk_path;
    if (!dir_len || dir_len >= sizeof(apk_dir))
        return -EINVAL;
    memcpy(apk_dir, apk_path, dir_len);
    apk_dir[dir_len] = '\0';
    if (get_pkg_from_apk_dir_path(apk_pkg, apk_dir) < 0 ||
        strcmp(apk_pkg, package))
        return -EINVAL;

    if (!ksu_check_apk_signature(apk_path, identity->cert_size, identity->cert_hash))
        return -EKEYREJECTED;

    ksu_manager_set_active(package);
    ksu_set_manager_appid(uid % KSU_PER_USER_RANGE);
    ksu_throne_tracker_invalidate_cache();
    if (identity->profile != KSU_MANAGER_PROFILE_FINA)
        ksu_netisolate_reset();
    if (!ksu_manager_active_is_sukisu()) {
        ksu_feature_reset_non_upstream();
        ksu_extension_reset_non_upstream();
    }
    pr_info("manager switch: primary=%s (%s) uid=%u\n", package,
            ksu_manager_profile_name(identity->profile), uid);
    return count;
}

static ssize_t ksu_manager_switch_read(struct file *file, char __user *ubuf,
                                       size_t count, loff_t *ppos)
{
    char buf[160];
    int len;

    if (!uid_eq(current_euid(), GLOBAL_ROOT_UID))
        return -EPERM;

    len = snprintf(buf, sizeof(buf), "%s %s %u %u\n",
                   ksu_manager_get_active(),
                   ksu_manager_profile_name(ksu_manager_active_profile()),
                   ksu_manager_active_version(),
                   ksu_manager_active_feature_max());
    if (len < 0)
        return -EINVAL;

    return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

static const struct proc_ops ksu_manager_switch_ops = {
    .proc_read = ksu_manager_switch_read,
    .proc_write = ksu_manager_switch_write,
};

static struct proc_dir_entry *ksu_manager_switch_entry;

int ksu_manager_switch_init(void)
{
    ksu_manager_switch_entry = proc_create("kernelsu_manager", 0600, NULL,
                                           &ksu_manager_switch_ops);
    if (!ksu_manager_switch_entry) {
        pr_err("manager switch: failed to create /proc/kernelsu_manager\n");
        return -ENOMEM;
    }
    return 0;
}

void ksu_manager_switch_exit(void)
{
    if (ksu_manager_switch_entry) {
        proc_remove(ksu_manager_switch_entry);
        ksu_manager_switch_entry = NULL;
    }
}
