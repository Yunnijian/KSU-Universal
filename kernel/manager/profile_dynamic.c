// SPDX-License-Identifier: GPL-2.0
/*
 * Dynamic-manager state for the BakaSU and FinaSU profiles.
 *
 * The universal module keeps one primary manager (the App's hot-switch
 * target), but BakaSU/FinaSU also let users authorize additional APK
 * signatures as managers. This file stores that per-profile state and
 * answers the profile's private ioctls. Heavy optional features that are
 * not required for jailbreak (netisolate, per-process UTS view) are not
 * implemented; their ioctls return -EOPNOTSUPP.
 */
#include <linux/ctype.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "manager/apk_sign.h"
#include "manager/manager_identity.h"
#include "manager/manager_table.h"
#include "manager/profile_dynamic.h"

#define FINA_MAX_SIGNS 64
#define FINA_MAX_APPS 64
#define BAKA_MAX_APPS 64

#define FINA_DYNAMIC_MANAGER_FILE "/data/adb/ksu/dynamic_manager"
#define FINA_DYNAMIC_MAGIC 0x4d554b53 /* KSUM */
#define FINA_DYNAMIC_VERSION 2
#define FINA_DYNAMIC_FLAG_GRANTS_STRICT (1U << 0)

struct fina_disk_sign {
    u32 size;
    u32 version_code;
    char hash[65];
};

struct fina_sign {
    u32 size;
    u32 version_code;
    char hash[65];
};

struct fina_app {
    u32 appid;
    u32 version_code;
    u32 flags;
};

#define FINA_APP_TRUSTED (1U << 1)
#define FINA_APP_GRANTED (1U << 2)

static DEFINE_MUTEX(profile_dynamic_lock);
static struct fina_sign fina_signs[FINA_MAX_SIGNS];
static u32 fina_sign_count;
static struct fina_app fina_apps[FINA_MAX_APPS];
static u32 fina_app_count;
static bool fina_dynamic_enabled = true;
static bool fina_grants_strict;
static u32 baka_size;
static char baka_hash[65];
static bool baka_set;
static struct ksu_baka_manager_record baka_managers[BAKA_MAX_APPS];
static u32 baka_manager_count;

static bool hash_valid(const char *hash)
{
    int i;

    if (strnlen(hash, 65) != 64)
        return false;
    for (i = 0; i < 64; i++) {
        if (!isxdigit(hash[i]))
            return false;
    }
    return true;
}

static struct fina_app *fina_find_app_locked(u32 appid)
{
    u32 i;

    for (i = 0; i < fina_app_count; i++) {
        if (fina_apps[i].appid == appid)
            return &fina_apps[i];
    }
    return NULL;
}

static void fina_add_app_locked(u32 appid, u32 version_code, u32 flags)
{
    struct fina_app *app = fina_find_app_locked(appid);

    if (app) {
        app->flags |= flags;
        if (version_code)
            app->version_code = version_code;
        return;
    }
    if (fina_app_count == FINA_MAX_APPS)
        return;
    fina_apps[fina_app_count].appid = appid;
    fina_apps[fina_app_count].version_code = version_code;
    fina_apps[fina_app_count].flags = flags;
    fina_app_count++;
}

bool ksu_fina_dynamic_is_enabled(void)
{
    return READ_ONCE(fina_dynamic_enabled);
}

void ksu_fina_dynamic_set_enabled(bool enabled)
{
    WRITE_ONCE(fina_dynamic_enabled, enabled);
}

static void ksu_fina_dynamic_save_locked(struct file *fp)
{
    struct fina_disk_sign disk;
    loff_t off = 0;
    u32 magic = FINA_DYNAMIC_MAGIC;
    u32 version = FINA_DYNAMIC_VERSION;
    u32 flags = 0;
    u32 grant_count = 0;
    u32 i;

    if (fina_grants_strict)
        flags |= FINA_DYNAMIC_FLAG_GRANTS_STRICT;

    for (i = 0; i < fina_app_count; i++) {
        if (fina_apps[i].flags & FINA_APP_GRANTED)
            grant_count++;
    }

    if (kernel_write(fp, &magic, sizeof(magic), &off) != sizeof(magic) ||
        kernel_write(fp, &version, sizeof(version), &off) != sizeof(version) ||
        kernel_write(fp, &flags, sizeof(flags), &off) != sizeof(flags) ||
        kernel_write(fp, &grant_count, sizeof(grant_count), &off) != sizeof(grant_count))
        return;

    for (i = 0; i < fina_app_count; i++) {
        u32 appid;

        if (!(fina_apps[i].flags & FINA_APP_GRANTED))
            continue;
        appid = fina_apps[i].appid;
        if (kernel_write(fp, &appid, sizeof(appid), &off) != sizeof(appid))
            return;
    }

    for (i = 0; i < fina_sign_count; i++) {
        memset(&disk, 0, sizeof(disk));
        disk.size = fina_signs[i].size;
        disk.version_code = fina_signs[i].version_code;
        strscpy(disk.hash, fina_signs[i].hash, sizeof(disk.hash));
        if (kernel_write(fp, &disk, sizeof(disk), &off) != sizeof(disk))
            return;
    }
}

void ksu_fina_dynamic_save(void)
{
    const struct cred *saved;
    struct file *fp;

    saved = override_creds(ksu_cred);
    fp = filp_open(FINA_DYNAMIC_MANAGER_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(fp)) {
        pr_err("dynamic_manager: create file failed: %ld\n", PTR_ERR(fp));
        revert_creds(saved);
        return;
    }

    mutex_lock(&profile_dynamic_lock);
    ksu_fina_dynamic_save_locked(fp);
    mutex_unlock(&profile_dynamic_lock);

    filp_close(fp, NULL);
    revert_creds(saved);
}

void ksu_fina_dynamic_load(void)
{
    const struct cred *saved;
    struct file *fp;
    struct fina_disk_sign disk;
    u32 grants[FINA_MAX_APPS];
    u32 magic, version, flags = 0, grant_count = 0;
    loff_t off = 0;
    u32 i;

    saved = override_creds(ksu_cred);
    fp = filp_open(FINA_DYNAMIC_MANAGER_FILE, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        pr_info("dynamic_manager: no persisted list: %ld\n", PTR_ERR(fp));
        revert_creds(saved);
        return;
    }

    if (kernel_read(fp, &magic, sizeof(magic), &off) != sizeof(magic) ||
        magic != FINA_DYNAMIC_MAGIC ||
        kernel_read(fp, &version, sizeof(version), &off) != sizeof(version) ||
        (version != 1 && version != FINA_DYNAMIC_VERSION))
        goto out;

    if (version >= 2) {
        if (kernel_read(fp, &flags, sizeof(flags), &off) != sizeof(flags) ||
            kernel_read(fp, &grant_count, sizeof(grant_count), &off) != sizeof(grant_count) ||
            grant_count > FINA_MAX_APPS)
            goto out;

        for (i = 0; i < grant_count; i++) {
            if (kernel_read(fp, &grants[i], sizeof(grants[i]), &off) != sizeof(grants[i]) ||
                grants[i] >= KSU_PER_USER_RANGE)
                goto out;
        }
    }

    mutex_lock(&profile_dynamic_lock);
    memset(fina_signs, 0, sizeof(fina_signs));
    fina_sign_count = 0;
    memset(fina_apps, 0, sizeof(fina_apps));
    fina_app_count = 0;
    fina_grants_strict = (flags & FINA_DYNAMIC_FLAG_GRANTS_STRICT) != 0;

    for (i = 0; i < grant_count; i++)
        fina_add_app_locked(grants[i], 0, FINA_APP_GRANTED);

    while (fina_sign_count < FINA_MAX_SIGNS &&
           kernel_read(fp, &disk, sizeof(disk), &off) == sizeof(disk)) {
        if (!disk.size || !hash_valid(disk.hash))
            continue;
        fina_signs[fina_sign_count].size = disk.size;
        fina_signs[fina_sign_count].version_code = disk.version_code;
        strscpy(fina_signs[fina_sign_count].hash, disk.hash,
                sizeof(fina_signs[fina_sign_count].hash));
        fina_sign_count++;
    }
    mutex_unlock(&profile_dynamic_lock);

    pr_info("dynamic_manager: loaded %u signatures, %u grants\n",
            fina_sign_count, grant_count);

out:
    filp_close(fp, NULL);
    revert_creds(saved);
}

int ksu_fina_dynamic_set_signs(const struct ksu_fina_dynamic_manager_sign *signs, u32 count)
{
    u32 i;

    if (count > FINA_MAX_SIGNS)
        return -EINVAL;
    for (i = 0; i < count; i++) {
        if (signs[i].size < 0x100 || signs[i].size > 0x1000 ||
            !hash_valid(signs[i].hash))
            return -EINVAL;
    }

    mutex_lock(&profile_dynamic_lock);
    fina_sign_count = count;
    if (count)
        memcpy(fina_signs, signs, count * sizeof(*signs));
    for (i = 0; i < fina_app_count; i++) {
        fina_apps[i].flags &= ~FINA_APP_TRUSTED;
        fina_apps[i].version_code = 0;
    }
    mutex_unlock(&profile_dynamic_lock);
    ksu_fina_dynamic_save();
    return 0;
}

u32 ksu_fina_dynamic_get_apps(void __user *apps, u32 capacity, u32 *total)
{
    u32 count = 0;
    u32 i;
    struct ksu_fina_dynamic_manager_app {
        u32 appid;
        u32 flags;
    } entry;

    mutex_lock(&profile_dynamic_lock);
    for (i = 0; i < fina_app_count; i++) {
        if (!fina_apps[i].flags)
            continue;
        if (count < capacity) {
            entry.appid = fina_apps[i].appid;
            entry.flags = fina_apps[i].flags;
            if (copy_to_user((char __user *)apps + count * sizeof(entry), &entry, sizeof(entry))) {
                mutex_unlock(&profile_dynamic_lock);
                return count;
            }
        }
        count++;
    }
    *total = count;
    mutex_unlock(&profile_dynamic_lock);
    return min(capacity, count);
}

int ksu_fina_dynamic_set_grants(const __u32 *appids, u32 count)
{
    u32 i;

    if (count > FINA_MAX_APPS)
        return -EINVAL;

    mutex_lock(&profile_dynamic_lock);
    for (i = 0; i < fina_app_count; i++)
        fina_apps[i].flags &= ~FINA_APP_GRANTED;
    for (i = 0; i < count; i++)
        fina_add_app_locked(appids[i], 0, FINA_APP_GRANTED);
    fina_grants_strict = true;
    mutex_unlock(&profile_dynamic_lock);
    ksu_fina_dynamic_save();
    return 0;
}

bool ksu_fina_dynamic_uid_authorized(uid_t uid)
{
    u32 appid = uid % KSU_PER_USER_RANGE;
    u32 i;
    bool found = false;

    if (ksu_manager_active_profile() != KSU_MANAGER_PROFILE_FINA)
        return false;
    mutex_lock(&profile_dynamic_lock);
    for (i = 0; i < fina_app_count; i++) {
        if (fina_apps[i].appid == appid &&
            (fina_apps[i].flags & FINA_APP_TRUSTED) &&
            ((fina_apps[i].flags & FINA_APP_GRANTED) || !fina_grants_strict)) {
            found = true;
            break;
        }
    }
    mutex_unlock(&profile_dynamic_lock);
    return found;
}

bool ksu_baka_dynamic_get(u32 *size, char hash[65])
{
    bool set;

    mutex_lock(&profile_dynamic_lock);
    set = baka_set;
    if (set) {
        *size = baka_size;
        memcpy(hash, baka_hash, sizeof(baka_hash));
    }
    mutex_unlock(&profile_dynamic_lock);
    return set;
}

int ksu_baka_dynamic_set(u32 size, const char *hash)
{
    if (size < 0x100 || size > 0x1000 || !hash_valid(hash))
        return -EINVAL;
    mutex_lock(&profile_dynamic_lock);
    baka_size = size;
    memcpy(baka_hash, hash, 64);
    baka_hash[64] = '\0';
    baka_set = true;
    mutex_unlock(&profile_dynamic_lock);
    return 0;
}

void ksu_baka_dynamic_wipe(void)
{
    u32 i, out = 0;

    mutex_lock(&profile_dynamic_lock);
    baka_size = 0;
    baka_hash[0] = '\0';
    baka_set = false;
    for (i = 0; i < baka_manager_count; i++) {
        if (baka_managers[i].signature_index != 255)
            baka_managers[out++] = baka_managers[i];
    }
    baka_manager_count = out;
    mutex_unlock(&profile_dynamic_lock);
}

void ksu_baka_register_manager(u32 appid, u8 signature_index)
{
    u32 i;

    mutex_lock(&profile_dynamic_lock);
    for (i = 0; i < baka_manager_count; i++) {
        if (baka_managers[i].appid == appid) {
            baka_managers[i].signature_index = signature_index;
            mutex_unlock(&profile_dynamic_lock);
            return;
        }
    }
    if (baka_manager_count < BAKA_MAX_APPS) {
        baka_managers[baka_manager_count].appid = appid;
        baka_managers[baka_manager_count].signature_index = signature_index;
        baka_manager_count++;
    }
    mutex_unlock(&profile_dynamic_lock);
}

u32 ksu_baka_get_managers(struct ksu_baka_manager_record *records, u32 capacity)
{
    u32 count;

    mutex_lock(&profile_dynamic_lock);
    count = min(capacity, baka_manager_count);
    if (count)
        memcpy(records, baka_managers, count * sizeof(*records));
    mutex_unlock(&profile_dynamic_lock);
    return count;
}

bool ksu_baka_dynamic_uid_authorized(uid_t uid)
{
    u32 appid = uid % KSU_PER_USER_RANGE;
    u32 i;
    bool found = false;

    if (ksu_manager_active_profile() != KSU_MANAGER_PROFILE_BAKA)
        return false;
    mutex_lock(&profile_dynamic_lock);
    for (i = 0; i < baka_manager_count; i++) {
        if (baka_managers[i].appid == appid) {
            found = true;
            break;
        }
    }
    mutex_unlock(&profile_dynamic_lock);
    return found;
}

bool ksu_fina_dynamic_version_code(uid_t uid, u32 *version)
{
    u32 appid = uid % KSU_PER_USER_RANGE;
    u32 i;
    bool found = false;

    if (!version || ksu_manager_active_profile() != KSU_MANAGER_PROFILE_FINA)
        return false;
    mutex_lock(&profile_dynamic_lock);
    for (i = 0; i < fina_app_count; i++) {
        if (fina_apps[i].appid == appid &&
            (fina_apps[i].flags & FINA_APP_TRUSTED) &&
            fina_apps[i].version_code) {
            *version = fina_apps[i].version_code;
            found = true;
            break;
        }
    }
    mutex_unlock(&profile_dynamic_lock);
    return found;
}

bool ksu_profile_dynamic_uid_authorized(uid_t uid)
{
    switch (ksu_manager_active_profile()) {
    case KSU_MANAGER_PROFILE_FINA:
        return ksu_fina_dynamic_uid_authorized(uid);
    case KSU_MANAGER_PROFILE_BAKA:
        return ksu_baka_dynamic_uid_authorized(uid);
    default:
        return false;
    }
}

static bool fina_sign_matches(unsigned int cert_size, const char *hash)
{
    u32 i;
    bool found = false;

    mutex_lock(&profile_dynamic_lock);
    for (i = 0; i < fina_sign_count; i++) {
        if (fina_signs[i].size == cert_size && !strcmp(fina_signs[i].hash, hash)) {
            found = true;
            break;
        }
    }
    mutex_unlock(&profile_dynamic_lock);
    return found;
}

bool ksu_profile_dynamic_has_state(void)
{
    switch (ksu_manager_active_profile()) {
    case KSU_MANAGER_PROFILE_FINA:
        return fina_dynamic_enabled && READ_ONCE(fina_sign_count) != 0;
    case KSU_MANAGER_PROFILE_BAKA:
        return READ_ONCE(baka_set);
    default:
        return false;
    }
}

bool ksu_profile_dynamic_match(unsigned int cert_size, const char *hash)
{
    switch (ksu_manager_active_profile()) {
    case KSU_MANAGER_PROFILE_FINA:
        return fina_dynamic_enabled && fina_sign_matches(cert_size, hash);
    case KSU_MANAGER_PROFILE_BAKA: {
        bool found;

        mutex_lock(&profile_dynamic_lock);
        found = baka_set && baka_size == cert_size && !strcmp(baka_hash, hash);
        mutex_unlock(&profile_dynamic_lock);
        return found;
    }
    default:
        return false;
    }
}

static bool fina_dynamic_apk_version(char *path, u32 *version)
{
    unsigned int i;

    if (!version)
        return false;
    mutex_lock(&profile_dynamic_lock);
    for (i = 0; i < fina_sign_count; i++) {
        if (ksu_check_apk_signature(path, fina_signs[i].size, fina_signs[i].hash)) {
            *version = fina_signs[i].version_code;
            mutex_unlock(&profile_dynamic_lock);
            return true;
        }
    }
    mutex_unlock(&profile_dynamic_lock);
    return false;
}

bool ksu_profile_dynamic_apk_match(char *path)
{
    unsigned int i;

    switch (ksu_manager_active_profile()) {
    case KSU_MANAGER_PROFILE_FINA:
        mutex_lock(&profile_dynamic_lock);
        for (i = 0; i < fina_sign_count; i++) {
            if (ksu_check_apk_signature(path, fina_signs[i].size, fina_signs[i].hash)) {
                mutex_unlock(&profile_dynamic_lock);
                return true;
            }
        }
        mutex_unlock(&profile_dynamic_lock);
        return false;
    case KSU_MANAGER_PROFILE_BAKA: {
        bool found;
        u32 size;
        char hash[65];

        if (!ksu_baka_dynamic_get(&size, hash))
            return false;
        found = ksu_check_apk_signature(path, size, hash);
        return found;
    }
    default:
        return false;
    }
}

void ksu_profile_dynamic_register_uid(const char *package, uid_t uid, char *apk_path)
{
    (void)package;

    if (!ksu_profile_dynamic_apk_match(apk_path))
        return;

    if (ksu_manager_active_profile() == KSU_MANAGER_PROFILE_FINA) {
        u32 version = 0;

        fina_dynamic_apk_version(apk_path, &version);
        mutex_lock(&profile_dynamic_lock);
        fina_add_app_locked(uid % KSU_PER_USER_RANGE, version, FINA_APP_TRUSTED);
        mutex_unlock(&profile_dynamic_lock);
    } else if (ksu_manager_active_profile() == KSU_MANAGER_PROFILE_BAKA) {
        ksu_baka_register_manager(uid % KSU_PER_USER_RANGE, 255);
    }
}

void ksu_profile_dynamic_reset(void)
{
    mutex_lock(&profile_dynamic_lock);
    memset(fina_signs, 0, sizeof(fina_signs));
    fina_sign_count = 0;
    memset(fina_apps, 0, sizeof(fina_apps));
    fina_app_count = 0;
    fina_dynamic_enabled = true;
    fina_grants_strict = false;
    baka_size = 0;
    baka_hash[0] = '\0';
    baka_set = false;
    baka_manager_count = 0;
    mutex_unlock(&profile_dynamic_lock);
}
