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
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "klog.h" // IWYU pragma: keep
#include "manager/apk_sign.h"
#include "manager/manager_identity.h"
#include "manager/manager_table.h"
#include "manager/profile_dynamic.h"

#define FINA_MAX_SIGNS 64
#define FINA_MAX_APPS 64
#define BAKA_MAX_APPS 64

struct fina_sign {
    u32 size;
    u32 version_code;
    char hash[65];
};

struct fina_app {
    u32 appid;
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
static u32 baka_size;
static char baka_hash[65];
static bool baka_set;
static u32 baka_appids[BAKA_MAX_APPS];
static u32 baka_app_count;

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

static void fina_add_app_locked(u32 appid, u32 flags)
{
    struct fina_app *app = fina_find_app_locked(appid);

    if (app) {
        app->flags |= flags;
        return;
    }
    if (fina_app_count == FINA_MAX_APPS)
        return;
    fina_apps[fina_app_count].appid = appid;
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
    mutex_unlock(&profile_dynamic_lock);
    return 0;
}

u32 ksu_fina_dynamic_get_apps(void __user *apps, u32 capacity, u32 *total)
{
    u32 count;
    u32 i;
    struct ksu_fina_dynamic_manager_app {
        u32 appid;
        u32 flags;
    } entry;

    mutex_lock(&profile_dynamic_lock);
    *total = fina_app_count;
    count = min(capacity, fina_app_count);
    for (i = 0; i < count; i++) {
        entry.appid = fina_apps[i].appid;
        entry.flags = fina_apps[i].flags;
        if (copy_to_user((char __user *)apps + i * sizeof(entry), &entry, sizeof(entry))) {
            mutex_unlock(&profile_dynamic_lock);
            return 0;
        }
    }
    mutex_unlock(&profile_dynamic_lock);
    return count;
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
        fina_add_app_locked(appids[i], FINA_APP_TRUSTED | FINA_APP_GRANTED);
    mutex_unlock(&profile_dynamic_lock);
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
        if (fina_apps[i].appid == appid && (fina_apps[i].flags & FINA_APP_GRANTED)) {
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
    mutex_lock(&profile_dynamic_lock);
    baka_size = 0;
    baka_hash[0] = '\0';
    baka_set = false;
    baka_app_count = 0;
    mutex_unlock(&profile_dynamic_lock);
}

u32 ksu_baka_dynamic_get_appids(u32 *appids, u32 capacity)
{
    u32 count;

    mutex_lock(&profile_dynamic_lock);
    count = min(capacity, baka_app_count);
    if (count)
        memcpy(appids, baka_appids, count * sizeof(*appids));
    mutex_unlock(&profile_dynamic_lock);
    return count;
}

bool ksu_baka_dynamic_uid_authorized(uid_t uid){
    u32 appid = uid % KSU_PER_USER_RANGE;
    u32 i;
    bool found = false;

    if (ksu_manager_active_profile() != KSU_MANAGER_PROFILE_BAKA)
        return false;
    mutex_lock(&profile_dynamic_lock);
    for (i = 0; i < baka_app_count; i++) {
        if (baka_appids[i] == appid) {
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
        mutex_lock(&profile_dynamic_lock);
        fina_add_app_locked(uid % KSU_PER_USER_RANGE, FINA_APP_TRUSTED | FINA_APP_GRANTED);
        mutex_unlock(&profile_dynamic_lock);
    } else if (ksu_manager_active_profile() == KSU_MANAGER_PROFILE_BAKA) {
        u32 appid = uid % KSU_PER_USER_RANGE;
        u32 i;

        mutex_lock(&profile_dynamic_lock);
        for (i = 0; i < baka_app_count; i++) {
            if (baka_appids[i] == appid) {
                mutex_unlock(&profile_dynamic_lock);
                return;
            }
        }
        if (baka_app_count < BAKA_MAX_APPS)
            baka_appids[baka_app_count++] = appid;
        mutex_unlock(&profile_dynamic_lock);
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
    baka_size = 0;
    baka_hash[0] = '\0';
    baka_set = false;
    baka_app_count = 0;
    mutex_unlock(&profile_dynamic_lock);
}
