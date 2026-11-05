// SPDX-License-Identifier: GPL-2.0
#ifndef __KSU_H_PROFILE_DYNAMIC
#define __KSU_H_PROFILE_DYNAMIC

#include <linux/types.h>
#include "manager/profile_uapi.h"

bool ksu_fina_dynamic_is_enabled(void);
void ksu_fina_dynamic_set_enabled(bool enabled);
int ksu_fina_dynamic_set_signs(const struct ksu_fina_dynamic_manager_sign *signs, u32 count);
u32 ksu_fina_dynamic_get_apps(void __user *apps, u32 capacity, u32 *total);
int ksu_fina_dynamic_set_grants(const __u32 *appids, u32 count);
bool ksu_fina_dynamic_uid_authorized(uid_t uid);

bool ksu_baka_dynamic_get(u32 *size, char hash[65]);
int ksu_baka_dynamic_set(u32 size, const char *hash);
void ksu_baka_dynamic_wipe(void);
u32 ksu_baka_dynamic_get_appids(u32 *appids, u32 capacity);
bool ksu_baka_dynamic_uid_authorized(uid_t uid);

/* Profile-dispatched check used by the manager authorization paths. */
bool ksu_profile_dynamic_uid_authorized(uid_t uid);

/* Shared helpers used by apk_sign.c and throne_tracker.c. */
bool ksu_profile_dynamic_has_state(void);
bool ksu_profile_dynamic_match(unsigned int cert_size, const char *hash);
bool ksu_profile_dynamic_apk_match(char *path);
void ksu_profile_dynamic_register_uid(const char *package, uid_t uid, char *apk_path);

void ksu_profile_dynamic_reset(void);

#endif /* __KSU_H_PROFILE_DYNAMIC */
