// SPDX-License-Identifier: GPL-2.0
#ifndef __KSU_H_MANAGER_TABLE
#define __KSU_H_MANAGER_TABLE

#include <linux/types.h>
#include "uapi/app_profile.h"

enum ksu_manager_profile {
    KSU_MANAGER_PROFILE_SUKISU = 0,
    KSU_MANAGER_PROFILE_OFFICIAL = 1,
    KSU_MANAGER_PROFILE_NEXT = 2,
    KSU_MANAGER_PROFILE_BAKA = 3,
    KSU_MANAGER_PROFILE_FINA = 4,
};

struct ksu_manager_identity {
    const char *package;
    unsigned int cert_size;
    const char *cert_hash;
    __u32 version_code;
    const char *version_full;
    const char *version_tag;
    const char *hook_mode;
    const char *hook_type;
    __u32 feature_max;
    enum ksu_manager_profile profile;
};

const struct ksu_manager_identity *ksu_manager_identity_for_package(const char *package);
bool ksu_manager_package_known(const char *package);
bool ksu_manager_package_active(const char *package);
void ksu_manager_set_active(const char *package);
const char *ksu_manager_get_active(void);
const struct ksu_manager_identity *ksu_manager_active_identity(void);
const struct ksu_manager_identity *ksu_manager_default_identity(void);
__u32 ksu_manager_active_version(void);
const char *ksu_manager_active_full_version(void);
const char *ksu_manager_active_version_tag(void);
const char *ksu_manager_active_hook_mode(void);
const char *ksu_manager_active_hook_type(void);
__u32 ksu_manager_active_feature_max(void);
bool ksu_manager_active_is_sukisu(void);
enum ksu_manager_profile ksu_manager_active_profile(void);
const char *ksu_manager_profile_name(enum ksu_manager_profile profile);
int ksu_manager_signature_index_for_package(const char *package);

#endif /* __KSU_H_MANAGER_TABLE */
