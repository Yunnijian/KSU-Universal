// SPDX-License-Identifier: GPL-2.0
/*
 * Static manager profiles for the universal build.
 *
 * Each entry mirrors the kernel a stock install of that manager would load:
 * the certificate identifies the APK, and the version/feature fields are what
 * the manager expects to read back from GET_INFO/GET_FULL_VERSION. Only the
 * active profile's surface is exposed; the other entries are still accepted
 * as switch targets through /proc/kernelsu_manager.
 */
#include <linux/kernel.h>
#include <linux/string.h>
#include "manager/manager_table.h"

static const struct ksu_manager_identity ksu_manager_identities[] = {
    {
        .package = "me.weishu.kernelsu",
        .cert_size = 0x033b,
        .cert_hash = "c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6",
        .version_code = 32707,
        .version_full = "v3.3.1-27-gdb6263d3",
        .version_tag = "v3.3.1",
        .hook_mode = "Tracepoint",
        .hook_type = "Tracepoint Syscall Redirect",
        .feature_max = 7,
        .profile = KSU_MANAGER_PROFILE_OFFICIAL,
    },
    {
        .package = "com.rifsxd.ksunext",
        .cert_size = 0x3e6,
        .cert_hash = "79e590113c4c4c0c222978e413a5faa801666957b1212a328e46c00c69821bf7",
        .version_code = 33442,
        .version_full = "v3.4.2-87-gda0b3f37",
        .version_tag = "v3.4.2",
        .hook_mode = "Tracepoint",
        .hook_type = "Tracepoint Syscall Redirect",
        .feature_max = 10004,
        .profile = KSU_MANAGER_PROFILE_NEXT,
    },
    {
        .package = "com.resukisu.resukisu",
        .cert_size = 0x377,
        .cert_hash = "d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64",
        .version_code = 35257,
        .version_full = "v4.2.0-rc3-516d3e87@BakaSU",
        .version_tag = "v4.2.0-rc3",
        .hook_mode = "Tracepoint",
        .hook_type = "Tracepoint Syscall Redirect",
        .feature_max = 7,
        .profile = KSU_MANAGER_PROFILE_BAKA,
    },
    {
        .package = "com.sukisu.ultra",
        .cert_size = 0x35c,
        .cert_hash = "947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef",
        .version_code = 41140,
        .version_full = "v4.3.0-r1-0a4c3132@main",
        .version_tag = "v4.3.0-r1",
        .hook_mode = "Tracepoint",
        .hook_type = "Tracepoint Syscall Redirect",
        .feature_max = 10004,
        .profile = KSU_MANAGER_PROFILE_SUKISU,
    },
    {
        .package = "me.yuki.fina",
        .cert_size = 0x2cc,
        .cert_hash = "2d89b50aaf1db013c2b6738f973f48b62ea21a3a8d7216bfec3521065d448458",
        .version_code = 33168,
        .version_full = "v1.4.5-a839ce2d@main",
        .version_tag = "v1.4.5",
        .hook_mode = "Tracepoint",
        .hook_type = "Tracepoint Syscall Redirect",
        .feature_max = 11,
        .profile = KSU_MANAGER_PROFILE_FINA,
    },
};

/* Dynamic Switching starts as KernelSU; the App may switch after late-load. */
static char ksu_active_manager[KSU_MAX_PACKAGE_NAME] = "me.weishu.kernelsu";

const struct ksu_manager_identity *ksu_manager_identity_for_package(const char *package)
{
    int i;

    if (!package || !*package)
        return NULL;

    for (i = 0; i < ARRAY_SIZE(ksu_manager_identities); i++) {
        if (!strcmp(package, ksu_manager_identities[i].package))
            return &ksu_manager_identities[i];
    }
    return NULL;
}

const struct ksu_manager_identity *ksu_manager_default_identity(void)
{
    return ksu_manager_identity_for_package("me.weishu.kernelsu");
}

bool ksu_manager_package_known(const char *package)
{
    return ksu_manager_identity_for_package(package) != NULL;
}

bool ksu_manager_package_active(const char *package)
{
    if (!ksu_manager_package_known(package))
        return false;
    return !strcmp(package, ksu_active_manager);
}

void ksu_manager_set_active(const char *package)
{
    if (!package || !ksu_manager_package_known(package)) {
        strscpy(ksu_active_manager, "me.weishu.kernelsu", sizeof(ksu_active_manager));
        return;
    }
    strscpy(ksu_active_manager, package, sizeof(ksu_active_manager));
}

const char *ksu_manager_get_active(void)
{
    return ksu_active_manager;
}

const struct ksu_manager_identity *ksu_manager_active_identity(void)
{
    const struct ksu_manager_identity *identity =
        ksu_manager_identity_for_package(ksu_active_manager);

    /* Dynamic Switching always starts as the official manager. */
    return identity ? identity : ksu_manager_default_identity();
}

__u32 ksu_manager_active_version(void)
{
    return ksu_manager_active_identity()->version_code;
}

const char *ksu_manager_active_full_version(void)
{
    return ksu_manager_active_identity()->version_full;
}

const char *ksu_manager_active_version_tag(void)
{
    return ksu_manager_active_identity()->version_tag;
}

const char *ksu_manager_active_hook_mode(void)
{
    return ksu_manager_active_identity()->hook_mode;
}

const char *ksu_manager_active_hook_type(void)
{
    return ksu_manager_active_identity()->hook_type;
}

__u32 ksu_manager_active_feature_max(void)
{
    return ksu_manager_active_identity()->feature_max;
}

bool ksu_manager_active_is_sukisu(void)
{
    return ksu_manager_active_identity()->profile == KSU_MANAGER_PROFILE_SUKISU;
}

enum ksu_manager_profile ksu_manager_active_profile(void)
{
    return ksu_manager_active_identity()->profile;
}

const char *ksu_manager_profile_name(enum ksu_manager_profile profile)
{
    switch (profile) {
    case KSU_MANAGER_PROFILE_SUKISU:
        return "SukiSU";
    case KSU_MANAGER_PROFILE_OFFICIAL:
        return "KernelSU";
    case KSU_MANAGER_PROFILE_NEXT:
        return "KernelSU-Next";
    case KSU_MANAGER_PROFILE_BAKA:
        return "BakaSU";
    case KSU_MANAGER_PROFILE_FINA:
        return "FinaSU";
    }
    return "unknown";
}
