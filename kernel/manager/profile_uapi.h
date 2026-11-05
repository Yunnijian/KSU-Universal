// SPDX-License-Identifier: GPL-2.0
#ifndef __KSU_H_PROFILE_UAPI
#define __KSU_H_PROFILE_UAPI

#include <linux/ioctl.h>
#include <linux/types.h>

/* KernelSU-Next private commands. */
struct ksu_next_get_hook_mode_cmd {
    char mode[16];
};

struct ksu_next_get_version_tag_cmd {
    char tag[32];
};

#define KSU_IOCTL_NEXT_GET_HOOK_MODE _IOC(_IOC_READ, 'K', 98, 0)
#define KSU_IOCTL_NEXT_GET_VERSION_TAG _IOC(_IOC_READ, 'K', 99, 0)

/* BakaSU private commands. */
struct ksu_baka_dynamic_manager_cmd {
    __u8 operation;
    __u32 size;
    __u8 hash[64];
};

struct ksu_baka_manager_entry {
    __u32 uid;
    __u8 signature_index;
} __attribute__((packed));

struct ksu_baka_get_managers_cmd {
    __u16 count;
    __u16 total_count;
    struct ksu_baka_manager_entry managers[];
} __attribute__((packed));

struct ksu_baka_kernel_patch_cmd {
    __u8 type;
};

#define KSU_IOCTL_BAKA_DYNAMIC_MANAGER _IOC(_IOC_READ | _IOC_WRITE, 'K', 103, 0)
#define KSU_IOCTL_BAKA_GET_MANAGERS _IOC(_IOC_READ | _IOC_WRITE, 'K', 105, 0)
#define KSU_IOCTL_BAKA_GET_KERNEL_PATCH _IOC(_IOC_READ, 'K', 106, 0)

/* FinaSU private commands and structures. */
struct ksu_fina_get_full_version_cmd {
    char version_full[64];
};

struct ksu_fina_get_dynamic_managers_cmd {
    __u32 count;
    __u32 total_count;
    __aligned_u64 apps;
};

struct ksu_fina_dynamic_manager_sign {
    __u32 size;
    __u32 version_code;
    char hash[65];
};

struct ksu_fina_set_dynamic_managers_cmd {
    __u32 count;
    __aligned_u64 signs;
};

struct ksu_fina_uts_view_config {
    __u32 field_mask;
    __u32 state;
    __u32 generation;
    __u32 mode;
    __u32 matched;
    __u32 discarded;
    __u32 last_pid;
    __u32 last_uid;
    __u32 skip_not_app;
    __u32 skip_isolated;
    __u32 skip_not_target;
    __u32 skip_not_zygote;
    __u32 skip_private_ns;
    __u32 reserved0;
    __u32 unshare_failed;
    __u32 merge_missing_ns;
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
    __u32 target_count;
    __u32 target_uids[128];
};

struct ksu_fina_get_try_umount_cmd {
    __u32 size;
    __u32 count;
    __aligned_u64 entries;
};

#define KSU_IOCTL_FINA_SET_DYNAMIC_MANAGERS _IOC(_IOC_WRITE, 'K', 22, 0)
#define KSU_IOCTL_FINA_GET_DYNAMIC_MANAGERS \
    _IOWR('K', 23, struct ksu_fina_get_dynamic_managers_cmd)
#define KSU_IOCTL_FINA_SET_DYNAMIC_GRANTS _IOC(_IOC_WRITE, 'K', 24, 0)
#define KSU_IOCTL_FINA_GET_UTS_VIEW _IOWR('K', 25, struct ksu_fina_uts_view_config)
#define KSU_IOCTL_FINA_SET_UTS_VIEW _IOW('K', 26, struct ksu_fina_uts_view_config)
#define KSU_IOCTL_FINA_GET_NETISOLATE_CONFIG _IOC(_IOC_READ | _IOC_WRITE, 'K', 27, 1040)
#define KSU_IOCTL_FINA_SET_NETISOLATE_CONFIG _IOC(_IOC_WRITE, 'K', 28, 1040)
#define KSU_IOCTL_FINA_GET_NETISOLATE_POLICIES _IOC(_IOC_READ | _IOC_WRITE, 'K', 29, 2064)
#define KSU_IOCTL_FINA_SET_NETISOLATE_POLICIES _IOC(_IOC_WRITE, 'K', 30, 2064)
#define KSU_IOCTL_FINA_GET_NETISOLATE_EVENTS _IOC(_IOC_READ | _IOC_WRITE, 'K', 31, 2576)
#define KSU_IOCTL_FINA_CLEAR_NETISOLATE_EVENTS _IOC(_IOC_WRITE, 'K', 32, 2576)
#define KSU_IOCTL_FINA_GET_TRY_UMOUNT \
    _IOWR('K', 33, struct ksu_fina_get_try_umount_cmd)
#define KSU_IOCTL_FINA_GET_FULL_VERSION _IOR('K', 29, struct ksu_fina_get_full_version_cmd)

#endif /* __KSU_H_PROFILE_UAPI */
