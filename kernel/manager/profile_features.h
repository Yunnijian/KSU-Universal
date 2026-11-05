// SPDX-License-Identifier: GPL-2.0
#ifndef __KSU_H_PROFILE_FEATURES
#define __KSU_H_PROFILE_FEATURES

#include <linux/init.h>

/* FinaSU's public feature ids (uapi/feature.h of FinaSU). */
#define KSU_FEATURE_FINA_DYNAMIC_MANAGER 5
#define KSU_FEATURE_FINA_AVC_SPOOF 6
#define KSU_FEATURE_FINA_SHELL_SU_ADB_ONLY 7
#define KSU_FEATURE_FINA_DYNAMIC_MANAGER_GRANTS 8
#define KSU_FEATURE_FINA_UTS_VIEW 9
#define KSU_FEATURE_FINA_MOUNT_VIEW_FILTER 10

/*
 * Internal handler ids. They live above the public SukiSU id space but
 * below KSU_FEATURE_MAX, so both feature tables remain one array.
 */
#define KSU_FEATURE_FINA_DYNAMIC_MANAGER_HANDLER 10000
#define KSU_FEATURE_FINA_DYNAMIC_MANAGER_GRANTS_HANDLER 10001
#define KSU_FEATURE_FINA_UTS_VIEW_HANDLER 10002

int __init ksu_profile_features_init(void);
void ksu_profile_features_exit(void);

#endif /* __KSU_H_PROFILE_FEATURES */
