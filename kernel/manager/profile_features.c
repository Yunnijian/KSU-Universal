// SPDX-License-Identifier: GPL-2.0
/*
 * FinaSU feature adapters.
 *
 * FinaSU numbers its features 5..10 while SukiSU uses a different layout.
 * The feature dispatcher translates 5/8/9/10 to these private ids; the
 * dynamic-manager bits are backed by manager/profile_dynamic.c.
 */
#include <linux/types.h>

#include "klog.h" // IWYU pragma: keep
#include "manager/profile_dynamic.h"
#include "manager/profile_features.h"
#include "policy/feature.h"
#include "uapi/extension.h"

static int fina_dynamic_get(u64 *value)
{
    *value = ksu_fina_dynamic_is_enabled() ? 1 : 0;
    return 0;
}

static int fina_dynamic_set(u64 value)
{
    ksu_fina_dynamic_set_enabled(value != 0);
    return 0;
}

static int fina_grants_get(u64 *value)
{
    /* The authorized-appid list is supported by this profile. */
    *value = 1;
    return 0;
}

static int fina_grants_set(u64 value)
{
    (void)value;
    return 0;
}

static const struct ksu_feature_handler fina_dynamic_handler = {
    .feature_id = KSU_FEATURE_FINA_DYNAMIC_MANAGER_HANDLER,
    .name = "fina_dynamic_manager",
    .get_handler = fina_dynamic_get,
    .set_handler = fina_dynamic_set,
};

static const struct ksu_feature_handler fina_grants_handler = {
    .feature_id = KSU_FEATURE_FINA_DYNAMIC_MANAGER_GRANTS_HANDLER,
    .name = "fina_dynamic_manager_grants",
    .get_handler = fina_grants_get,
    .set_handler = fina_grants_set,
};

int __init ksu_profile_features_init(void)
{
    int ret = 0;

    ret |= ksu_register_feature_handler(&fina_dynamic_handler);
    ret |= ksu_register_feature_handler(&fina_grants_handler);
    return ret;
}

void ksu_profile_features_exit(void)
{
    ksu_unregister_feature_handler(KSU_FEATURE_FINA_DYNAMIC_MANAGER_HANDLER);
    ksu_unregister_feature_handler(KSU_FEATURE_FINA_DYNAMIC_MANAGER_GRANTS_HANDLER);
}
