#include "policy/feature.h"
#include "manager/manager_table.h"
#include "manager/profile_features.h"
#include "klog.h" // IWYU pragma: keep

#include <linux/bitmap.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/string.h>

static const struct ksu_feature_handler *feature_handlers[KSU_FEATURE_MAX];

static DEFINE_MUTEX(feature_mutex);

static const char *const feature_names[KSU_FEATURE_MAX] = {
    [KSU_FEATURE_SU_COMPAT] = "su_compat",
    [KSU_FEATURE_KERNEL_UMOUNT] = "kernel_umount",
    [KSU_FEATURE_SULOG] = "sulog",
    [KSU_FEATURE_ADB_ROOT] = "adb_root",
    [KSU_FEATURE_SELINUX_HIDE] = "selinux_hide",
    [KSU_FEATURE_SHELL_SU_ADB_ONLY] = "shell_su_adb_only",
    [KSU_FEATURE_MOUNT_HIDE] = "mount_hide",
    [KSU_FEATURE_AVC_SPOOF] = "avc_spoof",
};

/*
 * Each manager sees exactly the feature id space its own kernel exports.
 * Unsupported ids are reported as such instead of falling through to a
 * handler that belongs to another fork.
 */
static bool profile_supports_feature(enum ksu_manager_profile profile, u32 manager_id)
{
    switch (profile) {
    case KSU_MANAGER_PROFILE_SUKISU:
        return manager_id <= KSU_FEATURE_SELINUX_HIDE ||
               manager_id == KSU_FEATURE_SHELL_SU_ADB_ONLY ||
               manager_id == KSU_FEATURE_MOUNT_HIDE ||
               manager_id == KSU_FEATURE_AVC_SPOOF;
    case KSU_MANAGER_PROFILE_OFFICIAL:
    case KSU_MANAGER_PROFILE_BAKA:
        return manager_id <= KSU_FEATURE_SELINUX_HIDE ||
               manager_id == KSU_FEATURE_SHELL_SU_ADB_ONLY;
    case KSU_MANAGER_PROFILE_NEXT:
        return manager_id <= KSU_FEATURE_SELINUX_HIDE ||
               manager_id == KSU_FEATURE_SHELL_SU_ADB_ONLY ||
               manager_id == KSU_FEATURE_AVC_SPOOF;
    case KSU_MANAGER_PROFILE_FINA:
        return manager_id <= KSU_FEATURE_FINA_MOUNT_VIEW_FILTER;
    }
    return false;
}

static bool translate_feature_id(u32 manager_id, u32 *internal_id)
{
    enum ksu_manager_profile profile = ksu_manager_active_profile();

    if (!profile_supports_feature(profile, manager_id))
        return false;

    if (profile != KSU_MANAGER_PROFILE_FINA) {
        *internal_id = manager_id;
        return true;
    }

    switch (manager_id) {
    case KSU_FEATURE_SU_COMPAT:
    case KSU_FEATURE_KERNEL_UMOUNT:
    case KSU_FEATURE_SULOG:
    case KSU_FEATURE_ADB_ROOT:
    case KSU_FEATURE_SELINUX_HIDE:
        *internal_id = manager_id;
        return true;
    case KSU_FEATURE_FINA_DYNAMIC_MANAGER:
        *internal_id = KSU_FEATURE_FINA_DYNAMIC_MANAGER_HANDLER;
        return true;
    case KSU_FEATURE_FINA_AVC_SPOOF:
        *internal_id = KSU_FEATURE_AVC_SPOOF;
        return true;
    case KSU_FEATURE_FINA_SHELL_SU_ADB_ONLY:
        *internal_id = KSU_FEATURE_SHELL_SU_ADB_ONLY;
        return true;
    case KSU_FEATURE_FINA_DYNAMIC_MANAGER_GRANTS:
        *internal_id = KSU_FEATURE_FINA_DYNAMIC_MANAGER_GRANTS_HANDLER;
        return true;
    case KSU_FEATURE_FINA_UTS_VIEW:
        *internal_id = KSU_FEATURE_FINA_UTS_VIEW_HANDLER;
        return true;
    case KSU_FEATURE_FINA_MOUNT_VIEW_FILTER:
        *internal_id = KSU_FEATURE_FINA_MOUNT_VIEW_FILTER_HANDLER;
        return true;
    default:
        return false;
    }
}

// Features forced by boot config. Written only while parsing module params
// (before kernelsu_init), read-only afterwards.
static u64 forced_values[KSU_FEATURE_MAX];
static DECLARE_BITMAP(forced_mask, KSU_FEATURE_MAX);
// Forced features whose value has not been applied successfully yet
static DECLARE_BITMAP(forced_pending, KSU_FEATURE_MAX);

static int parse_feature_id(const char *name, u32 *id)
{
    u32 i;

    if (!kstrtou32(name, 10, id)) {
        return *id < KSU_FEATURE_MAX ? 0 : -EINVAL;
    }

    for (i = 0; i < KSU_FEATURE_MAX; i++) {
        if (feature_names[i] && !strcmp(name, feature_names[i])) {
            *id = i;
            return 0;
        }
    }

    return -EINVAL;
}

// force_feature=<name|id>:<value>[,<name|id>:<value>...]
// May be specified multiple times. Invalid entries are skipped instead of
// failing, as a param error would prevent KernelSU from loading at all.
// This may run before the slab allocator is up (built-in), so don't allocate.
static int force_feature_param_set(const char *val, const struct kernel_param *kp)
{
    char name[32], num[24];
    const char *p = val, *end, *sep;
    size_t name_len, num_len;
    u32 id;
    u64 value;

    if (!val) {
        return 0;
    }

    for (; *p; p = *end ? end + 1 : end) {
        end = strchrnul(p, ',');
        if (end == p) {
            continue;
        }

        sep = memchr(p, ':', end - p);
        name_len = sep ? sep - p : 0;
        num_len = sep ? end - sep - 1 : 0;
        if (!name_len || name_len >= sizeof(name) || !num_len || num_len >= sizeof(num)) {
            pr_err("feature: invalid force_feature entry '%.*s'\n", (int)(end - p), p);
            continue;
        }

        memcpy(name, p, name_len);
        name[name_len] = '\0';
        memcpy(num, sep + 1, num_len);
        num[num_len] = '\0';

        if (parse_feature_id(name, &id) || kstrtou64(num, 0, &value)) {
            pr_err("feature: invalid force_feature entry '%s:%s'\n", name, num);
            continue;
        }

        forced_values[id] = value;
        set_bit(id, forced_mask);
        set_bit(id, forced_pending);
        pr_info("feature: %s (id=%u) forced to %llu\n", feature_names[id], id, value);
    }

    return 0;
}

static const struct kernel_param_ops force_feature_param_ops = {
    // A bare `force_feature` would otherwise fail parse_args() and the whole module load
    .flags = KERNEL_PARAM_OPS_FL_NOARG,
    .set = force_feature_param_set,
};
module_param_cb(force_feature, &force_feature_param_ops, NULL, 0);

int __init ksu_register_feature_handler(const struct ksu_feature_handler *handler)
{
    if (!handler) {
        pr_err("feature: register handler is NULL\n");
        return -EINVAL;
    }

    if (handler->feature_id >= KSU_FEATURE_MAX) {
        pr_err("feature: invalid feature_id %u\n", handler->feature_id);
        return -EINVAL;
    }

    if (!handler->get_handler && !handler->set_handler) {
        pr_err("feature: no handler provided for feature %u\n", handler->feature_id);
        return -EINVAL;
    }

    mutex_lock(&feature_mutex);

    if (feature_handlers[handler->feature_id]) {
        pr_warn("feature: handler for %u already registered, overwriting\n", handler->feature_id);
    }

    feature_handlers[handler->feature_id] = handler;

    pr_info("feature: registered handler for %s (id=%u)\n", handler->name ? handler->name : "unknown",
            handler->feature_id);

    mutex_unlock(&feature_mutex);
    return 0;
}

int ksu_unregister_feature_handler(u32 feature_id)
{
    int ret = 0;

    if (feature_id >= KSU_FEATURE_MAX) {
        pr_err("feature: invalid feature_id %u\n", feature_id);
        return -EINVAL;
    }

    mutex_lock(&feature_mutex);

    if (!feature_handlers[feature_id]) {
        pr_warn("feature: no handler registered for %u\n", feature_id);
        ret = -ENOENT;
        goto out;
    }

    feature_handlers[feature_id] = NULL;

    pr_info("feature: unregistered handler for id=%u\n", feature_id);

out:
    mutex_unlock(&feature_mutex);
    return ret;
}

int ksu_get_feature(u32 feature_id, u64 *value, bool *supported)
{
    int ret = 0;
    const struct ksu_feature_handler *handler;
    u32 internal_id;

    if (!value || !supported) {
        pr_err("feature: invalid parameters\n");
        return -EINVAL;
    }

    if (!translate_feature_id(feature_id, &internal_id)) {
        *supported = false;
        *value = 0;
        return 0;
    }

    mutex_lock(&feature_mutex);

    handler = feature_handlers[internal_id];

    if (!handler) {
        *supported = false;
        *value = 0;
        pr_debug("feature: feature %u not supported\n", feature_id);
        goto out;
    }

    *supported = true;

    if (!handler->get_handler) {
        pr_warn("feature: no get_handler for feature %u\n", feature_id);
        ret = -EOPNOTSUPP;
        goto out;
    }

    ret = handler->get_handler(value);
    if (ret) {
        pr_err("feature: get_handler for %u failed: %d\n", feature_id, ret);
    }

out:
    mutex_unlock(&feature_mutex);
    return ret;
}

int ksu_set_feature(u32 feature_id, u64 value)
{
    int ret = 0;
    const struct ksu_feature_handler *handler;
    u32 internal_id;

    if (!translate_feature_id(feature_id, &internal_id)) {
        return -EOPNOTSUPP;
    }

    if (test_bit(internal_id, forced_mask)) {
        pr_warn("feature: feature %u is forced by boot config\n", internal_id);
        return -EPERM;
    }

    mutex_lock(&feature_mutex);

    handler = feature_handlers[internal_id];

    if (!handler) {
        pr_err("feature: feature %u not registered\n", feature_id);
        ret = -EOPNOTSUPP;
        goto out;
    }

    if (!handler->set_handler) {
        pr_warn("feature: no set_handler for feature %u\n", feature_id);
        ret = -EOPNOTSUPP;
        goto out;
    }

    ret = handler->set_handler(value);
    if (ret) {
        pr_err("feature: set_handler for %u failed: %d\n", feature_id, ret);
    }

out:
    mutex_unlock(&feature_mutex);
    return ret;
}

bool ksu_feature_is_forced(u32 feature_id)
{
    return feature_id < KSU_FEATURE_MAX && test_bit(feature_id, forced_mask);
}

void ksu_feature_reset_non_upstream(void)
{
    static const u32 extras[] = {
        KSU_FEATURE_MOUNT_HIDE,
        KSU_FEATURE_AVC_SPOOF,
        KSU_FEATURE_FINA_DYNAMIC_MANAGER_HANDLER,
        KSU_FEATURE_FINA_DYNAMIC_MANAGER_GRANTS_HANDLER,
        KSU_FEATURE_FINA_UTS_VIEW_HANDLER,
        KSU_FEATURE_FINA_MOUNT_VIEW_FILTER_HANDLER,
    };
    const struct ksu_feature_handler *handler;
    unsigned int i;

    mutex_lock(&feature_mutex);
    for (i = 0; i < ARRAY_SIZE(extras); i++) {
        handler = feature_handlers[extras[i]];
        if (handler && handler->set_handler)
            (void)handler->set_handler(0);
    }
    mutex_unlock(&feature_mutex);
}

void ksu_feature_apply_forced(void)
{
    const struct ksu_feature_handler *handler;
    unsigned int id;
    int ret;

    mutex_lock(&feature_mutex);

    for_each_set_bit (id, forced_pending, KSU_FEATURE_MAX) {
        if (!ksu_manager_active_is_sukisu() &&
            id >= ksu_manager_active_feature_max())
            continue;
        handler = feature_handlers[id];
        if (!handler || !handler->set_handler) {
            continue;
        }

        ret = handler->set_handler(forced_values[id]);
        if (ret) {
            pr_warn("feature: apply forced %s=%llu failed: %d\n", feature_names[id], forced_values[id], ret);
            continue;
        }

        clear_bit(id, forced_pending);
        pr_info("feature: applied forced %s=%llu\n", feature_names[id], forced_values[id]);
    }

    mutex_unlock(&feature_mutex);
}

void __init ksu_feature_init(void)
{
    int i;

    for (i = 0; i < KSU_FEATURE_MAX; i++) {
        feature_handlers[i] = NULL;
    }

    pr_info("feature: feature management initialized\n");
}

void __exit ksu_feature_exit(void)
{
    int i;

    mutex_lock(&feature_mutex);

    for (i = 0; i < KSU_FEATURE_MAX; i++) {
        feature_handlers[i] = NULL;
    }

    mutex_unlock(&feature_mutex);

    pr_info("feature: feature management cleaned up\n");
}
