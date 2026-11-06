/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_BAKA_COMPAT
#define __KSU_H_BAKA_COMPAT

#include <linux/types.h>

int ksu_baka_setuid(uid_t old_uid, uid_t new_uid);
void ksu_baka_deactivate(void);

#endif /* __KSU_H_BAKA_COMPAT */
