# Manager Ops

`manager/manager_ops.c` is the per-profile control-flow layer added on top of
the SukiSU base. It does not replace the SukiSU hook backend: the syscall
tracepoint and dispatcher stay the same for every profile.

## Contract

```c
struct ksu_manager_ops {
    const char *name;
    int (*setuid)(uid_t old_uid, uid_t new_uid);
    int (*umount)(uid_t old_uid, uid_t new_uid);
    long (*module_load)(int orig_nr, const struct pt_regs *regs, bool *handled);
    void (*dynamic_load)(void);
    void (*dynamic_save)(void);
    void (*activate)(void);
    void (*deactivate)(void);
};
```

`ksu_manager_ops_select(profile)` swaps the static table with `WRITE_ONCE`;
hot paths read it with `READ_ONCE`. The table is selected by
`/proc/kernelsu_manager` together with the active manager identity.

`module_load` returns `*handled = false` to let the direct hook call the
original syscall. A profile that wants to filter a load sets `*handled = true`
and returns the value userspace should observe. `init_module`/`finit_module`
are hooked directly in the syscall table, not through the sys_enter
dispatcher: the filters parse ELF and may read a file, which is not safe in
tracepoint context.

## Profile mapping

| Profile | setuid | umount | module_load | dynamic state |
| --- | --- | --- | --- | --- |
| KernelSU / Next / SukiSU | SukiSU default | SukiSU default | pass through | SukiSU extension |
| BakaSU | `feature/baka_compat.c` | `ksu_handle_umount_baka` | `block_modules` filter | `profile_dynamic.c` Baka table |
| FinaSU | SukiSU default + UTS view | SukiSU default | `vivo_module_filter` | `KSUM` v2 file |

## BakaSU

`feature/baka_compat.c` ports the parts of BakaSU's setuid path that do not
depend on the optional inline SUSFS frontend:

- only zygote children are considered;
- allowed UIDs get the seccomp reboot allowance and the tracepoint flag;
- manager UIDs get `/data/adb/ksud` marked writable and the manager fd;
- other UIDs get the tracepoint flag cleared and run Baka's umount path.

Leaving BakaSU calls `ksu_baka_deactivate()`, which restores
`/data/adb/ksud` to writable so the next profile is not affected.

`feature/module_load_filter.c` implements Baka's `block_modules` behavior.
The module parameter is a comma-separated list; matching modules are
acknowledged without loading. The hook is installed once in the shared
`init_module`/`finit_module` dispatcher and is inert when the parameter is
empty or the active profile is not BakaSU.

`app_profile.c` adds `CAP_DAC_READ_SEARCH` to the effective capability set
only for the BakaSU profile. This mirrors BakaSU's root-profile setup for
`/data/adb/ksud` access.

## FinaSU

`feature/fina_module_filter.c` ports FinaSU's vivo `init_module_filter`.
`vivo_module_filter=auto` maps to the module name `vr`; `0` disables the
filter; otherwise the value is a comma-separated module list. With the
parameter enabled and `CAP_SYS_MODULE` present, matching module loads are
acknowledged without loading.

FinaSU dynamic-manager state is persisted in the same v2 format used by
FinaSU:

```text
u32 magic      0x4d554b53 ('KSUM')
u32 version    2
u32 flags      bit 0 = grants are strict
u32 grant_count
u32 appid[grant_count]
{ u32 size; u32 version_code; char hash[65]; } * N
```

The path is `/data/adb/ksu/dynamic_manager`, separate from SukiSU's
`/data/adb/ksu/.dynamic_managers`. The FinaSU ops load it on profile
activation and save it on profile deactivation; `SET_DYNAMIC_MANAGERS` and
`SET_DYNAMIC_GRANTS` also save immediately.

## Deliberately not ported

- BakaSU `KSU_MANUAL_HOOK`, LSM magic hooks and arm32 hooks. The manual hook
  requires `KSU != m` and kernel-source call sites (`kernel/sys.c`,
  `fs/exec.c`, `fs/read_write.c`, ...). A stock 6.18 LKM has no such call
  sites, so runtime hook-backend switching is not possible.
- BakaSU/FinaSU inline SUSFS frontends. Their `KSU_SUSFS` code is the
  KernelSU-side interface; the SUSFS implementation remains the external
  guard LKM. The guard does not export the KSU-side `susfs_*` ABI symbols.
- KPM. `CONFIG_KPM` stays off.

## Verification

Static/build evidence:

- 6.18: `ksu_universal-android17-6.18.ko`, vermagic `6.18.21-4k`.
- 6.12: `ksu_universal-android16-6.12.ko`, vermagic `6.12.76-4k`.

Device evidence on PYB110 (6.18.21 `g7fcbff`):

- clean-boot late-load of the new KO through a temporary loader;
- five-profile switch loop: all `rc=0`, state strings matched the profile
  table, and `su -c id` stayed `uid=0(root)` / `u:r:ksu:s0`;
- BakaSU logs showed `baka: install fd for manager` and
  `baka: mark /data/adb/ksud read write`;
- FinaSU loaded 1 signature from `/data/adb/ksu/dynamic_manager`; switching
  away and back preserved the file byte-for-byte.

Still pending:

1. `block_modules` / `vivo_module_filter` hit paths (need a reload with
   module parameters);
2. Baka umount with an actually mounted module;
3. FinaSU netisolate/UTS view/mount_view_filter regression on the new ops;
4. 6.12.69 and V2505A runtime checks;
5. rebuilding the production App loader with the new KO (the device test
   used `/data/local/tmp/ksud-new`).
