# KSU-Universal

面向 Android 6.18 GKI 的多管理器 KernelSU 内核模块。项目以 SukiSU Ultra
`v4.3.0-r1` 为基线，在同一个 LKM 内提供五套 manager profile，并通过
`/proc/kernelsu_manager` 在运行时切换 primary manager，无需卸载模块、
重新 late-load 或重启系统。

## 支持范围

| Profile | 包名 | versionCode | feature_max | 证书长度 |
| --- | --- | ---: | ---: | ---: |
| KernelSU | `me.weishu.kernelsu` | 32707 | 7 | `0x033b` |
| KernelSU-Next | `com.rifsxd.ksunext` | 33442 | 10004 | `0x3e6` |
| BakaSU | `com.resukisu.resukisu` | 35257 | 7 | `0x377` |
| SukiSU Ultra | `com.sukisu.ultra` | 41140 | 10004 | `0x35c` |
| FinaSU | `me.yuki.fina` | 33168 | 11 | `0x2cc` |

适用内核：`6.18.21-4k` / `6.12.76-4k`（arm64，GKI 2.0）。当前在 OnePlus 16
（PYB110，`g7fcbff`）上完成 6.18 验证；6.12 使用同一套 profile 源码构建，
目标为 Android 16 / 6.12 GKI。

### 构建产物

| File | Android / kernel |
| --- | --- |
| `ksu_universal-android16-6.12.ko` | Android 16 / 6.12 |
| `ksu_universal-android17-6.18.ko` | Android 17 / 6.18 |
| `ksud_universal` | 双 KMI late-load loader（内嵌上述两个 KO） |

## 功能

- **单一常驻模块**：五家管理器的版本、feature、hook 信息和私有 ioctl
  由 active profile 决定，切换不替换内核模块。
- **运行时切换**：root 写入 `/proc/kernelsu_manager` 即可更换 primary
  manager，模块保持加载，`su` 不需要重新安装。
- **profile 隔离**：非 active 管理器的 feature、extension 和私有 ioctl
  返回 `-EOPNOTSUPP`；SukiSU extension 只在 SukiSU profile 下可见。
- **动态管理器**：BakaSU/FinaSU 的签名与授权接口可用；BakaSU profile
  还会扫描并注册全部已安装静态管理器，使多个 manager appid 同时拥有
  manager 权限；primary profile 仍只有一个。
- **FinaSU 可选功能**：netisolate（27-32）、per-process UTS view
  （feature 9 / ioctl 25-26）、mount view filter（feature 10）和
  `GET_TRY_UMOUNT`（33）已按 Fina 行为接入。
- **BakaSU 行为补齐**：Baka profile 使用 Baka 的 setuid/zygote 语义、
  `/data/adb/ksud` 只读保护、Baka 版 umount 流程和 root profile 的
  `CAP_DAC_READ_SEARCH`；`block_modules` 参数启用模块加载过滤（命中的
  模块返回成功但不实际加载）。
- **FinaSU 行为补齐**：`vivo_module_filter` 参数启用 vivo 模块过滤；
  动态管理器按 Fina `KSUM` v2 格式持久化到
  `/data/adb/ksu/dynamic_manager`，切换进入 Fina 时加载，切走时保存。
- **状态查询**：`/proc/kernelsu_manager` 可由 root 读取，返回当前
  profile、versionCode 和 feature_max。

KPM 默认关闭（`CONFIG_KPM=n`），不参与 profile 切换。

## 工作原理

SukiSU 的 UAPI 保留官方 KernelSU 基线，并扩展了 extension、动态管理器
等能力，因此无需合并五份完整内核模块。本项目的差异集中在四层：

1. **身份层**：`manager/manager_table.c` 保存五家静态 profile；APK 签名
   校验通过包名选择对应的证书长度与 SHA-256，非表内 APK 无法加冕。
2. **表面层**：`GET_INFO`、`GET_INFO_LEGACY`、`GET_FULL_VERSION`、
   `HOOK_TYPE`、Next 的 `GET_HOOK_MODE`/`GET_VERSION_TAG`、Fina 的
   29 号 typed full-version 按 active profile 返回。
3. **feature 层**：`policy/feature.c` 按 profile 维护 ID 白名单与映射；
   FinaSU 的 5-10 号 feature 映射到内部 handler，10003/16 等 SukiSU
   专属 ID 不会泄露到其他 profile。
4. **ioctl 层**：BakaSU 103/105/106、FinaSU 22-33/29 以及 SukiSU
   extension 均按 profile 门控；UTS view、netisolate、动态管理器状态由
   各 profile 自己的实现承接。
5. **ops 层**：`manager/manager_ops.c` 为每个 profile 保存
   `setuid`/`umount`/`module_load`/`dynamic_load`/`dynamic_save` 等控制流；
   切换 profile 时只替换 ops 表，不替换 hook 后端。`init_module`/
   `finit_module` 共用同一个 module_load dispatcher，未配置过滤的
   profile 直接调用原 syscall。

`throne_tracker` 只加冕 active package；切换时清理 active-manager APK
缓存，避免五家同时安装时扫描到错误目标。`/proc/kernelsu_manager` 的写入
还会校验 APK 所在目录的包名与声明一致，防止证书与 UID 被交叉使用。

## 接口

`/proc/kernelsu_manager` 为 `0600 root` 节点。

读取：

```text
<package> <profile> <versionCode> <featureMax>
```

示例：

```text
me.weishu.kernelsu KernelSU 32707 7
```

写入：

```text
<package> <uid> <base.apk path>
```

示例：

```sh
pkg=com.resukisu.resukisu
apk=$(pm path "$pkg" | head -n1 | sed s/^package://)
uid=$(stat -c %u "/data/data/$pkg")
printf '%s %u %s' "$pkg" "$uid" "$apk" > /proc/kernelsu_manager
```

内核会验证：

- 调用者 euid 为 root；
- 包名在静态 profile 表内；
- APK 路径所属目录的包名与声明一致；
- APK 的 v2 证书长度和 SHA-256 与 profile 匹配。

切换成功后，目标管理器应用需要重新打开以刷新自身状态。

## 构建

依赖：

- Linux x86_64 构建主机（或 Docker）；
- 对应 KMI 的 KDIR；
- clang/LLVM 与 Docker；
- 基线源码已随仓库提供，版本为 SukiSU Ultra `v4.3.0-r1`
  （commit `0a4c3132`）。

内核模块：

```sh
# Android 17 / 6.18
KSU_BUILD=/path/to/build scripts/build.sh android17-6.18

# Android 16 / 6.12
KSU_BUILD=/path/to/build scripts/build.sh android16-6.12
```

6.18 默认使用 `$KSU_BUILD/kdir/android17-6.18`；6.12 默认使用 DDK 镜像
内的 `/opt/ddk/kdir/android16-6.12`。可用 `KDIR` / `IMAGE` 覆盖。
构建产物写入 `dist/`，文件名分别为
`ksu_universal-android17-6.18.ko` 与 `ksu_universal-android16-6.12.ko`。

可选的 late-load loader 不属于内核模块本身，构建方式如下（在 SukiSU
`v4.3.0-r1` 的 `userspace/ksud` 中操作）：

```sh
cp kernel/kernelsu.ko userspace/ksud/bin/aarch64/android17-6.18_kernelsu.ko

export NDK=/path/to/android-ndk
export SYSROOT="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/sysroot"
export CC_aarch64_linux_android="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android31-clang"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"
cargo build --release -p ksud --target aarch64-linux-android
```

生成的可执行文件会将该 KO 作为 late-load 载荷嵌入，仅作为加载辅助，
不改变内核模块的 ABI 或 profile 行为。

## 验证

在 PYB110（6.18.21 `g7fcbff`）上完成：

- 通用 KO 经 late-load 加载成功；
- 依次切换 KernelSU → KernelSU-Next → BakaSU → SukiSU → FinaSU，
  五次返回 0；
- 每次切换后 `su -c id` 均为 `uid=0(root)`；
- 各管理器自带的 `libksud` 读取到对应 versionCode/features：
  - KernelSU 32707 / `0x7`
  - KernelSU-Next 33442 / `0x2714`
  - BakaSU 35257 / `0x7`
  - SukiSU 41140 / `0x2714`
  - FinaSU 33168 / `0xb`
- BakaSU 与 FinaSU 的 `GET_FULL_VERSION` 返回其真实构建串；
- feature 边界符合预期：10003 只对 Next/SukiSU 开放，16 只对 SukiSU
  开放；
- FinaSU 的 UTS view（feature 9）与 netisolate（27-32）运行时探针均
  返回 `supported=true`，配置与状态读取正常；
- FinaSU mount view filter（feature 10）可 set 1 / get 1 / set 0；
- FinaSU `GET_TRY_UMOUNT` 实测 add → list 返回条目 → del → list 为空；
- BakaSU 切换后扫描到五家管理器并注册：`me.weishu.kernelsu` index 0、
  `com.rifsxd.ksunext` index 1、`com.resukisu.resukisu` index 2、
  `com.sukisu.ultra` index 3、`me.yuki.fina` index 4。

6.12 产物使用 `android16-6.12` GKI 6.12.76 KDIR 编译，尚未在 6.12.69
设备上完成运行时回归。

### 2026-11-06 补齐后的验证状态

- 6.18 / 6.12 双 KMI 均已重新编译通过：
  - `ksu_universal-android17-6.18.ko`，vermagic `6.18.21-4k`；
  - `ksu_universal-android16-6.12.ko`，vermagic `6.12.76-4k`。
- 新增的 profile ops、Baka setuid/ksud 保护/umount、Baka module filter、
  Fina module filter 和 Fina 动态管理器持久化，尚待在 PYB110 / 6.12.69 /
  V2505A 真机上做逐项切换回归；在此之前按“代码与构建已验证”看待，不当作
  运行时已验证。

## 目录结构

```text
kernel/        KernelSU 模块源码（含 manager profile、feature、ioctl）
uapi/          与内核模块共享的 UAPI 头文件
scripts/       构建脚本
loader/        可选的预编译 late-load loader（不提交到源码仓库）
dist/          打包产物（不提交到源码仓库）
```

## 已知边界

- KPM 关闭；不参与 profile 切换。
- 同一时间只有一个 primary profile；BakaSU 下可有多个 manager appid
  同时拥有 manager 权限，FinaSU 的动态 manager 通过签名 + grant 授权；
  它们都不会切换 active profile 的版本/feature 表面。
- 官方/Next/Baka 的 ABI、feature、extension 和授权面已隔离，但模块以
  SukiSU 内核实现为底座，不复制三家各自的内核私有行为。
- **不支持 Baka 的 manual hook / LSM magic hook / arm32 hook**：Baka 的
  `KSU_MANUAL_HOOK` 依赖 `KSU != m`，且 6.8+ 需要改 `kernel/sys.c` 等
  内核源码；stock 6.18 内核没有这些调用点，LKM 无法在运行时安装。
- **不内置 Baka/Fina 的 inline SUSFS frontend**：BakaSU/FinaSU 的
  `KSU_SUSFS` 只是 KernelSU 侧接口，真正的 SUSFS 实现仍是外部 SUSFS
  guard LKM；两者通过各自的 hook/supercall 协作，不合并进本 KO。
- 通用 KO 与 stock KSU 同名同 hook，必须在无 KSU 已加载的干净 boot
  上首次加载；已加载 `kernelsu` 时不能热替换。

## 许可

本项目基于 SukiSU Ultra `v4.3.0-r1`（commit `0a4c3132`）源码，按
GPL-3.0 发布，见 `LICENSE`。第三方组件保留其原始版权与许可证。
