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

适用内核：`6.18.21-4k`（arm64，GKI 2.0）。当前在 OnePlus 16（PYB110，
`g7fcbff`）上完成验证；同 KMI 的其他 6.18.21 设备可作为兼容目标。

## 功能

- **单一常驻模块**：五家管理器的版本、feature、hook 信息和私有 ioctl
  由 active profile 决定，切换不替换内核模块。
- **运行时切换**：root 写入 `/proc/kernelsu_manager` 即可更换 primary
  manager，模块保持加载，`su` 不需要重新安装。
- **profile 隔离**：非 active 管理器的 feature、extension 和私有 ioctl
  返回 `-EOPNOTSUPP`；SukiSU extension 只在 SukiSU profile 下可见。
- **动态管理器**：BakaSU/FinaSU 的签名与授权接口可用；被授权的动态
  manager appid 可获得 manager 权限，但不会改变 active profile。
- **FinaSU 可选功能**：netisolate（27-32）、per-process UTS view
  （feature 9 / ioctl 25-26）和 mount view filter 已接入。
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
- Android 17-6.18 的 KDIR；
- clang/LLVM 与 Docker；
- 基线源码已随仓库提供，版本为 SukiSU Ultra `v4.3.0-r1`
  （commit `0a4c3132`）。

内核模块：

```sh
KSU_BUILD=/path/to/build scripts/build.sh
```

`KSU_BUILD` 需包含 `kdir/android17-6.18`；`IMAGE` 可覆盖默认的 DDK
镜像。构建产物为 `kernel/kernelsu.ko`，vermagic 应为 `6.18.21-4k`。

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
  返回 `supported=true`，配置与状态读取正常。

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
- 同一时间只有一个 primary profile；动态 manager 可以追加 manager 权限，
  但不会切换版本/feature 表面。
- 官方/Next/Baka 的 ABI、feature、extension 和授权面已隔离，但模块以
  SukiSU 内核实现为底座，不复制三家各自的内核私有行为。
- 通用 KO 与 stock KSU 同名同 hook，必须在无 KSU 已加载的干净 boot
  上首次加载；已加载 `kernelsu` 时不能热替换。

## 许可

本项目基于 SukiSU Ultra `v4.3.0-r1`（commit `0a4c3132`）源码，按
GPL-3.0 发布，见 `LICENSE`。第三方组件保留其原始版权与许可证。
