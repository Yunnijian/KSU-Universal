# KSU-Universal

五家管理器热切换原型：以 SukiSU Ultra `v4.3.0-r1` 内核模块为基线，内置
KernelSU / KernelSU-Next / BakaSU / SukiSU / FinaSU 五套静态 profile，
运行时通过 `/proc/kernelsu_manager` 切换主管理器，不 rmmod、不重新
late-load、不重启。

目标设备：OnePlus 16（PYB110），内核 `6.18.21-4k`（g7fcbff）。

## 当前状态

已在 PYB110 6.18.21（g7fcbff）真机验证（2026-11-05）：

- 通用 KO 经 98260 链 + 自定义 `ksud-universal` late-load 成功；
- 官方 KernelSU → KernelSU-Next → BakaSU → SukiSU → FinaSU 逐家切换，
  五次 `rc=0`；
- 每次切换后 `su -c id` 均为 `uid=0(root) ... context=u:r:ksu:s0`；
- `GET_INFO` 上报与安装版本一致：

| 管理器 | 包名 | versionCode | features | 备注 |
| --- | --- | --- | --- | --- |
| KernelSU | `me.weishu.kernelsu` | 32707 | `0x7` | 官方 v3.3.1-27-gdb6263d3 |
| KernelSU-Next | `com.rifsxd.ksunext` | 33442 | `0x2714` | v3.4.2-87-gda0b3f37，支持 10003 |
| BakaSU | `com.resukisu.resukisu` | 35257 | `0x7` | 完整版本串 `v4.2.0-rc3-516d3e87@BakaSU` |
| SukiSU Ultra | `com.sukisu.ultra` | 41140 | `0x2714` | v4.3.0-r1，支持 16 / 10003 |
| FinaSU | `me.yuki.fina` | 33168 | `0xb`（11） | 完整版本串 `v1.4.5-a839ce2d@main` |

- 各管理器自带的 `libksud.so debug info` 能读到对应 profile 的
  version/features；BakaSU 与 FinaSU 的 `GET_FULL_VERSION` 返回其真实
  构建串；
- feature 边界已隔离：10003 只对 Next/SukiSU 开放，16 只对 SukiSU
  开放；FinaSU 的 5/6/7/8/10 可用，9（UTS view）明确不支持；
- `/proc/kernelsu_manager` 现为 0600 root，可读可写：
  - 读：`<package> <profile> <versionCode> <featureMax>`
  - 写：`<package> <uid> <base.apk path>`

App v1.97 已接入：

- ROOT 管理器下拉框在 6.18 链下多出 **Dynamic Switching** 一项；选中后
  走通用 KO，初始主管理器为 KernelSU；
- 拓展页的 **管理器热切换** 卡片只在 6.18 且 `/proc/kernelsu_manager`
  存在时显示；下拉五家管理器，按钮通过 root 写节点完成切换；
- 卡片读取节点显示当前实际管理器。

## 原理

SukiSU 是官方 KernelSU 的超集，UAPI 保留官方基线，并额外提供
extension/KPM、manager.h、动态管理器等；因此不需要合并五份完整内核
模块。差异集中在：

1. **身份**：静态表按包名选择证书长度/SHA-256；只有表内 APK 能被加冕
   为 manager，动态切换后其他 manager 不再拥有 primary appid。
2. **版本/feature 面**：`GET_INFO`、`GET_INFO_LEGACY`、
   `GET_FULL_VERSION`、`HOOK_TYPE`、Next 的 `GET_HOOK_MODE`/
   `GET_VERSION_TAG` 都按 active profile 返回。
3. **feature 白名单**：`policy/feature.c` 按 profile 翻译/拒绝 feature ID；
   SukiSU extension 只在 SukiSU profile 下可访问。
4. **私有 ioctl**：BakaSU 的 103/105/106，FinaSU 的 22-33、29
   full-version 均按 profile 门控；Netisolate 与 per-process UTS view
   未实现，返回 `-EOPNOTSUPP`。
5. **默认与缓存**：通用 KO 默认 active=官方 KernelSU；扫描只加冕 active
   包，切换时清掉 `cached_manager_apk_path`，避免五家同时安装时加冕错家。
6. **动态管理器**：FinaSU 的签名/授权列表已接入（`SET/GET_DYNAMIC_MANAGERS`、
   grants），BakaSU 的 103 读写已接入；本原型的定位仍是 App 的
   “单主管理器热切换”，未实现多家同时拥有 primary appid。

## 产物

- `dist/kernelsu-universal-6.18.21.ko` — 7,048,176 B，
  vermagic `6.18.21-4k`；
- `dist/ksud-universal` — 9,216,496 B，嵌入上述 KO；
- `dist/SHA256SUMS`。

SHA-256：

```text
c20f0d03a4cdc34ceb94829eef8ed8f9442e0031454e0ea2ce257b1f2ac9d492  kernelsu-universal-6.18.21.ko
3b4b526254619052bb2c74b54bab99dc3086bbaf9b4a9007e44e1bc4be1f9f79  ksud-universal
```

## 加载

模块名与 hook 与现有 KSU 相同，必须在**没有 KSU 已加载的干净 boot**上加载；
已有 `kernelsu` 时不能热替换（rmmod 不安全）。

```sh
# 干净 boot 后，用自定义 loader 走 late-load
ksud-universal late-load
```

App 的 98260 链通过 `PYB110_UNIVERSAL=1` +
`PYB110_UNIVERSAL_KSUD=<libksud_universal.so>` 使用本 loader。

## 切换

root 下执行：

```sh
pkg=com.resukisu.resukisu
apk=$(pm path "$pkg" | head -n1 | sed s/^package://)
uid=$(stat -c %u "/data/data/$pkg")
printf '%s %u %s' "$pkg" "$uid" "$apk" > /proc/kernelsu_manager
cat /proc/kernelsu_manager
```

内核会校验 APK 的包名归属与证书；不在静态表里的包会被拒绝。
切换后目标管理器 App 需要重新打开才能刷新自身状态。

## 构建

内核 KO（Docker DDK + 本地 6.18.21 KDIR）：

```sh
scripts/build.sh
```

自定义 ksud：在 SukiSU `v4.3.0-r1`（`0a4c3132`）的 `userspace/ksud`
构建前，把 `kernel/kernelsu.ko` 复制到
`userspace/ksud/bin/aarch64/android17-6.18_kernelsu.ko`，然后用
NDK 28.2 编译 `aarch64-linux-android` 的 `ksud`：

```sh
export NDK=/opt/android-sdk/ndk/28.2.13676358
export SYSROOT="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/sysroot"
export CC_aarch64_linux_android="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android31-clang"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"
cargo build --release -p ksud --target aarch64-linux-android
```

## 已知边界

- KPM 按需求关闭，不参与 profile 切换；
- FinaSU 的 netisolate 与 per-process UTS view 已接入（netisolate 走 syscall 表 hook，UTS view 走 setresuid 回调）；
- BakaSU/FinaSU 的动态管理器接口已接入签名/授权与 APK 扫描；primary profile 仍只有一个，
  但被授权的动态 manager appid 可同时拥有 manager 权限；
- 非 active 管理器的私有 ioctl 一律 `-EOPNOTSUPP`，与真实 KO 的
  “没有该命令”效果一致；
- 通用 KO 以 SukiSU 内核实现为底座，官方/Next/Baka 的 ABI、feature、
  extension 与授权面已隔离，但不会复制三家各自的内核私有行为。

## 许可

基于 SukiSU Ultra `v4.3.0-r1`（`0a4c3132`，GPL-3.0）源码；修改同样按
GPL-3.0 发布，见 `LICENSE`。
