# SFHook —— 顺丰 iOS 加密入参 Hook

hook CommonCrypto 底层加密函数，dump 出顺丰 iOS 端 sytToken / 盐 / AES key 的原始输入。

## Hook 点（全覆盖）

| Hook | 作用 |
|---|---|
| `CC_MD5` | **核心**：sytToken = MD5(...)，直接看到喂进去的含盐拼接串 |
| `CC_SHA1/224/256/384/512` | 盐可能用 SHA 派生 |
| `CC_SHA3_256/384/512` | `sytSHA3Salt` 函数名提示盐用 SHA3（iOS13+ 才 hook） |
| `CCCrypt` | AES/DES：dump **key + iv + dataIn**（盐若是 ENCRYPTED 密文，这里能看到解密 key） |
| `CCKeyDerivationPBKDF` | PBKDF：dump **password + salt**（盐很可能在这里） |
| `CCHmac` | HMAC 的 key + data |
| `RCTModuleMethod.invoke` | React Native 模块调用：看到 `encryptMD5` 等方法名 + 参数 |
| 类扫描 | 启动时列出 App 内所有加密相关类/方法，帮定位 iOS 类名 |

## 编译

### 方式 A：GitHub Actions（推荐，无需本地环境）

项目里已经带好 `.github/workflows/build.yml`，直接：

1. 把整个 `iOSHook` 目录 push 到 GitHub 一个仓库（作为仓库根）
2. 打开仓库 **Actions** 页 → 会自动跑 `Build iOS SFHook dylib`
3. 跑完后进 **Artifacts** → 下载 `SFHook-iOS.zip`
4. 解压得到 `SFHook.dylib`（和可选 `.deb`）

> 用的是 macOS runner（自带 Xcode + iPhoneOS SDK），Linux/Windows 上无法本地编译 iOS tweak，只能靠 macOS。

### 方式 B：本地 macOS + theos

```bash
# 1. 安装 theos：git clone --recursive https://github.com/theos/theos.git
#    并 export THEOS=<theos路径>、PATH 加上 $THEOS/bin

# 2. 进入项目目录
cd iOSHook

# 3. 编译（生成 .dylib 和 .deb）
make package
```

产物：
- `.theos/obj/debug/arm64/SFHook.dylib` ← 这个就是注入用的 dylib
- `packages/com.sfhook_1.0_iphoneos-arm64.deb`

> `fishhook.c` / `fishhook.h` 已随项目自带，无需额外下载。

## 注入顺丰 App（TrollStore）

方式 A —— 用 ElleKit（推荐，TrollStore 环境）：
1. 装 ElleKit（TrollStore 里安装 ElleKit 的 tipa/注入器）
2. 把 `SFHook.dylib` 通过 ElleKit 注入到「顺丰速运」App

方式 B —— 用 TrollFools（更简单）：
1. TrollStore 安装 TrollFools
2. TrollFools 里选「顺丰速运」→ 添加 dylib → 选 `SFHook.dylib`
3. 重新打开顺丰 App

## 看日志

日志同时写两个位置：
- `/tmp/sf_hook.log`（Filza 或 SSH `cat /tmp/sf_hook.log`）
- App Documents 目录的 `sf_hook.log`

用 Filza 打开 `/tmp/sf_hook.log`，或者：
```bash
# SSH 进手机后
cat /tmp/sf_hook.log
# 或实时跟踪
tail -f /tmp/sf_hook.log
```

## 预期输出

冷启动顺丰 App 后，触发登录/扫码/首页请求，日志里会看到：

```
[SF] ==== CC_MD5 (len=xxx) ====
[SF]   hex : 434e7363...   (CNsc + md5(body) + ... + 盐)
[SF]   str : CNsc0a1b2c...9.95.2...db05c4d1...ba999f2c...
[SF] ==== CCCrypt (AES) ====
[SF]   CCCrypt.key : <hex>
[SF]   CCCrypt.dataIn : <hex>
[SF] ==== RCTModuleMethod.invoke ====
[SF]   method : encryptMD5
[SF]   arg[0] : {"code":"xxx"}
```

**重点看 `CC_MD5` 的 `str` 那行** —— 那就是含盐的完整拼接串，拿到它，盐和公式就都出来了。

## 崩溃排查

如果注入后顺丰 App 闪退，按顺序试：

1. **先注释掉 `Tweak.xm` 里的 `%hook RCTModuleMethod ... %end` 整段**（RN 方法签名随版本变化，最可能出问题），保留 CommonCrypto hook 再编译一次。
2. 确认 dylib 架构是 `arm64`（`file SFHook.dylib` 看输出）。
3. 看崩溃日志确认是不是这个 dylib 引起：Filza 或 `log show --predicate 'eventMessage CONTAINS "SFHook"'`。

## 如果 CC_MD5 抓不到

顺丰 iOS 若静态链接了 OpenSSL（而非系统 CommonCrypto），CC_MD5 就不会命中。
这种情况把日志里「类扫描」的结果发我，我看到 iOS 的类名/方法名后，再针对性 hook。
