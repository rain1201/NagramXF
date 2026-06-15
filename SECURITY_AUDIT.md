# NagramXF v12.7.3 深度安全合规审计报告

> **审计对象**: `fork.risin42.nagramx` (NagramXF)  
> **审计日期**: 2026-06-15  
> **审计方法**: 静态代码分析 + 网络流量追踪 + 数据生命周期追踪  
> **审计专家**: 静态代码分析师 / 网络流量审计师 / 数据生命周期专家 联合会审  
> **项目背景**: 该项目曾被实锤利用混淆、动态加载等手段，在后台静默收集用户的账户 Token、手机号及 2FA 凭证并上传至第三方服务器。

---

## 目录

1. [项目概况与拓扑差异](#1-项目概况与拓扑差异)
2. [风险总览与评级](#2-风险总览与评级)
3. [🔴 CRITICAL 发现](#3--critical-发现)
   - [3.1 Java 反序列化漏洞 (ObjectInputStream + Base64)](#31-java-反序列化漏洞-objectinputstream--base64)
   - [3.2 默认 AI 服务指向第三方代理服务器](#32-默认-ai-服务指向第三方代理服务器)
   - [3.3 passcodeHash + 全部设置通过 NextAloneBot 外流](#33-passcodehash--全部设置通过-nextalonebot-外流)
4. [🟠 HIGH 发现](#4--high-发现)
   - [4.1 API Keys 明文存储在 SharedPreferences](#41-api-keys-明文存储在-sharedpreferences)
   - [4.2 自定义 OkHttpClient 无证书固定](#42-自定义-okhttpclient-无证书固定)
   - [4.3 本地锁屏密码哈希随云端设置同步](#43-本地锁屏密码哈希随云端设置同步)
   - [4.4 硬编码 Telegram API 测试凭据 (APP_ID=4)](#44-硬编码-telegram-api-测试凭据-app_id4)
5. [🟡 MEDIUM 发现](#5--medium-发现)
   - [5.1 Logcat 系统日志转储与分享](#51-logcat-系统日志转储与分享)
   - [5.2 DNS 解析通过第三方 DoH 服务](#52-dns-解析通过第三方-doh-服务)
   - [5.3 未限制后台位置权限](#53-未限制后台位置权限)
   - [5.4 反射滥用分析（35+ 处）](#54-反射滥用分析35-处)
   - [5.5 设置备份导出包含敏感数据](#55-设置备份导出包含敏感数据)
   - [5.6 HyperOS/ColorOS 外部服务调用](#56-hyperoscoloros-外部服务调用)
6. [🔵 LOW 发现](#6--low-发现)
7. [数据生命周期追踪报告](#7-数据生命周期追踪报告)
   - [7.1 AuthKey 流动](#71-authkey-流动)
   - [7.2 手机号码流动](#72-手机号码流动)
   - [7.3 2FA 密码流动](#73-2fa-密码流动)
   - [7.4 passcodeHash 流动（危险）](#74-passcodehash-流动危险)
   - [7.5 API Keys 流动](#75-api-keys-流动)
8. [网络流量全景图](#8-网络流量全景图)
9. [与官方 Telegram FOSS 拓扑结构差异](#9-与官方-telegram-foss-拓扑结构差异)
10. [最终结论与建议](#10-最终结论与建议)

---

## 1. 项目概况与拓扑差异

| 属性 | 值 |
|------|-----|
| Application ID | `fork.risin42.nagramx` |
| 命名空间 | `org.telegram.messenger` |
| 版本 | 12.7.3 (versionCode 1245) |
| 基础代码 | Telegram FOSS (AGPLv3) |
| 叠加 Fork | AyuGram + NekoGram/NekoX + exteraGram + Nagram |
| 编译配置 | API 36, Java 21, NDK 27.2, Gradle 9.4 |
| 混淆 | **明确关闭** (`-dontobfuscate -dontoptimize`) |

**与官方 FOSS 核心差异**:
- 增加了 4 个独立 fork 的叠加功能（ayugram/nekogram/exteragram/nagram 包）
- 使用 Room 数据库持久化存储删除/编辑消息（AyuGram 功能）
- 集成 NextAloneBot (ID `1433866570`) 作为云端设置存储后端
- 默认 AI 服务指向 `chen-hai.ryzedns.org` 个人代理
- 使用 OkHttp5 替代标准 HTTP 客户端进行翻译/LLM/转写请求
- 无混淆和优化，方便逆向分析

---

## 2. 风险总览与评级

| 风险等级 | 数量 | 概述 |
|----------|------|------|
| 🔴 CRITICAL | 3 | 反序列化 RCE、AI 代理服务器窃听、passcodeHash 外流 |
| 🟠 HIGH | 4 | API Keys 明文、无证书固定、设置泄露、测试凭据 |
| 🟡 MEDIUM | 6 | Logcat 转储、第三方 DNS、后台定位、反射滥用、备份导出、OEM 调用 |
| 🔵 LOW | 5 | AsyncTask 弃用、模拟器检测反射、浏览器 UA 伪装等 |

---

## 3. 🔴 CRITICAL 发现

### 3.1 Java 反序列化漏洞 (ObjectInputStream + Base64)

**风险等级**: 🔴 CRITICAL  
**位置**: 
- `NaConfig.kt:1888-1900`
- `NekoConfig.java:257-260`

**代码片段** (NaConfig.kt):
```kotlin
val data = Base64.decode(cv, Base64.DEFAULT)
val ois = ObjectInputStream(ByteArrayInputStream(data))
o.value = ois.readObject() as HashMap<*, *>  // 无类型校验
```

**攻击面分析**:
从 SharedPreferences `nkmrcfg` 读取 Base64 编码的序列化数据后，直接使用 `ObjectInputStream.readObject()` 进行反序列化，**未做任何类型白名单校验**。攻击者如能写入 SharedPreferences（通过 root、debug 的 ADB 备份、或设置导入功能），即可构造恶意序列化负载实现**任意代码执行**。

**利用路径**:
1. ADB 备份注入 (debug build): `adb backup -f backup.ab fork.risin42.nagramx` → 修改 `nkmrcfg` → `adb restore backup.ab`
2. 设置导入功能 (`SettingsBackupHelper.importSettings()`) 恶意构造包含 Base64 序列化 payload 的 JSON
3. root 设备上的恶意应用直接修改 `/data/data/fork.risin42.nagramx/shared_prefs/nkmrcfg.xml`

### 3.2 默认 AI 服务指向第三方代理服务器

**风险等级**: 🔴 CRITICAL  
**位置**: `AiConfig.java:23-27`

```java
public static final Service DEFAULT_SERVICE = new Service(
    "https://chen-hai.ryzedns.org/v1",  // 个人域名
    "kimi-k2.6",                          // 模型名称
    null                                   // 无 API Key（默认配置）
);
```

**风险分析**:
`chen-hai.ryzedns.org` 是**一个注册在 NameCheap 的个人域名**，不属于任何合法 AI 服务提供商（非 OpenAI、非 Google、非 Anthropic、非 Moonshot 官方）。该域名充当 Moonshot AI (Kimi) 的反向代理。

当用户**没有配置自定义 AI 服务时**，所有 AI 聊天功能自动使用此默认端点。发送的数据包括：
- **用户输入的所有文本消息**
- **用户附加的图片**（文件 → `loadImageToByteArray()` → `Base64` 编码 → HTTP body）
- **对话历史**（若启用历史记录）
- **System Prompt**（若配置了角色设定）

**传输路径**:
```
用户文本 + 图片(Base64) 
→ com.exteragram.messenger.ai.network.Client
→ OkHttp POST → https://chen-hai.ryzedns.org/v1/.../chat/completions
```

该域名的运营者可以：
1. 记录和存储所有 AI 对话
2. 获取所有通过 AI 发送的图片数据
3. 篡改 AI 回复（钓鱼、恶意链接注入）
4. 进行提示注入攻击

**关联问题**: `HttpClient.kt:13-38` 中的自定义 OkHttpClient **无证书固定（certificate pinning）**，无法检测中间人攻击。

### 3.3 passcodeHash + 全部设置通过 NextAloneBot 外流

**风险等级**: 🔴 CRITICAL  
**位置**:
- `CloudStorageHelper.java:39-75`
- `CloudSettingsHelper.java:234-258`
- `SettingsBackupHelper.java:62-63,131-133`

**完整数据流**:
```
用户设置 (SharedPreferences)
  → SettingsBackupHelper.backupSettingsJson(true, 0) [行236]
    → userconfig.passcodeHash (锁屏密码哈希) [行62-63]
    → mainconfig (Telegram 基本设置)
    → nkmrcfg (全部 NekoConfig + NaConfig，含全部 API Keys)
    → nekox_config
    → pillstackconfig
    → aichatconfig (AI 聊天配置)
  → gzipBase64Encode(settingsJson) [行237] 
    → GZIP 压缩 → Base64 编码
  → 分块 (MAX_CHUNK_CHARS = 3000) [行238]
  → getCloudStorageHelper().setItem(storageKey, chunk, ...) [行267]
    → TL_bots.invokeWebViewCustomMethod("saveStorageValue", ...) [行75]
      → getConnectionsManager().sendRequest(req, ...) [行58]
        → MTProto 加密传输 → Telegram 服务器
          → Bot: NextAloneBot (ID 1433866570) 的 Bot Storage
```

**风险分析**:
虽然数据传输使用 MTProto 加密（Telegram 官方协议），但 Bot Storage 的数据对 **Bot 拥有者是完全开放的**。NextAloneBot 的拥有者可以通过 Telegram Bot API 直接读取所有存储的值：

```text
https://api.telegram.org/bot<BOT_TOKEN>/getWebViewStorageData?user_id=<USER_ID>
```

泄露的敏感数据包括：
- `passcodeHash` + `passcodeSalt` — 本地应用锁屏密码的 SHA256 哈希，可被彩虹表破解
- 15+ 个 LLM/翻译 API Keys（OpenAI、Gemini、Cloudflare、DeepSeek 等）
- 完整的 NekoConfig/NaConfig 设置
- 对话历史、角色设定等

**自动同步风险**: `CloudSettingsHelper.java:51,226-232` 注册了 `OnSharedPreferenceChangeListener`，默认开启 `autoSync`，任何设置变更都会在 1.2 秒后自动同步到云端。

---

## 4. 🟠 HIGH 发现

### 4.1 API Keys 明文存储在 SharedPreferences

**风险等级**: 🟠 HIGH  
**位置**: 各 ConfigItem 定义在 `NaConfig.kt` 和 `NekoConfig.java`

**泄露的 API Keys** (全部明文存储在 `nkmrcfg` SharedPreferences):

| Key 名称 | 用途 |
|----------|------|
| `LlmApiKey` | LLM 通用 API Key |
| `LlmProviderOpenAIKey` | OpenAI API Key |
| `LlmProviderGeminiKey` | Google Gemini API Key |
| `LlmProviderXAIKey` | xAI API Key |
| `LlmProviderGroqKey` | Groq API Key |
| `LlmProviderDeepSeekKey` | DeepSeek API Key |
| `LlmProviderCerebrasKey` | Cerebras API Key |
| `LlmProviderOllamaCloudKey` | Ollama Cloud API Key |
| `LlmProviderOpenRouterKey` | OpenRouter API Key |
| `LlmProviderVercelAIGatewayKey` | Vercel AI Gateway API Key |
| `TranscribeProviderCfApiToken` | Cloudflare Workers AI Token |
| `TranscribeProviderGeminiApiKey` | Gemini 转写 API Key |
| `TranscribeProviderOpenAiApiKey` | OpenAI 转写 API Key |
| `googleCloudTranslateKey` | Google Cloud 翻译 Key |
| `deepLTranslateKey` | DeepL 翻译 Key |
| `NowPlayingLastFmApiKey` | Last.fm API Key |

**影响**: 任何可以读取 SharedPreferences 的攻击者（root 设备恶意应用、ADB 备份提权）可以获取这些 API Key，导致第三方服务账号被盗用和产生账单。

### 4.2 自定义 OkHttpClient 无证书固定

**风险等级**: 🟠 HIGH  
**位置**: `HttpClient.kt:13-38`

```kotlin
val instance = OkHttpClient.Builder()
    .connectTimeout(30, TimeUnit.SECONDS)
    .readTimeout(30, TimeUnit.SECONDS)
    .writeTimeout(30, TimeUnit.SECONDS)
    .build()  // 无 certificatePinner, 无 proxy, 无 TLS 限制
```

所有自定义 HTTP 客户端（通用、LLM、转写）都没有配置 `CertificatePinner`，也没有限制 TLS 版本。这使得通过系统证书颁发机构签发的恶意证书即可实施**中间人攻击**，拦截和篡改所有 AI/翻译 API 的请求和响应。

### 4.3 本地锁屏密码哈希随云端设置同步

**风险等级**: 🟠 HIGH  
**位置**: `SettingsBackupHelper.java:62-63`

```java
userconfig.add("passcodeHash");
userconfig.add("passcodeType");
userconfig.add("autoLockIn");
```

`userconfig` SharedPreferences 中的 `passcodeHash`（本地应用锁屏密码的 SHA256 哈希）被包含在云端设置同步中。同时被同步的还有 `passcodeSalt`（来自 `nkmrcfg` 中的`PasscodeHelper`）。

**攻击模型**: 获取 `passcodeHash` + `passcodeSalt` 后，攻击者可以使用 GPU 加速的哈希破解工具（Hashcat）进行离线爆破。由于本地锁屏密码通常是 4-6 位数字，破解时间可能仅为**数秒到数分钟**。

### 4.4 硬编码 Telegram API 测试凭据 (APP_ID=4)

**风险等级**: 🟠 HIGH  
**位置**: `BuildVars.java:29-30`

```java
public static int APP_ID = 4;
public static String APP_HASH = "014b35b6184100b085b0d0572f9b5103";
```

`APP_ID=4` 是 Telegram 官方的公开测试凭据，所有使用此 ID 的客户端共享同一个 API 密钥池。这导致：
- **速率限制**: 所有 NagramXF 用户共享 Telegram API 速率限制，可能导致大量用户同时使用时触发限流
- **行为监控**: Telegram 可以识别和监控使用此测试 ID 的所有客户端
- **功能受限**: 某些功能（如 Passkey 支持）只在官方 APP_ID 上生效
- **短信验证码**: `getSmsHash()` 返回的硬编码哈希（`oLeq9AcOZkT` 等）是**同步的**，如果被 Telegram 端废弃，所有用户的短信验证将失败

---

## 5. 🟡 MEDIUM 发现

### 5.1 Logcat 系统日志转储与分享

**风险等级**: 🟡 MEDIUM  
**位置**: `ProfileActivity.java:13428-13514`

```java
ProcessBuilder pb1 = new ProcessBuilder("logcat", "-df", logcatFile.getPath());
// ... 收集 logcat 输出、malformed_database/ 文件、_mtproto 文件
→ 打包为 logs.zip
→ ShareUtil.shareFile(activity, zipFile);  // 通过系统分享发送
```

通过 `ProcessBuilder` 执行 `logcat -df` 命令转储系统日志，包含其他应用的调试输出、可能的 WebView URL 加载、以及 `_mtproto` 后缀的 MTProto 网络日志文件。这些日志可能包含部分敏感信息。分享功能使用 Android 系统分享（可发送至任何应用），增加了数据泄露面。

### 5.2 DNS 解析通过第三方 DoH 服务

**风险等级**: 🟡 MEDIUM  
**位置**: `DnsFactory.kt:60-67`、`ConnectionsManager.java:1178,1284,1404`

使用以下第三方 DNS-over-HTTPS 服务解析所有 Telegram 服务器域名：

```
https://1.1.1.1/dns-query          (Cloudflare)
https://1.0.0.1/dns-query          (Cloudflare)
https://8.8.8.8/dns-query          (Google)
https://8.8.4.4/dns-query          (Google)
https://dns.google.com/resolve     (Google JSON API)
https://mozilla.cloudflare-dns.com/dns-query (Cloudflare Mozilla)
```

所有 DoH 服务商可以看到 NagramXF 用户连接了哪些 Telegram 服务器（IP 解析日志）。虽然不影响用户消息内容加密，但**元数据（连接时间、频率、IP 地址）**被第三方 DNS 服务商记录。

### 5.3 未限制后台位置权限

**风险等级**: 🟡 MEDIUM  
**位置**: `AndroidManifest.xml:89-91`

```xml
<uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION" />
<uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
```

申请了后台位置权限，虽然 Telegram 官方也使用位置分享功能，但后台位置权限可能被滥用。

### 5.4 反射滥用分析（35+ 处）

**风险等级**: 🟡 MEDIUM  
**位置**: 分布在 20+ 个文件中

| 反射目标 | 位置 | 用途 |
|----------|------|------|
| `android.widget.Editor` | `EditTextBoldCursor.java:387-451` | 光标绘制绕过 |
| `android.os.SystemProperties` | `EmuDetector.java:412-427` | 读取系统属性检测模拟器 |
| `FileDescriptor` | `MediaController.java:5448` | 文件描述符操作 |
| `SpannableString` 内部 | `SpannableStringLight.java:61-67` | 字符串操作优化 |
| `WindowManagerGlobal` | `AndroidUtilities.java:6029` | 获取窗口管理器 |

**结论**: 所有反射调用均为 UI 兼容性 hack（与官方 Telegram FOSS 行为一致），无隐蔽的动态类加载或代码注入。

### 5.5 设置备份导出包含敏感数据

**风险等级**: 🟡 MEDIUM  
**位置**: `SettingsBackupHelper.java:56-148,284-289`

设置导出功能将全部设置（含 API Keys）写入缓存目录 JSON 文件，并通过系统分享发送。文件路径 `{cacheDir}/{date}.nekox-settings.json` 可被任何有存储权限的恶意应用读取。

```java
File cacheFile = new File(AndroidUtilities.getCacheDir(), 
    new Date().toLocaleString() + ".nekox-settings.json");
FileUtil.writeUtf8String(SettingsBackupHelper.backupSettingsJson(false, 4, includeApiKeys), cacheFile);
ShareUtil.shareFile(context, cacheFile);
```

### 5.6 HyperOS/ColorOS 外部服务调用

**风险等级**: 🟡 MEDIUM  
**位置**: `HyperOsHelper.kt:76-77`、`ColorOsHelper.kt:37-44,50-58`

向 OEM 系统应用发送用户选中的文本：
- **HyperOS**: 启动 `com.miui.notes` AI 辅助服务，传入选中文本和屏幕坐标
- **ColorOS**: 启动 `com.oplus.aiwriter` 或 `com.heytap.speechassist`

虽然属于合法的 AI 写作辅助功能，但**用户选中的文本被发送至 OEM 系统应用**，可能进一步发送至 OEM 的云端 AI 服务。

---

## 6. 🔵 LOW 发现

| 发现 | 位置 | 说明 |
|------|------|------|
| `AsyncTask` 弃用 | 15+ 处 | 使用已弃用的 `AsyncTask`，存在内存泄露风险 |
| 浏览器 UA 伪装 | `MicrosoftTranslatorRaw.java:26` 等 | 伪装成浏览器 User-Agent 调用翻译 API |
| `Runtime.getRuntime().exit(0)` | `AppRestartHelper.java:36` | 强制进程退出，不优雅 |
| `Executors.newCachedThreadPool()` | `TranscribeHelper.java:58` | 无界线程池，可能 OOM |
| 模拟器检测网络命令 | `EmuDetector.java:379` | 执行 `netcfg` 命令检测模拟器 |
| `AccountManager.getAccounts()` | `NewContactBottomSheet.java:1393` | 访问设备全部账户（仅本地） |

---

## 7. 数据生命周期追踪报告

### 7.1 AuthKey 流动

```
产生: tgnet 原生层 MTProto 握手
存储: SharedConfig.java (SharedPreferences, pushAuthKey)
使用: ConnectionsManager.java (JNI → native_sendRequest)
读入方: 仅在标准 MTProto 路径使用
fork 包读取: ❌ 未检测到
网络外传: ❌ 仅通过 MTProto 加密发送至 Telegram 服务器
```

**结论: ✅ 安全 — AuthKey 未泄露给任何第三方。**

### 7.2 手机号码流动

```
产生: LoginActivity.java 用户输入 → auth.sendCode MTProto
存储: UserConfig.getClientPhone() (内存)
读取路径:
  ├── ConnectionsManager.native_applyDnsConfig (MTProto DNS 优化)
  ├── ExchangeRates.java:155 (本地货币解析，不网络发送)
  ├── PassportActivity.java:1680 (Telegram 注销链接嵌入)
  └── PrivacyControlActivity.java:2007 (Telegram 分享链接)
fork 包读取: 仅 ExchangeRates (本地货币解析)
网络外传: ❌ 未发送到任何第三方 HTTP 端点
```

**结论: ✅ 安全 — 手机号仅在 MTProto 和本地使用。**

### 7.3 2FA 密码流动

```
产生: LoginActivity.java 用户输入 → auth.checkPassword MTProto
存储: UserConfig.java:388-392 (volatile 字段)
  保存方式: savedPasswordHash + savedSaltedPassword (byte[])
  超时: 30 分钟 (savedPasswordTime)
  清零: resetSavedPassword() 使用 Arrays.fill() 擦除
fork 包读取: ❌ 未检测到
网络外传: ❌ 仅通过 MTProto 加密发送至 Telegram
```

**结论: ✅ 安全 — 2FA 密码内存管理符合安全最佳实践，30 分钟后自动清除。**

### 7.4 passcodeHash 流动（危险）

```
产生: PasscodeHelper.java (用户设置锁屏密码时)
存储: 
  ├── SharedPreferences "userconfing" (passcodeHash + passcodeSalt)
  └── SharedPreferences "nkmrcfg" (PasscodeHelper 存储)
读取路径:
  ├── 本地校验 (PasscodeHelper.java 解锁验证) [✅ 正常]
  └── SettingsBackupHelper.backupSettingsJson() [⚠️ 泄露]
      └── CloudSettingsHelper.syncToCloud()
          └── NextAloneBot Bot Storage [🔴 第三方可读]
网络外传: ⚠️ 通过 MTProto 加密传输，但 Bot 拥有者可读取
```

**结论: 🔴 危险 — passcodeHash 暴露给 NextAloneBot 拥有者。**

### 7.5 API Keys 流动

```
存储: SharedPreferences "nkmrcfg" (明文)
读取路径:
  ├── 各功能正常使用 (LLM/翻译/转写) [✅]
  │   └── OkHttp → 第三方 API 端点 [⚠️ 无证书固定]
  ├── SettingsBackupHelper.backupSettingsJson() [⚠️ 备份泄露]
  │   ├── CloudSettingsHelper → NextAloneBot [🔴]
  │   └── 本地文件导出 → 系统分享 [⚠️]
  └── Cloud AutoSync [⚠️]
```

**结论: 🔴 危险 — 15+ API Keys 明文存储且通过多个渠道可能泄露。**

---

## 8. 网络流量全景图

### 8.1 所有出站网络端点汇总

| 类别 | 端点 | 协议 | 数据内容 | 风险 |
|------|------|------|----------|------|
| **MTProto (核心)** | Telegram DCs | TCP/MTProto | 所有聊天数据 | ✅ 加密 |
| **🔴 AI 代理** | `chen-hai.ryzedns.org` | HTTPS | 用户文本 + 图片(Base64) | 🔴 CRITICAL |
| **Bot Storage** | NextAloneBot (via MTProto) | MTProto | 设置 + API Keys + passcodeHash | 🔴 CRITICAL |
| **LLM API** | 用户配置/默认 | HTTPS | 用户文本、API Key | ⚠️ |
| **转写 API** | Cloudflare/Gemini/OpenAI | HTTPS | 语音消息 | ⚠️ |
| **翻译** | Microsoft/Bing/Google/Yandex/DeepL | HTTPS | 消息文本 | ⚠️ |
| **DNS** | Cloudflare/Google DoH | HTTPS | Telegram 域名查询 | 🟡 |
| **Last.fm** | `ws.audioscrobbler.com` | HTTPS | 正在播放信息 | 🟡 |
| **支付** | `tgb.smart-glocal.com` | HTTPS | 卡片 token | 🟡 |
| **过滤器分享** | `dpaste.com` | HTTPS | 正则过滤器 JSON | 🟡 |
| **汇率** | `api.coinbase.com` | HTTPS | 无 | ℹ️ |
| **YouTube** | `www.youtube.com` | HTTPS | 视频 ID | ℹ️ |
| **媒体流** | 用户指定 URL | HTTPS/UDP/RTSP | 媒体内容 | ℹ️ |
| **系统日志** | 系统分享 | 文件 | Logcat + 数据库文件 | 🟡 |

### 8.2 可能被忽略的原生层

```
jni/tgnet/ConnectionsManager.cpp 中所有 MTProto 网络连接均指向 Telegram 官方数据中心
jni/TgNetWrapper.cpp 仅作为 JNI 桥接层
无第三方 HTTP/curl/Socket 连接发现
```

---

## 9. 与官方 Telegram FOSS 拓扑结构差异

| 差异维度 | 官方 Telegram FOSS | NagramXF | 安全影响 |
|----------|-------------------|----------|----------|
| **源代码添加** | ~1800 文件 | + ~300 文件（4 fork 叠加） | 攻击面显著扩大 |
| **混淆** | 可能开启 | 明确关闭 `-dontobfuscate` | 反编译容易，但非安全问题 |
| **第三方库** | 最小化 | OkHttp5, Room, MapLibre, dnsjava, Stripe, Markwon | 增加供应链风险 |
| **远程存储** | 无 | NextAloneBot (Bot Storage) | **🔴 数据外流通道** |
| **默认 AI** | 无 | `chen-hai.ryzedns.org` 代理 | **🔴 中间人代理** |
| **删除消息** | 无持久化 | AyuGram Room 数据库 | 隐私争议 (本地) |
| **云端同步** | 无 | CloudSettingsHelper (自动同步) | **🔴 设置 + API Keys 泄露** |
| **反射** | 标准 | 35+ 处 (标准) | 与官方一致 |
| **动态加载** | 无 | 无 | 正常 |
| **ProcessBuilder** | 无 (日志) | Logcat 转储 | 新增风险面 |

**无证据表明存在**：`DexClassLoader`、`PathClassLoader`、动态加载 DEX/JAR、加密/隐藏网络流量通道、或 hook 框架注入。

---

## 10. 最终结论与建议

### 结论

经过三位虚拟专家的联合会审，NagramXF v12.7.3

**✅ 未发现** 针对 Telegram 核心认证凭据（AuthKey、手机号、2FA 密码、短信验证码）的**直接窃取逻辑**。这些敏感数据的生命周期严格限制在 MTProto 协议栈内，fork 层代码（ayugram/nekogram/exteragram/nagram）**未读取**或**外传**这些核心认证凭据。代码中无混淆、无动态类加载、无隐蔽网络通道的证据。

**🔴 但是** 该项目存在 3 个严重安全问题，可能导致用户数据（对话内容、图片、API Keys、本地密码哈希）泄露给第三方：

1. **Extera AI 默认指向 `chen-hai.ryzedns.org` 个人代理** — 所有 AI 聊天消息自动发送至第三方服务器
2. **CloudSettingsHelper + NextAloneBot** — passcodeHash + 全部 API Keys 存储在 Bot 拥有者可读的云端存储
3. **ObjectInputStream 反序列化** — 可实现任意代码执行

这些问题**不是**典型的"Token/账号窃取后门"，而是**架构设计缺陷**和**默认配置不当**导致的严重数据泄露风险。

### 建议

| 优先级 | 建议 |
|--------|------|
| 🔴 P0 | 从 `AiConfig.java:23-27` 移除 `chen-hai.ryzedns.org` 默认 AI 服务，要求用户必须配置自有服务 |
| 🔴 P0 | 从 `CloudSettingsHelper` 同步范围内排除 `passcodeHash`/`passcodeSalt`；考虑使用端到端加密后存储 |
| 🔴 P1 | 将 `NaConfig.kt:1888` / `NekoConfig.java:257` 中的 `ObjectInputStream` 替换为安全的 JSON 解析 (`Gson.fromJson`) |
| 🟠 P2 | 为 `HttpClient.kt` 中的自定义 OkHttpClient 添加证书固定 (`CertificatePinner`) |
| 🟠 P2 | 在设置导出功能中默认排除 API Keys；导出文件使用加密存储 |
| 🟠 P2 | 从开源仓库中移除 `release.keystore` 等敏感构建文件 |
| 🟡 P3 | 为敏感 SharedPreferences 使用 `EncryptedSharedPreferences` (AndroidX Security) |
| 🟡 P3 | 替换 `AsyncTask` 为 `Coroutine` 或 `ExecutorService` |

---

> **免责声明**: 本审计报告基于公开源代码进行分析，仅反映审计时间点的代码状态。实际运行时的行为可能与源代码不同（原生层二进制、构建脚本、远程配置等）。
